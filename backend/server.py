import os
import re
import sys
from datetime import datetime, timezone
from urllib.parse import unquote, urlparse
from flask import Flask, jsonify, request
from flask_cors import CORS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    import pg8000.native
    PG_AVAILABLE = True
except Exception:
    PG_AVAILABLE = False

try:
    from etl_pipeline import (
        extract_cisa_kev,
        fetch_nvd_vulnerabilities,
        transform_and_validate,
        parse_synthetic_logs,
    )
    ETL_IMPORT_ERROR = None
except Exception as exc:
    ETL_IMPORT_ERROR = str(exc)

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})


def get_db_connection(prefer_direct_host=False):
    db_url = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
    if not db_url or not PG_AVAILABLE:
        return None
    parsed = urlparse(db_url)
    host = parsed.hostname
    if prefer_direct_host and host and "-pooler." in host:
        host = host.replace("-pooler.", ".", 1)
    return pg8000.native.Connection(
        user=unquote(parsed.username or ""),
        password=unquote(parsed.password or ""),
        host=host,
        port=parsed.port or 5432,
        database=(parsed.path or "/neondb").lstrip("/"),
        ssl_context=True,
    )


def run_query(sql, **params):
    last_exc = None
    for attempt in range(3):
        conn = None
        try:
            conn = get_db_connection(prefer_direct_host=(attempt >= 1))
            if not conn:
                raise RuntimeError("Database not configured")
            if params:
                return conn.run(sql, **params)
            return conn.run(sql)
        except Exception as exc:
            last_exc = exc
            err_msg = str(exc).lower()
            if attempt < 2 and (
                "26000" in err_msg
                or "prepared statement" in err_msg
                or "closed" in err_msg
                or "connection" in err_msg
            ):
                continue
            raise
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
    raise last_exc


def ensure_logs_table():
    run_query("""
        CREATE TABLE IF NOT EXISTS live_logs (
            id SERIAL PRIMARY KEY,
            ip_address VARCHAR(100),
            endpoint TEXT,
            method VARCHAR(20),
            attack_type VARCHAR(50),
            user_agent TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)
    run_query("""
        ALTER TABLE live_logs
        ADD COLUMN IF NOT EXISTS user_agent TEXT,
        ADD COLUMN IF NOT EXISTS method VARCHAR(20),
        ADD COLUMN IF NOT EXISTS attack_type VARCHAR(50),
        ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()
    """)


def ensure_blocked_ips_table():
    run_query("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip_address VARCHAR(100) PRIMARY KEY,
            reason TEXT,
            blocked_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)


def get_blocked_ip_set():
    try:
        ensure_blocked_ips_table()
        rows = run_query("SELECT ip_address FROM blocked_ips")
        return {str(r[0]).strip() for r in rows if r and r[0]}
    except Exception:
        return set()


def detect_attack_type(endpoint_str):
    text = unquote(endpoint_str or "").lower()
    if re.search(r"(\bor\b\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+|union\s+select|drop\s+table|--|')", text):
        return "SQL_INJECTION"
    if re.search(r"(\.\./|\.\.\\|/etc/passwd|boot\.ini|win\.ini)", text):
        return "PATH_TRAVERSAL"
    if re.search(r"(<script|javascript:|onerror=|onload=|<img)", text):
        return "XSS_ATTACK"
    if re.search(r"(/wp-admin|/phpmyadmin|\.env|/config|/api/auth)", text):
        return "BRUTE_FORCE_PROBE"
    return "NORMAL_TRAFFIC"


def get_client_ip():
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.headers.get("x-real-ip") or request.remote_addr or "127.0.0.1"


def _track_visit():
    payload = request.get_json(silent=True) or {}
    ip_addr = (payload.get("ip_address") or get_client_ip()).strip()
    visited_endpoint = payload.get("endpoint") or request.args.get("path") or request.full_path or "/"
    method = payload.get("method") or request.method
    user_agent = payload.get("user_agent") or request.headers.get("User-Agent", "")
    attack_type = payload.get("attack_type") or detect_attack_type(visited_endpoint)

    try:
        db_url = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
        if db_url and PG_AVAILABLE:
            ensure_logs_table()
            blocked_set = get_blocked_ip_set()
            is_blocked = ip_addr in blocked_set
            run_query(
                """
                INSERT INTO live_logs (ip_address, endpoint, method, attack_type, user_agent, created_at)
                VALUES (:ip, :ep, :m, :at, :ua, NOW())
                """,
                ip=ip_addr,
                ep=visited_endpoint,
                m=method,
                at=attack_type,
                ua=user_agent[:300],
            )
            return jsonify({
                "status": "blocked_recorded" if is_blocked else "recorded",
                "blocked": is_blocked,
                "ip_address": ip_addr,
                "endpoint": visited_endpoint,
                "attack_type": attack_type,
            }), 201

        return jsonify({
            "status": "db_not_configured",
            "blocked": False,
            "ip_address": ip_addr,
            "endpoint": visited_endpoint,
            "attack_type": attack_type,
        }), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


def _vulnerabilities_response():
    if ETL_IMPORT_ERROR:
        return jsonify({"error": ETL_IMPORT_ERROR}), 500
    try:
        keyword = request.args.get("keyword", "apache")
        kev_set = extract_cisa_kev()
        raw_nvd = fetch_nvd_vulnerabilities(keyword=keyword, results_limit=10)
        cleaned = transform_and_validate(raw_nvd, kev_set)
        return jsonify(cleaned), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


def _logs_response():
    limit_param = request.args.get("limit", "1000")
    try:
        row_limit = max(1, min(int(limit_param), 5000))
    except ValueError:
        row_limit = 1000

    try:
        db_url = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
        if db_url and PG_AVAILABLE:
            ensure_logs_table()
            blocked_set = get_blocked_ip_set()
            rows = run_query(f"""
                SELECT id, ip_address, endpoint, method, attack_type, created_at
                FROM live_logs
                ORDER BY created_at DESC, id DESC
                LIMIT {row_limit}
            """)
            if rows is not None:
                logs = []
                for r in rows:
                    ip_val = (r[1] or "Unknown").strip()
                    created_val = r[5].isoformat() if hasattr(r[5], "isoformat") else str(r[5])
                    logs.append({
                        "id": r[0],
                        "ip_address": ip_val,
                        "endpoint": r[2] or "/",
                        "method": r[3] or "GET",
                        "attack_type": r[4] or "NORMAL_TRAFFIC",
                        "type": r[4] or "NORMAL_TRAFFIC",
                        "blocked": ip_val in blocked_set,
                        "created_at": created_val,
                        "timestamp": created_val,
                    })
                return jsonify(logs), 200
    except Exception:
        pass

    if ETL_IMPORT_ERROR:
        return jsonify({"error": ETL_IMPORT_ERROR}), 500

    try:
        log_path = os.path.join(BASE_DIR, "logs", "sample_access.log")
        attacks = parse_synthetic_logs(log_path)
    except Exception:
        attacks = []

    now_iso = datetime.now(timezone.utc).isoformat()
    if not attacks:
        attacks = [
            {
                "type": "SQL_INJECTION",
                "attack_type": "SQL_INJECTION",
                "ip_address": "192.168.1.45",
                "endpoint": "/login.php?user=admin' OR '1'='1",
                "method": "GET",
                "blocked": False,
                "timestamp": now_iso,
                "created_at": now_iso,
                "log": '192.168.1.45 - - [20/Nov/2026:10:14:22 +0000] "GET /login.php?user=admin\' OR \'1\'=\'1 HTTP/1.1" 200 1024',
            },
            {
                "type": "PATH_TRAVERSAL",
                "attack_type": "PATH_TRAVERSAL",
                "ip_address": "10.0.0.88",
                "endpoint": "/download?file=../../../../etc/passwd",
                "method": "GET",
                "blocked": False,
                "timestamp": now_iso,
                "created_at": now_iso,
                "log": '10.0.0.88 - - [20/Nov/2026:10:15:09 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 403 512',
            },
            {
                "type": "BRUTE_FORCE_PROBE",
                "attack_type": "BRUTE_FORCE_PROBE",
                "ip_address": "172.16.0.12",
                "endpoint": "/api/auth",
                "method": "POST",
                "blocked": False,
                "timestamp": now_iso,
                "created_at": now_iso,
                "log": '172.16.0.12 - - [20/Nov/2026:10:16:41 +0000] "POST /api/auth HTTP/1.1" 401 256',
            },
        ]
    else:
        normalized = []
        for item in attacks:
            if isinstance(item, dict):
                raw_log = item.get("log", "")
                ip_guess = (item.get("ip_address") or (raw_log.split(" ")[0] if raw_log else "192.168.1.45")).strip()
                ep_guess = item.get("endpoint") or raw_log or "/"
                t_val = item.get("attack_type") or item.get("type") or "NORMAL_TRAFFIC"
                ts_val = item.get("timestamp") or item.get("created_at") or now_iso
                normalized.append({
                    **item,
                    "ip_address": ip_guess,
                    "endpoint": ep_guess,
                    "method": item.get("method") or "GET",
                    "attack_type": t_val,
                    "type": t_val,
                    "blocked": bool(item.get("blocked", False)),
                    "timestamp": ts_val,
                    "created_at": ts_val,
                })
        attacks = normalized

    return jsonify(attacks), 200


def _clear_logs_action():
    payload = request.get_json(silent=True) or {}
    clear_all = bool(payload.get("all", False) or str(request.args.get("all", "")).lower() in ("1", "true", "yes"))
    older_than_days = payload.get("older_than_days")

    try:
        db_url = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
        if not db_url or not PG_AVAILABLE:
            return jsonify({"error": "Database not configured"}), 500
        ensure_logs_table()

        before_rows = run_query("SELECT COUNT(*) FROM live_logs")
        before_count = int(before_rows[0][0]) if before_rows else 0

        if clear_all:
            run_query("DELETE FROM live_logs")
        else:
            try:
                days_val = int(older_than_days if older_than_days is not None else request.args.get("days", 1))
                days_val = max(0, min(days_val, 365))
            except ValueError:
                days_val = 1

            if days_val == 0:
                run_query("DELETE FROM live_logs")
            else:
                run_query(
                    "DELETE FROM live_logs WHERE created_at < NOW() - (:d * INTERVAL '1 day')",
                    d=days_val,
                )

        after_rows = run_query("SELECT COUNT(*) FROM live_logs")
        after_count = int(after_rows[0][0]) if after_rows else 0
        deleted_count = max(0, before_count - after_count)

        return jsonify({
            "status": "cleared",
            "deleted_count": deleted_count,
            "remaining_count": after_count,
        }), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


def _block_ip_action():
    payload = request.get_json(silent=True) or {}
    ip_addr = (payload.get("ip_address") or request.args.get("ip") or "").strip()
    reason = (payload.get("reason") or "Blocked via UniShield SOC").strip()
    if not ip_addr:
        return jsonify({"error": "ip_address is required"}), 400

    try:
        db_url = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
        if not db_url or not PG_AVAILABLE:
            return jsonify({"error": "Database not configured"}), 500
        ensure_blocked_ips_table()
        run_query(
            """
            INSERT INTO blocked_ips (ip_address, reason, blocked_at)
            VALUES (:ip, :r, NOW())
            ON CONFLICT (ip_address) DO UPDATE SET reason = :r, blocked_at = NOW()
            """,
            ip=ip_addr,
            r=reason,
        )
        return jsonify({"status": "blocked", "ip_address": ip_addr}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


def _unblock_ip_action():
    payload = request.get_json(silent=True) or {}
    ip_addr = (payload.get("ip_address") or request.args.get("ip") or "").strip()
    if not ip_addr:
        return jsonify({"error": "ip_address is required"}), 400

    try:
        db_url = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
        if not db_url or not PG_AVAILABLE:
            return jsonify({"error": "Database not configured"}), 500
        ensure_blocked_ips_table()
        run_query("DELETE FROM blocked_ips WHERE ip_address = :ip", ip=ip_addr)
        return jsonify({"status": "unblocked", "ip_address": ip_addr}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


def _blocked_ips_list():
    try:
        db_url = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
        if not db_url or not PG_AVAILABLE:
            return jsonify([]), 200
        ensure_blocked_ips_table()
        rows = run_query("SELECT ip_address, reason, blocked_at FROM blocked_ips ORDER BY blocked_at DESC")
        data = [
            {
                "ip_address": r[0],
                "reason": r[1] or "",
                "blocked_at": r[2].isoformat() if hasattr(r[2], "isoformat") else str(r[2]),
            }
            for r in rows
        ]
        return jsonify(data), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


def _chat_response():
    payload = request.get_json(silent=True) or {}
    user_msg = str(
        payload.get("message")
        or payload.get("query")
        or payload.get("prompt")
        or payload.get("text")
        or request.args.get("message")
        or ""
    ).strip()

    if not user_msg:
        return jsonify({
            "reply": "Please ask a question about CVEs, CISA KEV vulnerabilities, SQL injection, XSS, path traversal, or blocking IPs."
        }), 200

    lower = user_msg.lower()

    db_stats_note = ""
    try:
        db_url = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
        if db_url and PG_AVAILABLE:
            ensure_logs_table()
            ensure_blocked_ips_table()
            log_cnt_rows = run_query("SELECT COUNT(*) FROM live_logs")
            blk_cnt_rows = run_query("SELECT COUNT(*) FROM blocked_ips")
            total_logs = int(log_cnt_rows[0][0]) if log_cnt_rows else 0
            total_blocked = int(blk_cnt_rows[0][0]) if blk_cnt_rows else 0
            db_stats_note = f" (Current DB: {total_logs} live logs, {total_blocked} blocked IPs)"
    except Exception:
        db_stats_note = ""

    if any(g in lower for g in ("aoa", "assalam", "hello", "hi", "hey", "salam")):
        reply = (
            f"Walaikum Assalam! I am the UniShield AI Security Assistant{db_stats_note}. "
            "Ask me about critical vulnerabilities, CISA KEV items, SQL injection, XSS, path traversal, or IP blocking."
        )
    elif "kev" in lower or "exploited" in lower:
        reply = (
            "CISA KEV (Known Exploited Vulnerabilities) lists CVEs with confirmed active exploitation. "
            "Prioritize patching KEV items first, especially public-facing web apps, servers, and plugins."
        )
    elif "sql" in lower or "sqli" in lower:
        reply = (
            "SQL Injection happens when untrusted input reaches SQL queries without proper parameterization. "
            "Always use parameterized queries/prepared statements, validate input types, and block repeat attacker IPs."
        )
    elif "xss" in lower or "script" in lower:
        reply = (
            "Cross-Site Scripting (XSS) runs untrusted scripts in a victim's browser. "
            "Use context-aware output encoding, sanitize HTML inputs, and enforce a Content Security Policy (CSP)."
        )
    elif "path" in lower or "traversal" in lower or "../" in lower:
        reply = (
            "Path Traversal attempts to access restricted files outside the web root using sequences like '../'. "
            "Canonicalize paths, enforce an allow-list/base directory check, and block probing IPs."
        )
    elif "block" in lower or "ip" in lower or "firewall" in lower:
        reply = (
            f"To block or unblock an IP in UniShield{db_stats_note}, open the Attack Map tab, "
            "enter the IP in the manual rule box or use the row action button, and refresh to verify persistence."
        )
    elif "cve" in lower or "critical" in lower or "patch" in lower or "vulnerability" in lower:
        reply = (
            "Prioritize CVEs by combining CVSS score, CISA KEV exploitation status, and exposure on internet-facing assets. "
            "Review the Fix First and CVE Explorer tabs for prioritized items."
        )
    else:
        reply = (
            f"UniShield SOC Assistant{db_stats_note}: For '{user_msg}', monitor real-time traffic in Attack Map, "
            "filter attack types (SQL_INJECTION, XSS_ATTACK, PATH_TRAVERSAL, BRUTE_FORCE_PROBE), and block repeat offenders."
        )

    return jsonify({
        "reply": reply,
        "response": reply,
        "message": reply,
    }), 200


@app.route("/", methods=["GET", "POST", "DELETE", "OPTIONS"])
@app.route("/server.py", methods=["GET", "POST", "DELETE", "OPTIONS"])
@app.route("/api/health", methods=["GET"])
def health_check():
    if request.method == "OPTIONS":
        return ("", 204)

    endpoint = (request.args.get("endpoint") or "").strip().lower()

    if endpoint == "chat":
        return _chat_response()
    if endpoint == "block_ip":
        return _block_ip_action()
    if endpoint == "unblock_ip":
        return _unblock_ip_action()
    if endpoint == "blocked_ips":
        return _blocked_ips_list()
    if endpoint == "clear_logs" or request.method == "DELETE":
        return _clear_logs_action()
    if endpoint == "logs":
        return _logs_response()
    if endpoint == "vulnerabilities":
        return _vulnerabilities_response()
    if endpoint == "track" or request.method == "POST":
        return _track_visit()

    return jsonify({
        "status": "ok" if ETL_IMPORT_ERROR is None else "degraded",
        "service": "UniShield Backend",
        "etl_import_error": ETL_IMPORT_ERROR,
        "db_driver_ready": PG_AVAILABLE,
        "db_url_configured": bool(os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")),
    }), 200


@app.route("/api/chat", methods=["POST", "GET"])
@app.route("/chat", methods=["POST", "GET"])
def api_chat():
    return _chat_response()


@app.route("/api/track", methods=["POST", "GET"])
def track_route():
    return _track_visit()


@app.route("/api/vulnerabilities", methods=["GET"])
def get_vulnerabilities():
    return _vulnerabilities_response()


@app.route("/api/logs", methods=["GET", "DELETE"])
def get_logs():
    if request.method == "DELETE":
        return _clear_logs_action()
    return _logs_response()


@app.route("/api/clear-logs", methods=["POST", "DELETE"])
def api_clear_logs():
    return _clear_logs_action()


@app.route("/api/block-ip", methods=["POST"])
def api_block_ip():
    return _block_ip_action()


@app.route("/api/unblock-ip", methods=["POST"])
def api_unblock_ip():
    return _unblock_ip_action()


@app.route("/api/blocked-ips", methods=["GET"])
def api_blocked_ips():
    return _blocked_ips_list()


class VercelPathFixMiddleware:
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path_info = environ.get("PATH_INFO", "")
        if path_info in ("", "/server.py"):
            for key in (
                "HTTP_X_VERCEL_ORIGINAL_URL",
                "HTTP_X_MATCHED_PATH",
                "HTTP_X_INVOKE_PATH",
                "HTTP_X_REWRITE_URL",
                "REQUEST_URI",
            ):
                val = environ.get(key, "")
                if val:
                    clean = val.split("?")[0]
                    if clean and clean != "/server.py":
                        environ["PATH_INFO"] = clean
                        break
            else:
                environ["PATH_INFO"] = "/"
        return self.wsgi_app(environ, start_response)


app.wsgi_app = VercelPathFixMiddleware(app.wsgi_app)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)