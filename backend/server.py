import os
import sys
from flask import Flask, jsonify, request
from flask_cors import CORS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

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
    if ETL_IMPORT_ERROR:
        return jsonify({"error": ETL_IMPORT_ERROR}), 500
    try:
        log_path = os.path.join(BASE_DIR, "logs", "sample_access.log")
        attacks = parse_synthetic_logs(log_path)
        if not attacks:
            attacks = [
                {
                    "type": "SQL Injection",
                    "log": '192.168.1.45 - - [20/Nov/2026:10:14:22 +0000] "GET /login.php?user=admin\' OR \'1\'=\'1 HTTP/1.1" 200 1024',
                },
                {
                    "type": "Path Traversal",
                    "log": '10.0.0.88 - - [20/Nov/2026:10:15:09 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 403 512',
                },
                {
                    "type": "Brute Force",
                    "log": '172.16.0.12 - - [20/Nov/2026:10:16:41 +0000] "POST /api/auth HTTP/1.1" 401 256',
                },
            ]
        return jsonify(attacks), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/", methods=["GET"])
@app.route("/server.py", methods=["GET"])
@app.route("/api/health", methods=["GET"])
def health_check():
    endpoint = request.args.get("endpoint", "").lower()
    if endpoint == "logs":
        return _logs_response()
    if endpoint == "vulnerabilities":
        return _vulnerabilities_response()
    return jsonify({
        "status": "ok" if ETL_IMPORT_ERROR is None else "degraded",
        "service": "UniShield Backend",
        "etl_import_error": ETL_IMPORT_ERROR,
    }), 200


@app.route("/api/vulnerabilities", methods=["GET"])
def get_vulnerabilities():
    return _vulnerabilities_response()


@app.route("/api/logs", methods=["GET"])
def get_logs():
    return _logs_response()


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