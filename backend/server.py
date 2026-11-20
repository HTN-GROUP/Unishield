from http.server import BaseHTTPRequestHandler
import importlib.util
import json
import os
import sys


def get_dir_snapshot(root_path, max_depth=3):
    snapshot = []
    if not os.path.exists(root_path):
        return [f"MISSING: {root_path}"]

    root_depth = root_path.rstrip("\\/").count(os.sep)
    for current_root, dirs, files in os.walk(root_path):
        # Heavy/noisy folders skip karein
        dirs[:] = [
            d for d in dirs
            if d not in {".git", "node_modules", ".venv", "venv", "__pycache__", ".vercel"}
        ]
        current_depth = current_root.rstrip("\\/").count(os.sep) - root_depth
        if current_depth > max_depth:
            dirs[:] = []
            continue

        rel_dir = os.path.relpath(current_root, root_path)
        for name in sorted(files):
            rel_file = name if rel_dir == "." else os.path.join(rel_dir, name)
            full_file = os.path.join(current_root, name)
            try:
                size = os.path.getsize(full_file)
            except OSError:
                size = -1
            snapshot.append({"path": rel_file.replace("\\", "/"), "size": size})
    return snapshot


def read_requirements_if_exists(base_dir):
    candidates = [
        os.path.join(base_dir, "requirements.txt"),
        os.path.join(base_dir, "backend", "requirements.txt"),
        "/var/task/requirements.txt",
        "/var/task/backend/requirements.txt",
    ]
    found = {}
    for path in candidates:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    found[path] = f.read()
            except Exception as e:
                found[path] = f"READ_ERROR: {e}"
    return found


class handler(BaseHTTPRequestHandler):
    def _send_json(self, status_code, payload):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        cwd = os.getcwd()
        script_dir = os.path.dirname(os.path.abspath(__file__))

        report = {
            "status": "debug_alive",
            "requested_path": self.path,
            "python_version": sys.version,
            "cwd": cwd,
            "script_dir": script_dir,
            "sys_path": sys.path,
            "flask_spec_found": importlib.util.find_spec("flask") is not None,
            "pydantic_spec_found": importlib.util.find_spec("pydantic") is not None,
            "requests_spec_found": importlib.util.find_spec("requests") is not None,
            "requirements_found": read_requirements_if_exists(script_dir),
            "files_in_script_dir": get_dir_snapshot(script_dir, max_depth=2),
            "files_in_cwd": get_dir_snapshot(cwd, max_depth=2),
            "env_keys_sample": sorted([
                k for k in os.environ.keys()
                if any(word in k.upper() for word in ["VERCEL", "PYTHON", "ROOT", "API", "PATH"])
            ]),
        }
        self._send_json(200, report)