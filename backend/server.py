import os
import sys
from flask import Flask, jsonify
from flask_cors import CORS

# Ensure backend directory is in sys.path on Vercel
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


@app.route("/", methods=["GET"])
@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "ok" if ETL_IMPORT_ERROR is None else "degraded",
        "etl_import_error": ETL_IMPORT_ERROR,
    }), 200


@app.route("/api/vulnerabilities", methods=["GET"])
def get_vulnerabilities():
    if ETL_IMPORT_ERROR:
        return jsonify({"error": ETL_IMPORT_ERROR}), 500
    try:
        kev_set = extract_cisa_kev()
        raw_nvd = fetch_nvd_vulnerabilities(keyword="apache", results_limit=10)
        cleaned = transform_and_validate(raw_nvd, kev_set)
        return jsonify(cleaned), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/logs", methods=["GET"])
def get_logs():
    if ETL_IMPORT_ERROR:
        return jsonify({"error": ETL_IMPORT_ERROR}), 500
    try:
        log_path = os.path.join(BASE_DIR, "logs", "sample_access.log")
        attacks = parse_synthetic_logs(log_path)
        return jsonify(attacks), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)