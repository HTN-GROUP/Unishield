from flask import Flask, jsonify
from flask_cors import CORS
from etl_pipeline import extract_cisa_kev, fetch_nvd_vulnerabilities, transform_and_validate, parse_synthetic_logs

app = Flask(__name__)
CORS(app)

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    kev_set = extract_cisa_kev()
    raw_nvd = fetch_nvd_vulnerabilities(keyword="apache", results_limit=10)
    cleaned = transform_and_validate(raw_nvd, kev_set)
    return jsonify(cleaned)

@app.route('/api/logs', methods=['GET'])
def get_logs():
    attacks = parse_synthetic_logs("logs/sample_access.log")
    return jsonify(attacks)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)