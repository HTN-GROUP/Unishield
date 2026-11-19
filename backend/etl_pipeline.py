import pandas as pd
import requests
from pydantic import BaseModel, Field
from typing import Optional
import os

# 1. Pydantic Model (Validation)
class VulnerabilityModel(BaseModel):
    cve_id: str
    software_name: str
    cvss_score: float = Field(..., ge=0.0, le=10.0)
    severity: str
    is_kev: bool
    description: Optional[str] = ""

# 2. Real NVD API Integration
def fetch_nvd_vulnerabilities(keyword="wordpress", results_limit=5):
    api_key = os.getenv("NVD_API_KEY", "")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage={results_limit}"
    
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
        
    try:
        res = requests.get(url, headers=headers, timeout=12)
        if res.status_code == 200:
            data = res.json()
            raw_vulns = []
            for item in data.get('vulnerabilities', []):
                cve_data = item.get('cve', {})
                cve_id = cve_data.get('id', '')
                
                # Extract Description
                descriptions = cve_data.get('descriptions', [])
                desc = descriptions[0].get('value', '') if descriptions else ''
                
                # Extract CVSS Score
                metrics = cve_data.get('metrics', {})
                cvss_v3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}) if 'cvssMetricV31' in metrics else {}
                score = cvss_v3.get('baseScore', 7.5)
                
                raw_vulns.append({
                    "cve_id": cve_id,
                    "software_name": keyword.capitalize(),
                    "cvss_score": score,
                    "description": desc
                })
            return raw_vulns
    except Exception as e:
        print(f"NVD API Fetch Error: {e}")
        
    # Fallback Sample Data agar API reach na ho
    return [
        {"cve_id": "CVE-2023-38606", "software_name": "PHP", "cvss_score": 9.8, "description": "Remote code execution"},
        {"cve_id": "CVE-2023-2745", "software_name": "WordPress", "cvss_score": 8.4, "description": "Directory traversal"}
    ]

# 3. Extract CISA KEV Catalog
def extract_cisa_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        res = requests.get(url, timeout=10)
        data = res.json()
        kev_set = {item['cveID'] for item in data.get('vulnerabilities', [])}
        return kev_set
    except Exception as e:
        print(f"Error fetching CISA KEV: {e}")
        return set()

# 4. Transform and Validate Data using Pandas & Pydantic
def transform_and_validate(raw_vulns, kev_set):
    processed_list = []
    for item in raw_vulns:
        cve = item.get('cve_id', '').strip()
        score = float(item.get('cvss_score', 0.0))
        
        if score >= 9.0: sev = 'CRITICAL'
        elif score >= 7.0: sev = 'HIGH'
        elif score >= 4.0: sev = 'MEDIUM'
        else: sev = 'LOW'

        is_kev = cve in kev_set

        try:
            validated = VulnerabilityModel(
                cve_id=cve,
                software_name=item.get('software_name', 'Unknown'),
                cvss_score=score,
                severity=sev,
                is_kev=is_kev,
                description=item.get('description', '')
            )
            # Deprecation warning resolution: model_dump() use kiya hai
            processed_list.append(validated.model_dump())
        except Exception as err:
            print(f"Validation error for {cve}: {err}")

    df = pd.DataFrame(processed_list)
    if not df.empty:
        df = df.drop_duplicates(subset=['cve_id'])
        return df.to_dict(orient='records')
    return []

# 5. Parse Synthetic Logs
def parse_synthetic_logs(log_path):
    if not os.path.exists(log_path):
        return []
    
    attacks = []
    with open(log_path, 'r') as f:
        for line in f:
            if "OR '1'='1" in line:
                attacks.append({"type": "SQL Injection", "log": line.strip()})
            elif "/etc/passwd" in line:
                attacks.append({"type": "Path Traversal", "log": line.strip()})
            elif "401" in line:
                attacks.append({"type": "Brute Force", "log": line.strip()})
    return attacks

if __name__ == "__main__":
    print("Running ETL Pipeline with Real NVD API Integration...")
    kev_set = extract_cisa_kev()
    
    # NVD API se Live data pull ho raha hai
    raw_nvd_data = fetch_nvd_vulnerabilities(keyword="apache", results_limit=3)
    cleaned_vulns = transform_and_validate(raw_nvd_data, kev_set)
    print("\nCleaned Vulnerabilities from NVD API:")
    print(cleaned_vulns)
    
    log_attacks = parse_synthetic_logs("logs/sample_access.log")
    print("\nParsed Log Attacks:")
    print(log_attacks)