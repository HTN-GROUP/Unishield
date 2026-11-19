import os
import requests
import pandas as pd
from pydantic import BaseModel, Field, ValidationError
from typing import Optional
import psycopg2
from dotenv import load_dotenv

# Environment variables load karein
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
NVD_API_KEY = os.getenv("NVD_API_KEY")

class VulnerabilityRecord(BaseModel):
    cve_id: str = Field(..., description="CVE Identifier")
    description: str
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS score between 0 and 10")
    severity: Optional[str] = "UNKNOWN"
    is_kev: bool = False

def extract_data():
    """Extracts live mixed vulnerability records from NVD API and cross-references with CISA KEV catalog"""
    print("Step 1: Extracting live data from NVD API and CISA KEV catalog...")
    vulnerabilities = []
    kev_cves = set()
    
    # 1. CISA KEV IDs fetch karein
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        kev_response = requests.get(kev_url, timeout=15)
        if kev_response.status_code == 200:
            kev_data = kev_response.json()
            for item in kev_data.get("vulnerabilities", []):
                cve_id = item.get("cveID")
                if cve_id:
                    kev_cves.add(cve_id)
            print(f"Loaded {len(kev_cves)} KEV CVE IDs for cross-matching.")
    except Exception as e:
        print(f"CISA KEV fetch error: {e}")

    # 2. NVD API v2 stable base endpoint
    nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {
        "User-Agent": "UniShield-Security-App/1.0"
    }
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        nvd_response = requests.get(nvd_url, headers=headers, timeout=20)
        print(f"NVD API Response Status Code: {nvd_response.status_code}")
        
        if nvd_response.status_code == 200:
            nvd_data = nvd_response.json()
            items = nvd_data.get("vulnerabilities", [])
            
            for item in items:
                cve_item = item.get("cve", {})
                cve_id = cve_item.get("id", "UNKNOWN")
                
                # Description extract karein
                descriptions = cve_item.get("descriptions", [])
                desc = "No description available"
                for d in descriptions:
                    if d.get("lang") == "en":
                        desc = d.get("value", desc)
                        break
                
                # CVSS Score aur Severity extract karein
                cvss_score = 0.0
                severity = "UNKNOWN"
                metrics = cve_item.get("metrics", {})
                
                cvss_v3 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
                if cvss_v3:
                    cvss_data = cvss_v3[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
                
                # Check karein ke yeh KEV list mein hai ya nahi
                is_kev = cve_id in kev_cves

                vulnerabilities.append({
                    "cve_id": cve_id,
                    "description": desc[:500],
                    "cvss_score": float(cvss_score),
                    "severity": severity,
                    "is_kev": is_kev
                })
            print(f"Successfully fetched {len(vulnerabilities)} live mixed records from NVD API!")
            
    except Exception as e:
        print(f"NVD API fetch error: {e}")

    # Fallback agar API restrict ho ya data na aaye (Mixed severities ke sath)
    if not vulnerabilities:
        print("Warning: Using fallback sample data with mixed severities.")
        vulnerabilities = [
            {"cve_id": "CVE-2023-1111", "description": "Sample Medium vulnerability in software package", "cvss_score": 5.3, "severity": "MEDIUM", "is_kev": False},
            {"cve_id": "CVE-2023-2222", "description": "Sample Critical KEV vulnerability actively exploited", "cvss_score": 9.8, "severity": "CRITICAL", "is_kev": True},
            {"cve_id": "CVE-2023-3333", "description": "Sample High severity vulnerability in network stack", "cvss_score": 7.5, "severity": "HIGH", "is_kev": False},
            {"cve_id": "CVE-2023-4444", "description": "Sample Low severity configuration issue", "cvss_score": 3.1, "severity": "LOW", "is_kev": False}
        ]

    return vulnerabilities

def transform_and_validate(raw_data):
    """Cleans data using pandas and validates using Pydantic"""
    print("Step 2: Transforming and validating data...")
    df = pd.DataFrame(raw_data)
    df = df.drop_duplicates(subset=["cve_id"])
    df['severity'] = df['severity'].fillna("UNKNOWN")
    df['cvss_score'] = df['cvss_score'].fillna(0.0)
    
    validated_records = []
    for _, row in df.iterrows():
        try:
            record = VulnerabilityRecord(
                cve_id=row['cve_id'],
                description=row['description'],
                cvss_score=row['cvss_score'],
                severity=row['severity'],
                is_kev=row['is_kev']
            )
            validated_records.append(record.model_dump())
        except ValidationError as e:
            print(f"Validation error for record {row.get('cve_id')}: {e}")
            
    return validated_records

def load_to_neon(records):
    """Loads validated records into Neon PostgreSQL"""
    print("Step 3: Loading mixed records into Neon PostgreSQL...")
    if not records:
        print("No valid records to load.")
        return

    try:
        connection = psycopg2.connect(DATABASE_URL)
        cursor = connection.cursor()
        
        cursor.execute("DROP TABLE IF EXISTS vulnerabilities;")
        cursor.execute("""
            CREATE TABLE vulnerabilities (
                cve_id VARCHAR(50) PRIMARY KEY,
                description TEXT,
                cvss_score NUMERIC(3,1),
                severity VARCHAR(20),
                is_kev BOOLEAN
            );
        """)
        
        for rec in records:
            cursor.execute("""
                INSERT INTO vulnerabilities (cve_id, description, cvss_score, severity, is_kev)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (cve_id) DO UPDATE 
                SET description = EXCLUDED.description,
                    cvss_score = EXCLUDED.cvss_score,
                    severity = EXCLUDED.severity,
                    is_kev = EXCLUDED.is_kev;
            """, (rec['cve_id'], rec['description'], rec['cvss_score'], rec['severity'], rec['is_kev']))
            
        connection.commit()
        cursor.close()
        connection.close()
        print("Successfully loaded mixed NVD & KEV records into Neon database!")
        
    except Exception as error:
        print(f"Database loading failed: {error}")

if __name__ == "__main__":
    raw = extract_data()
    cleaned_valid_data = transform_and_validate(raw)
    load_to_neon(cleaned_valid_data)