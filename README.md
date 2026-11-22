# 🛡️ UniShield — University Vulnerability & Attack Monitoring SOC Platform

**UniShield** is an end-to-end **ETL + EDA + Security Operations Center (SOC)** web platform designed to monitor software vulnerabilities, detect real-time web attack patterns, and enforce IP-level firewall rules across university and enterprise web ecosystems (including integration with the **Nexus Enterprise Portal**).

---

## 🌐 Live Deployment Links

* **Primary SOC Dashboard (Custom Subdomain):** [https://shield.nexustechautomation.me](https://shield.nexustechautomation.me)
* **Vercel Frontend Mirror:** [https://unishield-theta.vercel.app](https://unishield-theta.vercel.app)
* **Backend API Endpoint:** [https://unishield-backend.vercel.app](https://unishield-backend.vercel.app)

---

## 🎯 Project Objectives & Architecture (ETL + EDA Pipeline)

1. **Extract (Data Ingestion):**
   * Fetches live vulnerability intelligence from the **National Vulnerability Database (NVD API)** and **CISA Known Exploited Vulnerabilities (KEV)** catalog.
   * Captures real-time HTTP traffic, route visits, user agents, and client IP addresses via `unishieldTracker.js` and backend telemetry endpoints.
2. **Transform & Validate (Data Cleaning & Threat Classification):**
   * Uses `pandas` and `Pydantic` validation schemas in `etl_pipeline.py` to normalize severity scores, CVSS metrics, KEV status, and timestamps.
   * Classifies incoming requests into threat categories:
     * `SQL_INJECTION`
     * `XSS_ATTACK`
     * `PATH_TRAVERSAL`
     * `BRUTE_FORCE_PROBE`
     * `NORMAL_TRAFFIC`
3. **Load (Persistent Cloud Storage):**
   * Stores processed traffic logs in **Neon PostgreSQL** (`live_logs` table) and active firewall restrictions in `blocked_ips` using resilient retry logic (`run_query`) to handle serverless connection pooling.
4. **Exploratory Data Analysis (EDA) & Interactive SOC Dashboard:**
   * Visualizes vulnerability severity breakdowns, KEV prioritization ("Fix First"), CVE search/filtering, live attack logs, CSV log exports, log retention controls, IP block/unblock actions, and an **AI Security Assistant**.

---

## 🛠️ Tech Stack

* **Frontend:** React, Tailwind CSS, JavaScript (`App.js`, `Chatbot.js`, `unishieldTracker.js`)
* **Backend:** Python, Flask, Flask-CORS, `pg8000` (`server.py`, `etl_pipeline.py`)
* **Data & Validation:** `pandas`, `Pydantic`, NVD API, CISA KEV Feed
* **Database:** Neon Serverless PostgreSQL (`live_logs`, `blocked_ips`)
* **Hosting & DNS:** Vercel (CI/CD) + Namecheap DNS (`shield.nexustechautomation.me`)

---

## 📂 Key Repository Structure

```text
├── server.py               # Flask API, Neon DB persistence, IP firewall & AI chat endpoints
├── etl_pipeline.py         # NVD & CISA KEV extraction, pandas/Pydantic transformation & log parsing
├── test_db.py              # PostgreSQL connectivity & table verification script
├── requirements.txt        # Python backend dependencies
├── package.json            # React frontend dependencies & build scripts
└── src/
    ├── App.js              # Main SOC Dashboard UI (Overview, Fix First, Attack Map, CVE Explorer)
    ├── components/
    │   └── Chatbot.js      # Interactive AI Security Assistant widget
    └── utils/
        └── unishieldTracker.js  # Real-time traffic & attack telemetry tracker
```

---

## 🔌 Core Backend API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Service & database health check |
| `GET` | `/api/vulnerabilities?keyword=apache` | Extracted & validated NVD + CISA KEV vulnerabilities |
| `POST` | `/api/track` (`/?endpoint=track`) | Logs incoming traffic, classifies threat type, and checks IP block status |
| `GET` | `/api/logs?limit=1000` | Retrieves live traffic and threat logs |
| `POST` | `/api/block-ip` | Adds an IP address to the persistent `blocked_ips` firewall table |
| `POST` | `/api/unblock-ip` | Removes an IP address from `blocked_ips` |
| `GET` | `/api/blocked-ips` | Lists all currently blocked IP addresses |
| `POST` / `DELETE` | `/api/clear-logs` | Clears logs older than N days or purges all logs |
| `POST` | `/api/chat` (`/?endpoint=chat`) | AI Security Assistant endpoint for SOC & CVE queries |

---

## ⚙️ Local Setup & Installation

### 1. Backend Setup (Python / Flask)
```bash
pip install -r requirements.txt
export DATABASE_URL="postgresql://<user>:<password>@<host>/<dbname>?sslmode=require"
python server.py
```

### 2. Frontend Setup (React)
```bash
npm install
npm start
```

---

## 🧪 Key SOC & Security Features

* **Real-Time Threat Detection:** Automatically flags SQLi, XSS, Path Traversal, and Brute-Force probes from URL payloads.
* **Persistent IP Firewall:** Blocking an IP in UniShield persists in PostgreSQL and enforces an `"Access Restricted"` screen on connected portals (`nexustechautomation.me`).
* **Log Management & Export:** Filter logs by attack type or blocked status, export filtered logs to CSV, and manage retention (1 day, 7 days, or clear all).
* **AI Security Assistant:** Built-in SOC helper for quick CVE, KEV, and mitigation guidance.