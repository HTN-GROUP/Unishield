const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5001;

// CORS configured for live website (nexustechautomation.me) and local dashboard
app.use(cors({
    origin: ['https://nexustechautomation.me', 'https://www.nexustechautomation.me', 'http://localhost:3000', '*'],
    methods: ['GET', 'POST']
}));
app.use(express.json());

// Neon PostgreSQL Database Connection Pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Test API Route
app.get('/', (req, res) => {
    res.json({ message: "UniShield Backend Server Running Successfully with Neon DB & Live Logging!" });
});

// API Endpoint to get vulnerabilities from Neon PostgreSQL (with fallback)
app.get('/api/vulnerabilities', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM vulnerabilities;');
        if (result.rows && result.rows.length > 0) {
            return res.json(result.rows);
        }
        throw new Error("Table empty");
    } catch (err) {
        console.log("Using fallback mock vulnerabilities.");
        const fallbackVulns = [
            { cve_id: "CVE-2023-3863", software_name: "Apache", cvss_score: 7.5, severity: "HIGH", is_kev: true, description: "Apache HTTP Server path traversal vulnerability." },
            { cve_id: "CVE-2021-44228", software_name: "WordPress", cvss_score: 10.0, severity: "CRITICAL", is_kev: true, description: "WordPress component remote code execution." },
            { cve_id: "CVE-2024-1234", software_name: "PHP", cvss_score: 9.8, severity: "CRITICAL", is_kev: false, description: "PHP core remote buffer overflow vulnerability." }
        ];
        res.json(fallbackVulns);
    }
});

// API Endpoint to receive live logs from nexustechautomation.me and save to Neon PostgreSQL
app.post('/api/ingest-log', async (req, res) => {
    try {
        const { attack_type, ip_address, endpoint, method } = req.body;

        // Auto-create live_logs table in Neon if it doesn't exist yet
        await pool.query(`
            CREATE TABLE IF NOT EXISTS live_logs (
                id SERIAL PRIMARY KEY,
                domain VARCHAR(100) DEFAULT 'nexustechautomation.me',
                attack_type VARCHAR(50),
                ip_address VARCHAR(50),
                endpoint TEXT,
                method VARCHAR(10),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Insert live log into Neon DB
        await pool.query(
            'INSERT INTO live_logs (attack_type, ip_address, endpoint, method) VALUES ($1, $2, $3, $4)',
            [attack_type || 'NORMAL_TRAFFIC', ip_address || 'unknown', endpoint || '/', method || 'GET']
        );

        res.status(201).json({ status: 'Log saved successfully to Neon DB' });
    } catch (err) {
        console.error("Log ingest error:", err);
        res.status(500).json({ error: "Failed to save log" });
    }
});

// API Endpoint to fetch live logs from Neon DB for the dashboard
app.get('/api/logs', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM live_logs ORDER BY created_at DESC LIMIT 50;');
        if (result.rows && result.rows.length > 0) {
            return res.json(result.rows);
        }
        throw new Error("No live logs yet");
    } catch (err) {
        // Fallback mock logs if table is empty
        const mockLogs = [
            { attack_type: "SQL_INJECTION", ip_address: "ip_d871.ec", endpoint: "/api/users?id=1' OR '1'='1", domain: "nexustechautomation.me", created_at: new Date() },
            { attack_type: "BRUTE_FORCE", ip_address: "ip_bdfc.6e", endpoint: "/login", domain: "nexustechautomation.me", created_at: new Date() }
        ];
        res.json(mockLogs);
    }
});

// Smart AI Security Assistant Chat Endpoint (English Responses)[cite: 9]
app.post('/api/chat', async (req, res) => {
    try {
        const { message } = req.body;
        if (!message) {
            return res.status(400).json({ error: "Message is required" });
        }

        // Fetch vulnerabilities from database to provide contextual awareness[cite: 9]
        let vulns = [];
        try {
            const result = await pool.query("SELECT * FROM vulnerabilities");
            vulns = result.rows;
        } catch (dbErr) {
            console.error("Database fetch failed in chat:", dbErr);
        }

        const lowerMsg = message.toLowerCase().trim();
        let reply = "";

        const criticalCount = vulns.filter(v => v.severity === 'CRITICAL').length;
        const highCount = vulns.filter(v => v.severity === 'HIGH').length;
        const mediumCount = vulns.filter(v => v.severity === 'MEDIUM').length;
        const lowCount = vulns.filter(v => v.severity === 'LOW').length;
        const kevCount = vulns.filter(v => v.is_kev === true).length;

        // Intelligent keyword matching in English[cite: 9]
        if (lowerMsg.includes("api")) {
            reply = "An API (Application Programming Interface) is a set of defined rules that enables different software applications to communicate with one another. In UniShield, APIs bridge the React frontend UI with our Node.js server and Neon PostgreSQL database.";
        } else if (lowerMsg.includes("cve")) {
            reply = "CVE (Common Vulnerabilities and Exposures) is a standardized list of publicly known cybersecurity vulnerabilities. Each entry receives a unique ID (e.g., CVE-2023-1234) for universal tracking.";
        } else if (lowerMsg.includes("cvss")) {
            reply = "CVSS (Common Vulnerability Scoring System) is an open framework ranging from 0.0 to 10.0 that measures the technical severity of software vulnerabilities.";
        } else if (lowerMsg.includes("critical") || lowerMsg.includes("highest")) {
            reply = `There are currently ${criticalCount} Critical severity vulnerabilities logged in the database, including active CISA KEV threats. Immediate remediation is strongly advised!`;
        } else if (lowerMsg.includes("kev") || lowerMsg.includes("exploited")) {
            reply = `We have ${kevCount} vulnerabilities cataloged under CISA Known Explouted Vulnerabilities (KEV) that are confirmed to be actively exploited in the wild.`;
        } else if (lowerMsg.includes("high")) {
            reply = `There are ${highCount} High severity vulnerabilities present in the UniShield database.`;
        } else if (lowerMsg.includes("medium")) {
            reply = `There are ${mediumCount} Medium severity vulnerabilities recorded in the system.`;
        } else if (lowerMsg.includes("low")) {
            reply = `There are ${lowCount} Low severity vulnerabilities listed in the dashboard.`;
        } else if (lowerMsg.includes("total") || lowerMsg.includes("how many") || lowerMsg.includes("count")) {
            reply = `UniShield is currently monitoring ${vulns.length} vulnerabilities across Critical, High, Medium, and Low risk levels.`;
        } else if (lowerMsg.includes("hello") || lowerMsg.includes("hi") || lowerMsg.includes("hey")) {
            reply = "Hello! I am your UniShield AI Security Assistant. Feel free to ask about vulnerability analytics, KEV alerts, or core concepts like APIs, CVEs, and CVSS scores!";
        } else {
            reply = `Regarding "${message}": I am specialized in cybersecurity intelligence and system metrics. You can ask me about vulnerability statuses (Critical, KEV, High), counts, or concepts like APIs and CVSS!`;
        }

        res.json({ reply });
    } catch (err) {
        console.error("Chat API error:", err);
        res.status(500).json({ error: "Server error in AI chat" });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});