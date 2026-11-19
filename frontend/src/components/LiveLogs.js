import React, { useState, useEffect } from 'react';

function LiveLogs() {
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);

    const fetchLiveLogs = async () => {
        try {
            // Yeh local backend se live logs fetch karega
            const response = await fetch('http://localhost:5001/api/logs');
            const data = await response.json();
            setLogs(data);
            setLoading(false);
        } catch (error) {
            console.error("Failed to fetch live logs:", error);
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchLiveLogs();
        // Har 5 second baad auto-refresh hoga taaki naye attacks foran nazar aayein
        const interval = setInterval(fetchLiveLogs, 5000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div style={{ padding: '20px', background: '#0f172a', color: '#fff', borderRadius: '8px', marginTop: '20px' }}>
            <h3>🛡️ Live Website Attack Logs (nexustechautomation.me)</h3>

            {loading ? (
                <p>Loading live security logs...</p>
            ) : logs.length === 0 ? (
                <p>No live attacks detected yet. Visit your live website to test!</p>
            ) : (
                <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '10px' }}>
                        <thead>
                            <tr style={{ borderBottom: '1px solid #334155', textAlign: 'left' }}>
                                <th style={{ padding: '10px' }}>Attack Type</th>
                                <th style={{ padding: '10px' }}>Endpoint</th>
                                <th style={{ padding: '10px' }}>Method</th>
                                <th style={{ padding: '10px' }}>IP Address</th>
                                <th style={{ padding: '10px' }}>Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            {logs.map((log, index) => (
                                <tr key={index} style={{ borderBottom: '1px solid #1e293b' }}>
                                    <td style={{ padding: '10px', color: '#f87171', fontWeight: 'bold' }}>{log.attack_type}</td>
                                    <td style={{ padding: '10px', color: '#38bdf8' }}>{log.endpoint || '/'}</td>
                                    <td style={{ padding: '10px' }}>{log.method || 'GET'}</td>
                                    <td style={{ padding: '10px', color: '#facc15' }}>{log.ip_address}</td>
                                    <td style={{ padding: '10px', color: '#94a3b8' }}>
                                        {new Date(log.created_at || log.timestamp).toLocaleTimeString()}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}

export default LiveLogs;