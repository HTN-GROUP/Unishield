import React, { useState, useEffect, useMemo, useCallback } from 'react';

const API_BASE = process.env.REACT_APP_API_URL || 'https://unishield-backend.vercel.app';

function LiveLogs() {
    const [logs, setLogs] = useState([]);
    const [blockedIps, setBlockedIps] = useState([]);
    const [loading, setLoading] = useState(true);
    const [busyIp, setBusyIp] = useState('');
    const [attackFilter, setAttackFilter] = useState('ALL');
    const [statusFilter, setStatusFilter] = useState('ALL'); // ALL | THREATS_ONLY | BLOCKED_ONLY
    const [searchQuery, setSearchQuery] = useState('');

    const fetchLiveLogs = useCallback(async () => {
        try {
            const [logsRes, blockedRes] = await Promise.all([
                fetch(`${API_BASE}/?endpoint=logs`),
                fetch(`${API_BASE}/?endpoint=blocked_ips`).catch(() => null),
            ]);

            const logsData = await logsRes.json();
            const parsedLogs = Array.isArray(logsData) ? logsData : [];
            setLogs(parsedLogs);

            if (blockedRes && blockedRes.ok) {
                const blockedData = await blockedRes.json();
                if (Array.isArray(blockedData)) {
                    setBlockedIps(blockedData.map((item) => item.ip_address).filter(Boolean));
                }
            } else {
                const fromLogs = parsedLogs.filter((item) => item.blocked).map((item) => item.ip_address);
                setBlockedIps([...new Set(fromLogs)]);
            }

            setLoading(false);
        } catch (error) {
            console.error('Failed to fetch live logs:', error);
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchLiveLogs();
        const interval = setInterval(fetchLiveLogs, 5000);
        return () => clearInterval(interval);
    }, [fetchLiveLogs]);

    const blockedSet = useMemo(() => new Set(blockedIps), [blockedIps]);

    const handleBlockOrUnblock = async (ipAddress) => {
        if (!ipAddress || ipAddress === 'Unknown') return;
        setBusyIp(ipAddress);
        const alreadyBlocked = blockedSet.has(ipAddress);
        const endpointName = alreadyBlocked ? 'unblock_ip' : 'block_ip';

        try {
            const res = await fetch(`${API_BASE}/?endpoint=${endpointName}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip_address: ipAddress }),
            });
            if (res.ok) {
                await fetchLiveLogs();
            }
        } catch (error) {
            console.error(`Failed to ${alreadyBlocked ? 'unblock' : 'block'} IP:`, error);
        } finally {
            setBusyIp('');
        }
    };

    const filteredLogs = useMemo(() => {
        return logs.filter((log) => {
            const typeVal = (log.attack_type || log.type || 'NORMAL_TRAFFIC').toUpperCase();
            const ipVal = (log.ip_address || '').toLowerCase();
            const epVal = (log.endpoint || log.log || '/').toLowerCase();
            const methodVal = (log.method || 'GET').toLowerCase();
            const query = searchQuery.trim().toLowerCase();
            const isIpBlocked = Boolean(log.blocked) || blockedSet.has(log.ip_address);

            if (attackFilter !== 'ALL' && typeVal !== attackFilter) {
                return false;
            }

            if (statusFilter === 'THREATS_ONLY' && typeVal.includes('NORMAL')) {
                return false;
            }

            if (statusFilter === 'BLOCKED_ONLY' && !isIpBlocked) {
                return false;
            }

            if (
                query &&
                !ipVal.includes(query) &&
                !epVal.includes(query) &&
                !typeVal.includes(query) &&
                !methodVal.includes(query)
            ) {
                return false;
            }

            return true;
        });
    }, [logs, attackFilter, statusFilter, searchQuery, blockedSet]);

    return (
        <div style={{ padding: '20px', background: '#0f172a', color: '#fff', borderRadius: '8px', marginTop: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
                <h3 style={{ margin: 0 }}>🛡️ Live Website Attack Logs (nexustechautomation.me)</h3>
                <button
                    type="button"
                    onClick={fetchLiveLogs}
                    style={{
                        padding: '6px 12px',
                        background: '#1e293b',
                        color: '#e2e8f0',
                        border: '1px solid #475569',
                        borderRadius: '6px',
                        cursor: 'pointer',
                    }}
                >
                    Refresh Now
                </button>
            </div>

            {/* Filters Bar */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', marginTop: '14px' }}>
                <input
                    type="text"
                    placeholder="Search IP, endpoint, method..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    style={{
                        padding: '7px 11px',
                        background: '#1e293b',
                        color: '#fff',
                        border: '1px solid #334155',
                        borderRadius: '6px',
                        minWidth: '220px',
                    }}
                />

                <select
                    value={attackFilter}
                    onChange={(e) => setAttackFilter(e.target.value)}
                    style={{
                        padding: '7px 11px',
                        background: '#1e293b',
                        color: '#fff',
                        border: '1px solid #334155',
                        borderRadius: '6px',
                    }}
                >
                    <option value="ALL">All Attack Types</option>
                    <option value="SQL_INJECTION">SQL_INJECTION</option>
                    <option value="XSS_ATTACK">XSS_ATTACK</option>
                    <option value="PATH_TRAVERSAL">PATH_TRAVERSAL</option>
                    <option value="BRUTE_FORCE_PROBE">BRUTE_FORCE_PROBE</option>
                    <option value="NORMAL_TRAFFIC">NORMAL_TRAFFIC</option>
                    <option value="NORMAL_VISIT">NORMAL_VISIT</option>
                </select>

                <select
                    value={statusFilter}
                    onChange={(e) => setStatusFilter(e.target.value)}
                    style={{
                        padding: '7px 11px',
                        background: '#1e293b',
                        color: '#fff',
                        border: '1px solid #334155',
                        borderRadius: '6px',
                    }}
                >
                    <option value="ALL">All Logs ({logs.length})</option>
                    <option value="THREATS_ONLY">Threats Only</option>
                    <option value="BLOCKED_ONLY">Blocked IPs Only ({blockedIps.length})</option>
                </select>
            </div>

            {/* Blocked IPs Quick Unblock Strip */}
            {blockedIps.length > 0 && (
                <div
                    style={{
                        marginTop: '14px',
                        padding: '10px 12px',
                        background: '#1e293b',
                        border: '1px solid #7f1d1d',
                        borderRadius: '6px',
                        display: 'flex',
                        flexWrap: 'wrap',
                        alignItems: 'center',
                        gap: '8px',
                    }}
                >
                    <strong style={{ color: '#fca5a5' }}>Blocked IPs:</strong>
                    {blockedIps.map((ip) => (
                        <span
                            key={ip}
                            style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '6px',
                                padding: '3px 8px',
                                background: '#0f172a',
                                borderRadius: '4px',
                                fontSize: '13px',
                            }}
                        >
                            <span style={{ color: '#facc15' }}>{ip}</span>
                            <button
                                type="button"
                                disabled={busyIp === ip}
                                onClick={() => handleBlockOrUnblock(ip)}
                                style={{
                                    padding: '2px 8px',
                                    background: '#16a34a',
                                    color: '#fff',
                                    border: 'none',
                                    borderRadius: '4px',
                                    cursor: 'pointer',
                                    fontSize: '12px',
                                    fontWeight: 'bold',
                                }}
                            >
                                {busyIp === ip ? '...' : 'UNBLOCK'}
                            </button>
                        </span>
                    ))}
                </div>
            )}

            {loading ? (
                <p style={{ marginTop: '14px' }}>Loading live security logs...</p>
            ) : filteredLogs.length === 0 ? (
                <p style={{ marginTop: '14px' }}>No matching logs found for the selected filter.</p>
            ) : (
                <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '12px' }}>
                        <thead>
                            <tr style={{ borderBottom: '1px solid #334155', textAlign: 'left' }}>
                                <th style={{ padding: '10px' }}>Attack Type</th>
                                <th style={{ padding: '10px' }}>Endpoint</th>
                                <th style={{ padding: '10px' }}>Method</th>
                                <th style={{ padding: '10px' }}>IP Address</th>
                                <th style={{ padding: '10px' }}>Time</th>
                                <th style={{ padding: '10px', textAlign: 'right' }}>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredLogs.map((log, index) => {
                                const ip = log.ip_address || '192.168.1.45';
                                const isBlocked = Boolean(log.blocked) || blockedSet.has(ip);
                                const typeLabel = log.attack_type || log.type || 'NORMAL_TRAFFIC';
                                const isThreat = !typeLabel.toUpperCase().includes('NORMAL');

                                return (
                                    <tr key={log.id || `${ip}-${index}`} style={{ borderBottom: '1px solid #1e293b' }}>
                                        <td
                                            style={{
                                                padding: '10px',
                                                color: isThreat ? '#f87171' : '#4ade80',
                                                fontWeight: 'bold',
                                            }}
                                        >
                                            {typeLabel}
                                        </td>
                                        <td style={{ padding: '10px', color: '#38bdf8' }}>{log.endpoint || '/'}</td>
                                        <td style={{ padding: '10px' }}>{log.method || 'GET'}</td>
                                        <td style={{ padding: '10px', color: '#facc15' }}>{ip}</td>
                                        <td style={{ padding: '10px', color: '#94a3b8' }}>
                                            {(log.created_at || log.timestamp)
                                                ? new Date(log.created_at || log.timestamp).toLocaleTimeString()
                                                : 'Just now'}
                                        </td>
                                        <td style={{ padding: '10px', textAlign: 'right' }}>
                                            <button
                                                type="button"
                                                disabled={busyIp === ip}
                                                onClick={() => handleBlockOrUnblock(ip)}
                                                style={{
                                                    padding: '5px 10px',
                                                    background: isBlocked ? '#16a34a' : '#dc2626',
                                                    color: '#fff',
                                                    border: 'none',
                                                    borderRadius: '4px',
                                                    cursor: 'pointer',
                                                    fontWeight: 'bold',
                                                    fontSize: '12px',
                                                }}
                                            >
                                                {busyIp === ip ? '...' : isBlocked ? 'UNBLOCK IP' : 'BLOCK IP'}
                                            </button>
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}

export default LiveLogs;