import React, { useState, useEffect, useMemo, useCallback } from 'react';

const API_BASE = process.env.REACT_APP_API_URL || 'https://unishield-backend.vercel.app';
const LOG_LIMIT = 1000;

function LiveLogs() {
    const [logs, setLogs] = useState([]);
    const [blockedIps, setBlockedIps] = useState([]);
    const [loading, setLoading] = useState(true);
    const [busyIp, setBusyIp] = useState('');
    const [clearing, setClearing] = useState(false);
    const [statusMessage, setStatusMessage] = useState('');

    const [attackFilter, setAttackFilter] = useState('ALL');
    const [statusFilter, setStatusFilter] = useState('ALL'); // ALL | THREATS_ONLY | BLOCKED_ONLY
    const [clearMode, setClearMode] = useState('1'); // '1' = >1 day, '7' = >7 days, 'ALL' = all logs
    const [searchQuery, setSearchQuery] = useState('');
    const [autoRefresh, setAutoRefresh] = useState(true);

    const fetchLiveLogs = useCallback(async () => {
        try {
            const [logsRes, blockedRes] = await Promise.all([
                fetch(`${API_BASE}/?endpoint=logs&limit=${LOG_LIMIT}`),
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
        if (!autoRefresh) return undefined;
        const interval = setInterval(fetchLiveLogs, 5000);
        return () => clearInterval(interval);
    }, [fetchLiveLogs, autoRefresh]);

    const blockedSet = useMemo(() => new Set(blockedIps), [blockedIps]);

    const ipFrequencyMap = useMemo(() => {
        const counts = {};
        logs.forEach((item) => {
            const ip = (item.ip_address || 'Unknown').trim();
            counts[ip] = (counts[ip] || 0) + 1;
        });
        return counts;
    }, [logs]);

    const stats = useMemo(() => {
        const total = logs.length;
        const threats = logs.filter((l) => {
            const t = (l.attack_type || l.type || 'NORMAL_TRAFFIC').toUpperCase();
            return !t.includes('NORMAL');
        }).length;
        const uniqueIps = Object.keys(ipFrequencyMap).length;
        return { total, threats, uniqueIps, blocked: blockedIps.length };
    }, [logs, ipFrequencyMap, blockedIps]);

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
                setStatusMessage(
                    alreadyBlocked ? `Unblocked IP ${ipAddress}.` : `Blocked IP ${ipAddress} persistently.`
                );
                await fetchLiveLogs();
            }
        } catch (error) {
            console.error(`Failed to ${alreadyBlocked ? 'unblock' : 'block'} IP:`, error);
        } finally {
            setBusyIp('');
        }
    };

    const handleClearLogs = async () => {
        const confirmMsg =
            clearMode === 'ALL'
                ? 'Are you sure you want to delete ALL stored logs so fresh logs start cleanly?'
                : `Delete logs older than ${clearMode} day(s)?`;

        if (!window.confirm(confirmMsg)) return;

        setClearing(true);
        setStatusMessage('');
        try {
            const bodyPayload =
                clearMode === 'ALL'
                    ? { all: true }
                    : { all: false, older_than_days: Number(clearMode) };

            const res = await fetch(`${API_BASE}/?endpoint=clear_logs`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(bodyPayload),
            });
            const data = await res.json();
            if (res.ok) {
                setStatusMessage(
                    `Cleared ${data.deleted_count ?? 0} log(s). Remaining: ${data.remaining_count ?? 0}.`
                );
                await fetchLiveLogs();
            } else {
                setStatusMessage(data.error || 'Failed to clear logs.');
            }
        } catch (error) {
            console.error('Failed to clear logs:', error);
            setStatusMessage('Error clearing logs.');
        } finally {
            setClearing(false);
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

    const handleExportCsv = () => {
        const headers = ['ID', 'Attack Type', 'Endpoint', 'Method', 'IP Address', 'Hits', 'Blocked', 'Timestamp'];
        const rows = filteredLogs.map((item) => {
            const ip = item.ip_address || 'Unknown';
            const blockedFlag = Boolean(item.blocked) || blockedSet.has(ip);
            const ts = item.created_at || item.timestamp || '';
            return [
                item.id ?? '',
                item.attack_type || item.type || 'NORMAL_TRAFFIC',
                item.endpoint || '/',
                item.method || 'GET',
                ip,
                ipFrequencyMap[ip] || 1,
                blockedFlag ? 'YES' : 'NO',
                ts,
            ]
                .map((val) => `"${String(val).replace(/"/g, '""')}"`)
                .join(',');
        });

        const csvContent = [headers.join(','), ...rows].join('\n');
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `unishield-logs-${new Date().toISOString().slice(0, 10)}.csv`;
        link.click();
        URL.revokeObjectURL(url);
    };

    return (
        <div style={{ padding: '20px', background: '#0f172a', color: '#fff', borderRadius: '10px', marginTop: '20px', border: '1px solid #1e293b' }}>
            {/* Top Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
                <div>
                    <h3 style={{ margin: 0 }}>🛡️ Live Website Attack Logs & SOC Console</h3>
                    <small style={{ color: '#94a3b8' }}>Showing up to {LOG_LIMIT} latest records • Persistent IP Firewall & Retention Control</small>
                </div>

                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center' }}>
                    <button
                        type="button"
                        onClick={() => setAutoRefresh((prev) => !prev)}
                        style={{
                            padding: '6px 12px',
                            background: autoRefresh ? '#065f46' : '#1e293b',
                            color: '#ecfdf5',
                            border: '1px solid #10b981',
                            borderRadius: '6px',
                            cursor: 'pointer',
                            fontSize: '12px',
                            fontWeight: 'bold',
                        }}
                    >
                        {autoRefresh ? 'Auto-Sync: ON (5s)' : 'Auto-Sync: PAUSED'}
                    </button>

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
                            fontSize: '12px',
                        }}
                    >
                        Refresh Now
                    </button>

                    <button
                        type="button"
                        onClick={handleExportCsv}
                        style={{
                            padding: '6px 12px',
                            background: '#1d4ed8',
                            color: '#fff',
                            border: 'none',
                            borderRadius: '6px',
                            cursor: 'pointer',
                            fontSize: '12px',
                            fontWeight: 'bold',
                        }}
                    >
                        Export CSV
                    </button>
                </div>
            </div>

            {/* KPI Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '10px', marginTop: '14px' }}>
                <div style={{ background: '#1e293b', padding: '12px', borderRadius: '8px', border: '1px solid #334155' }}>
                    <div style={{ fontSize: '11px', color: '#94a3b8', textTransform: 'uppercase' }}>Loaded Logs (Max {LOG_LIMIT})</div>
                    <div style={{ fontSize: '22px', fontWeight: 'bold', marginTop: '4px' }}>{stats.total}</div>
                </div>
                <div style={{ background: '#1e293b', padding: '12px', borderRadius: '8px', border: '1px solid #334155' }}>
                    <div style={{ fontSize: '11px', color: '#fca5a5', textTransform: 'uppercase' }}>Security Threats</div>
                    <div style={{ fontSize: '22px', fontWeight: 'bold', color: '#f87171', marginTop: '4px' }}>{stats.threats}</div>
                </div>
                <div style={{ background: '#1e293b', padding: '12px', borderRadius: '8px', border: '1px solid #334155' }}>
                    <div style={{ fontSize: '11px', color: '#fde047', textTransform: 'uppercase' }}>Unique IPs</div>
                    <div style={{ fontSize: '22px', fontWeight: 'bold', color: '#facc15', marginTop: '4px' }}>{stats.uniqueIps}</div>
                </div>
                <div style={{ background: '#1e293b', padding: '12px', borderRadius: '8px', border: '1px solid #334155' }}>
                    <div style={{ fontSize: '11px', color: '#86efac', textTransform: 'uppercase' }}>Blocked IPs</div>
                    <div style={{ fontSize: '22px', fontWeight: 'bold', color: '#4ade80', marginTop: '4px' }}>{stats.blocked}</div>
                </div>
            </div>

            {/* Filters + Clear Old Data Bar */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', marginTop: '14px', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px' }}>
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
                            minWidth: '210px',
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
                        <option value="ALL">All Statuses ({logs.length})</option>
                        <option value="THREATS_ONLY">Threats Only</option>
                        <option value="BLOCKED_ONLY">Blocked IPs Only ({blockedIps.length})</option>
                    </select>
                </div>

                {/* Clear Old Data Controls */}
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center' }}>
                    <select
                        value={clearMode}
                        onChange={(e) => setClearMode(e.target.value)}
                        style={{
                            padding: '7px 10px',
                            background: '#1e293b',
                            color: '#fde68a',
                            border: '1px solid #475569',
                            borderRadius: '6px',
                            fontSize: '12px',
                        }}
                    >
                        <option value="1">Older than 1 Day</option>
                        <option value="7">Older than 7 Days</option>
                        <option value="ALL">All Stored Logs (Fresh Start)</option>
                    </select>

                    <button
                        type="button"
                        disabled={clearing}
                        onClick={handleClearLogs}
                        style={{
                            padding: '7px 12px',
                            background: '#991b1b',
                            color: '#fff',
                            border: '1px solid #ef4444',
                            borderRadius: '6px',
                            cursor: 'pointer',
                            fontSize: '12px',
                            fontWeight: 'bold',
                        }}
                    >
                        {clearing ? 'Clearing...' : '🗑️ Clear Old Logs'}
                    </button>
                </div>
            </div>

            {statusMessage && (
                <div
                    style={{
                        marginTop: '10px',
                        padding: '8px 12px',
                        background: '#1e293b',
                        borderLeft: '4px solid #38bdf8',
                        borderRadius: '4px',
                        fontSize: '13px',
                        color: '#e0f2fe',
                    }}
                >
                    {statusMessage}
                </div>
            )}

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
                    <strong style={{ color: '#fca5a5' }}>Active Blocked IPs:</strong>
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
                                <th style={{ padding: '10px' }}>Hits</th>
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
                                const hits = ipFrequencyMap[ip] || 1;

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
                                        <td style={{ padding: '10px', color: '#38bdf8', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                            {log.endpoint || '/'}
                                        </td>
                                        <td style={{ padding: '10px' }}>{log.method || 'GET'}</td>
                                        <td style={{ padding: '10px', color: '#facc15', fontFamily: 'monospace' }}>{ip}</td>
                                        <td style={{ padding: '10px', color: hits >= 5 ? '#f87171' : '#cbd5e1', fontWeight: hits >= 5 ? 'bold' : 'normal' }}>
                                            {hits}x
                                        </td>
                                        <td style={{ padding: '10px', color: '#94a3b8', fontSize: '12px' }}>
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