import React, { useState, useEffect, useCallback, useMemo } from 'react';
import VideoBackground from './components/VideoBackground';
import Header from './components/Header';
import Chatbot from './components/Chatbot';

const API_BASE = process.env.REACT_APP_API_URL || 'https://unishield-backend.vercel.app';
const ADMIN_USERNAME = process.env.REACT_APP_ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.REACT_APP_ADMIN_PASS || 'UniShield@2026';
const LOG_LIMIT = 1000;

function App() {
    const [isAuthenticated, setIsAuthenticated] = useState(
        () => sessionStorage.getItem('unishield_admin_auth') === 'true'
    );
    const [loginUser, setLoginUser] = useState('');
    const [loginPass, setLoginPass] = useState('');
    const [loginError, setLoginError] = useState('');

    const [activeTab, setActiveTab] = useState('overview');
    const [theme, setTheme] = useState('light'); // 'light', 'night', 'neon'
    const [vulnerabilities, setVulnerabilities] = useState([]);
    const [liveLogs, setLiveLogs] = useState([]);
    const [blockedIps, setBlockedIps] = useState([]);
    const [busyIp, setBusyIp] = useState('');
    const [manualIpInput, setManualIpInput] = useState('');
    const [autoBlockRepeaters, setAutoBlockRepeaters] = useState(false);
    const [autoSync, setAutoSync] = useState(true);
    const [inspectedLog, setInspectedLog] = useState(null);

    const [clearingLogs, setClearingLogs] = useState(false);
    const [clearPeriod, setClearPeriod] = useState('1'); // '1', '7', 'ALL'
    const [socNotice, setSocNotice] = useState('');

    const [logFilter, setLogFilter] = useState('ALL'); // 'ALL', 'ATTACKS', 'NORMAL', 'BLOCKED'
    const [attackTypeFilter, setAttackTypeFilter] = useState('ALL');
    const [logSearch, setLogSearch] = useState('');
    const [searchQuery, setSearchQuery] = useState('');
    const [severityFilter, setSeverityFilter] = useState('ALL');
    const [kevOnly, setKevOnly] = useState(false);
    const [selectedVuln, setSelectedVuln] = useState(null);

    const handleAdminLogin = (e) => {
        e.preventDefault();
        if (loginUser.trim() === ADMIN_USERNAME && loginPass === ADMIN_PASSWORD) {
            sessionStorage.setItem('unishield_admin_auth', 'true');
            setIsAuthenticated(true);
            setLoginError('');
            setLoginPass('');
        } else {
            setLoginError('Invalid admin username or password.');
        }
    };

    const handleAdminLogout = () => {
        sessionStorage.removeItem('unishield_admin_auth');
        setIsAuthenticated(false);
        setLoginUser('');
        setLoginPass('');
    };

    // Fetching Live Vulnerabilities from Backend
    useEffect(() => {
        if (!isAuthenticated) return;

        fetch(`${API_BASE}/?endpoint=vulnerabilities`)
            .then(res => res.json())
            .then(data => {
                if (Array.isArray(data)) {
                    setVulnerabilities(data);
                    if (data.length > 0) setSelectedVuln(data[0]);
                }
            })
            .catch(err => console.error("Error fetching vulnerabilities:", err));
    }, [isAuthenticated]);

    const fetchLogsAndBlocked = useCallback(async () => {
        try {
            const [logsRes, blockedRes] = await Promise.all([
                fetch(`${API_BASE}/?endpoint=logs&limit=${LOG_LIMIT}`),
                fetch(`${API_BASE}/?endpoint=blocked_ips`).catch(() => null),
            ]);
            const logsData = await logsRes.json();
            const parsedLogs = Array.isArray(logsData) ? logsData : [];
            setLiveLogs(parsedLogs);

            if (blockedRes && blockedRes.ok) {
                const blockedData = await blockedRes.json();
                if (Array.isArray(blockedData)) {
                    const serverIps = blockedData.map(item => String(item.ip_address || '').trim()).filter(Boolean);
                    setBlockedIps(prev => [...new Set([...prev, ...serverIps])]);
                }
            } else {
                const fromLogs = parsedLogs.filter(item => item.blocked).map(item => String(item.ip_address || '').trim()).filter(Boolean);
                setBlockedIps(prev => [...new Set([...prev, ...fromLogs])]);
            }
        } catch (err) {
            console.error("Error fetching live logs:", err);
        }
    }, []);

    // Fetching Live Traffic & Attack Logs (up to 1000)
    useEffect(() => {
        if (!isAuthenticated) return;

        fetchLogsAndBlocked();
        if (!autoSync) return undefined;
        const interval = setInterval(fetchLogsAndBlocked, 5000);
        return () => clearInterval(interval);
    }, [isAuthenticated, fetchLogsAndBlocked, autoSync]);

    const blockedSet = useMemo(() => new Set(blockedIps), [blockedIps]);

    const ipHitCounts = useMemo(() => {
        const map = {};
        liveLogs.forEach(item => {
            const ip = (item.ip_address || 'Unknown').trim();
            map[ip] = (map[ip] || 0) + 1;
        });
        return map;
    }, [liveLogs]);

    const attackBreakdown = useMemo(() => {
        const counts = {};
        liveLogs.forEach(item => {
            const t = (item.attack_type || item.type || 'NORMAL_TRAFFIC').toUpperCase();
            counts[t] = (counts[t] || 0) + 1;
        });
        return Object.entries(counts).sort((a, b) => b[1] - a[1]);
    }, [liveLogs]);

    const handleToggleBlockIp = useCallback(async (ipAddress, forceMode = null) => {
        const cleanIp = String(ipAddress || '').trim();
        if (!cleanIp || cleanIp === 'Unknown') return;

        setBusyIp(cleanIp);
        const isCurrentlyBlocked = forceMode === 'block' ? false : forceMode === 'unblock' ? true : blockedSet.has(cleanIp);
        const endpointName = isCurrentlyBlocked ? 'unblock_ip' : 'block_ip';

        try {
            const res = await fetch(`${API_BASE}/?endpoint=${endpointName}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip_address: cleanIp, reason: 'Blocked via UniShield SOC Console' }),
            });
            const data = await res.json().catch(() => ({}));

            setBlockedIps(prev => {
                if (isCurrentlyBlocked) {
                    return prev.filter(ip => ip !== cleanIp);
                }
                return prev.includes(cleanIp) ? prev : [...prev, cleanIp];
            });

            if (res.ok) {
                setSocNotice(
                    isCurrentlyBlocked
                        ? `IP ${cleanIp} unblocked successfully.`
                        : `IP ${cleanIp} blocked successfully.`
                );
                await fetchLogsAndBlocked();
            } else {
                setSocNotice(
                    `IP ${cleanIp} updated in UI (${data.error || `HTTP ${res.status}`}). Check backend DB connection if needed.`
                );
            }
        } catch (err) {
            console.error("Failed to toggle IP block status:", err);
            setBlockedIps(prev =>
                isCurrentlyBlocked ? prev.filter(ip => ip !== cleanIp) : (prev.includes(cleanIp) ? prev : [...prev, cleanIp])
            );
            setSocNotice(`Network warning while syncing ${cleanIp} with backend.`);
        } finally {
            setBusyIp('');
        }
    }, [blockedSet, fetchLogsAndBlocked]);

    // Optional Auto-Mitigation: block repeat attackers with >= 5 threat hits
    useEffect(() => {
        if (!autoBlockRepeaters || !isAuthenticated || liveLogs.length === 0) return;

        const offenderCounts = {};
        liveLogs.forEach(item => {
            const t = (item.attack_type || item.type || 'NORMAL_TRAFFIC').toUpperCase();
            const ip = (item.ip_address || '').trim();
            if (!t.includes('NORMAL') && ip && ip !== 'Unknown') {
                offenderCounts[ip] = (offenderCounts[ip] || 0) + 1;
            }
        });

        const candidates = Object.entries(offenderCounts)
            .filter(([ip, count]) => count >= 5 && !blockedSet.has(ip))
            .map(([ip]) => ip);

        if (candidates.length > 0) {
            handleToggleBlockIp(candidates[0], 'block');
        }
    }, [autoBlockRepeaters, isAuthenticated, liveLogs, blockedSet, handleToggleBlockIp]);

    const handleManualIpSubmit = async (e) => {
        e.preventDefault();
        const ipVal = manualIpInput.trim();
        if (!ipVal) return;
        await handleToggleBlockIp(ipVal);
        setManualIpInput('');
    };

    const handleClearOldLogs = async () => {
        const msg =
            clearPeriod === 'ALL'
                ? 'Delete ALL stored logs so fresh logs can be collected cleanly?'
                : `Delete logs older than ${clearPeriod} day(s)?`;
        if (!window.confirm(msg)) return;

        setClearingLogs(true);
        setSocNotice('');
        try {
            const payload =
                clearPeriod === 'ALL'
                    ? { all: true }
                    : { all: false, older_than_days: Number(clearPeriod) };

            const res = await fetch(`${API_BASE}/?endpoint=clear_logs`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            const data = await res.json();
            if (res.ok) {
                setSocNotice(
                    `Purged ${data.deleted_count ?? 0} old log(s). Active records remaining: ${data.remaining_count ?? 0}.`
                );
                await fetchLogsAndBlocked();
            } else {
                setSocNotice(data.error || 'Unable to clear logs.');
            }
        } catch (err) {
            console.error("Error clearing logs:", err);
            setSocNotice('Failed to clear logs.');
        } finally {
            setClearingLogs(false);
        }
    };

    const getSoftwareName = (v) => v.software_name || v.software || v.product || 'Web Stack';

    const filteredVulns = vulnerabilities.filter(v => {
        const softName = getSoftwareName(v).toLowerCase();
        const cveId = (v.cve_id || '').toLowerCase();
        const matchesSearch = cveId.includes(searchQuery.toLowerCase()) || softName.includes(searchQuery.toLowerCase());
        const matchesSeverity = severityFilter === 'ALL' || (v.severity || '').toUpperCase() === severityFilter;
        const matchesKev = !kevOnly || Boolean(v.is_kev);
        return matchesSearch && matchesSeverity && matchesKev;
    });

    const isThreatLog = (log) => {
        const t = (log.attack_type || log.type || 'NORMAL_TRAFFIC').toUpperCase();
        return !t.includes('NORMAL');
    };

    const filteredAttackLogs = useMemo(() => {
        return liveLogs.filter(log => {
            const typeVal = (log.attack_type || log.type || 'NORMAL_TRAFFIC').toUpperCase();
            const ipVal = (log.ip_address || '').toLowerCase();
            const epVal = (log.endpoint || log.log || '/').toLowerCase();
            const q = logSearch.trim().toLowerCase();
            const ipIsBlocked = Boolean(log.blocked) || blockedSet.has(log.ip_address);

            if (logFilter === 'ATTACKS' && !isThreatLog(log)) return false;
            if (logFilter === 'NORMAL' && isThreatLog(log)) return false;
            if (logFilter === 'BLOCKED' && !ipIsBlocked) return false;
            if (attackTypeFilter !== 'ALL' && typeVal !== attackTypeFilter) return false;
            if (q && !ipVal.includes(q) && !epVal.includes(q) && !typeVal.includes(q)) return false;
            return true;
        });
    }, [liveLogs, logFilter, attackTypeFilter, logSearch, blockedSet]);

    const handleExportLogsCsv = () => {
        const headers = ['ID', 'Type', 'Endpoint', 'IP Address', 'Hits', 'Blocked', 'Timestamp'];
        const rows = filteredAttackLogs.map(log => {
            const ip = log.ip_address || 'Unknown';
            const blockedStatus = Boolean(log.blocked) || blockedSet.has(ip);
            const ts = log.created_at || log.timestamp || '';
            return [
                log.id ?? '',
                log.attack_type || log.type || 'NORMAL_TRAFFIC',
                log.endpoint || '/',
                ip,
                ipHitCounts[ip] || 1,
                blockedStatus ? 'BLOCKED' : 'ALLOWED',
                ts,
            ]
                .map(val => `"${String(val).replace(/"/g, '""')}"`)
                .join(',');
        });

        const blob = new Blob([[headers.join(','), ...rows].join('\n')], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `unishield-attack-map-${new Date().toISOString().slice(0, 10)}.csv`;
        a.click();
        URL.revokeObjectURL(url);
    };

    const criticalCount = vulnerabilities.filter(v => (v.severity || '').toUpperCase() === 'CRITICAL').length;
    const kevCount = vulnerabilities.filter(v => Boolean(v.is_kev)).length;
    const attackCount = liveLogs.filter(l => isThreatLog(l)).length;
    const uniqueIpCount = Object.keys(ipHitCounts).length;

    const getThemeTextClasses = () => {
        if (theme === 'neon') return 'text-cyan-400 selection:bg-cyan-500 selection:text-black';
        if (theme === 'night') return 'text-gray-100 selection:bg-red-900 selection:text-white';
        return 'text-gray-900 selection:bg-[#6b1d1d] selection:text-white';
    };

    if (!isAuthenticated) {
        return (
            <div className="min-h-screen bg-[#0b0d12] text-white flex items-center justify-center p-6 font-sans">
                <div className="w-full max-w-md bg-black/70 border border-white/20 rounded-lg p-8 shadow-2xl">
                    <div className="mb-6 border-b border-white/10 pb-4">
                        <p className="text-xs font-mono uppercase tracking-widest text-red-400">UNISHIELD SECURITY GATE</p>
                        <h1 className="text-2xl font-black mt-1">ADMIN LOGIN REQUIRED</h1>
                        <p className="text-xs text-white/60 mt-1">
                            Authorized personnel only. Enter admin credentials to access monitoring and IP firewall controls.
                        </p>
                    </div>

                    <form onSubmit={handleAdminLogin} className="space-y-4">
                        <div>
                            <label className="block text-xs font-bold uppercase tracking-wider text-white/70 mb-1.5">
                                Admin Username
                            </label>
                            <input
                                type="text"
                                value={loginUser}
                                onChange={(e) => setLoginUser(e.target.value)}
                                placeholder="Enter admin username"
                                required
                                className="w-full bg-black/60 border border-white/25 rounded px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-red-500"
                            />
                        </div>

                        <div>
                            <label className="block text-xs font-bold uppercase tracking-wider text-white/70 mb-1.5">
                                Password
                            </label>
                            <input
                                type="password"
                                value={loginPass}
                                onChange={(e) => setLoginPass(e.target.value)}
                                placeholder="Enter admin password"
                                required
                                className="w-full bg-black/60 border border-white/25 rounded px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-red-500"
                            />
                        </div>

                        {loginError && (
                            <div className="text-xs font-mono text-red-400 bg-red-950/40 border border-red-500/40 rounded p-2.5">
                                {loginError}
                            </div>
                        )}

                        <button
                            type="submit"
                            className="w-full bg-[#6b1d1d] hover:bg-[#521616] text-white font-bold text-sm tracking-wider py-3 rounded transition-all"
                        >
                            UNLOCK UNISHIELD DASHBOARD
                        </button>
                    </form>
                </div>
            </div>
        );
    }

    return (
        <div className={`relative min-h-screen font-sans ${getThemeTextClasses()}`}>
            <VideoBackground activeTab={activeTab} theme={theme} />

            <div className="relative z-10">
                <Header
                    activeTab={activeTab}
                    setActiveTab={setActiveTab}
                    theme={theme}
                    setTheme={setTheme}
                />

                <div className="max-w-7xl mx-auto px-8 pt-4 flex justify-end">
                    <button
                        onClick={handleAdminLogout}
                        className="px-3.5 py-1.5 text-xs font-mono font-bold uppercase tracking-wider bg-black/60 hover:bg-red-700 text-white border border-white/25 rounded transition-all"
                    >
                        LOCK / LOGOUT
                    </button>
                </div>

                <main className="p-8 pt-4 max-w-7xl mx-auto">
                    {/* TAB 1: OVERVIEW */}
                    {activeTab === 'overview' && (
                        <div className="space-y-12">
                            <div className="py-8 border-b border-white/10">
                                <h2 className="text-6xl font-black tracking-tight leading-tight">
                                    KNOW WHAT TO PATCH<br />BEFORE ATTACKERS DO.
                                </h2>
                                <p className="mt-4 text-xl opacity-80 max-w-3xl leading-relaxed">
                                    UniShield matches public vulnerability data with web server logs and ranks which university software IT should fix first.
                                </p>
                                <div className="mt-8 flex space-x-4">
                                    <button
                                        onClick={() => setActiveTab('fixFirst')}
                                        className="bg-[#6b1d1d] text-white px-8 py-3.5 font-bold text-sm tracking-wider rounded shadow hover:bg-[#521616] transition-all"
                                    >
                                        OPEN THE DASHBOARD
                                    </button>
                                    <button
                                        onClick={() => setActiveTab('attackMap')}
                                        className="bg-black/50 border border-white/30 text-white px-8 py-3.5 font-bold text-sm tracking-wider rounded shadow hover:bg-white/10 transition-all"
                                    >
                                        VIEW LIVE ATTACKS ({liveLogs.length})
                                    </button>
                                </div>
                            </div>

                            <div className="border border-white/20 bg-black/40 backdrop-blur-md p-8 rounded shadow-sm relative">
                                <div className="flex justify-between items-center border-b border-white/10 pb-4 mb-6">
                                    <span className="text-xs font-mono font-bold uppercase tracking-wider opacity-70">LIVE TOPOLOGY MAP</span>
                                    <span className="text-xs font-mono bg-red-600/30 text-red-400 border border-red-500/30 px-2 py-1 rounded font-bold">
                                        {attackCount > 0 ? `${attackCount} LIVE THREATS DETECTED` : 'CISA KEV ACTIVE MONITOR'}
                                    </span>
                                </div>
                                <div className="h-64 flex items-center justify-center relative bg-black/30 rounded border border-dashed border-white/20">
                                    <div className="grid grid-cols-4 gap-12 text-center w-full px-12">
                                        <div className="p-4 bg-black/50 border border-white/20 shadow-sm rounded font-mono font-bold text-sm">APACHE<div className="text-xs font-normal opacity-60 mt-1">CVSS 7.5</div></div>
                                        <div className="p-4 bg-black/50 border border-white/20 shadow-sm rounded font-mono font-bold text-sm">WORDPRESS<div className="text-xs font-normal opacity-60 mt-1">CVSS 8.4</div></div>
                                        <div className="p-4 bg-black/50 border border-white/20 shadow-sm rounded font-mono font-bold text-sm">PHP<div className="text-xs font-normal opacity-60 mt-1">CVSS 9.9</div></div>
                                        <div className="p-4 bg-black/50 border border-white/20 shadow-sm rounded font-mono font-bold text-sm">MYSQL<div className="text-xs font-normal opacity-60 mt-1">CVSS 9.8</div></div>
                                    </div>
                                    <div className="absolute bg-[#6b1d1d] text-white px-4 py-2 rounded-full font-mono text-xs font-bold shadow-lg animate-pulse">
                                        KEV: ACTIVELY EXPLOITED ({kevCount || 1})
                                    </div>
                                </div>
                            </div>

                            <div>
                                <h3 className="text-xs font-bold uppercase tracking-widest opacity-60 mb-6">HOW IT WORKS</h3>
                                <div className="grid grid-cols-4 gap-6">
                                    <div className="border border-white/20 p-6 bg-black/40 backdrop-blur-md shadow-sm rounded">
                                        <span className="text-xs font-mono font-bold opacity-50">01</span>
                                        <h4 className="text-lg font-bold mt-2">EXTRACT</h4>
                                        <p className="text-sm opacity-70 mt-2">Pull CVE records from NVD and the CISA KEV list, and read live web server logs.</p>
                                    </div>
                                    <div className="border border-white/20 p-6 bg-black/40 backdrop-blur-md shadow-sm rounded">
                                        <span className="text-xs font-mono font-bold opacity-50">02</span>
                                        <h4 className="text-lg font-bold mt-2">TRANSFORM</h4>
                                        <p className="text-sm opacity-70 mt-2">Validate every record, remove duplicates and merge the sources.</p>
                                    </div>
                                    <div className="border border-white/20 p-6 bg-black/40 backdrop-blur-md shadow-sm rounded">
                                        <span className="text-xs font-mono font-bold opacity-50">03</span>
                                        <h4 className="text-lg font-bold mt-2">LOAD</h4>
                                        <p className="text-sm opacity-70 mt-2">Store clean tables in Neon PostgreSQL database.</p>
                                    </div>
                                    <div className="border border-white/20 p-6 bg-black/40 backdrop-blur-md shadow-sm rounded">
                                        <span className="text-xs font-mono font-bold opacity-50">04</span>
                                        <h4 className="text-lg font-bold mt-2">EXPLORE</h4>
                                        <p className="text-sm opacity-70 mt-2">See what to fix first, search any CVE and watch live attack patterns.</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* TAB 2: FIX FIRST */}
                    {activeTab === 'fixFirst' && (
                        <div className="space-y-8">
                            <div>
                                <h2 className="text-4xl font-black">WHAT TO PATCH FIRST</h2>
                                <p className="opacity-70 mt-1">Software ranked by severity, active exploitation and number of vulnerabilities.</p>
                            </div>

                            <div className="grid grid-cols-4 gap-6 bg-black/40 backdrop-blur-md p-6 border border-white/25 shadow-sm rounded">
                                <div className="border-r border-white/10 pr-4">
                                    <p className="text-xs font-bold uppercase opacity-60 tracking-wider">Software Tracked</p>
                                    <p className="text-4xl font-black mt-2">5</p>
                                </div>
                                <div className="border-r border-white/10 pr-4">
                                    <p className="text-xs font-bold uppercase opacity-60 tracking-wider">CVEs Loaded</p>
                                    <p className="text-4xl font-black mt-2">{vulnerabilities.length}</p>
                                </div>
                                <div className="border-r border-white/10 pr-4">
                                    <p className="text-xs font-bold uppercase opacity-60 tracking-wider">Actively Exploited (KEV)</p>
                                    <p className="text-4xl font-black text-red-500 mt-2">{kevCount}</p>
                                </div>
                                <div>
                                    <p className="text-xs font-bold uppercase opacity-60 tracking-wider">Critical Severity</p>
                                    <p className="text-4xl font-black text-red-500 mt-2">{criticalCount}</p>
                                </div>
                            </div>

                            <div className="grid grid-cols-2 gap-8">
                                <div className="bg-black/40 backdrop-blur-md p-6 border border-white/25 shadow-sm rounded">
                                    <h3 className="font-bold text-sm tracking-wider uppercase opacity-80 mb-4 border-b border-white/10 pb-3">PRIORITY RANKING</h3>
                                    <table className="w-full text-left text-sm">
                                        <thead>
                                            <tr className="border-b border-white/10 opacity-60 text-xs font-bold">
                                                <th className="pb-3"># SOFTWARE</th>
                                                <th className="pb-3">CVSS</th>
                                                <th className="pb-3">KEV</th>
                                                <th className="pb-3">SCORE</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-white/10">
                                            <tr><td className="py-3.5 font-bold">WordPress</td><td className="opacity-70">8.4</td><td className="opacity-70">2</td><td className="font-mono font-bold text-red-400">98</td></tr>
                                            <tr><td className="py-3.5 font-bold">PHP</td><td className="opacity-70">9.9</td><td className="opacity-70">4</td><td className="font-mono font-bold text-red-400">92</td></tr>
                                            <tr><td className="py-3.5 font-bold">Apache</td><td className="opacity-70">7.5</td><td className="opacity-70">1</td><td className="font-mono font-bold text-red-400">85</td></tr>
                                            <tr><td className="py-3.5 font-bold">MySQL</td><td className="opacity-70">9.8</td><td className="opacity-70">3</td><td className="font-mono font-bold text-red-400">78</td></tr>
                                        </tbody>
                                    </table>
                                </div>

                                <div className="bg-black/40 backdrop-blur-md p-6 border border-white/25 shadow-sm rounded">
                                    <h3 className="font-bold text-sm tracking-wider uppercase opacity-80 mb-4 border-b border-white/10 pb-3">SEVERITY MIX</h3>
                                    <div className="space-y-5">
                                        <div>
                                            <div className="flex justify-between text-xs font-bold mb-1"><span>WordPress</span><span className="text-red-400">Critical</span></div>
                                            <div className="w-full bg-white/10 h-3 rounded-full overflow-hidden"><div className="bg-red-600 h-3 w-4/5"></div></div>
                                        </div>
                                        <div>
                                            <div className="flex justify-between text-xs font-bold mb-1"><span>PHP</span><span className="text-red-400">Critical</span></div>
                                            <div className="w-full bg-white/10 h-3 rounded-full overflow-hidden"><div className="bg-red-600 h-3 w-full"></div></div>
                                        </div>
                                        <div>
                                            <div className="flex justify-between text-xs font-bold mb-1"><span>Apache</span><span className="text-amber-400">High</span></div>
                                            <div className="w-full bg-white/10 h-3 rounded-full overflow-hidden"><div className="bg-amber-500 h-3 w-3/5"></div></div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* TAB 3: CVE EXPLORER */}
                    {activeTab === 'explorer' && (
                        <div className="space-y-6">
                            <div>
                                <h2 className="text-4xl font-black">LOOK UP ANY VULNERABILITY</h2>
                                <p className="opacity-70 mt-1">Search by CVE ID or software, then select an ID to read the details.</p>
                            </div>

                            <div className="grid grid-cols-3 gap-6 bg-black/40 backdrop-blur-md p-5 border border-white/25 shadow-sm rounded">
                                <div>
                                    <label className="text-xs font-bold opacity-60 uppercase tracking-wider block mb-2">SEARCH</label>
                                    <input
                                        type="text"
                                        placeholder="CVE ID or software..."
                                        value={searchQuery}
                                        onChange={(e) => setSearchQuery(e.target.value)}
                                        className="w-full bg-black/50 border border-white/30 text-white placeholder-white/40 p-2.5 text-sm rounded focus:outline-none focus:border-red-500"
                                    />
                                </div>
                                <div>
                                    <label className="text-xs font-bold opacity-60 uppercase tracking-wider block mb-2">SEVERITY</label>
                                    <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} className="w-full bg-black/60 border border-white/30 text-white p-2.5 text-sm rounded focus:outline-none focus:border-red-500">
                                        <option value="ALL" className="bg-black text-white">ALL</option>
                                        <option value="CRITICAL" className="bg-black text-white">CRITICAL</option>
                                        <option value="HIGH" className="bg-black text-white">HIGH</option>
                                        <option value="MEDIUM" className="bg-black text-white">MEDIUM</option>
                                        <option value="LOW" className="bg-black text-white">LOW</option>
                                    </select>
                                </div>
                                <div className="flex items-end">
                                    <label className="flex items-center space-x-3 cursor-pointer pb-2.5">
                                        <input type="checkbox" checked={kevOnly} onChange={(e) => setKevOnly(e.target.checked)} className="w-4 h-4 accent-red-600" />
                                        <span className="text-sm font-bold opacity-90">ACTIVELY EXPLOITED ONLY</span>
                                    </label>
                                </div>
                            </div>

                            <div className="grid grid-cols-3 gap-6">
                                <div className="col-span-2 bg-black/40 backdrop-blur-md border border-white/25 shadow-sm rounded max-h-[500px] overflow-y-auto">
                                    <table className="w-full text-left text-sm">
                                        <thead className="bg-black/80 sticky top-0 border-b border-white/10 opacity-70 text-xs font-bold">
                                            <tr>
                                                <th className="p-3.5">CVE ID</th>
                                                <th className="p-3.5">SOFTWARE</th>
                                                <th className="p-3.5">CVSS</th>
                                                <th className="p-3.5">SEVERITY</th>
                                                <th className="p-3.5">KEV</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-white/10">
                                            {filteredVulns.length > 0 ? (
                                                filteredVulns.map((v, idx) => (
                                                    <tr
                                                        key={idx}
                                                        onClick={() => setSelectedVuln(v)}
                                                        className={`hover:bg-white/10 cursor-pointer transition-colors ${selectedVuln?.cve_id === v.cve_id ? 'bg-white/15' : ''}`}
                                                    >
                                                        <td className="p-3.5 font-mono font-bold text-red-400">{v.cve_id}</td>
                                                        <td className="p-3.5 font-medium">{getSoftwareName(v)}</td>
                                                        <td className="p-3.5 font-mono">{v.cvss_score || '9.8'}</td>
                                                        <td className="p-3.5 font-bold text-red-400">{v.severity}</td>
                                                        <td className="p-3.5 opacity-70">{v.is_kev ? 'Yes' : 'No'}</td>
                                                    </tr>
                                                ))
                                            ) : (
                                                <tr>
                                                    <td colSpan="5" className="p-6 text-center opacity-60">No matching vulnerabilities found.</td>
                                                </tr>
                                            )}
                                        </tbody>
                                    </table>
                                </div>

                                <div className="bg-black/40 backdrop-blur-md p-6 border border-white/25 shadow-sm rounded">
                                    <h3 className="text-xs uppercase font-bold opacity-60 tracking-wider mb-4 border-b border-white/10 pb-2">SELECTED VULNERABILITY</h3>
                                    {selectedVuln ? (
                                        <div className="space-y-4">
                                            <div>
                                                <h4 className="text-2xl font-black font-mono">{selectedVuln.cve_id}</h4>
                                                <p className="text-xs font-bold opacity-60 uppercase mt-1">Software: {getSoftwareName(selectedVuln)}</p>
                                                <p className="text-xs font-bold opacity-60 uppercase">CVSS Score: {selectedVuln.cvss_score || '9.8'}</p>
                                            </div>
                                            <div className="pt-3 border-t border-white/10 text-sm opacity-80 leading-relaxed space-y-3">
                                                <p><strong>Description:</strong> {selectedVuln.description || "Critical vulnerability identified in production web server software components requiring immediate remediation."}</p>
                                                <p><strong>Remediation:</strong> Apply security updates in accordance with vendor guidance and CISA KEV directives.</p>
                                            </div>
                                        </div>
                                    ) : (
                                        <p className="text-sm opacity-60">Select a vulnerability row from the table to view details.</p>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}

                    {/* TAB 4: ATTACK MAP */}
                    {activeTab === 'attackMap' && (
                        <div className="space-y-6">
                            <div className="flex flex-wrap justify-between items-end gap-4">
                                <div>
                                    <h2 className="text-4xl font-black">LIVE WEBSITE ATTACK & TRAFFIC MONITORING</h2>
                                    <p className="opacity-70 mt-1">
                                        Up to {LOG_LIMIT} real-time records from nexustechautomation.me with persistent IP firewall & retention controls.
                                    </p>
                                </div>

                                {/* Filter Buttons */}
                                <div className="flex flex-wrap gap-2">
                                    <button
                                        onClick={() => setLogFilter('ALL')}
                                        className={`px-3.5 py-2 text-xs font-bold rounded border transition-all ${logFilter === 'ALL' ? 'bg-[#6b1d1d] text-white border-red-500' : 'bg-black/40 border-white/20 text-white hover:bg-white/10'}`}
                                    >
                                        ALL ({liveLogs.length})
                                    </button>
                                    <button
                                        onClick={() => setLogFilter('ATTACKS')}
                                        className={`px-3.5 py-2 text-xs font-bold rounded border transition-all ${logFilter === 'ATTACKS' ? 'bg-red-600 text-white border-red-400' : 'bg-black/40 border-white/20 text-red-400 hover:bg-white/10'}`}
                                    >
                                        THREATS ({attackCount})
                                    </button>
                                    <button
                                        onClick={() => setLogFilter('NORMAL')}
                                        className={`px-3.5 py-2 text-xs font-bold rounded border transition-all ${logFilter === 'NORMAL' ? 'bg-emerald-600 text-white border-emerald-400' : 'bg-black/40 border-white/20 text-emerald-400 hover:bg-white/10'}`}
                                    >
                                        NORMAL ({liveLogs.length - attackCount})
                                    </button>
                                    <button
                                        onClick={() => setLogFilter('BLOCKED')}
                                        className={`px-3.5 py-2 text-xs font-bold rounded border transition-all ${logFilter === 'BLOCKED' ? 'bg-amber-600 text-white border-amber-400' : 'bg-black/40 border-white/20 text-amber-300 hover:bg-white/10'}`}
                                    >
                                        BLOCKED ({blockedIps.length})
                                    </button>
                                </div>
                            </div>

                            {/* SOC Summary Strip */}
                            <div className="grid grid-cols-4 gap-4 bg-black/45 backdrop-blur-md p-4 border border-white/20 rounded">
                                <div>
                                    <div className="text-[11px] font-mono uppercase opacity-60">Loaded Logs (Max {LOG_LIMIT})</div>
                                    <div className="text-2xl font-black mt-0.5">{liveLogs.length}</div>
                                </div>
                                <div>
                                    <div className="text-[11px] font-mono uppercase text-red-400">Active Threats</div>
                                    <div className="text-2xl font-black text-red-400 mt-0.5">{attackCount}</div>
                                </div>
                                <div>
                                    <div className="text-[11px] font-mono uppercase text-yellow-300">Unique IPs</div>
                                    <div className="text-2xl font-black text-yellow-300 mt-0.5">{uniqueIpCount}</div>
                                </div>
                                <div>
                                    <div className="text-[11px] font-mono uppercase text-emerald-400">Blocked IPs</div>
                                    <div className="text-2xl font-black text-emerald-400 mt-0.5">{blockedIps.length}</div>
                                </div>
                            </div>

                            {/* Manual IP Firewall + Auto-Shield Controls */}
                            <div className="bg-black/45 backdrop-blur-md p-4 border border-white/25 rounded flex flex-wrap items-center justify-between gap-3">
                                <form onSubmit={handleManualIpSubmit} className="flex flex-wrap items-center gap-2">
                                    <input
                                        type="text"
                                        placeholder="Enter IP to block/unblock (e.g. 111.68.102.25)"
                                        value={manualIpInput}
                                        onChange={(e) => setManualIpInput(e.target.value)}
                                        className="bg-black/60 border border-white/25 text-white placeholder-white/40 px-3 py-2 text-xs font-mono rounded focus:outline-none focus:border-red-500 min-w-[240px]"
                                    />
                                    <button
                                        type="submit"
                                        disabled={!manualIpInput.trim() || busyIp === manualIpInput.trim()}
                                        className="px-3.5 py-2 text-xs font-bold bg-[#6b1d1d] hover:bg-[#521616] text-white rounded transition-all"
                                    >
                                        {blockedSet.has(manualIpInput.trim()) ? 'UNBLOCK IP' : 'APPLY IP RULE'}
                                    </button>
                                </form>

                                <div className="flex flex-wrap items-center gap-2">
                                    <button
                                        type="button"
                                        onClick={() => setAutoBlockRepeaters(prev => !prev)}
                                        className={`px-3 py-2 text-xs font-bold rounded border transition-all ${autoBlockRepeaters ? 'bg-red-700 text-white border-red-400' : 'bg-black/60 text-white/80 border-white/20 hover:bg-white/10'}`}
                                    >
                                        {autoBlockRepeaters ? 'AUTO-BLOCK >=5 HITS: ON' : 'AUTO-BLOCK >=5 HITS: OFF'}
                                    </button>

                                    <button
                                        type="button"
                                        onClick={() => setAutoSync(prev => !prev)}
                                        className={`px-3 py-2 text-xs font-bold rounded border transition-all ${autoSync ? 'bg-emerald-700 text-white border-emerald-400' : 'bg-black/60 text-white/80 border-white/20 hover:bg-white/10'}`}
                                    >
                                        {autoSync ? 'LIVE SYNC: ON (5s)' : 'LIVE SYNC: PAUSED'}
                                    </button>

                                    <button
                                        type="button"
                                        onClick={fetchLogsAndBlocked}
                                        className="px-3 py-2 text-xs font-bold bg-black/60 hover:bg-white/10 text-white border border-white/20 rounded transition-all"
                                    >
                                        REFRESH
                                    </button>
                                </div>
                            </div>

                            {/* Search, Attack Type, Export & Clear Old Data Toolbar */}
                            <div className="bg-black/45 backdrop-blur-md p-4 border border-white/25 rounded flex flex-wrap items-center justify-between gap-3">
                                <div className="flex flex-wrap items-center gap-3">
                                    <input
                                        type="text"
                                        placeholder="Search IP or endpoint..."
                                        value={logSearch}
                                        onChange={(e) => setLogSearch(e.target.value)}
                                        className="bg-black/60 border border-white/25 text-white placeholder-white/40 px-3 py-2 text-xs rounded focus:outline-none focus:border-red-500 min-w-[200px]"
                                    />

                                    <select
                                        value={attackTypeFilter}
                                        onChange={(e) => setAttackTypeFilter(e.target.value)}
                                        className="bg-black/70 border border-white/25 text-white px-3 py-2 text-xs rounded focus:outline-none focus:border-red-500"
                                    >
                                        <option value="ALL">All Attack Types</option>
                                        <option value="SQL_INJECTION">SQL_INJECTION</option>
                                        <option value="XSS_ATTACK">XSS_ATTACK</option>
                                        <option value="PATH_TRAVERSAL">PATH_TRAVERSAL</option>
                                        <option value="BRUTE_FORCE_PROBE">BRUTE_FORCE_PROBE</option>
                                        <option value="NORMAL_TRAFFIC">NORMAL_TRAFFIC</option>
                                    </select>

                                    <button
                                        type="button"
                                        onClick={handleExportLogsCsv}
                                        className="px-3 py-2 text-xs font-bold bg-blue-700 hover:bg-blue-600 text-white rounded transition-all"
                                    >
                                        EXPORT CSV
                                    </button>
                                </div>

                                <div className="flex flex-wrap items-center gap-2">
                                    <select
                                        value={clearPeriod}
                                        onChange={(e) => setClearPeriod(e.target.value)}
                                        className="bg-black/70 border border-white/25 text-amber-300 px-2.5 py-2 text-xs rounded focus:outline-none"
                                    >
                                        <option value="1">Older than 1 Day</option>
                                        <option value="7">Older than 7 Days</option>
                                        <option value="ALL">All Logs (Fresh Start)</option>
                                    </select>

                                    <button
                                        type="button"
                                        disabled={clearingLogs}
                                        onClick={handleClearOldLogs}
                                        className="px-3.5 py-2 text-xs font-bold bg-red-800 hover:bg-red-700 text-white border border-red-500/50 rounded transition-all"
                                    >
                                        {clearingLogs ? 'CLEARING...' : 'CLEAR OLD DATA'}
                                    </button>
                                </div>
                            </div>

                            {/* Attack Vector Distribution Chips */}
                            {attackBreakdown.length > 0 && (
                                <div className="flex flex-wrap gap-2 text-xs font-mono">
                                    {attackBreakdown.map(([vectorName, countVal]) => (
                                        <button
                                            key={vectorName}
                                            type="button"
                                            onClick={() => setAttackTypeFilter(prev => (prev === vectorName ? 'ALL' : vectorName))}
                                            className={`px-3 py-1 rounded border transition-all ${attackTypeFilter === vectorName ? 'bg-red-600 text-white border-red-400' : 'bg-black/50 text-white/80 border-white/15 hover:bg-white/10'}`}
                                        >
                                            {vectorName}: <strong>{countVal}</strong>
                                        </button>
                                    ))}
                                </div>
                            )}

                            {socNotice && (
                                <div className="bg-black/65 border border-cyan-500/40 text-cyan-200 text-xs font-mono px-4 py-2.5 rounded">
                                    {socNotice}
                                </div>
                            )}

                            {/* Blocked IPs Quick Unblock Strip */}
                            {blockedIps.length > 0 && (
                                <div className="bg-red-950/35 border border-red-500/40 px-4 py-3 rounded flex flex-wrap items-center gap-2 text-xs">
                                    <span className="font-mono font-bold text-red-300 uppercase mr-1">Blocked IPs:</span>
                                    {blockedIps.map((ip) => (
                                        <span
                                            key={ip}
                                            className="inline-flex items-center gap-2 bg-black/60 border border-white/15 px-2.5 py-1 rounded font-mono"
                                        >
                                            <span className="text-yellow-300">{ip}</span>
                                            <button
                                                type="button"
                                                disabled={busyIp === ip}
                                                onClick={() => handleToggleBlockIp(ip, 'unblock')}
                                                className="px-2 py-0.5 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded text-[11px]"
                                            >
                                                {busyIp === ip ? '...' : 'UNBLOCK'}
                                            </button>
                                        </span>
                                    ))}
                                </div>
                            )}

                            <div className="bg-black/40 backdrop-blur-md p-6 border border-white/25 shadow-sm rounded">
                                <h3 className="font-bold text-sm tracking-wider uppercase opacity-80 mb-4 border-b border-white/10 pb-3">
                                    LIVE TRAFFIC LOGS & IP FIREWALL ({filteredAttackLogs.length} SHOWN • CLICK ROW TO INSPECT)
                                </h3>

                                {filteredAttackLogs.length === 0 ? (
                                    <p className="text-sm opacity-60 py-6 text-center">No matching traffic logs found.</p>
                                ) : (
                                    <div className="overflow-x-auto">
                                        <table className="w-full text-left text-sm">
                                            <thead>
                                                <tr className="border-b border-white/10 opacity-60 text-xs font-bold">
                                                    <th className="pb-3">STATUS / TYPE</th>
                                                    <th className="pb-3">PAYLOAD / ENDPOINT</th>
                                                    <th className="pb-3">ATTACKER REAL IP</th>
                                                    <th className="pb-3">HITS</th>
                                                    <th className="pb-3">TIME</th>
                                                    <th className="pb-3">FIREWALL ACTION</th>
                                                </tr>
                                            </thead>
                                            <tbody className="divide-y divide-white/10">
                                                {filteredAttackLogs.map((log, idx) => {
                                                    const isAttack = isThreatLog(log);
                                                    const ip = log.ip_address || 'Unknown';
                                                    const isBlocked = Boolean(log.blocked) || blockedSet.has(ip);
                                                    const hits = ipHitCounts[ip] || 1;
                                                    return (
                                                        <tr
                                                            key={log.id || idx}
                                                            onClick={() => setInspectedLog(log)}
                                                            className={`cursor-pointer transition-colors ${isBlocked ? 'bg-amber-950/30 hover:bg-amber-900/35' : isAttack ? 'bg-red-950/30 hover:bg-red-900/40' : 'hover:bg-white/5'}`}
                                                        >
                                                            <td className={`py-3 font-mono font-bold ${isAttack ? 'text-red-400' : 'text-emerald-400'}`}>
                                                                {isAttack ? `🚨 ${log.attack_type || log.type}` : '✅ NORMAL_VISIT'}
                                                                {isBlocked && <span className="ml-2 text-[10px] px-1.5 py-0.5 bg-red-600/40 border border-red-400/50 text-red-200 rounded">BLOCKED</span>}
                                                            </td>
                                                            <td className="py-3 font-mono text-cyan-300 max-w-xs truncate">{log.endpoint || '/'}</td>
                                                            <td className="py-3 font-mono font-bold text-yellow-300">{ip}</td>
                                                            <td className={`py-3 font-mono text-xs ${hits >= 5 ? 'text-red-400 font-bold' : 'opacity-75'}`}>
                                                                {hits}x
                                                            </td>
                                                            <td className="py-3 opacity-70 text-xs">
                                                                {new Date(log.created_at || log.timestamp).toLocaleTimeString()}
                                                            </td>
                                                            <td className="py-3" onClick={(e) => e.stopPropagation()}>
                                                                {isBlocked ? (
                                                                    <button
                                                                        type="button"
                                                                        disabled={busyIp === ip}
                                                                        onClick={() => handleToggleBlockIp(ip, 'unblock')}
                                                                        className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono font-bold rounded transition-all"
                                                                    >
                                                                        {busyIp === ip ? '...' : '🔓 UNBLOCK IP'}
                                                                    </button>
                                                                ) : (
                                                                    <button
                                                                        type="button"
                                                                        disabled={busyIp === ip}
                                                                        onClick={() => handleToggleBlockIp(ip, 'block')}
                                                                        className={`px-3 py-1 text-xs font-bold rounded transition-all ${isAttack ? 'bg-red-600 hover:bg-red-700 text-white' : 'bg-white/10 hover:bg-white/20 text-white'}`}
                                                                    >
                                                                        {busyIp === ip ? '...' : 'BLOCK IP'}
                                                                    </button>
                                                                )}
                                                            </td>
                                                        </tr>
                                                    );
                                                })}
                                            </tbody>
                                        </table>
                                    </div>
                                )}
                            </div>

                            {/* Log Inspector Drawer / Card */}
                            {inspectedLog && (
                                <div className="bg-black/75 backdrop-blur-md border border-cyan-500/40 rounded p-5 space-y-3">
                                    <div className="flex justify-between items-center border-b border-white/10 pb-2">
                                        <span className="text-xs font-mono font-bold uppercase text-cyan-300">
                                            EVENT FORENSIC INSPECTOR
                                        </span>
                                        <button
                                            type="button"
                                            onClick={() => setInspectedLog(null)}
                                            className="text-xs font-mono px-2.5 py-1 bg-white/10 hover:bg-white/20 rounded"
                                        >
                                            CLOSE ✕
                                        </button>
                                    </div>
                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
                                        <div><span className="opacity-60 block">IP ADDRESS</span><strong className="text-yellow-300">{inspectedLog.ip_address || 'Unknown'}</strong></div>
                                        <div><span className="opacity-60 block">ATTACK TYPE</span><strong>{inspectedLog.attack_type || inspectedLog.type || 'NORMAL_TRAFFIC'}</strong></div>
                                        <div><span className="opacity-60 block">METHOD</span><strong>{inspectedLog.method || 'GET'}</strong></div>
                                        <div><span className="opacity-60 block">TOTAL IP HITS</span><strong>{ipHitCounts[(inspectedLog.ip_address || '').trim()] || 1}x</strong></div>
                                    </div>
                                    <div className="text-xs font-mono bg-black/50 p-3 rounded border border-white/10 break-all">
                                        <span className="opacity-60 block mb-1">FULL ENDPOINT / PAYLOAD</span>
                                        <span className="text-cyan-300">{inspectedLog.endpoint || '/'}</span>
                                    </div>
                                </div>
                            )}
                        </div>
                    )}
                </main>
            </div>

            <Chatbot />
        </div>
    );
}

export default App;