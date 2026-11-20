import React, { useState, useEffect } from 'react';
import VideoBackground from './components/VideoBackground';
import Header from './components/Header';
import Chatbot from './components/Chatbot';

const API_BASE = process.env.REACT_APP_API_URL || 'https://unishield-backend.vercel.app';
const ADMIN_USERNAME = process.env.REACT_APP_ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.REACT_APP_ADMIN_PASS || 'UniShield@2026';

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
    const [logFilter, setLogFilter] = useState('ALL'); // 'ALL', 'ATTACKS', 'NORMAL'
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

    // Fetching Live Traffic & Attack Logs from Backend
    useEffect(() => {
        if (!isAuthenticated) return;

        const fetchLogs = () => {
            fetch(`${API_BASE}/?endpoint=logs`)
                .then(res => res.json())
                .then(data => {
                    if (Array.isArray(data)) {
                        setLiveLogs(data);
                    }
                })
                .catch(err => console.error("Error fetching live logs:", err));
        };

        fetchLogs();
        const interval = setInterval(fetchLogs, 5000);
        return () => clearInterval(interval);
    }, [isAuthenticated]);

    // Helper to safely extract software name regardless of backend column name
    const getSoftwareName = (v) => v.software_name || v.software || v.product || 'Web Stack';

    // Filter logic for CVE Explorer
    const filteredVulns = vulnerabilities.filter(v => {
        const softName = getSoftwareName(v).toLowerCase();
        const cveId = (v.cve_id || '').toLowerCase();
        const matchesSearch = cveId.includes(searchQuery.toLowerCase()) || softName.includes(searchQuery.toLowerCase());
        const matchesSeverity = severityFilter === 'ALL' || (v.severity || '').toUpperCase() === severityFilter;
        const matchesKev = !kevOnly || Boolean(v.is_kev);
        return matchesSearch && matchesSeverity && matchesKev;
    });

    const criticalCount = vulnerabilities.filter(v => (v.severity || '').toUpperCase() === 'CRITICAL').length;
    const kevCount = vulnerabilities.filter(v => Boolean(v.is_kev)).length;
    const attackCount = liveLogs.filter(l => l.attack_type && l.attack_type !== 'NORMAL_TRAFFIC').length;

    // Theme ke mutabiq dynamic text colors
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
            {/* Background Video Layer with Theme Support */}
            <VideoBackground activeTab={activeTab} theme={theme} />

            {/* Foreground Content */}
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
                        <div className="space-y-8">
                            <div className="flex flex-wrap justify-between items-end gap-4">
                                <div>
                                    <h2 className="text-4xl font-black">LIVE WEBSITE ATTACK & TRAFFIC MONITORING</h2>
                                    <p className="opacity-70 mt-1">Real-time visitor IPs and hacking attempts captured from nexustechautomation.me.</p>
                                </div>

                                {/* Filter Buttons: Normal vs Attacks */}
                                <div className="flex space-x-2">
                                    <button
                                        onClick={() => setLogFilter('ALL')}
                                        className={`px-4 py-2 text-xs font-bold rounded border transition-all ${logFilter === 'ALL' ? 'bg-[#6b1d1d] text-white border-red-500' : 'bg-black/40 border-white/20 hover:bg-white/10'}`}
                                    >
                                        ALL ({liveLogs.length})
                                    </button>
                                    <button
                                        onClick={() => setLogFilter('ATTACKS')}
                                        className={`px-4 py-2 text-xs font-bold rounded border transition-all ${logFilter === 'ATTACKS' ? 'bg-red-600 text-white border-red-400' : 'bg-black/40 border-white/20 text-red-400 hover:bg-white/10'}`}
                                    >
                                        HACKING ATTACKS ({attackCount})
                                    </button>
                                    <button
                                        onClick={() => setLogFilter('NORMAL')}
                                        className={`px-4 py-2 text-xs font-bold rounded border transition-all ${logFilter === 'NORMAL' ? 'bg-emerald-600 text-white border-emerald-400' : 'bg-black/40 border-white/20 text-emerald-400 hover:bg-white/10'}`}
                                    >
                                        NORMAL VISITS ({liveLogs.length - attackCount})
                                    </button>
                                </div>
                            </div>

                            <div className="bg-black/40 backdrop-blur-md p-6 border border-white/25 shadow-sm rounded">
                                <h3 className="font-bold text-sm tracking-wider uppercase opacity-80 mb-4 border-b border-white/10 pb-3">
                                    LIVE TRAFFIC LOGS & IP FIREWALL
                                </h3>

                                {liveLogs.length === 0 ? (
                                    <p className="text-sm opacity-60 py-6 text-center">No live traffic recorded yet. Visit <span className="text-red-400 font-bold">nexustechautomation.me</span> to generate live logs!</p>
                                ) : (
                                    <div className="overflow-x-auto">
                                        <table className="w-full text-left text-sm">
                                            <thead>
                                                <tr className="border-b border-white/10 opacity-60 text-xs font-bold">
                                                    <th className="pb-3">STATUS / TYPE</th>
                                                    <th className="pb-3">PAYLOAD / ENDPOINT</th>
                                                    <th className="pb-3">ATTACKER REAL IP</th>
                                                    <th className="pb-3">TIME</th>
                                                    <th className="pb-3">FIREWALL ACTION</th>
                                                </tr>
                                            </thead>
                                            <tbody className="divide-y divide-white/10">
                                                {liveLogs
                                                    .filter(log => {
                                                        if (logFilter === 'ATTACKS') return log.attack_type && log.attack_type !== 'NORMAL_TRAFFIC';
                                                        if (logFilter === 'NORMAL') return !log.attack_type || log.attack_type === 'NORMAL_TRAFFIC';
                                                        return true;
                                                    })
                                                    .map((log, idx) => {
                                                        const isAttack = log.attack_type && log.attack_type !== 'NORMAL_TRAFFIC';
                                                        const isBlocked = blockedIps.includes(log.ip_address);
                                                        return (
                                                            <tr key={idx} className={`transition-colors ${isAttack ? 'bg-red-950/30 hover:bg-red-900/40' : 'hover:bg-white/5'}`}>
                                                                <td className={`py-3 font-mono font-bold ${isAttack ? 'text-red-400' : 'text-emerald-400'}`}>
                                                                    {isAttack ? `🚨 ${log.attack_type}` : '✅ NORMAL_VISIT'}
                                                                </td>
                                                                <td className="py-3 font-mono text-cyan-300 max-w-xs truncate">{log.endpoint || '/'}</td>
                                                                <td className="py-3 font-mono font-bold text-yellow-300">{log.ip_address}</td>
                                                                <td className="py-3 opacity-70 text-xs">
                                                                    {new Date(log.created_at || log.timestamp).toLocaleTimeString()}
                                                                </td>
                                                                <td className="py-3">
                                                                    {isBlocked ? (
                                                                        <span className="px-3 py-1 bg-red-600/30 border border-red-500 text-red-300 text-xs font-mono font-bold rounded">
                                                                            🚫 IP BLOCKED
                                                                        </span>
                                                                    ) : (
                                                                        <button
                                                                            onClick={() => setBlockedIps([...blockedIps, log.ip_address])}
                                                                            className={`px-3 py-1 text-xs font-bold rounded transition-all ${isAttack ? 'bg-red-600 hover:bg-red-700 text-white' : 'bg-white/10 hover:bg-white/20 text-white'}`}
                                                                        >
                                                                            BLOCK IP
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
                        </div>
                    )}
                </main>
            </div>

            <Chatbot />
        </div>
    );
}

export default App;