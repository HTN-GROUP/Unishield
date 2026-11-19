import React, { useState } from 'react';

const Explorer = ({ vulnerabilities }) => {
    const [searchQuery, setSearchQuery] = useState('');
    const [severityFilter, setSeverityFilter] = useState('ALL');
    const [kevOnly, setKevOnly] = useState(false);
    const [selectedVuln, setSelectedVuln] = useState(vulnerabilities[0] || null);

    // ETL / Data Filter Logic
    const filteredVulns = vulnerabilities.filter(v => {
        const matchesSearch = v.cve_id?.toLowerCase().includes(searchQuery.toLowerCase()) ||
            v.software_name?.toLowerCase().includes(searchQuery.toLowerCase());
        const matchesSeverity = severityFilter === 'ALL' || v.severity === severityFilter;
        const matchesKev = !kevOnly || v.is_kev === true;
        return matchesSearch && matchesSeverity && matchesKev;
    });

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-4xl font-black">LOOK UP ANY VULNERABILITY</h2>
                <p className="opacity-70 mt-1">Search by CVE ID or software, then select an ID to read details.</p>
            </div>

            {/* Filter Bar */}
            <div className="grid grid-cols-3 gap-6 bg-black/40 backdrop-blur-md p-5 border border-white/25 rounded shadow-sm">
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
                    <select
                        value={severityFilter}
                        onChange={(e) => setSeverityFilter(e.target.value)}
                        className="w-full bg-black/60 border border-white/30 text-white p-2.5 text-sm rounded focus:outline-none focus:border-red-500"
                    >
                        <option value="ALL" className="bg-black">ALL</option>
                        <option value="CRITICAL" className="bg-black">CRITICAL</option>
                        <option value="HIGH" className="bg-black">HIGH</option>
                        <option value="MEDIUM" className="bg-black">MEDIUM</option>
                        <option value="LOW" className="bg-black">LOW</option>
                    </select>
                </div>
                <div className="flex items-end">
                    <label className="flex items-center space-x-3 cursor-pointer pb-2.5">
                        <input
                            type="checkbox"
                            checked={kevOnly}
                            onChange={(e) => setKevOnly(e.target.checked)}
                            className="w-4 h-4 accent-red-600"
                        />
                        <span className="text-sm font-bold opacity-90">ACTIVELY EXPLOITED ONLY (KEV)</span>
                    </label>
                </div>
            </div>

            {/* Results Table & Detail Card */}
            <div className="grid grid-cols-3 gap-6">
                <div className="col-span-2 bg-black/40 backdrop-blur-md border border-white/25 rounded max-h-[500px] overflow-y-auto">
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
                            {filteredVulns.map((v, idx) => (
                                <tr key={idx} onClick={() => setSelectedVuln(v)} className="hover:bg-white/10 cursor-pointer transition-colors">
                                    <td className="p-3.5 font-mono font-bold text-red-400">{v.cve_id}</td>
                                    <td className="p-3.5 font-medium">{v.software_name}</td>
                                    <td className="p-3.5 font-mono">{v.cvss_score || '9.8'}</td>
                                    <td className="p-3.5 font-bold text-red-400">{v.severity}</td>
                                    <td className="p-3.5 opacity-70">{v.is_kev ? 'Yes' : 'No'}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>

                {/* Selected Vuln View */}
                <div className="bg-black/40 backdrop-blur-md p-6 border border-white/25 rounded">
                    <h3 className="text-xs uppercase font-bold opacity-60 tracking-wider mb-4 border-b border-white/10 pb-2">SELECTED VULNERABILITY</h3>
                    {selectedVuln ? (
                        <div className="space-y-4">
                            <div>
                                <h4 className="text-2xl font-black font-mono">{selectedVuln.cve_id}</h4>
                                <p className="text-xs font-bold opacity-60 uppercase mt-1">Software: {selectedVuln.software_name}</p>
                                <p className="text-xs font-bold opacity-60 uppercase">CVSS Score: {selectedVuln.cvss_score || '9.8'}</p>
                            </div>
                            <div className="pt-3 border-t border-white/10 text-sm opacity-80 leading-relaxed space-y-3">
                                <p><strong>Description:</strong> {selectedVuln.description || "Critical vulnerability identified in software components requiring immediate remediation."}</p>
                                <p><strong>KEV Action:</strong> {selectedVuln.is_kev ? "Apply vendor updates immediately per CISA directive." : "Standard patch window applies."}</p>
                            </div>
                        </div>
                    ) : (
                        <p className="text-sm opacity-60">Select a row to see details.</p>
                    )}
                </div>
            </div>
        </div>
    );
};

export default Explorer;