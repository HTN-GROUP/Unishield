import React from 'react';

const Header = ({ activeTab, setActiveTab, theme, setTheme }) => {
    return (
        <header className="bg-[#6b1d1d]/95 backdrop-blur-md text-white px-8 py-4 flex justify-between items-center shadow-lg sticky top-0 z-40 border-b border-white/10">
            <div className="flex items-center space-x-4">
                <h1 className="text-2xl font-black tracking-wider">UNISHIELD</h1>
                <span className="text-xs uppercase bg-black/25 px-2.5 py-1 rounded tracking-widest font-semibold border border-white/10">
                    University Web Security Monitor
                </span>
            </div>

            <nav className="flex items-center space-x-8 text-sm font-bold tracking-wider">
                <button onClick={() => setActiveTab('overview')} className={`pb-1 transition-all ${activeTab === 'overview' ? 'border-b-2 border-white text-white' : 'text-white/70 hover:text-white'}`}>00 OVERVIEW</button>
                <button onClick={() => setActiveTab('fixFirst')} className={`pb-1 transition-all ${activeTab === 'fixFirst' ? 'border-b-2 border-white text-white' : 'text-white/70 hover:text-white'}`}>01 FIX FIRST</button>
                <button onClick={() => setActiveTab('explorer')} className={`pb-1 transition-all ${activeTab === 'explorer' ? 'border-b-2 border-white text-white' : 'text-white/70 hover:text-white'}`}>02 EXPLORER</button>
                <button onClick={() => setActiveTab('attackMap')} className={`pb-1 transition-all ${activeTab === 'attackMap' ? 'border-b-2 border-white text-white' : 'text-white/70 hover:text-white'}`}>03 ATTACK MAP</button>

                {/* Theme Switcher Dropdown */}
                <div className="pl-4 border-l border-white/20 flex items-center space-x-2">
                    <span className="text-xs text-white/70 uppercase">Theme:</span>
                    <select
                        value={theme}
                        onChange={(e) => setTheme(e.target.value)}
                        className="bg-black/40 text-white border border-white/30 rounded px-2 py-1 text-xs font-bold focus:outline-none cursor-pointer"
                    >
                        <option value="light" className="text-black">Light Mode</option>
                        <option value="night" className="text-black">Night Mode</option>
                        <option value="neon" className="text-black">Neon Cyber</option>
                    </select>
                </div>
            </nav>
        </header>
    );
};

export default Header;