import React, { useState } from 'react';

const Chatbot = () => {
    const [isChatOpen, setIsChatOpen] = useState(false);
    const [chatMessages, setChatMessages] = useState([
        { sender: 'ai', text: 'Hello! I am the UniShield AI Security Assistant. You can ask me about critical vulnerabilities, KEV counts, APIs, or CVE definitions.' }
    ]);
    const [inputMessage, setInputMessage] = useState('');

    const handleSendMessage = async (e) => {
        e.preventDefault();
        if (!inputMessage.trim()) return;

        const userMsg = inputMessage;
        setChatMessages(prev => [...prev, { sender: 'user', text: userMsg }]);
        setInputMessage('');

        try {
            const res = await fetch('http://localhost:5001/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: userMsg })
            });
            const data = await res.json();
            setChatMessages(prev => [...prev, { sender: 'ai', text: data.reply || "Analyzing security context..." }]);
        } catch (err) {
            setChatMessages(prev => [...prev, { sender: 'ai', text: "Server error connecting to AI Assistant." }]);
        }
    };

    return (
        <div className="fixed bottom-6 right-6 z-50">
            {!isChatOpen ? (
                <button
                    onClick={() => setIsChatOpen(true)}
                    className="bg-[#6b1d1d] text-white p-4 rounded-full shadow-2xl flex items-center justify-center hover:scale-105 transition-all text-xl font-bold"
                >
                    💬
                </button>
            ) : (
                <div className="w-80 bg-white border border-gray-300 rounded-lg shadow-2xl flex flex-col h-96">
                    <div className="bg-[#6b1d1d] text-white p-3.5 flex justify-between items-center rounded-t-lg">
                        <span className="font-bold text-sm tracking-wide">🤖 AI Security Assistant</span>
                        <button onClick={() => setIsChatOpen(false)} className="text-white font-bold">✕</button>
                    </div>
                    <div className="flex-1 p-3.5 overflow-y-auto space-y-3 text-sm bg-gray-50">
                        {chatMessages.map((msg, idx) => (
                            <div key={idx} className={`p-2.5 rounded-lg max-w-[85%] ${msg.sender === 'user' ? 'ml-auto bg-[#6b1d1d] text-white text-right' : 'bg-white border border-gray-200 text-left text-gray-800 shadow-sm'}`}>
                                {msg.text}
                            </div>
                        ))}
                    </div>
                    <form onSubmit={handleSendMessage} className="p-3 border-t bg-white flex rounded-b-lg">
                        <input
                            type="text"
                            placeholder="Ask AI Assistant..."
                            value={inputMessage}
                            onChange={(e) => setInputMessage(e.target.value)}
                            className="flex-1 border border-gray-300 p-2 text-sm rounded-l focus:outline-none focus:border-[#6b1d1d]"
                        />
                        <button type="submit" className="bg-[#6b1d1d] text-white px-3.5 text-sm font-bold rounded-r">Send</button>
                    </form>
                </div>
            )}
        </div>
    );
};

export default Chatbot;