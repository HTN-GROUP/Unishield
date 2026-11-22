import React, { useState } from 'react';

const API_BASE = (
    process.env.REACT_APP_API_URL || 'https://unishield-backend.vercel.app'
).replace(/\/+$/, '');

const Chatbot = () => {
    const [isChatOpen, setIsChatOpen] = useState(false);
    const [chatMessages, setChatMessages] = useState([
        {
            sender: 'ai',
            text: 'Hello! I am the UniShield AI Security Assistant. You can ask me about critical vulnerabilities, KEV counts, APIs, or CVE definitions.'
        }
    ]);
    const [inputMessage, setInputMessage] = useState('');
    const [isSending, setIsSending] = useState(false);

    const handleSendMessage = async (e) => {
        e.preventDefault();
        const trimmed = inputMessage.trim();
        if (!trimmed || isSending) return;

        setChatMessages(prev => [...prev, { sender: 'user', text: trimmed }]);
        setInputMessage('');
        setIsSending(true);

        try {
            let res = await fetch(`${API_BASE}/?endpoint=chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: trimmed })
            });

            if (!res.ok) {
                res = await fetch(`${API_BASE}/api/chat`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message: trimmed })
                });
            }

            if (!res.ok) {
                throw new Error(`HTTP ${res.status}`);
            }

            const data = await res.json();
            const botReply = data.reply || data.response || data.message || 'Analyzing security context...';
            setChatMessages(prev => [...prev, { sender: 'ai', text: botReply }]);
        } catch (err) {
            setChatMessages(prev => [...prev, { sender: 'ai', text: 'Server error connecting to AI Assistant.' }]);
        } finally {
            setIsSending(false);
        }
    };

    return (
        <div className="fixed bottom-6 right-6 z-50">
            {!isChatOpen ? (
                <button
                    type="button"
                    onClick={() => setIsChatOpen(true)}
                    className="bg-[#6b1d1d] text-white p-4 rounded-full shadow-2xl flex items-center justify-center hover:scale-105 transition-all text-xl font-bold"
                >
                    💬
                </button>
            ) : (
                <div className="w-80 bg-white border border-gray-300 rounded-lg shadow-2xl flex flex-col h-96">
                    <div className="bg-[#6b1d1d] text-white p-3.5 flex justify-between items-center rounded-t-lg">
                        <span className="font-bold text-sm tracking-wide">🤖 AI Security Assistant</span>
                        <button type="button" onClick={() => setIsChatOpen(false)} className="text-white font-bold">✕</button>
                    </div>
                    <div className="flex-1 p-3.5 overflow-y-auto space-y-3 text-sm bg-gray-50">
                        {chatMessages.map((msg, idx) => (
                            <div
                                key={idx}
                                className={`p-2.5 rounded-lg max-w-[85%] ${msg.sender === 'user'
                                    ? 'ml-auto bg-[#6b1d1d] text-white text-right'
                                    : 'bg-white border border-gray-200 text-left text-gray-800 shadow-sm'
                                    }`}
                            >
                                {msg.text}
                            </div>
                        ))}
                        {isSending && (
                            <div className="p-2.5 rounded-lg max-w-[85%] bg-white border border-gray-200 text-left text-gray-500 italic shadow-sm">
                                Thinking...
                            </div>
                        )}
                    </div>
                    <form onSubmit={handleSendMessage} className="p-3 border-t bg-white flex rounded-b-lg">
                        <input
                            type="text"
                            placeholder="Ask AI Assistant..."
                            value={inputMessage}
                            onChange={(e) => setInputMessage(e.target.value)}
                            disabled={isSending}
                            className="flex-1 border border-gray-300 p-2 text-sm rounded-l focus:outline-none focus:border-[#6b1d1d]"
                        />
                        <button
                            type="submit"
                            disabled={isSending}
                            className="bg-[#6b1d1d] text-white px-3.5 text-sm font-bold rounded-r disabled:opacity-60"
                        >
                            Send
                        </button>
                    </form>
                </div>
            )}
        </div>
    );
};

export default Chatbot;