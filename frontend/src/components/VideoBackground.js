import React from 'react';

const VideoBackground = ({ activeTab, theme }) => {
    const videoSrc = (activeTab === 'overview' || activeTab === 'fixFirst')
        ? '/bg-video-1.mp4'
        : '/bg-video-2.mp4';

    // Theme ke hisab se overlay color aur opacity set karna
    const getOverlayStyle = () => {
        if (theme === 'neon') return { backgroundColor: '#000000', opacity: 0.55 }; // Neon mode ke liye dark glowing look
        if (theme === 'night') return { backgroundColor: '#0b0f19', opacity: 0.70 }; // Night mode ke liye
        return { backgroundColor: '#fcfbfa', opacity: 0.75 }; // Light mode ke liye
    };

    return (
        <div style={{
            position: 'fixed',
            top: 0,
            left: 0,
            width: '100vw',
            height: '100vh',
            overflow: 'hidden',
            zIndex: 0,
            pointerEvents: 'none'
        }}>
            <video
                key={videoSrc}
                autoPlay
                loop
                muted
                playsInline
                preload="auto"
                style={{
                    width: '100vw',
                    height: '100vh',
                    objectFit: 'cover',
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    filter: theme === 'neon' ? 'hue-rotate(90deg) contrast(1.2)' : 'none'
                }}
            >
                <source src={videoSrc} type="video/mp4" />
            </video>

            {/* Dynamic Theme Overlay */}
            <div style={{
                position: 'absolute',
                top: 0,
                left: 0,
                width: '100%',
                height: '100%',
                transition: 'background-color 0.3s ease',
                ...getOverlayStyle()
            }} />
        </div>
    );
};

export default VideoBackground;