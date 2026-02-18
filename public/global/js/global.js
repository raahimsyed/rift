document.addEventListener('DOMContentLoaded', function () {
    const typingText = document.getElementById('typingText');

    // Quotes to cycle through
    const quotes = [
        "the quiet keeps rifting wider",
        "time keeps moving through what's already rifted",
        "the space between moments keeps rifting",
        "the quiet keeps rifting wider"
    ];

    let currentQuoteIndex = 0;
    let currentCharIndex = 0;
    let isTyping = true;

    function typeEffect() {
        if (!typingText) return;
        if (isTyping) {
            if (currentCharIndex < quotes[currentQuoteIndex].length) {
                typingText.textContent += quotes[currentQuoteIndex].charAt(currentCharIndex);
                currentCharIndex++;
                setTimeout(typeEffect, 80);
            } else {
                isTyping = false;
                setTimeout(typeEffect, 2000); // Wait before erasing
            }
        } else {
            if (currentCharIndex > 0) {
                typingText.textContent = quotes[currentQuoteIndex].substring(0, currentCharIndex - 1);
                currentCharIndex--;
                setTimeout(typeEffect, 40);
            } else {
                isTyping = true;
                currentQuoteIndex = (currentQuoteIndex + 1) % quotes.length;
                setTimeout(typeEffect, 500); // Wait before typing next quote
            }
        }
    }

    // Start typing effect
    if (typingText) typeEffect();

    // Cursor light effect
    const cursorLight = document.createElement('div');
    cursorLight.className = 'cursor-light';
    document.body.appendChild(cursorLight);

    // Store previous positions for line trail
    let prevX = null;
    let prevY = null;

    document.addEventListener('mousemove', function (e) {
        // Skip cursor effects when game viewer is active
        const viewer = document.getElementById('game-viewer');
        if (viewer && viewer.classList.contains('active')) {
            cursorLight.style.display = 'none';
            return;
        }
        cursorLight.style.display = '';

        // Update light position
        cursorLight.style.left = e.clientX + 'px';
        cursorLight.style.top = e.clientY + 'px';

        // Create line trail
        if (prevX !== null && prevY !== null) {
            const trail = document.createElement('div');
            trail.className = 'cursor-trail';

            // Calculate distance and angle between points
            const dx = e.clientX - prevX;
            const dy = e.clientY - prevY;
            const distance = Math.sqrt(dx * dx + dy * dy);
            const angle = Math.atan2(dy, dx) * 180 / Math.PI;

            // Position and style the line
            trail.style.left = prevX + 'px';
            trail.style.top = prevY + 'px';
            trail.style.width = distance + 'px';
            trail.style.transform = `rotate(${angle}deg)`;
            trail.style.transformOrigin = '0 50%';

            document.body.appendChild(trail);

            // Remove trail after animation
            setTimeout(() => {
                trail.remove();
            }, 500);
        }

        prevX = e.clientX;
        prevY = e.clientY;
    });

    // Nav toggle
    const nav = document.querySelector('.bottom-nav');
    if (nav) {
        const toggle = document.createElement('button');
        toggle.className = 'nav-toggle';
        toggle.title = 'Toggle navigation';
        document.body.appendChild(toggle);

        toggle.addEventListener('click', () => {
            nav.classList.toggle('hidden');
            toggle.classList.toggle('nav-is-hidden');
        });
    }

    // Apply saved nav position on all pages
document.addEventListener('DOMContentLoaded', () => {
    const savedPosition = localStorage.getItem('rift__nav-position') || 'bottom';
    document.body.classList.add('nav-pos-' + savedPosition);
});

});

// Global auth/save helper for Rift pages.
(function () {
    const SETTINGS_KEYS = [
        'rift__nav-position',
        'rift__launch-mode',
        'rift__disguise-title',
        'rift__disguise-favicon',
    ];

    async function request(url, options = {}) {
        const res = await fetch(url, {
            credentials: 'include',
            headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
            ...options,
        });
        let payload = null;
        try {
            payload = await res.json();
        } catch {
            payload = null;
        }
        if (!res.ok) {
            const error = new Error(payload?.error || `request failed (${res.status})`);
            error.status = res.status;
            throw error;
        }
        return payload;
    }

    function collectLocalSettings() {
        const settings = {};
        for (const key of SETTINGS_KEYS) {
            const value = localStorage.getItem(key);
            if (value !== null) settings[key] = value;
        }
        return settings;
    }

    window.RiftAuth = {
        async me() {
            return await request('/api/auth/me');
        },
        async signup(username, password) {
            return await request('/api/auth/signup', {
                method: 'POST',
                body: JSON.stringify({ username, password }),
            });
        },
        async login(username, password) {
            return await request('/api/auth/login', {
                method: 'POST',
                body: JSON.stringify({ username, password }),
            });
        },
        async logout() {
            return await request('/api/auth/logout', { method: 'POST' });
        },
        async getSave() {
            return await request('/api/save');
        },
        async saveSettings(settings) {
            return await request('/api/save/settings', {
                method: 'PUT',
                body: JSON.stringify({ settings }),
            });
        },
        async saveLocalSettings() {
            const settings = collectLocalSettings();
            if (!Object.keys(settings).length) return { ok: true };
            return await this.saveSettings(settings);
        },
        async saveGameProgress(gameId, progress) {
            if (!gameId) return { ok: false };
            return await request(`/api/save/games/${encodeURIComponent(gameId)}`, {
                method: 'PUT',
                body: JSON.stringify({ progress }),
            });
        },
    };
})();
