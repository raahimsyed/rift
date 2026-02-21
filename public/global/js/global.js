const RIFT_APPEARANCE = {
    THEME_KEY: 'rift__theme',
    RAIN_KEY: 'rift__rain-enabled',
    DEFAULT_THEME: 'midnight',
    THEMES: [
        'midnight', 'ocean', 'emerald', 'sunset', 'rose', 'violet',
        'amber', 'crimson', 'arctic', 'graphite', 'neon', 'cobalt'
    ],
};

function applyRiftAppearance() {
    if (!document.body) return;

    const rawTheme = String(localStorage.getItem(RIFT_APPEARANCE.THEME_KEY) || RIFT_APPEARANCE.DEFAULT_THEME).toLowerCase();
    const theme = RIFT_APPEARANCE.THEMES.includes(rawTheme) ? rawTheme : RIFT_APPEARANCE.DEFAULT_THEME;

    for (const cls of Array.from(document.body.classList)) {
        if (cls.startsWith('theme-')) document.body.classList.remove(cls);
    }
    document.body.classList.add(`theme-${theme}`);

    const rainEnabled = localStorage.getItem(RIFT_APPEARANCE.RAIN_KEY) !== 'false';
    document.body.classList.toggle('rain-disabled', !rainEnabled);
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', applyRiftAppearance, { once: true });
} else {
    applyRiftAppearance();
}

window.addEventListener('storage', (event) => {
    if (event.key === RIFT_APPEARANCE.THEME_KEY || event.key === RIFT_APPEARANCE.RAIN_KEY) {
        applyRiftAppearance();
    }
});

window.RiftAppearance = {
    ...RIFT_APPEARANCE,
    apply: applyRiftAppearance,
    setTheme(theme) {
        const next = String(theme || '').toLowerCase();
        localStorage.setItem(this.THEME_KEY, this.THEMES.includes(next) ? next : this.DEFAULT_THEME);
        this.apply();
    },
    setRainEnabled(enabled) {
        localStorage.setItem(this.RAIN_KEY, enabled ? 'true' : 'false');
        this.apply();
    },
};

const RIFT_BOOT = {
    SESSION_KEY: 'rift__boot-screen-shown-v1',
    DISPLAY_MS: 10000,
    FADE_MS: 520,
};

function runRiftBootTerminal(bootRoot) {
    const output = bootRoot.querySelector('.rift-boot-terminal-output');
    if (!output) return () => {};

    const lines = [
        'rift@boot:~$ uname -sr',
        'Linux 6.8.0-rift',
        'rift@boot:~$ systemctl start scramjet.service',
        '[  ok  ] scramjet transport online',
        'rift@boot:~$ ./init-rift --profile infamous',
        '[  ok  ] powered by scramjet',
        '[  ok  ] inspired by infamous',
        'rift@boot:~$ launch rift',
        '[ done ] boot sequence complete',
        'rift$'
    ];

    let stopped = false;
    const timers = [];
    let lineIndex = 0;
    let charIndex = 0;

    function schedule(fn, delay) {
        const timer = window.setTimeout(() => {
            if (!stopped) fn();
        }, delay);
        timers.push(timer);
    }

    function step() {
        if (lineIndex >= lines.length) return;

        const current = lines[lineIndex];
        if (charIndex < current.length) {
            output.textContent += current.charAt(charIndex);
            charIndex += 1;
            schedule(step, 20 + Math.floor(Math.random() * 16));
            return;
        }

        output.textContent += '\n';
        lineIndex += 1;
        charIndex = 0;
        schedule(step, 190);
    }

    schedule(step, 220);

    return () => {
        stopped = true;
        for (const timer of timers) window.clearTimeout(timer);
    };
}

function mountRiftBootScreen() {
    if (!document.body) return;
    if (sessionStorage.getItem(RIFT_BOOT.SESSION_KEY) === 'true') return;
    sessionStorage.setItem(RIFT_BOOT.SESSION_KEY, 'true');

    const boot = document.createElement('div');
    boot.className = 'rift-boot-screen';
    boot.setAttribute('aria-hidden', 'true');
    boot.innerHTML = `
        <div class="rift-boot-grid"></div>
        <div class="rift-boot-content">
            <div class="rift-boot-logo">rift</div>
            <div class="rift-boot-subtitle">powered by scramjet</div>
            <div class="rift-boot-subtitle">inspired by infamous</div>
            <div class="rift-boot-terminal" aria-hidden="true">
                <pre class="rift-boot-terminal-output"></pre>
                <span class="rift-boot-terminal-caret"></span>
            </div>
        </div>
    `;

    document.body.classList.add('rift-boot-active');
    document.body.appendChild(boot);
    const stopTerminal = runRiftBootTerminal(boot);

    requestAnimationFrame(() => {
        boot.classList.add('is-visible');
    });

    window.setTimeout(() => {
        stopTerminal();
        boot.classList.add('is-exiting');
        document.body.classList.remove('rift-boot-active');
        window.setTimeout(() => boot.remove(), RIFT_BOOT.FADE_MS);
    }, RIFT_BOOT.DISPLAY_MS);
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mountRiftBootScreen, { once: true });
} else {
    mountRiftBootScreen();
}

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
        'rift__theme',
        'rift__rain-enabled',
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

// Global floating mini music player (left corner).
(function () {
    const STORAGE_KEY = 'rift__mini_player_v1';
    const UPDATE_EVENT = 'rift-mini-player-update';
    const audio = new Audio();
    audio.preload = 'metadata';

    const state = {
        queue: [],
        currentIndex: -1,
        isPlaying: false,
    };

    let elRoot = null;
    let elArt = null;
    let elTitle = null;
    let elTime = null;
    let elPlay = null;

    function safeParse(raw, fallback) {
        try { return JSON.parse(raw); } catch { return fallback; }
    }

    function fmt(seconds) {
        if (!Number.isFinite(seconds) || seconds < 0) return '0:00';
        const s = Math.floor(seconds % 60);
        const m = Math.floor(seconds / 60);
        return `${m}:${String(s).padStart(2, '0')}`;
    }

    function saveState() {
        const payload = {
            queue: state.queue.slice(0, 100),
            currentIndex: state.currentIndex,
            currentTime: Number(audio.currentTime || 0),
            isPlaying: !!state.isPlaying,
        };
        localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
    }

    function loadState() {
        const raw = localStorage.getItem(STORAGE_KEY);
        const parsed = safeParse(raw, null);
        if (!parsed || typeof parsed !== 'object') return;
        state.queue = Array.isArray(parsed.queue) ? parsed.queue : [];
        state.currentIndex = Number.isFinite(parsed.currentIndex) ? parsed.currentIndex : -1;
        if (state.currentIndex >= 0 && state.currentIndex < state.queue.length) {
            const t = state.queue[state.currentIndex];
            audio.src = `/api/music/stream/${encodeURIComponent(t.id)}?provider=${encodeURIComponent(t.provider || 'audius')}`;
            if (Number.isFinite(parsed.currentTime) && parsed.currentTime > 0) {
                audio.currentTime = parsed.currentTime;
            }
            state.isPlaying = !!parsed.isPlaying;
        }
    }

    function currentTrack() {
        if (state.currentIndex < 0 || state.currentIndex >= state.queue.length) return null;
        return state.queue[state.currentIndex];
    }

    function notify() {
        window.dispatchEvent(new CustomEvent(UPDATE_EVENT, {
            detail: {
                queue: state.queue,
                currentIndex: state.currentIndex,
                isPlaying: !audio.paused,
                currentTime: Number(audio.currentTime || 0),
                duration: Number(audio.duration || 0),
                track: currentTrack(),
            },
        }));
    }

    function syncUi() {
        if (!elRoot) return;
        const track = currentTrack();
        if (!track) {
            elRoot.style.display = 'none';
            return;
        }
        elRoot.style.display = '';
        elArt.src = track.artwork || '/favicon.ico';
        elTitle.textContent = track.title || 'Untitled';
        elTime.textContent = `${fmt(audio.currentTime)} / ${fmt(audio.duration)}`;
        elPlay.textContent = audio.paused ? 'play_arrow' : 'pause';
    }

    async function playTrackAt(index, autoplay = true) {
        if (!Number.isFinite(index) || index < 0 || index >= state.queue.length) return;
        state.currentIndex = index;
        const track = state.queue[index];
        audio.src = `/api/music/stream/${encodeURIComponent(track.id)}?provider=${encodeURIComponent(track.provider || 'audius')}`;
        if (autoplay) {
            try { await audio.play(); } catch {}
        }
        syncUi();
        saveState();
        notify();
    }

    async function toggle() {
        if (!currentTrack()) return;
        if (audio.paused) {
            try { await audio.play(); } catch {}
        } else {
            audio.pause();
        }
        syncUi();
        saveState();
        notify();
    }

    function next() {
        if (!state.queue.length) return;
        const nextIndex = state.currentIndex < state.queue.length - 1 ? state.currentIndex + 1 : 0;
        playTrackAt(nextIndex, true);
    }

    function prev() {
        if (!state.queue.length) return;
        const prevIndex = state.currentIndex > 0 ? state.currentIndex - 1 : state.queue.length - 1;
        playTrackAt(prevIndex, true);
    }

    function seekRatio(ratio) {
        const clamped = Math.max(0, Math.min(1, Number(ratio || 0)));
        if (!Number.isFinite(audio.duration) || audio.duration <= 0) return;
        audio.currentTime = audio.duration * clamped;
        syncUi();
        saveState();
        notify();
    }

    function setQueue(queue, startIndex = 0, autoplay = true) {
        state.queue = Array.isArray(queue) ? queue.slice(0, 100) : [];
        state.currentIndex = -1;
        if (!state.queue.length) {
            audio.pause();
            audio.src = '';
            syncUi();
            saveState();
            notify();
            return;
        }
        playTrackAt(startIndex, autoplay);
    }

    function injectStyle() {
        if (document.getElementById('rift-mini-player-style')) return;
        const style = document.createElement('style');
        style.id = 'rift-mini-player-style';
        style.textContent = `
            .rift-mini-player{position:fixed;left:12px;top:12px;z-index:11000;display:none;width:240px;padding:8px;border-radius:12px;border:1px solid rgba(255,255,255,.2);background:rgba(0,0,0,.72);backdrop-filter:blur(10px)}
            .rift-mini-top{display:grid;grid-template-columns:44px 1fr;gap:8px;align-items:center}
            .rift-mini-art{width:44px;height:44px;border-radius:8px;object-fit:cover;background:#111}
            .rift-mini-title{color:#fff;font-size:11px;line-height:1.2;max-height:2.4em;overflow:hidden}
            .rift-mini-time{color:rgba(255,255,255,.65);font-size:10px;margin-top:2px}
            .rift-mini-controls{margin-top:7px;display:grid;grid-template-columns:repeat(3,1fr);gap:6px}
            .rift-mini-btn{height:28px;border-radius:8px;border:1px solid rgba(255,255,255,.2);background:rgba(255,255,255,.12);color:#fff;display:grid;place-items:center;cursor:pointer}
            .rift-mini-btn .material-icons{font-size:18px}
        `;
        document.head.appendChild(style);
    }

    function createUi() {
        injectStyle();
        const root = document.createElement('div');
        root.className = 'rift-mini-player';
        root.innerHTML = `
            <div class="rift-mini-top">
                <img class="rift-mini-art" alt="">
                <div>
                    <div class="rift-mini-title"></div>
                    <div class="rift-mini-time"></div>
                </div>
            </div>
            <div class="rift-mini-controls">
                <button class="rift-mini-btn" type="button" data-action="prev"><span class="material-icons">skip_previous</span></button>
                <button class="rift-mini-btn" type="button" data-action="play"><span class="material-icons">play_arrow</span></button>
                <button class="rift-mini-btn" type="button" data-action="next"><span class="material-icons">skip_next</span></button>
            </div>
        `;
        document.body.appendChild(root);
        elRoot = root;
        elArt = root.querySelector('.rift-mini-art');
        elTitle = root.querySelector('.rift-mini-title');
        elTime = root.querySelector('.rift-mini-time');
        elPlay = root.querySelector('[data-action="play"] .material-icons');
        root.querySelector('[data-action="prev"]').addEventListener('click', prev);
        root.querySelector('[data-action="play"]').addEventListener('click', () => { toggle(); });
        root.querySelector('[data-action="next"]').addEventListener('click', next);
    }

    audio.addEventListener('timeupdate', () => { syncUi(); notify(); saveState(); });
    audio.addEventListener('play', () => { state.isPlaying = true; syncUi(); notify(); saveState(); });
    audio.addEventListener('pause', () => { state.isPlaying = false; syncUi(); notify(); saveState(); });
    audio.addEventListener('ended', next);

    window.RiftMiniPlayer = {
        setQueue,
        playTrackAt,
        toggle,
        prev,
        next,
        seekRatio,
        getState() {
            return {
                queue: state.queue,
                currentIndex: state.currentIndex,
                isPlaying: !audio.paused,
                currentTime: Number(audio.currentTime || 0),
                duration: Number(audio.duration || 0),
                track: currentTrack(),
            };
        },
        updateEvent: UPDATE_EVENT,
    };

    window.addEventListener('beforeunload', saveState);
    document.addEventListener('DOMContentLoaded', () => {
        createUi();
        loadState();
        syncUi();
        notify();
    });
})();
