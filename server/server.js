const express = require('express');
const path = require('path');
const fs = require('fs').promises;
const dns = require('dns').promises;
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Prevent stale HTML/CSS/JS from being served to clients during rapid updates.
app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
});
app.use(express.json({ limit: '1mb' }));

// Comma-separated IP allowlist. Defaults to current Oracle public IP.
const VALIDATE_TARGET_IPS = (process.env.VALIDATE_TARGET_IPS || '161.153.8.72')
    .split(',')
    .map((ip) => ip.trim())
    .filter(Boolean);

const validateCache = new Map();
const VALIDATE_TTL_MS = 60 * 1000;
const SDXP_HTML_ROOT = path.join(__dirname, '..', 'public', 'sdxp', 'html');
const DUCKMATH_GAMES_PAGE = 'https://cdn.jsdelivr.net/gh/Divij-Agarwal-42/duckmath.github.io@main/g4m3s.html';
const DUCKMATH_BASE = 'https://cdn.jsdelivr.net/gh/Divij-Agarwal-42/duckmath.github.io@main/';
const TRUFFLED_GAMES_JSON = 'https://truffled.lol/js/json/g.json';
const TRUFFLED_BASE = 'https://truffled.lol/';
const VELARA_GAMES_JSON = 'https://velara.my/data/games.json';
const VELARA_BASE = 'https://velara.my/';
const VELARA_ORIGIN = 'https://velara.my';
const AUTH_DB_PATH = path.join(__dirname, '..', 'data', 'auth-db.json');
const SESSION_COOKIE = 'rift_sid';
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 30; // 30 days
let authWriteLock = Promise.resolve();

async function readRawBody(req) {
    return await new Promise((resolve, reject) => {
        const chunks = [];
        req.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        req.on('end', () => resolve(Buffer.concat(chunks)));
        req.on('error', reject);
    });
}

async function proxyVelara(req, res, basePath, tail = '') {
    try {
        const normalizedTail = tail ? `/${tail}` : '';
        const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
        const targetUrl = `${VELARA_ORIGIN}${basePath}${normalizedTail}${query}`;

        const method = req.method || 'GET';
        const isBodyMethod = !['GET', 'HEAD'].includes(method.toUpperCase());
        const body = isBodyMethod ? await readRawBody(req) : undefined;

        const headers = {};
        const blocked = new Set([
            'host',
            'connection',
            'content-length',
            'accept-encoding',
            'x-forwarded-for',
            'x-forwarded-host',
            'x-forwarded-proto',
        ]);
        for (const [name, value] of Object.entries(req.headers || {})) {
            if (!name || blocked.has(String(name).toLowerCase())) continue;
            if (typeof value === 'undefined') continue;
            headers[name] = value;
        }

        const upstream = await fetch(targetUrl, {
            method,
            headers,
            body,
        });

        res.status(upstream.status);
        const contentType = upstream.headers.get('content-type');
        if (contentType) res.setHeader('Content-Type', contentType);
        const setCookie = upstream.headers.get('set-cookie');
        if (setCookie) res.setHeader('Set-Cookie', setCookie);

        const raw = Buffer.from(await upstream.arrayBuffer());
        return res.send(raw);
    } catch (error) {
        return res.status(502).json({ error: `velara astra proxy failed: ${error.message}` });
    }
}

function humanizeFolderName(folder) {
    return folder
        .replace(/[-_]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
        .replace(/\b\w/g, (c) => c.toUpperCase());
}

async function pickSdxpCover(indexFile) {
    const dir = path.dirname(indexFile);
    const sdxpRoot = path.join(__dirname, '..', 'public', 'sdxp');
    const preferredOrder = [
        'splash.png', 'splash.webp', 'splash.jpg', 'splash.jpeg',
        'cover.png', 'cover.webp', 'cover.jpg', 'cover.jpeg',
        'thumbnail.png', 'thumbnail.webp', 'thumbnail.jpg', 'thumbnail.jpeg',
        'icon.png', 'icon.webp', 'icon.jpg', 'icon.jpeg',
        'logo.png', 'logo.webp', 'logo.jpg', 'logo.jpeg',
    ];

    try {
        const entries = await fs.readdir(dir, { withFileTypes: true });
        const files = entries
            .filter((entry) => entry.isFile())
            .map((entry) => entry.name);
        const lowered = new Map(files.map((name) => [name.toLowerCase(), name]));

        let chosen = '';
        for (const wanted of preferredOrder) {
            const match = lowered.get(wanted);
            if (match) {
                chosen = match;
                break;
            }
        }

        if (!chosen) {
            const fallback = files.find((name) => /\.(png|jpe?g|webp|gif|ico)$/i.test(name));
            if (!fallback) return '';
            chosen = fallback;
        }

        const abs = path.join(dir, chosen);
        const rel = path.relative(sdxpRoot, abs).replace(/\\/g, '/');
        return `/sdxp/${rel}`;
    } catch {
        return '';
    }
}

async function collectIndexFiles(dir) {
    const out = [];
    const entries = await fs.readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            out.push(...await collectIndexFiles(full));
        } else if (entry.isFile() && entry.name.toLowerCase() === 'index.html') {
            out.push(full);
        }
    }

    return out;
}

function isSafeHostname(hostname) {
    if (!hostname || typeof hostname !== 'string') return false;
    if (hostname.length > 253) return false;
    if (hostname.includes('/') || hostname.includes(':') || hostname.includes('\\')) return false;

    const labels = hostname.split('.');
    if (labels.length < 2) return false;

    return labels.every((label) =>
        /^[a-z0-9-]{1,63}$/i.test(label) &&
        !label.startsWith('-') &&
        !label.endsWith('-')
    );
}

function jsonError(res, status, error) {
    return res.status(status).json({ error });
}

function parseCookies(req) {
    const raw = String(req.headers.cookie || '');
    const out = {};
    if (!raw) return out;
    for (const entry of raw.split(';')) {
        const idx = entry.indexOf('=');
        if (idx === -1) continue;
        const key = entry.slice(0, idx).trim();
        const value = entry.slice(idx + 1).trim();
        if (!key) continue;
        out[key] = decodeURIComponent(value);
    }
    return out;
}

function setSessionCookie(res, token, expiresAt) {
    const expires = new Date(expiresAt).toUTCString();
    res.setHeader(
        'Set-Cookie',
        `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Expires=${expires}`
    );
}

function clearSessionCookie(res) {
    res.setHeader(
        'Set-Cookie',
        `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT`
    );
}

function createSalt() {
    return crypto.randomBytes(16).toString('hex');
}

function hashPassword(password, salt) {
    return crypto.scryptSync(password, salt, 64).toString('hex');
}

function createToken() {
    return crypto.randomBytes(32).toString('hex');
}

function sanitizeUsername(value) {
    return String(value || '').trim().toLowerCase();
}

function isValidUsername(username) {
    return /^[a-z0-9_]{3,24}$/.test(username);
}

function isValidPassword(password) {
    return typeof password === 'string' && password.length >= 8 && password.length <= 128;
}

async function ensureAuthDb() {
    try {
        await fs.access(AUTH_DB_PATH);
    } catch {
        await fs.mkdir(path.dirname(AUTH_DB_PATH), { recursive: true });
        await fs.writeFile(
            AUTH_DB_PATH,
            JSON.stringify({ users: [], sessions: [], saves: {} }, null, 2),
            'utf8'
        );
    }
}

async function readAuthDb() {
    await ensureAuthDb();
    const raw = await fs.readFile(AUTH_DB_PATH, 'utf8');
    const db = JSON.parse(raw || '{}');
    db.users = Array.isArray(db.users) ? db.users : [];
    db.sessions = Array.isArray(db.sessions) ? db.sessions : [];
    db.saves = db.saves && typeof db.saves === 'object' ? db.saves : {};
    return db;
}

async function writeAuthDb(db) {
    await fs.mkdir(path.dirname(AUTH_DB_PATH), { recursive: true });
    await fs.writeFile(AUTH_DB_PATH, JSON.stringify(db, null, 2), 'utf8');
}

async function updateAuthDb(mutator) {
    authWriteLock = authWriteLock
        .catch(() => {
            // Reset lock chain after failures so a rejected write doesn't poison future writes.
        })
        .then(async () => {
            const db = await readAuthDb();
            const updated = await mutator(db);
            await writeAuthDb(updated || db);
        });
    return authWriteLock;
}

async function getSessionFromRequest(req) {
    const cookies = parseCookies(req);
    const token = cookies[SESSION_COOKIE];
    if (!token) return null;
    const now = Date.now();
    const db = await readAuthDb();
    const session = db.sessions.find((entry) => entry && entry.token === token);
    if (!session || session.expiresAt <= now) return null;
    const user = db.users.find((entry) => entry && entry.id === session.userId);
    if (!user) return null;
    return { token, session, user, db };
}

function userSafeView(user) {
    return {
        id: user.id,
        username: user.username,
        createdAt: user.createdAt,
    };
}

function getUserSave(db, userId) {
    if (!db.saves[userId]) {
        db.saves[userId] = { settings: {}, games: {} };
    }
    const save = db.saves[userId];
    save.settings = save.settings && typeof save.settings === 'object' ? save.settings : {};
    save.games = save.games && typeof save.games === 'object' ? save.games : {};
    return save;
}

function getChatLog(db) {
    if (!Array.isArray(db.chat)) db.chat = [];
    return db.chat;
}

function sanitizeChatText(input) {
    const text = String(input || '')
        .replace(/\s+/g, ' ')
        .trim();
    if (!text) return '';
    return text.slice(0, 400);
}

function safeJsonForInlineScript(value) {
    return JSON.stringify(value)
        .replace(/</g, '\\u003c')
        .replace(/>/g, '\\u003e')
        .replace(/&/g, '\\u0026')
        .replace(/\u2028/g, '\\u2028')
        .replace(/\u2029/g, '\\u2029')
        .replace(/<\/script/gi, '<\\/script');
}

function parseProxyUpstreamFromReferer(req) {
    const referer = String(req.get('referer') || '').trim();
    if (!referer) return null;
    try {
        const refUrl = new URL(referer);
        if (refUrl.pathname !== '/proxy') return null;
        const upstream = refUrl.searchParams.get('url');
        if (!upstream) return null;
        return new URL(upstream);
    } catch {
        return null;
    }
}

function isLikelyAssetPath(pathname) {
    if (!pathname || pathname === '/') return false;
    if (pathname.startsWith('/assets/') || pathname.startsWith('/components/') || pathname.startsWith('/scramjet/') || pathname.startsWith('/baremux/') || pathname.startsWith('/libcurl/')) {
        return false;
    }
    return /\.(?:js|mjs|css|json|map|png|jpe?g|webp|gif|svg|ico|woff2?|ttf|otf|eot|mp3|ogg|wav|m4a|aac|flac|wasm|unityweb|data|bin|txt|xml)(?:$|\?)/i.test(pathname);
}

async function hostnamePointsToAllowedIp(hostname) {
    const now = Date.now();
    const cached = validateCache.get(hostname);

    if (cached && cached.expiresAt > now) {
        return cached.ok;
    }

    try {
        const records = await dns.lookup(hostname, { all: true });
        const addresses = new Set(records.map((r) => r.address));
        const ok = VALIDATE_TARGET_IPS.some((ip) => addresses.has(ip));

        validateCache.set(hostname, {
            ok,
            expiresAt: now + VALIDATE_TTL_MS,
        });

        return ok;
    } catch {
        validateCache.set(hostname, {
            ok: false,
            expiresAt: now + VALIDATE_TTL_MS,
        });

        return false;
    }
}

// Serve static files from public/, assets/, and components/
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use('/assets', express.static(path.join(__dirname, '..', 'assets')));
app.use('/components', express.static(path.join(__dirname, '..', 'components')));
app.use('/scramjet', express.static(path.join(__dirname, '..', 'node_modules', '@mercuryworkshop', 'scramjet', 'dist')));
app.use('/baremux', express.static(path.join(__dirname, '..', 'node_modules', '@mercuryworkshop', 'bare-mux', 'dist')));
app.use('/libcurl', express.static(path.join(__dirname, '..', 'node_modules', '@mercuryworkshop', 'libcurl-transport', 'dist')));

// Velara Astra passthrough so proxied pages can call /astra* endpoints from Rift origin.
app.all(/^\/astra(?:\/(.*))?$/, async (req, res) => {
    const tail = req.params?.[0] || '';
    return proxyVelara(req, res, '/astra', tail);
});

app.all(/^\/astra-accounts(?:\/(.*))?$/, async (req, res) => {
    const tail = req.params?.[0] || '';
    return proxyVelara(req, res, '/astra-accounts', tail);
});

app.post('/api/auth/signup', async (req, res) => {
    try {
        const username = sanitizeUsername(req.body?.username);
        const password = String(req.body?.password || '');
        if (!isValidUsername(username)) {
            return jsonError(res, 400, 'Username must be 3-24 chars: lowercase letters, numbers, underscore.');
        }
        if (!isValidPassword(password)) {
            return jsonError(res, 400, 'Password must be 8-128 characters.');
        }

        const userId = crypto.randomUUID();
        const now = Date.now();
        const salt = createSalt();
        const passwordHash = hashPassword(password, salt);
        const token = createToken();
        const expiresAt = now + SESSION_TTL_MS;

        await updateAuthDb((db) => {
            if (db.users.some((u) => u.username === username)) {
                throw new Error('USERNAME_TAKEN');
            }
            db.users.push({
                id: userId,
                username,
                passwordHash,
                passwordSalt: salt,
                createdAt: now,
            });
            db.sessions = db.sessions.filter((s) => s.expiresAt > now);
            db.sessions.push({
                token,
                userId,
                createdAt: now,
                lastSeenAt: now,
                expiresAt,
            });
            getUserSave(db, userId);
            return db;
        });

        setSessionCookie(res, token, expiresAt);
        return res.json({ ok: true, user: { id: userId, username, createdAt: now } });
    } catch (error) {
        if (error.message === 'USERNAME_TAKEN') {
            return jsonError(res, 409, 'Username already exists.');
        }
        return jsonError(res, 500, `Signup failed: ${error.message}`);
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const username = sanitizeUsername(req.body?.username);
        const password = String(req.body?.password || '');
        if (!username || !password) return jsonError(res, 400, 'Username and password are required.');

        const db = await readAuthDb();
        const user = db.users.find((u) => u.username === username);
        if (!user) return jsonError(res, 401, 'Invalid username or password.');

        const expected = hashPassword(password, user.passwordSalt);
        if (expected !== user.passwordHash) {
            return jsonError(res, 401, 'Invalid username or password.');
        }

        const now = Date.now();
        const token = createToken();
        const expiresAt = now + SESSION_TTL_MS;
        await updateAuthDb((nextDb) => {
            nextDb.sessions = nextDb.sessions.filter((s) => s.expiresAt > now && s.userId !== user.id);
            nextDb.sessions.push({
                token,
                userId: user.id,
                createdAt: now,
                lastSeenAt: now,
                expiresAt,
            });
            getUserSave(nextDb, user.id);
            return nextDb;
        });

        setSessionCookie(res, token, expiresAt);
        return res.json({ ok: true, user: userSafeView(user) });
    } catch (error) {
        return jsonError(res, 500, `Login failed: ${error.message}`);
    }
});

app.post('/api/auth/logout', async (req, res) => {
    try {
        const cookies = parseCookies(req);
        const token = cookies[SESSION_COOKIE];
        if (token) {
            await updateAuthDb((db) => {
                db.sessions = db.sessions.filter((s) => s.token !== token);
                return db;
            });
        }
        clearSessionCookie(res);
        return res.json({ ok: true });
    } catch (error) {
        return jsonError(res, 500, `Logout failed: ${error.message}`);
    }
});

app.get('/api/auth/me', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return res.status(401).json({ authenticated: false });

        const now = Date.now();
        await updateAuthDb((db) => {
            const session = db.sessions.find((s) => s.token === auth.token);
            if (session) {
                session.lastSeenAt = now;
            }
            return db;
        });

        return res.json({ authenticated: true, user: userSafeView(auth.user) });
    } catch (error) {
        return jsonError(res, 500, `Session check failed: ${error.message}`);
    }
});

app.get('/api/save', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const save = getUserSave(auth.db, auth.user.id);
        return res.json({ ok: true, save });
    } catch (error) {
        return jsonError(res, 500, `Save read failed: ${error.message}`);
    }
});

app.put('/api/save/settings', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const updates = req.body?.settings;
        if (!updates || typeof updates !== 'object') {
            return jsonError(res, 400, 'settings object is required');
        }
        await updateAuthDb((db) => {
            const save = getUserSave(db, auth.user.id);
            save.settings = { ...save.settings, ...updates };
            return db;
        });
        return res.json({ ok: true });
    } catch (error) {
        return jsonError(res, 500, `Settings save failed: ${error.message}`);
    }
});

app.put('/api/save/games/:gameId', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const gameId = String(req.params?.gameId || '').trim();
        if (!gameId || gameId.length > 120) return jsonError(res, 400, 'Invalid gameId');
        const progress = req.body?.progress;
        if (!progress || typeof progress !== 'object') {
            return jsonError(res, 400, 'progress object is required');
        }
        await updateAuthDb((db) => {
            const save = getUserSave(db, auth.user.id);
            const existing = save.games[gameId] && typeof save.games[gameId] === 'object'
                ? save.games[gameId]
                : {};
            const launchDelta = Number(progress.launches || 0);
            save.games[gameId] = {
                ...existing,
                ...progress,
                launches: Number(existing.launches || 0) + (Number.isFinite(launchDelta) ? launchDelta : 0),
                updatedAt: Date.now(),
            };
            return db;
        });
        return res.json({ ok: true });
    } catch (error) {
        return jsonError(res, 500, `Game save failed: ${error.message}`);
    }
});

app.get('/api/chat/messages', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const since = Number.parseInt(String(req.query?.since || '0'), 10) || 0;
        const db = await readAuthDb();
        const rows = getChatLog(db);
        const filtered = since > 0 ? rows.filter((m) => Number(m.createdAt) > since) : rows;
        const messages = filtered.slice(-120);
        return res.json({ ok: true, messages, now: Date.now() });
    } catch (error) {
        return jsonError(res, 500, `Chat read failed: ${error.message}`);
    }
});

app.post('/api/chat/messages', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const text = sanitizeChatText(req.body?.text);
        if (!text) return jsonError(res, 400, 'Message text required');

        const message = {
            id: crypto.randomUUID(),
            userId: auth.user.id,
            username: auth.user.username,
            text,
            createdAt: Date.now(),
        };

        await updateAuthDb((db) => {
            const rows = getChatLog(db);
            rows.push(message);
            if (rows.length > 500) {
                db.chat = rows.slice(-500);
            }
            return db;
        });

        return res.json({ ok: true, message });
    } catch (error) {
        return jsonError(res, 500, `Chat send failed: ${error.message}`);
    }
});

// Fallback for runtime same-origin asset requests emitted from proxied pages
// (e.g. Unity/WebGL games requesting /media/* or font files).
app.all('*', async (req, res, next) => {
    const upstreamRef = parseProxyUpstreamFromReferer(req);
    if (!upstreamRef) return next();

    const method = (req.method || 'GET').toUpperCase();
    const isBodyMethod = !['GET', 'HEAD'].includes(method);

    // Forward non-GET requests from proxied pages (e.g. form POST /zc.php)
    // so they don't hit Rift origin and fail with "Cannot POST ...".
    if (isBodyMethod) {
        try {
            const target = new URL(req.url, upstreamRef.origin).href;
            const body = await readRawBody(req);
            const headers = {};
            const blocked = new Set([
                'host',
                'connection',
                'content-length',
                'accept-encoding',
                'x-forwarded-for',
                'x-forwarded-host',
                'x-forwarded-proto',
            ]);
            for (const [name, value] of Object.entries(req.headers || {})) {
                if (!name || blocked.has(String(name).toLowerCase())) continue;
                if (typeof value === 'undefined') continue;
                headers[name] = value;
            }

            const targetUrl = new URL(target);
            if (headers.origin) headers.origin = targetUrl.origin;
            if (headers.referer) headers.referer = targetUrl.href;

            const upstream = await fetch(target, {
                method,
                headers,
                body,
                redirect: 'manual',
            });

            const contentType = upstream.headers.get('content-type');
            if (contentType) res.setHeader('Content-Type', contentType);
            const location = upstream.headers.get('location');
            if (location) {
                const resolved = new URL(location, target).href;
                res.setHeader('Location', `/proxy?url=${encodeURIComponent(resolved)}`);
            }
            const setCookie = upstream.headers.get('set-cookie');
            if (setCookie) res.setHeader('Set-Cookie', setCookie);

            const raw = Buffer.from(await upstream.arrayBuffer());
            return res.status(upstream.status).send(raw);
        } catch {
            return next();
        }
    }

    // Keep document navigations from proxied pages inside /proxy.
    // Example: upstream redirects to "/signup/" and browser requests it on Rift origin.
    if (!isLikelyAssetPath(req.path)) {
        // Never rewrite requests that are already using the proxy endpoint.
        if (req.path === '/proxy') {
            return next();
        }
        const dest = String(req.get('sec-fetch-dest') || '').toLowerCase();
        const accept = String(req.get('accept') || '').toLowerCase();
        const likelyDocument = dest === 'document' || dest === 'iframe' || accept.includes('text/html');
        if (likelyDocument) {
            try {
                const target = new URL(req.url, upstreamRef.origin).href;
                return res.redirect(302, `/proxy?url=${encodeURIComponent(target)}`);
            } catch {
                return next();
            }
        }
        return next();
    }

    try {
        const cleanPath = req.path.replace(/^\/+/, '');
        const fromRefDir = new URL(cleanPath, new URL('./', upstreamRef));
        const fromOriginRoot = new URL(req.path, upstreamRef.origin);
        const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
        const candidates = [
            `${fromRefDir.href}${query}`,
            `${fromOriginRoot.href}${query}`,
        ];

        for (const candidate of candidates) {
            try {
                const upstream = await fetch(candidate);
                if (!upstream.ok) continue;
                const contentType = upstream.headers.get('content-type');
                if (contentType) res.setHeader('Content-Type', contentType);
                const raw = Buffer.from(await upstream.arrayBuffer());
                return res.status(upstream.status).send(raw);
            } catch {
                // try next candidate
            }
        }

        return next();
    } catch {
        return next();
    }
});

// Clean URLs - serve .html files without extension
app.use((req, res, next) => {
    if (!req.path.includes('.') && req.path !== '/') {
        const file = path.join(__dirname, '..', 'public', req.path + '.html');
        res.sendFile(file, (err) => {
            if (err) next();
        });
    } else {
        next();
    }
});

// Proxy endpoint
app.all('/proxy', async (req, res) => {
    const targetUrl = req.query.url;

    if (!targetUrl) {
        return res.status(400).send('URL parameter is required');
    }

    try {
        const method = req.method || 'GET';
        const upperMethod = method.toUpperCase();
        const isBodyMethod = !['GET', 'HEAD'].includes(upperMethod);
        const body = isBodyMethod ? await readRawBody(req) : undefined;

        const headers = {};
        const blocked = new Set([
            'host',
            'connection',
            'content-length',
            'accept-encoding',
            'x-forwarded-for',
            'x-forwarded-host',
            'x-forwarded-proto',
        ]);
        for (const [name, value] of Object.entries(req.headers || {})) {
            if (!name || blocked.has(String(name).toLowerCase())) continue;
            if (typeof value === 'undefined') continue;
            headers[name] = value;
        }

        // Many signup/login flows validate origin/referer for POSTs.
        try {
            const target = new URL(String(targetUrl));
            if (headers.origin) headers.origin = target.origin;
            if (headers.referer) headers.referer = target.href;
        } catch {}

        const response = await fetch(targetUrl, {
            method,
            headers,
            body,
        });
        const contentType = (response.headers.get('content-type') || '').toLowerCase();
        const parsedTargetUrl = new URL(targetUrl);
        const isHtml =
            contentType.includes('text/html') ||
            parsedTargetUrl.pathname.toLowerCase().endsWith('.html') ||
            parsedTargetUrl.pathname.toLowerCase().endsWith('.htm');
        const isManifest =
            contentType.includes('application/manifest+json') ||
            (contentType.includes('application/json') && parsedTargetUrl.pathname.endsWith('/manifest.json'));

        if (isManifest) {
            const manifestText = await response.text();
            const rewrittenManifest = manifestText.replace(
                /"src"\s*:\s*"\/([^"]+)"/g,
                (match, iconPath) => {
                    const fullUrl = new URL(`/${iconPath}`, parsedTargetUrl).href;
                    return `"src":"/proxy?url=${encodeURIComponent(fullUrl)}"`;
                }
            );
            res.setHeader('Content-Type', contentType || 'application/manifest+json; charset=utf-8');
            const setCookie = response.headers.get('set-cookie');
            if (setCookie) res.setHeader('Set-Cookie', setCookie);
            return res.status(response.status).send(rewrittenManifest);
        }

        // Do not rewrite non-HTML assets. Rewriting JS/CSS text can corrupt syntax.
        if (!isHtml) {
            const raw = Buffer.from(await response.arrayBuffer());
            if (contentType) {
                res.setHeader('Content-Type', contentType);
            }
            const setCookie = response.headers.get('set-cookie');
            if (setCookie) res.setHeader('Set-Cookie', setCookie);
            return res.status(response.status).send(raw);
        }

        const content = await response.text();

        const baseUrl = new URL(targetUrl);
        const rewriteProxyUrl = (rawUrl) => {
            const value = String(rawUrl || '').trim();
            if (!value) return null;
            if (value.startsWith('/proxy?url=')) return null;
            if (/^(?:https?:|\/\/|data:|blob:|javascript:|mailto:|tel:|#)/i.test(value)) return null;
            try {
                return `/proxy?url=${encodeURIComponent(new URL(value, baseUrl).href)}`;
            } catch {
                return null;
            }
        };

        let modifiedContent = content.replace(
            /\b(href|src|action)\s*=\s*(["'])(.*?)\2/gi,
            (match, attr, quote, value) => {
                const rewritten = rewriteProxyUrl(value);
                if (!rewritten) return match;
                return `${attr}=${quote}${rewritten}${quote}`;
            }
        );

        modifiedContent = modifiedContent.replace(
            /\bsrcset\s*=\s*(["'])(.*?)\1/gi,
            (match, quote, value) => {
                const rewrittenSet = value
                    .split(',')
                    .map((entry) => {
                        const token = entry.trim();
                        if (!token) return token;
                        const parts = token.split(/\s+/);
                        const candidate = parts[0];
                        const rewritten = rewriteProxyUrl(candidate);
                        if (!rewritten) return token;
                        parts[0] = rewritten;
                        return parts.join(' ');
                    })
                    .join(', ');
                return `srcset=${quote}${rewrittenSet}${quote}`;
            }
        );

        const buildUrlMatch = modifiedContent.match(/\b(?:var|let|const)\s+buildUrl\s*=\s*["']([^"']+)["']/i);
        if (buildUrlMatch) {
            const buildDir = String(buildUrlMatch[1] || '').replace(/^\.?\//, '').replace(/\/+$/, '');
            if (buildDir) {
                modifiedContent = modifiedContent.replace(
                    /buildUrl\s*\+\s*["']\/([^"']+)["']/g,
                    (match, assetPath) => {
                        const absolute = new URL(`${buildDir}/${assetPath}`, baseUrl).href;
                        return `"${`/proxy?url=${encodeURIComponent(absolute)}`}"`;
                    }
                );
            }
        }

        // Many mirror game builds reference YaGames SDK; when blocked/unavailable,
        // inline startup scripts crash before the game boots. Provide a no-op shim.
        const yaGamesShim = '<script id="rift-yagames-shim">(function(){if(window.YaGames)return;window.YaGames={init:function(){return Promise.resolve({adv:{showFullscreenAdv:function(){return Promise.resolve();},showRewardedVideo:function(){return Promise.resolve();}},features:{LoadingAPI:{ready:function(){}}}});}};})();</script>';
        if (/<head[^>]*>/i.test(modifiedContent)) {
            modifiedContent = modifiedContent.replace(/<head[^>]*>/i, `$&${yaGamesShim}`);
        } else {
            modifiedContent = yaGamesShim + modifiedContent;
        }

        // Logged-in cloud sync for proxied game localStorage.
        // This allows saves to follow the user's Rift account across domains.
        try {
            const auth = await getSessionFromRequest(req);
            if (auth) {
                const scope = new URL('.', parsedTargetUrl).href;
                const storageGameId = `proxy-storage:${scope}`;
                const save = getUserSave(auth.db, auth.user.id);
                const stored = save.games?.[storageGameId]?.localStorage;
                const initialStorage = stored && typeof stored === 'object' ? stored : {};

                const storageScript = `<script id="rift-proxy-storage">(function(){try{if(window.__riftProxyStorageInit)return;window.__riftProxyStorageInit=true;var scope=${safeJsonForInlineScript(scope)};var gameId=${safeJsonForInlineScript(storageGameId)};var seed=${safeJsonForInlineScript(initialStorage)};for(var k in seed){if(Object.prototype.hasOwnProperty.call(seed,k)&&localStorage.getItem(k)===null){try{localStorage.setItem(k,String(seed[k]));}catch(_e){}}}var pending=null;var saveNow=function(){try{var out={};for(var i=0;i<localStorage.length;i++){var key=localStorage.key(i);if(key!=null){out[key]=localStorage.getItem(key);}}fetch('/api/save/games/'+encodeURIComponent(gameId),{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({progress:{localStorage:out,lastSyncedAt:Date.now(),scope:scope}}}).catch(function(){});}catch(_e){}};var schedule=function(){if(pending)clearTimeout(pending);pending=setTimeout(saveNow,600);};var sp=Storage.prototype;var _set=sp.setItem,_remove=sp.removeItem,_clear=sp.clear;sp.setItem=function(a,b){var r=_set.call(this,a,b);if(this===localStorage)schedule();return r;};sp.removeItem=function(a){var r=_remove.call(this,a);if(this===localStorage)schedule();return r;};sp.clear=function(){var r=_clear.call(this);if(this===localStorage)schedule();return r;};window.addEventListener('pagehide',saveNow);window.addEventListener('beforeunload',saveNow);}catch(_e){}})();</script>`;

                if (/<head[^>]*>/i.test(modifiedContent)) {
                    modifiedContent = modifiedContent.replace(/<head[^>]*>/i, `$&${storageScript}`);
                } else {
                    modifiedContent = storageScript + modifiedContent;
                }
            }
        } catch {
            // Ignore sync bootstrap failures and continue serving proxied page.
        }

        // Force Rift cursor inside proxied HTML pages rendered in the browser iframe.
        if (/^\s*</.test(modifiedContent)) {
            const cursorStyle = '<style id="rift-proxy-cursor">*,*::before,*::after{cursor:url("/assets/images/cursor.png") 16 16, auto !important;}.rift-proxy-cursor-light{position:fixed;width:150px;height:150px;border-radius:50%;background:radial-gradient(circle,rgba(255,255,255,.15) 0%,rgba(255,255,255,0) 70%);pointer-events:none;z-index:2147483647;transform:translate(-50%,-50%);mix-blend-mode:screen;}</style>';
            const cursorScript = '<script id="rift-proxy-cursor-script">(function(){if(window.__riftProxyCursorInit)return;window.__riftProxyCursorInit=true;var light=document.createElement("div");light.className="rift-proxy-cursor-light";document.documentElement.appendChild(light);document.addEventListener("mousemove",function(e){light.style.left=e.clientX+"px";light.style.top=e.clientY+"px";});document.addEventListener("mouseleave",function(){light.style.opacity="0";});document.addEventListener("mouseenter",function(){light.style.opacity="1";});})();</script>';
            if (/<head[^>]*>/i.test(modifiedContent)) {
                modifiedContent = modifiedContent.replace(/<head[^>]*>/i, `$&${cursorStyle}${cursorScript}`);
            } else {
                modifiedContent = cursorStyle + cursorScript + modifiedContent;
            }
        }

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        const setCookie = response.headers.get('set-cookie');
        if (setCookie) res.setHeader('Set-Cookie', setCookie);
        res.status(response.status).send(modifiedContent);
    } catch (error) {
        res.status(500).send('Error fetching the requested URL: ' + error.message);
    }
});

// Build SDXP catalog from local /public/sdxp/html tree.
app.get('/sdxp-catalog', async (_req, res) => {
    try {
        await fs.access(SDXP_HTML_ROOT);
    } catch {
        return res.json([]);
    }

    try {
        const indexFiles = await collectIndexFiles(SDXP_HTML_ROOT);
        const items = await Promise.all(indexFiles.map(async (file) => {
            const rel = path.relative(path.join(__dirname, '..', 'public', 'sdxp'), file).replace(/\\/g, '/');
            const gameFolder = path.basename(path.dirname(file));
            const cover = await pickSdxpCover(file);
            return {
                id: `sdxp-${rel}`,
                name: humanizeFolderName(gameFolder),
                url: `/sdxp/${rel}`,
                cover,
            };
        }));

        items.sort((a, b) => a.name.localeCompare(b.name));
        res.json(items);
    } catch (error) {
        res.status(500).json({ error: `failed to build sdxp catalog: ${error.message}` });
    }
});

// Build DuckMath catalog from public g4m3s page.
app.get('/duckmath-catalog', async (_req, res) => {
    try {
        const response = await fetch(DUCKMATH_GAMES_PAGE);
        if (!response.ok) {
            return res.status(502).json({ error: `duckmath fetch failed: ${response.status}` });
        }

        const html = await response.text();
        const re = /<a[^>]*href\s*=\s*["'](g4m3s\/[^"']+)["'][^>]*>[\s\S]*?<figcaption>([^<]+)<\/figcaption>/gi;
        const items = [];
        const seen = new Set();
        let m;

        while ((m = re.exec(html)) !== null) {
            const rel = m[1].trim();
            const name = m[2].trim();
            if (!rel || !name || seen.has(rel)) continue;
            seen.add(rel);

            items.push({
                id: `duckmath-${rel}`,
                name,
                url: new URL(rel, DUCKMATH_BASE).href,
                cover: '',
            });
        }

        items.sort((a, b) => a.name.localeCompare(b.name));
        return res.json(items);
    } catch (error) {
        return res.status(500).json({ error: `failed to build duckmath catalog: ${error.message}` });
    }
});

// Build Truffled catalog from public games page.
app.get('/truffled-catalog', async (_req, res) => {
    try {
        const response = await fetch(TRUFFLED_GAMES_JSON);
        if (!response.ok) {
            return res.status(502).json({ error: `truffled fetch failed: ${response.status}` });
        }

        const payload = await response.json();
        const rows = Array.isArray(payload?.games) ? payload.games : [];
        const items = [];
        const seen = new Set();
        for (const row of rows) {
            const href = String(row?.url || '').trim();
            const name = String(row?.name || '').trim();
            const thumbnail = String(row?.thumbnail || '').trim();
            if (!href || !name) continue;
            if (!(href.startsWith('/games/') || href.startsWith('/gamefile/'))) continue;
            if (seen.has(href)) continue;
            seen.add(href);

            const normalized = href.replace(/^\/+/, '');
            const normalizedThumb = thumbnail.replace(/^\/+/, '');
            items.push({
                id: `truffled-${normalized}`,
                name,
                url: new URL(normalized, TRUFFLED_BASE).href,
                cover: normalizedThumb ? new URL(normalizedThumb, TRUFFLED_BASE).href : '',
            });
        }

        items.sort((a, b) => a.name.localeCompare(b.name));
        return res.json(items);
    } catch (error) {
        return res.status(500).json({ error: `failed to build truffled catalog: ${error.message}` });
    }
});

// Build Velara catalog from its public gg.json.
app.get('/velara-catalog', async (_req, res) => {
    try {
        const response = await fetch(VELARA_GAMES_JSON);
        if (!response.ok) {
            return res.status(502).json({ error: `velara fetch failed: ${response.status}` });
        }

        const rows = await response.json();
        const items = [];
        const seen = new Set();
        for (const row of (Array.isArray(rows) ? rows : [])) {
            const name = String(row?.title || row?.name || '').trim();
            const link = String(row?.location || row?.link || '').trim();
            const img = String(row?.image || row?.imgpath || '').trim();
            if (!name || !link) continue;
            const key = `${name.toLowerCase()}|${link}`;
            if (seen.has(key)) continue;
            seen.add(key);

            const normalizedLink = link.startsWith('/') ? link : `/${link}`;
            const normalizedImg = img.startsWith('/') ? img : `/${img}`;
            items.push({
                id: `velara-${normalizedLink.replace(/^\/+/, '')}`,
                name,
                url: new URL(normalizedLink, VELARA_BASE).href,
                cover: img ? new URL(normalizedImg, VELARA_BASE).href : '',
            });
        }

        items.sort((a, b) => a.name.localeCompare(b.name));
        return res.json(items);
    } catch (error) {
        return res.status(500).json({ error: `failed to build velara catalog: ${error.message}` });
    }
});

// Caddy on-demand TLS validation endpoint
app.get('/validate', async (req, res) => {
    const domain = String(req.query.domain || '').toLowerCase().trim();

    if (!isSafeHostname(domain)) {
        return res.sendStatus(403);
    }

    const allowed = await hostnamePointsToAllowedIp(domain);
    return res.sendStatus(allowed ? 200 : 403);
});

app.listen(PORT, () => {
    console.log(`Rift running on http://localhost:${PORT}`);
});
