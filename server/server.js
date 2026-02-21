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
const TRUFFLED_LOCAL_JSON = path.join(__dirname, '..', 'truffled.g.json');
const TRUFFLED_BASE = 'https://truffled.lol/';
const TRUFFLED_ROOT_MANIFEST = path.join(__dirname, '..', 'data', 'truffled-root-manifest.json');
const TOTALLY_SCIENCE_BASE = 'https://d11jzht7mj96rr.cloudfront.net/';
const VELARA_GAMES_JSON = 'https://velara.my/data/games.json';
const VELARA_BASE = 'https://velara.my/';
const VELARA_ORIGIN = 'https://velara.my';
const AUDIUS_API_BASE = 'https://discoveryprovider.audius.co';
const JAMENDO_API_BASE = 'https://api.jamendo.com/v3.0';
const JAMENDO_CLIENT_ID = String(process.env.JAMENDO_CLIENT_ID || '').trim();
const AUTH_DB_PATH = process.env.AUTH_DB_PATH
    ? path.resolve(process.env.AUTH_DB_PATH)
    : (process.env.VERCEL
        ? path.join('/tmp', 'rift-data', 'auth-db.json')
        : path.join(__dirname, '..', 'data', 'auth-db.json'));
const SESSION_COOKIE = 'rift_sid';
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 30; // 30 days
const ACTIVE_USER_WINDOW_MS = 1000 * 60 * 10; // 10 minutes
const PRESENCE_TTL_MS = 1000 * 60; // 60 seconds
const CHAT_ROOM_INACTIVE_TTL_MS = 1000 * 60 * 60 * 24; // 24 hours
const SYSTEM_CHAT_ROOM_IDS = new Set(['lobby', 'links']);
let authWriteLock = Promise.resolve();
const presenceMap = new Map();

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

function toTruffledLocalSlug(input) {
    return String(input || '')
        .trim()
        .replace(/^\/+/, '')
        .replace(/[?#].*$/, '')
        .replace(/\.html?$/i, '')
        .replace(/[^a-z0-9/_\-\.]+/gi, '-')
        .replace(/\/+/g, '/')
        .replace(/^-+|-+$/g, '')
        .replace(/\//g, '__');
}

async function readTruffledRootMap() {
    try {
        const raw = await fs.readFile(TRUFFLED_ROOT_MANIFEST, 'utf8');
        const parsed = JSON.parse(raw);
        const map = parsed?.map && typeof parsed.map === 'object' ? parsed.map : {};
        return map;
    } catch {
        return {};
    }
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

function hasJamendoClientId() {
    return JAMENDO_CLIENT_ID.length >= 6;
}

function pickAudiusArtwork(track) {
    const artwork = track?.artwork;
    if (!artwork || typeof artwork !== 'object') return track?.user?.profile_picture || '';
    return artwork['480x480'] || artwork['150x150'] || artwork['1000x1000'] || '';
}

function jsonError(res, status, error) {
    return res.status(status).json({ error });
}

function normalizePresenceId(value) {
    const id = String(value || '').trim();
    if (!/^[a-z0-9_-]{8,80}$/i.test(id)) return '';
    return id;
}

function prunePresence(now = Date.now()) {
    for (const [id, entry] of presenceMap.entries()) {
        const lastSeenAt = Number(entry?.lastSeenAt || 0);
        if (!lastSeenAt || (now - lastSeenAt) > PRESENCE_TTL_MS) {
            presenceMap.delete(id);
        }
    }
}

function countActivePresence(now = Date.now()) {
    prunePresence(now);
    return presenceMap.size;
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
    if (pruneInactiveChatRooms(db)) {
        await writeAuthDb(db);
    }
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

function normalizeMusicTrack(input) {
    if (!input || typeof input !== 'object') return null;
    const provider = String(input.provider || '').trim().toLowerCase();
    const id = String(input.id || '').trim();
    const title = String(input.title || '').trim().slice(0, 180);
    const artist = String(input.artist || '').trim().slice(0, 120);
    const artwork = String(input.artwork || '').trim().slice(0, 1000);
    const durationMs = Number(input.durationMs || 0);
    if (!/^[a-z0-9_-]{2,20}$/i.test(provider)) return null;
    if (!/^[a-z0-9:_-]{1,140}$/i.test(id)) return null;
    if (!title) return null;
    return {
        id,
        provider,
        key: `${provider}:${id}`,
        title,
        artist: artist || 'Unknown artist',
        artwork,
        durationMs: Number.isFinite(durationMs) && durationMs > 0 ? Math.round(durationMs) : 0,
    };
}

function sanitizePlaylistName(value) {
    const name = String(value || '').trim().replace(/\s+/g, ' ');
    if (!name) return '';
    return name.slice(0, 60);
}

function getUserMusicLibrary(save, user) {
    if (!save.music || typeof save.music !== 'object') {
        save.music = {};
    }
    if (!Array.isArray(save.music.favorites)) save.music.favorites = [];
    if (!Array.isArray(save.music.playlists)) save.music.playlists = [];

    save.music.favorites = save.music.favorites
        .map((entry) => {
            const track = normalizeMusicTrack(entry);
            if (!track) return null;
            const favoritedAt = Number(entry?.favoritedAt || Date.now());
            return { ...track, favoritedAt };
        })
        .filter(Boolean);

    save.music.playlists = save.music.playlists
        .filter((playlist) => playlist && typeof playlist === 'object')
        .map((playlist) => {
            const name = sanitizePlaylistName(playlist.name);
            const id = String(playlist.id || '').trim() || crypto.randomUUID();
            const createdAt = Number(playlist.createdAt || Date.now());
            const updatedAt = Number(playlist.updatedAt || createdAt);
            const tracks = Array.isArray(playlist.tracks)
                ? playlist.tracks.map((entry) => normalizeMusicTrack(entry)).filter(Boolean)
                : [];
            return {
                id,
                name: name || 'untitled playlist',
                isPrivate: Boolean(playlist.isPrivate),
                ownerUserId: user.id,
                ownerUsername: user.username,
                createdAt,
                updatedAt,
                tracks,
            };
        });

    return save.music;
}

function toPlaylistPublicView(playlist) {
    return {
        id: playlist.id,
        name: playlist.name,
        isPrivate: !!playlist.isPrivate,
        ownerUsername: playlist.ownerUsername,
        createdAt: playlist.createdAt,
        updatedAt: playlist.updatedAt,
        trackCount: Array.isArray(playlist.tracks) ? playlist.tracks.length : 0,
        tracks: Array.isArray(playlist.tracks) ? playlist.tracks : [],
    };
}

function getChatLog(db) {
    if (!Array.isArray(db.chat)) db.chat = [];
    return db.chat;
}

function normalizeRoomName(input) {
    return String(input || '')
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9 _-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/-+/g, '-')
        .slice(0, 40);
}

function createSystemRoom(id, now) {
    return {
        id,
        name: id,
        ownerUserId: 'system',
        ownerUsername: 'system',
        isPrivate: false,
        createdAt: now,
        lastMessageAt: now,
    };
}

function getChatRooms(db) {
    const now = Date.now();
    if (!db.chatRooms || typeof db.chatRooms !== 'object') db.chatRooms = {};
    if (!db.chatRooms.lobby) db.chatRooms.lobby = createSystemRoom('lobby', now);
    if (!db.chatRooms.links) db.chatRooms.links = createSystemRoom('links', now);
    return db.chatRooms;
}

function getChatMessagesMap(db) {
    if (!db.chatMessages || typeof db.chatMessages !== 'object') db.chatMessages = {};
    return db.chatMessages;
}

function getRoomMessages(db, roomId) {
    const map = getChatMessagesMap(db);
    if (!Array.isArray(map[roomId])) map[roomId] = [];
    return map[roomId];
}

function toRoomPublicView(room) {
    return {
        id: room.id,
        name: room.name,
        ownerUsername: room.ownerUsername,
        isPrivate: !!room.isPrivate,
        createdAt: room.createdAt,
        lastMessageAt: room.lastMessageAt || room.createdAt,
    };
}

function verifyRoomPassword(room, password) {
    if (!room.isPrivate) return true;
    if (!password || typeof password !== 'string') return false;
    const hash = hashPassword(password, room.passwordSalt);
    return hash === room.passwordHash;
}

function isRiftAdminUser(user) {
    if (!user) return false;
    return sanitizeUsername(user.username) === 'rift';
}

function canAccessRoom(authUser, room, password) {
    if (!room?.isPrivate) return true;
    if (isRiftAdminUser(authUser)) return true;
    return verifyRoomPassword(room, password);
}

function pruneInactiveChatRooms(db) {
    const rooms = getChatRooms(db);
    const messagesMap = getChatMessagesMap(db);
    const now = Date.now();
    let changed = false;

    for (const [roomId, room] of Object.entries(rooms)) {
        if (SYSTEM_CHAT_ROOM_IDS.has(roomId)) continue;
        const lastActivity = Number(room.lastMessageAt || room.createdAt || 0);
        if (lastActivity <= 0 || (now - lastActivity) < CHAT_ROOM_INACTIVE_TTL_MS) continue;
        delete rooms[roomId];
        delete messagesMap[roomId];
        changed = true;
    }

    return changed;
}

function sortChatRoomsForList(a, b) {
    if (a.id === 'lobby') return -1;
    if (b.id === 'lobby') return 1;
    if (a.id === 'links') return -1;
    if (b.id === 'links') return 1;
    return (b.lastMessageAt || 0) - (a.lastMessageAt || 0);
}

function canDeleteRoom(authUser, room) {
    if (!authUser || !room) return false;
    if (SYSTEM_CHAT_ROOM_IDS.has(room.id)) return false;
    const username = sanitizeUsername(authUser.username);
    if (username === 'rift') return true;
    return room.ownerUserId === authUser.id;
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

// Explicit path aliases for clean trailing-slash URLs.
app.get('/games/', (_req, res) => {
    res.redirect(302, '/games?view=games-only');
});

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

app.get('/api/auth/ping', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return res.json({ ok: true, authenticated: false });
        const now = Date.now();
        await updateAuthDb((db) => {
            const session = db.sessions.find((s) => s.token === auth.token);
            if (session) session.lastSeenAt = now;
            return db;
        });
        return res.json({ ok: true, authenticated: true, now });
    } catch (error) {
        return jsonError(res, 500, `Ping failed: ${error.message}`);
    }
});

app.get('/api/stats/users', async (req, res) => {
    const now = Date.now();
    const activeTabs = countActivePresence(now);

    let totalUsers = 0;
    let activeSignedInUsers = 0;
    let dbAvailable = true;

    try {
        const db = await readAuthDb();
        totalUsers = Array.isArray(db.users) ? db.users.length : 0;

        const activeUserIds = new Set();
        const sessions = Array.isArray(db.sessions) ? db.sessions : [];
        for (const session of sessions) {
            if (!session || session.expiresAt <= now) continue;
            const lastSeenAt = Number(session.lastSeenAt || session.createdAt || 0);
            if (lastSeenAt > 0 && (now - lastSeenAt) <= ACTIVE_USER_WINDOW_MS) {
                activeUserIds.add(session.userId);
            }
        }
        activeSignedInUsers = activeUserIds.size;
    } catch (error) {
        dbAvailable = false;
        console.warn('User stats fallback (db unavailable):', error.message);
    }

    return res.json({
        ok: true,
        totalUsers,
        activeUsers: activeTabs,
        activeWindowMs: ACTIVE_USER_WINDOW_MS,
        activeTabs,
        activeSignedInUsers,
        dbAvailable,
    });
});

app.post('/api/presence/ping', async (req, res) => {
    try {
        const id = normalizePresenceId(req.body?.id);
        if (!id) return jsonError(res, 400, 'Invalid presence id');
        const now = Date.now();
        prunePresence(now);
        presenceMap.set(id, { lastSeenAt: now });
        return res.json({ ok: true, activeTabs: presenceMap.size, ttlMs: PRESENCE_TTL_MS });
    } catch (error) {
        return jsonError(res, 500, `Presence ping failed: ${error.message}`);
    }
});

app.post('/api/presence/leave', async (req, res) => {
    try {
        const id = normalizePresenceId(req.body?.id);
        if (!id) return jsonError(res, 400, 'Invalid presence id');
        presenceMap.delete(id);
        prunePresence(Date.now());
        return res.json({ ok: true, activeTabs: presenceMap.size });
    } catch (error) {
        return jsonError(res, 500, `Presence leave failed: ${error.message}`);
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

app.get('/api/music/search', async (req, res) => {
    try {
        const query = String(req.query?.q || '').trim().slice(0, 120);
        if (!query) return jsonError(res, 400, 'q is required');
        const source = String(req.query?.source || 'all').trim().toLowerCase();
        const limit = 24;
        const providers = source === 'audius' || source === 'jamendo'
            ? [source]
            : ['audius', 'jamendo'];
        const tracks = [];
        const warnings = [];

        if (providers.includes('audius')) {
            try {
                const endpoint = new URL(`${AUDIUS_API_BASE}/v1/tracks/search`);
                endpoint.searchParams.set('query', query);
                endpoint.searchParams.set('app_name', 'rift');
                endpoint.searchParams.set('limit', String(limit));
                const upstream = await fetch(endpoint.toString(), {
                    headers: { 'User-Agent': 'Rift-Music/1.0' },
                });
                if (upstream.ok) {
                    const data = await upstream.json();
                    const list = Array.isArray(data?.data) ? data.data : [];
                    for (const item of list) {
                        if (!item?.id) continue;
                        tracks.push({
                            id: String(item.id),
                            provider: 'audius',
                            title: String(item.title || ''),
                            artist: String(item?.user?.name || ''),
                            artwork: pickAudiusArtwork(item),
                            durationMs: Number(item.duration || 0) * 1000,
                        });
                    }
                } else {
                    warnings.push(`audius search failed (${upstream.status})`);
                }
            } catch (error) {
                warnings.push(`audius error: ${error.message}`);
            }
        }

        if (providers.includes('jamendo')) {
            if (!hasJamendoClientId()) {
                warnings.push('jamendo not configured (missing JAMENDO_CLIENT_ID)');
            } else {
                try {
                    const endpoint = new URL(`${JAMENDO_API_BASE}/tracks/`);
                    endpoint.searchParams.set('client_id', JAMENDO_CLIENT_ID);
                    endpoint.searchParams.set('format', 'json');
                    endpoint.searchParams.set('limit', String(limit));
                    endpoint.searchParams.set('search', query);
                    endpoint.searchParams.set('audioformat', 'mp32');
                    const upstream = await fetch(endpoint.toString(), {
                        headers: { 'User-Agent': 'Rift-Music/1.0' },
                    });
                    if (upstream.ok) {
                        const data = await upstream.json();
                        const list = Array.isArray(data?.results) ? data.results : [];
                        for (const item of list) {
                            if (!item?.id || !item?.audio) continue;
                            tracks.push({
                                id: String(item.id),
                                provider: 'jamendo',
                                title: String(item.name || ''),
                                artist: String(item.artist_name || ''),
                                artwork: String(item.image || ''),
                                durationMs: Number(item.duration || 0) * 1000,
                                streamUrl: String(item.audio || ''),
                            });
                        }
                    } else {
                        warnings.push(`jamendo search failed (${upstream.status})`);
                    }
                } catch (error) {
                    warnings.push(`jamendo error: ${error.message}`);
                }
            }
        }

        return res.json({
            ok: true,
            query,
            source,
            tracks: tracks.slice(0, 80),
            warnings,
        });
    } catch (error) {
        return jsonError(res, 500, `Music search failed: ${error.message}`);
    }
});

app.get('/api/music/stream/:trackId', async (req, res) => {
    try {
        const trackId = String(req.params?.trackId || '').trim();
        const provider = String(req.query?.provider || 'audius').trim().toLowerCase();

        if (provider === 'audius') {
            if (!/^[a-z0-9_-]+$/i.test(trackId)) return jsonError(res, 400, 'Invalid Audius track id');
            const streamEndpoint = new URL(`${AUDIUS_API_BASE}/v1/tracks/${trackId}/stream`);
            streamEndpoint.searchParams.set('app_name', 'rift');
            return res.redirect(302, streamEndpoint.toString());
        }

        if (provider === 'jamendo') {
            if (!/^\d+$/.test(trackId)) return jsonError(res, 400, 'Invalid Jamendo track id');
            if (!hasJamendoClientId()) {
                return jsonError(res, 503, 'Jamendo API not configured. Set JAMENDO_CLIENT_ID on server.');
            }
            const trackEndpoint = new URL(`${JAMENDO_API_BASE}/tracks/`);
            trackEndpoint.searchParams.set('client_id', JAMENDO_CLIENT_ID);
            trackEndpoint.searchParams.set('format', 'json');
            trackEndpoint.searchParams.set('id', trackId);
            trackEndpoint.searchParams.set('audioformat', 'mp32');
            const trackRes = await fetch(trackEndpoint.toString(), {
                headers: { 'User-Agent': 'Rift-Music/1.0' },
            });
            if (!trackRes.ok) {
                return jsonError(res, trackRes.status, `Jamendo track lookup failed (${trackRes.status})`);
            }
            const data = await trackRes.json();
            const item = Array.isArray(data?.results) ? data.results[0] : null;
            const streamUrl = String(item?.audio || '').trim();
            if (!streamUrl) return jsonError(res, 404, 'No playable stream found for this track.');
            return res.redirect(302, streamUrl);
        }

        return jsonError(res, 400, 'Unsupported provider');
    } catch (error) {
        return jsonError(res, 500, `Music stream failed: ${error.message}`);
    }
});

app.get('/api/music/library', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const save = getUserSave(auth.db, auth.user.id);
        const music = getUserMusicLibrary(save, auth.user);
        return res.json({
            ok: true,
            favorites: music.favorites,
            playlists: music.playlists.map((playlist) => toPlaylistPublicView(playlist)),
        });
    } catch (error) {
        return jsonError(res, 500, `Music library read failed: ${error.message}`);
    }
});

app.put('/api/music/favorites', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const track = normalizeMusicTrack(req.body?.track);
        if (!track) return jsonError(res, 400, 'Invalid track payload');
        let isFavorite = req.body?.isFavorite;
        if (typeof isFavorite !== 'boolean') isFavorite = null;

        let finalFavoriteState = false;
        let favorites = [];
        await updateAuthDb((db) => {
            const user = db.users.find((u) => u.id === auth.user.id) || auth.user;
            const save = getUserSave(db, auth.user.id);
            const music = getUserMusicLibrary(save, user);
            const existingIndex = music.favorites.findIndex((entry) => entry.key === track.key);
            const targetState = isFavorite === null ? existingIndex === -1 : isFavorite;

            if (targetState) {
                const next = { ...track, favoritedAt: Date.now() };
                if (existingIndex >= 0) {
                    music.favorites[existingIndex] = next;
                } else {
                    music.favorites.unshift(next);
                }
                finalFavoriteState = true;
            } else if (existingIndex >= 0) {
                music.favorites.splice(existingIndex, 1);
                finalFavoriteState = false;
            } else {
                finalFavoriteState = false;
            }
            favorites = music.favorites.slice(0, 500);
            music.favorites = favorites;
            return db;
        });

        return res.json({
            ok: true,
            isFavorite: finalFavoriteState,
            favoritesCount: favorites.length,
            favorites,
        });
    } catch (error) {
        return jsonError(res, 500, `Favorite update failed: ${error.message}`);
    }
});

app.post('/api/music/playlists', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const name = sanitizePlaylistName(req.body?.name);
        const isPrivate = Boolean(req.body?.isPrivate);
        if (!name) return jsonError(res, 400, 'Playlist name is required.');

        let created = null;
        await updateAuthDb((db) => {
            const user = db.users.find((u) => u.id === auth.user.id) || auth.user;
            const save = getUserSave(db, auth.user.id);
            const music = getUserMusicLibrary(save, user);
            if (music.playlists.length >= 100) {
                throw new Error('PLAYLIST_LIMIT_REACHED');
            }
            const now = Date.now();
            const playlist = {
                id: crypto.randomUUID(),
                name,
                isPrivate,
                ownerUserId: user.id,
                ownerUsername: user.username,
                createdAt: now,
                updatedAt: now,
                tracks: [],
            };
            music.playlists.unshift(playlist);
            created = toPlaylistPublicView(playlist);
            return db;
        });

        return res.json({ ok: true, playlist: created });
    } catch (error) {
        if (error.message === 'PLAYLIST_LIMIT_REACHED') {
            return jsonError(res, 409, 'Playlist limit reached (100).');
        }
        return jsonError(res, 500, `Playlist create failed: ${error.message}`);
    }
});

app.delete('/api/music/playlists/:playlistId', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const playlistId = String(req.params?.playlistId || '').trim();
        if (!playlistId) return jsonError(res, 400, 'Invalid playlist id');

        await updateAuthDb((db) => {
            const user = db.users.find((u) => u.id === auth.user.id) || auth.user;
            const save = getUserSave(db, auth.user.id);
            const music = getUserMusicLibrary(save, user);
            const before = music.playlists.length;
            music.playlists = music.playlists.filter((playlist) => playlist.id !== playlistId);
            if (music.playlists.length === before) throw new Error('PLAYLIST_NOT_FOUND');
            return db;
        });

        return res.json({ ok: true, deletedPlaylistId: playlistId });
    } catch (error) {
        if (error.message === 'PLAYLIST_NOT_FOUND') return jsonError(res, 404, 'Playlist not found');
        return jsonError(res, 500, `Playlist delete failed: ${error.message}`);
    }
});

app.post('/api/music/playlists/:playlistId/tracks', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const playlistId = String(req.params?.playlistId || '').trim();
        if (!playlistId) return jsonError(res, 400, 'Invalid playlist id');
        const track = normalizeMusicTrack(req.body?.track);
        if (!track) return jsonError(res, 400, 'Invalid track payload');

        let playlistView = null;
        await updateAuthDb((db) => {
            const user = db.users.find((u) => u.id === auth.user.id) || auth.user;
            const save = getUserSave(db, auth.user.id);
            const music = getUserMusicLibrary(save, user);
            const playlist = music.playlists.find((entry) => entry.id === playlistId);
            if (!playlist) throw new Error('PLAYLIST_NOT_FOUND');
            const existingIndex = playlist.tracks.findIndex((entry) => entry.key === track.key);
            if (existingIndex >= 0) {
                playlist.tracks[existingIndex] = track;
            } else {
                playlist.tracks.push(track);
            }
            playlist.updatedAt = Date.now();
            if (playlist.tracks.length > 500) {
                playlist.tracks = playlist.tracks.slice(-500);
            }
            playlistView = toPlaylistPublicView(playlist);
            return db;
        });

        return res.json({ ok: true, playlist: playlistView });
    } catch (error) {
        if (error.message === 'PLAYLIST_NOT_FOUND') return jsonError(res, 404, 'Playlist not found');
        return jsonError(res, 500, `Playlist track add failed: ${error.message}`);
    }
});

app.delete('/api/music/playlists/:playlistId/tracks/:trackKey', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const playlistId = String(req.params?.playlistId || '').trim();
        const trackKey = String(req.params?.trackKey || '').trim();
        if (!playlistId) return jsonError(res, 400, 'Invalid playlist id');
        if (!/^[a-z0-9_-]{2,20}:[a-z0-9:_-]{1,140}$/i.test(trackKey)) {
            return jsonError(res, 400, 'Invalid track key');
        }

        let playlistView = null;
        await updateAuthDb((db) => {
            const user = db.users.find((u) => u.id === auth.user.id) || auth.user;
            const save = getUserSave(db, auth.user.id);
            const music = getUserMusicLibrary(save, user);
            const playlist = music.playlists.find((entry) => entry.id === playlistId);
            if (!playlist) throw new Error('PLAYLIST_NOT_FOUND');
            const before = playlist.tracks.length;
            playlist.tracks = playlist.tracks.filter((entry) => entry.key !== trackKey);
            if (playlist.tracks.length === before) throw new Error('TRACK_NOT_FOUND');
            playlist.updatedAt = Date.now();
            playlistView = toPlaylistPublicView(playlist);
            return db;
        });

        return res.json({ ok: true, playlist: playlistView, removedTrackKey: trackKey });
    } catch (error) {
        if (error.message === 'PLAYLIST_NOT_FOUND') return jsonError(res, 404, 'Playlist not found');
        if (error.message === 'TRACK_NOT_FOUND') return jsonError(res, 404, 'Track not found in playlist');
        return jsonError(res, 500, `Playlist track remove failed: ${error.message}`);
    }
});

app.get('/api/music/playlists/public', async (req, res) => {
    try {
        const db = await readAuthDb();
        const usersById = new Map((Array.isArray(db.users) ? db.users : []).map((u) => [u.id, u]));
        const out = [];
        for (const [userId, save] of Object.entries(db.saves || {})) {
            const user = usersById.get(userId);
            if (!user) continue;
            const music = getUserMusicLibrary(save, user);
            for (const playlist of music.playlists) {
                if (playlist.isPrivate) continue;
                out.push({
                    userId,
                    ownerUsername: playlist.ownerUsername || user.username,
                    ...toPlaylistPublicView(playlist),
                });
            }
        }
        out.sort((a, b) => Number(b.updatedAt || 0) - Number(a.updatedAt || 0));
        return res.json({ ok: true, playlists: out.slice(0, 200) });
    } catch (error) {
        return jsonError(res, 500, `Public playlist list failed: ${error.message}`);
    }
});

app.get('/api/chat/messages', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const roomId = normalizeRoomName(req.query?.room || 'lobby') || 'lobby';
        const roomPassword = String(req.query?.password || '');
        const since = Number.parseInt(String(req.query?.since || '0'), 10) || 0;
        const db = await readAuthDb();
        const rooms = getChatRooms(db);
        const room = rooms[roomId];
        if (!room) return jsonError(res, 404, 'Room not found');
        if (!canAccessRoom(auth.user, room, roomPassword)) return jsonError(res, 403, 'Invalid room password');
        const rows = getRoomMessages(db, roomId);
        const filtered = since > 0 ? rows.filter((m) => Number(m.createdAt) > since) : rows;
        const messages = filtered.slice(-120);
        return res.json({ ok: true, room: toRoomPublicView(room), messages, now: Date.now() });
    } catch (error) {
        return jsonError(res, 500, `Chat read failed: ${error.message}`);
    }
});

app.post('/api/chat/messages', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const roomId = normalizeRoomName(req.body?.room || 'lobby') || 'lobby';
        const roomPassword = String(req.body?.password || '');
        const text = sanitizeChatText(req.body?.text);
        if (!text) return jsonError(res, 400, 'Message text required');
        const dbBefore = await readAuthDb();
        const roomsBefore = getChatRooms(dbBefore);
        const roomBefore = roomsBefore[roomId];
        if (!roomBefore) return jsonError(res, 404, 'Room not found');
        if (!canAccessRoom(auth.user, roomBefore, roomPassword)) return jsonError(res, 403, 'Invalid room password');

        const message = {
            id: crypto.randomUUID(),
            roomId,
            userId: auth.user.id,
            username: auth.user.username,
            text,
            createdAt: Date.now(),
        };

        await updateAuthDb((db) => {
            const rooms = getChatRooms(db);
            const room = rooms[roomId];
            if (!room || !canAccessRoom(auth.user, room, roomPassword)) {
                throw new Error('ROOM_ACCESS_DENIED');
            }
            const rows = getRoomMessages(db, roomId);
            rows.push(message);
            if (rows.length > 500) {
                getChatMessagesMap(db)[roomId] = rows.slice(-500);
            }
            room.lastMessageAt = message.createdAt;
            return db;
        });

        return res.json({ ok: true, message });
    } catch (error) {
        if (error.message === 'ROOM_ACCESS_DENIED') return jsonError(res, 403, 'Invalid room password');
        return jsonError(res, 500, `Chat send failed: ${error.message}`);
    }
});

app.get('/api/chat/rooms', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const db = await readAuthDb();
        const rooms = Object.values(getChatRooms(db))
            .map((room) => toRoomPublicView(room))
            .sort(sortChatRoomsForList);
        return res.json({ ok: true, rooms });
    } catch (error) {
        return jsonError(res, 500, `Room list failed: ${error.message}`);
    }
});

app.post('/api/chat/rooms', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const roomId = normalizeRoomName(req.body?.name);
        const isPrivate = Boolean(req.body?.isPrivate);
        const password = String(req.body?.password || '');
        if (!roomId || roomId.length < 3) {
            return jsonError(res, 400, 'Room name must be at least 3 characters.');
        }
        if (SYSTEM_CHAT_ROOM_IDS.has(roomId)) return jsonError(res, 409, 'Room name already exists.');
        if (isPrivate && password.length < 4) {
            return jsonError(res, 400, 'Private room password must be at least 4 characters.');
        }

        const now = Date.now();
        const room = {
            id: roomId,
            name: roomId,
            ownerUserId: auth.user.id,
            ownerUsername: auth.user.username,
            isPrivate,
            createdAt: now,
            lastMessageAt: now,
        };
        if (isPrivate) {
            room.passwordSalt = createSalt();
            room.passwordHash = hashPassword(password, room.passwordSalt);
        }

        await updateAuthDb((db) => {
            const rooms = getChatRooms(db);
            if (rooms[roomId]) throw new Error('ROOM_EXISTS');
            rooms[roomId] = room;
            getRoomMessages(db, roomId);
            return db;
        });

        return res.json({ ok: true, room: toRoomPublicView(room) });
    } catch (error) {
        if (error.message === 'ROOM_EXISTS') return jsonError(res, 409, 'Room name already exists.');
        return jsonError(res, 500, `Room create failed: ${error.message}`);
    }
});

app.delete('/api/chat/rooms/:roomId', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const roomId = normalizeRoomName(req.params?.roomId || '');
        if (!roomId) return jsonError(res, 400, 'Invalid room id');
        if (SYSTEM_CHAT_ROOM_IDS.has(roomId)) {
            return jsonError(res, 403, 'System rooms cannot be deleted.');
        }

        const db = await readAuthDb();
        const rooms = getChatRooms(db);
        const room = rooms[roomId];
        if (!room) return jsonError(res, 404, 'Room not found');
        if (!canDeleteRoom(auth.user, room)) return jsonError(res, 403, 'Not allowed to delete this room');

        await updateAuthDb((nextDb) => {
            const nextRooms = getChatRooms(nextDb);
            const nextRoom = nextRooms[roomId];
            if (!nextRoom) throw new Error('ROOM_NOT_FOUND');
            if (!canDeleteRoom(auth.user, nextRoom)) throw new Error('ROOM_DELETE_DENIED');
            delete nextRooms[roomId];
            const messagesMap = getChatMessagesMap(nextDb);
            delete messagesMap[roomId];
            return nextDb;
        });

        return res.json({ ok: true, deletedRoomId: roomId });
    } catch (error) {
        if (error.message === 'ROOM_NOT_FOUND') return jsonError(res, 404, 'Room not found');
        if (error.message === 'ROOM_DELETE_DENIED') return jsonError(res, 403, 'Not allowed to delete this room');
        return jsonError(res, 500, `Room delete failed: ${error.message}`);
    }
});

// Fallback for runtime same-origin asset requests emitted from proxied pages
// (e.g. Unity/WebGL games requesting /media/* or font files).
app.all('*', async (req, res, next) => {
    // Some proxied pages emit malformed same-origin requests like:
    // /cdn.jsdelivr.net/proxy?url=https://truffled.lol/...
    // Normalize these back into the real /proxy endpoint.
    const hostPrefixedProxy = String(req.path || '').match(/^\/([a-z0-9.-]+\.[a-z]{2,})\/proxy$/i);
    if (hostPrefixedProxy) {
        const nested = String(req.query?.url || '').trim();
        if (nested) {
            return res.redirect(302, `/proxy?url=${encodeURIComponent(nested)}`);
        }
        const host = hostPrefixedProxy[1];
        return res.redirect(302, `/proxy?url=${encodeURIComponent(`https://${host}/`)}`);
    }

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
    let targetUrl = req.query.url;

    const unwrapNestedProxyTarget = (rawValue) => {
        let current = String(rawValue || '').trim();
        for (let i = 0; i < 4; i++) {
            if (!current) break;
            try {
                // Handle absolute nested proxy URLs (e.g. https://host/proxy?url=...)
                const parsed = new URL(current);
                if (parsed.pathname === '/proxy' && parsed.searchParams.get('url')) {
                    current = parsed.searchParams.get('url');
                    continue;
                }
                break;
            } catch {
                // Handle relative nested proxy URLs (e.g. /proxy?url=...)
                if (current.startsWith('/proxy?url=')) {
                    try {
                        const rel = new URL(current, `http://${req.headers.host || 'localhost'}`);
                        const inner = rel.searchParams.get('url');
                        if (inner) {
                            current = inner;
                            continue;
                        }
                    } catch {}
                }

                // Handle host-prefixed nested proxy values without scheme:
                // cdn.jsdelivr.net/proxy?url=https://...
                const hostPrefixed = current.match(/^([a-z0-9.-]+\.[a-z]{2,})\/proxy\?url=(.+)$/i);
                if (hostPrefixed) {
                    try {
                        current = decodeURIComponent(hostPrefixed[2]);
                    } catch {
                        current = hostPrefixed[2];
                    }
                    continue;
                }
                break;
            }
        }
        return current;
    };

    targetUrl = unwrapNestedProxyTarget(targetUrl);

    if (!targetUrl) {
        // Recover malformed query shapes:
        // - /proxy?https://example.com
        // - /proxy?u=https://example.com
        // - /proxy?cdn.jsdelivr.net/proxy?url=https://...
        const rawQuery = req.url.includes('?') ? req.url.slice(req.url.indexOf('?') + 1) : '';
        if (rawQuery) {
            let decoded = rawQuery;
            try { decoded = decodeURIComponent(rawQuery); } catch {}
            if (/^https?:\/\//i.test(decoded)) {
                targetUrl = decoded;
            } else {
                const loose = new URLSearchParams(rawQuery);
                const alt =
                    loose.get('u') ||
                    loose.get('target') ||
                    loose.get('dest') ||
                    loose.get('href') ||
                    '';
                if (alt && /^https?:\/\//i.test(alt)) {
                    targetUrl = alt;
                } else {
                    for (const key of loose.keys()) {
                        if (/^https?:\/\//i.test(key)) {
                            targetUrl = key;
                            break;
                        }
                    }
                    if (!targetUrl && /^[a-z0-9.-]+\.[a-z]{2,}\/proxy\?url=/i.test(decoded)) {
                        targetUrl = decoded;
                    }
                }
            }
            targetUrl = unwrapNestedProxyTarget(targetUrl);
        }
    }

    if (!targetUrl) {
        // Some proxied pages submit relative GET forms to the current /proxy URL
        // (e.g. /proxy?name=foo). Recover the upstream target from referer.
        const referer = String(req.get('referer') || '').trim();
        try {
            const refUrl = new URL(referer);
            if (refUrl.pathname === '/proxy') {
                const refTargetRaw = refUrl.searchParams.get('url');
                if (refTargetRaw) {
                    let recovered;
                    try {
                        recovered = new URL(refTargetRaw);
                    } catch {
                        recovered = new URL(encodeURI(refTargetRaw));
                    }
                    const incomingQuery = new URLSearchParams(req.query || {});
                    incomingQuery.delete('url');
                    // Myinstants search forms often submit only "?name=...".
                    // Route these to the site's native search endpoint.
                    if (
                        incomingQuery.has('name') &&
                        /(^|\.)myinstants\.com$/i.test(String(recovered.hostname || '')) &&
                        /^\/en\/categories\//i.test(String(recovered.pathname || ''))
                    ) {
                        recovered.pathname = '/en/search/';
                    }
                    const nextQuery = incomingQuery.toString();
                    recovered.search = nextQuery ? `?${nextQuery}` : '';
                    return res.redirect(302, `/proxy?url=${encodeURIComponent(recovered.href)}`);
                }
            }
        } catch {
            // Fall through to default 400 when recover is not possible.
        }
        if ((req.method || 'GET').toUpperCase() === 'GET') {
            // Suppress noisy empty /proxy GETs from worker/runtime probes.
            return res.status(204).end();
        }
        return res.status(400).send('URL parameter is required');
    }

    try {
        // Truffled games rely on root-relative assets/scripts that break behind proxy.
        // Force those launches onto Truffled's own iframe loader instead.
        try {
            const parsedTarget = new URL(String(targetUrl));
            if (/(^|\.)truffled\.lol$/i.test(parsedTarget.hostname) &&
                /^\/games\/.+\/index\.html$/i.test(parsedTarget.pathname) &&
                !/\/iframe\.html$/i.test(parsedTarget.pathname)) {
                const embedded = `${parsedTarget.pathname}${parsedTarget.search}${parsedTarget.hash}` || '/';
                const redirectUrl = `https://truffled.lol/iframe.html?url=${encodeURIComponent(embedded)}`;
                return res.redirect(302, redirectUrl);
            }
        } catch {}

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

        // Truffled iframe pages use href="javascript:void(0)" for popout, which looks broken.
        // Keep their click behavior, but expose a real href so hover/status shows a usable URL.
        try {
            if (/(^|\.)truffled\.lol$/i.test(parsedTargetUrl.hostname) && /^\/iframe\.html$/i.test(parsedTargetUrl.pathname)) {
                const truffledPopoutScript = '<script id="rift-truffled-popout-link">(function(){function sync(){var btn=document.getElementById("aboutblank");var frame=document.getElementById("gameframe");if(!btn||!frame)return;var src=String(frame.src||"").trim();if(!src||/\\/404\\.html(?:$|\\?)/i.test(src))return;btn.setAttribute("href",src);btn.setAttribute("target","_blank");btn.setAttribute("rel","noopener noreferrer");}document.addEventListener("DOMContentLoaded",sync);setInterval(sync,800);})();</script>';
                if (/<\/body>/i.test(modifiedContent)) {
                    modifiedContent = modifiedContent.replace(/<\/body>/i, `${truffledPopoutScript}</body>`);
                } else {
                    modifiedContent += truffledPopoutScript;
                }
            }
        } catch {}

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
        let payload = null;
        try {
            const response = await fetch(TRUFFLED_GAMES_JSON);
            if (response.ok) {
                payload = await response.json();
            }
        } catch {
            // Fall back to local snapshot when remote source is unavailable.
        }
        if (!payload) {
            const localRaw = await fs.readFile(TRUFFLED_LOCAL_JSON, 'utf8');
            payload = JSON.parse(localRaw);
        }

        const rootMap = await readTruffledRootMap();
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
            const localSlug = toTruffledLocalSlug(normalized);
            const mappedFile = String(rootMap[normalized] || '').trim();
            const mappedUrl = mappedFile ? `/${mappedFile.replace(/^\/+/, '')}` : '';
            items.push({
                id: `truffled-${normalized}`,
                name,
                url: mappedUrl || `/truffled-html/${localSlug}.html`,
                cover: normalizedThumb ? new URL(normalizedThumb, TRUFFLED_BASE).href : '',
            });
        }

        items.sort((a, b) => a.name.localeCompare(b.name));
        return res.json(items);
    } catch (error) {
        return res.status(500).json({ error: `failed to build truffled catalog: ${error.message}` });
    }
});

// Build Totally Science catalog from CloudFront homepage cards.
app.get('/totalscience-catalog', async (_req, res) => {
    try {
        const response = await fetch(TOTALLY_SCIENCE_BASE);
        if (!response.ok) {
            return res.status(502).json({ error: `totally science fetch failed: ${response.status}` });
        }

        const html = await response.text();
        const items = [];
        const seen = new Set();
        const pushGame = (slugRaw, nameRaw, coverRaw = '') => {
            const slug = String(slugRaw || '').trim().replace(/^\.?\//, '').replace(/^\/+/, '').replace(/\/+$/, '');
            const name = String(nameRaw || '').trim().replace(/\s+/g, ' ');
            if (!slug || !name) return;
            if (/^(t|tag|about|contact|privacy-policy|all-tags|new-games|recently-played-games|page)(\/|$)/i.test(slug)) return;
            const key = `${slug.toLowerCase()}|${name.toLowerCase()}`;
            if (seen.has(key)) return;
            seen.add(key);

            const normalizedCover = String(coverRaw || '').trim().replace(/^\.?\//, '').replace(/^\/+/, '');
            items.push({
                id: `totalscience-${slug.toLowerCase()}`,
                name,
                url: new URL(`${slug}/`, TOTALLY_SCIENCE_BASE).href,
                cover: normalizedCover ? new URL(normalizedCover, TOTALLY_SCIENCE_BASE).href : '',
            });
        };

        const cardRe = /<article[^>]*class="[^"]*\bc-card\b[^"]*"[\s\S]*?<img[^>]*src="([^"]+)"[\s\S]*?<div[^>]*class="c-card__title"[^>]*>\s*<a[^>]*href="\.\/([^"\/]+)\/"[^>]*>([^<]+)<\/a>/gi;
        let m;
        while ((m = cardRe.exec(html)) !== null) {
            pushGame(m[2], m[3], m[1]);
        }

        const rowRe = /<div[^>]*onclick="location\.href='\/([^'\/]+)\/'"[^>]*>[\s\S]*?<img[^>]*src="([^"]+)"[\s\S]*?<h3[^>]*>([^<]+)<\/h3>/gi;
        while ((m = rowRe.exec(html)) !== null) {
            pushGame(m[1], m[3], m[2]);
        }

        items.sort((a, b) => a.name.localeCompare(b.name));
        return res.json(items);
    } catch (error) {
        return res.status(500).json({ error: `failed to build totally science catalog: ${error.message}` });
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
