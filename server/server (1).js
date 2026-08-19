const express = require('express');
const path = require('path');
const fs = require('fs').promises;
const dns = require('dns').promises;
const crypto = require('crypto');
const { uvPath } = require('@titaniumnetwork-dev/ultraviolet');
const { attachCloudControlRoutes } = require('./cloud-control');

const app = express();
const PORT = process.env.PORT || 3000;
const ENABLE_VELARA = ['1', 'true', 'yes', 'on'].includes(String(process.env.ENABLE_VELARA || '').trim().toLowerCase());

app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
});
app.use(express.json({ limit: '1mb' }));

const VALIDATE_TARGET_IPS = String(process.env.VALIDATE_TARGET_IPS || '')
    .split(',')
    .map((ip) => ip.trim())
    .filter(Boolean);

const validateCache = new Map();
const VALIDATE_TTL_MS = 60 * 1000;
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const SDXP_HTML_ROOT = path.join(PUBLIC_DIR, 'sdxp', 'html');
const GN_MATH_ZONES_JSON = 'https://cdn.jsdelivr.net/gh/gn-math/assets@main/zones.json';
const GN_MATH_BASE = 'https://cdn.jsdelivr.net/gh/gn-math/';
const GN_MATH_HTML_BASE = new URL('html@main/', GN_MATH_BASE).href;
const GN_MATH_COVER_BASE = new URL('covers@main/', GN_MATH_BASE).href;
const SDXP_FALLBACK_BASE = 'https://strongdog.com/';
const DUCKMATH_GAMES_PAGE = 'https://duckmath.org/g4m3s.html';
const DUCKMATH_BASE = 'https://duckmath.org/';
const CCPORTED_TREE_API = 'https://api.github.com/repos/ccported/games/git/trees/main?recursive=1';
const CCPORTED_RAW_BASE = 'https://raw.githubusercontent.com/ccported/games/main/';
const UGS_TREE_API = 'https://api.github.com/repos/bubbls/UGS-Assets/git/trees/main?recursive=1';
const UGS_RAW_BASE = 'https://raw.githubusercontent.com/bubbls/UGS-Assets/main/';
const SELENITE_TREE_API = 'https://api.github.com/repos/selenite-cc/selenite-old/git/trees/main?recursive=1';
const SELENITE_RAW_BASE = 'https://raw.githubusercontent.com/selenite-cc/selenite-old/main/';
const RADON_TREE_API = 'https://api.github.com/repos/Radon-Games/Radon-Games-Assets/git/trees/main?recursive=1';
const RADON_RAW_BASE = 'https://raw.githubusercontent.com/Radon-Games/Radon-Games-Assets/main/';
const FYINX_TREE_API = 'https://api.github.com/repos/aukak/fyinx/git/trees/main?recursive=1';
const FYINX_RAW_BASE = 'https://raw.githubusercontent.com/aukak/fyinx/main/';
const ELITE_TREE_API = 'https://api.github.com/repos/elite-gamez/Elite_gamez_games/git/trees/main?recursive=1';
const ELITE_RAW_BASE = 'https://raw.githubusercontent.com/elite-gamez/Elite_gamez_games/main/';
const CCPORTED_TITLE_SUFFIX_RE = /\s*(?:\||-)?\s*Unblocked on CCPorted\s*$/i;
const TRUFFLED_GAMES_JSON = 'https://truffled.lol/js/json/g.json';
const TRUFFLED_LOCAL_JSON = path.join(__dirname, '..', 'truffled.g.json');
const TRUFFLED_BASE = 'https://truffled.lol/';
const TRUFFLED_ROOT_MANIFEST = path.join(__dirname, '..', 'data', 'truffled-root-manifest.json');
const PETEZAH_GAMES_JSON = 'https://petezahgames.com/storage/data/collection.json';
const PETEZAH_LEGACY_GAMES_JSON = 'https://cdn.jsdelivr.net/gh/PeteZah-G/singlefile-json@main/search.json';
const PETEZAH_BASE = 'https://petezahgames.com/';
const TOTALLY_SCIENCE_BASE = 'https://d11jzht7mj96rr.cloudfront.net/';
const VELARA_GAMES_JSON = 'https://velara.my/data/games.json';
const VELARA_BASE = 'https://velara.my/';
const VELARA_ORIGIN = 'https://velara.my';
const SERAPH_GAMES_API = 'https://api.github.com/repos/a456pur/seraph/contents/games';
const SERAPH_BASE = 'https://raw.githubusercontent.com/a456pur/seraph/main/';
const AUDIUS_API_BASE = 'https://discoveryprovider.audius.co';
const JAMENDO_API_BASE = 'https://api.jamendo.com/v3.0';
const JAMENDO_CLIENT_ID = String(process.env.JAMENDO_CLIENT_ID || '').trim();
const MYINSTANTS_BASE = 'https://www.myinstants.com';
const MYINSTANTS_RESULT_LIMIT = 18;
const AUTH_DB_PATH = process.env.AUTH_DB_PATH
    ? path.resolve(process.env.AUTH_DB_PATH)
    : (process.env.VERCEL
        ? path.join('/tmp', 'rift-data', 'auth-db.json')
        : path.join(__dirname, '..', 'data', 'auth-db.json'));
const AUTH_DB_LOCK_PATH = `${AUTH_DB_PATH}.lock`;
const AUTH_DB_LOCK_TIMEOUT_MS = 8000;
const AUTH_DB_LOCK_STALE_MS = 1000 * 30;
const SESSION_COOKIE = 'rift_sid';
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 30; // 30 days
const SESSION_TOUCH_WRITE_INTERVAL_MS = 1000 * 60; // 1 minute
const ACTIVE_USER_WINDOW_MS = 1000 * 60 * 10; // 10 minutes
const USER_STATUS_MODES = new Set(['auto', 'online', 'idle', 'dnd']);
const USER_STATUS_AUTO_ONLINE_MS = 1000 * 60 * 2;
const USER_STATUS_OFFLINE_MS = 1000 * 60 * 12;
const USER_ACTIVITY_TTL_MS = 1000 * 60 * 30;
const PRESENCE_TTL_MS = 1000 * 60; // 60 seconds
const CHAT_ROOM_INACTIVE_TTL_MS = 1000 * 60 * 60 * 24; // 24 hours
const SYSTEM_CHAT_ROOM_IDS = new Set(['lobby', 'links']);
const CHAT_CALL_MEMBER_TTL_MS = 1000 * 45;
const CHAT_CALL_SIGNAL_TTL_MS = 1000 * 60 * 2;
const CHAT_TYPING_TTL_MS = 1000 * 6;
const CHAT_PIN_LIMIT = 3;
const CHAT_REACTION_EMOJIS = ['👍', '❤️', '😂', '🔥', '😮', '😢'];
const CHAT_BAD_WORDS = new Set([
    'asshole',
    'bastard',
    'bitch',
    'bullshit',
    'cunt',
    'dick',
    'fag',
    'faggot',
    'fuck',
    'motherfucker',
    'nigga',
    'nigger',
    'pussy',
    'shit',
    'slut',
    'whore',
]);
const CHAT_BAD_WORD_SUFFIXES = ['s', 'es', 'ed', 'er', 'ers', 'ing', 'in'];
const PROFILE_FRAME_EFFECTS = ['none', 'pulse', 'glow', 'orbit'];
const PROFILE_ACCENT_ANIMATIONS = ['none', 'shimmer', 'breathe', 'wave'];
const PROFILE_THEME_DEFS = [
    { id: 'classic', name: 'classic', requiresAchievementId: '' },
    { id: 'midnight', name: 'midnight', requiresAchievementId: '' },
    { id: 'starlight', name: 'starlight', requiresAchievementId: 'theme_editor' },
    { id: 'trailblazer', name: 'trailblazer', requiresAchievementId: 'explorer' },
    { id: 'party-flare', name: 'party flare', requiresAchievementId: 'party_up' },
];
const DAILY_QUEST_DEFS = [
    { id: 'daily_chat', name: 'chat runner', metric: 'chatMessages', target: 8, xp: 50 },
    { id: 'daily_games', name: 'game sprint', metric: 'gameLaunches', target: 4, xp: 70 },
    { id: 'daily_music', name: 'music curator', metric: 'musicActions', target: 3, xp: 45 },
];
const PROFILE_PRESET_SHARE_LIMIT = 200;
const PROFILE_PRESET_CODE_RE = /^[A-Z0-9]{6,12}$/;
const BUILTIN_PROFILE_PRESETS = [
    {
        code: 'RIFT01',
        name: 'rift pulse',
        style: { themeId: 'midnight', frameEffect: 'pulse', accentAnimation: 'breathe', accent: '#8ecbff' },
        builtIn: true,
        creatorUsername: 'system',
    },
    {
        code: 'WAVE01',
        name: 'wave trail',
        style: { themeId: 'trailblazer', frameEffect: 'orbit', accentAnimation: 'wave', accent: '#4dd7a5' },
        builtIn: true,
        creatorUsername: 'system',
    },
];
const RESERVED_TOP_LEVEL_PATHS = new Set([
    'api',
    'gn',
    'gn-catalog',
    'proxy',
    'assets',
    'components',
    'scramjet',
    'baremux',
    'libcurl',
    'epoxy',
    'uv',
    'wisp',
    'validate',
    'sdxp',
    'sdxp-catalog',
    'duckmath-catalog',
    'ccported-catalog',
    'ugs-catalog',
    'slnte-catalog',
    'rdn-catalog',
    'fyinx-catalog',
    'eltgmz-catalog',
    'dkmath',
    'ccptd',
    'ugs',
    'slnte',
    'rdn',
    'fyinx',
    'eltgmz',
    'truffled-catalog',
    'pzlite',
    'pzlite-catalog',
    'truf',
    'tllysc',
    'vlra',
    'sph',
    'totalscience-catalog',
    'velara-catalog',
    'seraph-catalog',
    'astra',
    'astra-accounts',
]);
const TRUFFLED_ALIAS_CACHE_TTL_MS = 5 * 60 * 1000;
const DUCKMATH_CACHE_TTL_MS = 5 * 60 * 1000;
const DUCKMATH_RESOLVED_TTL_MS = 30 * 60 * 1000;
const CCPORTED_CACHE_TTL_MS = 5 * 60 * 1000;
const UGS_CACHE_TTL_MS = 5 * 60 * 1000;
const SELENITE_CACHE_TTL_MS = 5 * 60 * 1000;
const RADON_CACHE_TTL_MS = 5 * 60 * 1000;
const FYINX_CACHE_TTL_MS = 5 * 60 * 1000;
const ELITE_CACHE_TTL_MS = 5 * 60 * 1000;
const PETEZAH_CACHE_TTL_MS = 5 * 60 * 1000;
const TOTALLY_SCIENCE_CACHE_TTL_MS = 5 * 60 * 1000;
const TOTALLY_SCIENCE_RESOLVED_TTL_MS = 30 * 60 * 1000;
const VELARA_CACHE_TTL_MS = 5 * 60 * 1000;
const VELARA_RESOLVED_TTL_MS = 30 * 60 * 1000;
const SERAPH_CACHE_TTL_MS = 5 * 60 * 1000;
const NOWGG_RESOLVE_TTL_MS = Math.max(5 * 1000, Number(process.env.NOWGG_RESOLVE_TTL_MS || 2 * 60 * 1000));
const NOWGG_RESOLVE_TIMEOUT_MS = Math.max(1500, Number(process.env.NOWGG_RESOLVE_TIMEOUT_MS || 5000));
const NOWGG_RESOLVE_CONCURRENCY = Math.max(1, Math.min(24, Number(process.env.NOWGG_RESOLVE_CONCURRENCY || 8)));
const NOWGG_RESOLVE_MAX_PREFIX = Math.max(8, Math.min(512, Number(process.env.NOWGG_RESOLVE_MAX_PREFIX || 255)));
const NOWGG_PREFIX_HINTS = Array.from(new Set(
    String(process.env.NOWGG_PREFIX_HINTS || '159,108')
        .split(',')
        .map((entry) => Number.parseInt(String(entry || '').trim(), 10))
        .filter((value) => Number.isInteger(value) && value > 0 && value <= NOWGG_RESOLVE_MAX_PREFIX)
));
let authWriteLock = Promise.resolve();
const sessionTouchWriteMap = new Map();
let lastKnownGoodAuthDb = null;
const presenceMap = new Map();
const userActivityMap = new Map();
let truffledAliasCache = { expiresAt: 0, map: new Map() };
let duckMathCatalogCache = { expiresAt: 0, items: [], map: new Map() };
let ccportedCatalogCache = { expiresAt: 0, items: [], map: new Map() };
const ccportedNameCache = new Map();
let ugsCatalogCache = { expiresAt: 0, items: [], map: new Map() };
let seleniteCatalogCache = { expiresAt: 0, items: [], map: new Map() };
let radonCatalogCache = { expiresAt: 0, items: [], map: new Map() };
let fyinxCatalogCache = { expiresAt: 0, items: [], map: new Map() };
let eliteCatalogCache = { expiresAt: 0, items: [], map: new Map() };
let petezahCatalogCache = { expiresAt: 0, items: [], map: new Map() };
let totallyScienceCatalogCache = { expiresAt: 0, items: [], map: new Map() };
let velaraCatalogCache = { expiresAt: 0, items: [], map: new Map() };
let seraphCatalogCache = { expiresAt: 0, items: [], map: new Map() };
const nowggResolveCache = new Map();
const totallyScienceResolvedLaunchCache = new Map();
const velaraResolvedLaunchCache = new Map();
const duckMathResolvedLaunchCache = new Map();
const chatCallRooms = new Map();
const chatTypingRooms = new Map();

const GN_MATH_BLOCKED_HTML_FILES = new Set([
    '114-f.html',
    '265.html',
    '303.html',
    '469.html',
]);

async function readRawBody(req) {
    return await new Promise((resolve, reject) => {
        const chunks = [];
        req.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        req.on('end', () => resolve(Buffer.concat(chunks)));
        req.on('error', reject);
    });
}

function isResolvableNowggHost(hostname) {
    const host = String(hostname || '').trim().toLowerCase();
    return host === 'now.gg'
        || host === 'www.now.gg'
        || host === 'nowgg.fun'
        || host === 'www.nowgg.fun'
        || /^\d+\.ip\.nowgg\.fun$/i.test(host);
}

function hashString(input) {
    let hash = 0;
    const value = String(input || '');
    for (let index = 0; index < value.length; index += 1) {
        hash = ((hash << 5) - hash) + value.charCodeAt(index);
        hash |= 0;
    }
    return Math.abs(hash);
}

function buildNowggCacheKey(targetUrl) {
    const parsed = new URL(targetUrl);
    return `${parsed.pathname}${parsed.search}`;
}

function isBrokenNowggHtml(html) {
    const source = String(html || '');
    return source.includes('undefined/undefined/undefined')
        || /<title[^>]*>\s*<\/title>/i.test(source)
        || /"url":"https?:\/\/[^"]*\/apps\/undefined\/undefined\/undefined\.html"/i.test(source);
}

function looksLikeResolvedNowggHtml(html, targetUrl) {
    const source = String(html || '');
    if (!source || isBrokenNowggHtml(source)) return false;
    if (!source.includes('__NEXT_DATA__')) return false;

    const parsed = new URL(targetUrl);
    const segments = parsed.pathname.split('/').filter(Boolean);
    if (segments.length >= 4 && segments[0] === 'apps') {
        const expectedIndex = JSON.stringify(segments.slice(1));
        if (!source.includes(`"index":${expectedIndex}`)) {
            return false;
        }
    }

    return true;
}

function buildNowggPrefixPlan(targetUrl) {
    const target = new URL(targetUrl);
    const ordered = [];
    const seen = new Set();
    const add = (value) => {
        const numeric = Number.parseInt(String(value || '').trim(), 10);
        if (!Number.isInteger(numeric) || numeric <= 0 || numeric > NOWGG_RESOLVE_MAX_PREFIX || seen.has(numeric)) return;
        seen.add(numeric);
        ordered.push(numeric);
    };
    const currentHostMatch = target.hostname.match(/^(\d+)\.ip\.nowgg\.fun$/i);
    if (currentHostMatch?.[1]) add(currentHostMatch[1]);
    NOWGG_PREFIX_HINTS.forEach(add);
    for (const hint of NOWGG_PREFIX_HINTS) {
        for (let offset = 1; offset <= 4; offset += 1) {
            add(hint - offset);
            add(hint + offset);
        }
    }

    const seed = hashString(`${target.pathname}${target.search}`);
    const start = (seed % NOWGG_RESOLVE_MAX_PREFIX) + 1;
    for (let offset = 0; offset < NOWGG_RESOLVE_MAX_PREFIX; offset += 1) {
        add(((start + offset - 1) % NOWGG_RESOLVE_MAX_PREFIX) + 1);
    }

    return ordered;
}

async function fetchNowggCandidateHtml(candidateUrl) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), NOWGG_RESOLVE_TIMEOUT_MS);
    try {
        const response = await fetch(candidateUrl, {
            redirect: 'follow',
            signal: controller.signal,
            headers: {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'pragma': 'no-cache',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
            },
        });
        const contentType = String(response.headers.get('content-type') || '').toLowerCase();
        const html = contentType.includes('text/html') || !contentType
            ? await response.text()
            : '';
        return {
            ok: response.ok,
            status: response.status,
            contentType,
            html,
            finalUrl: response.url || candidateUrl,
        };
    } finally {
        clearTimeout(timeout);
    }
}

async function resolveNowggLaunchUrl(targetUrl) {
    const normalized = new URL(targetUrl);
    if (!isResolvableNowggHost(normalized.hostname)) {
        throw new Error('unsupported now.gg host');
    }

    const cacheKey = buildNowggCacheKey(normalized.href);
    const cached = nowggResolveCache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
        return cached.value;
    }

    const tryCandidate = async (prefix) => {
        const candidate = new URL(normalized.href);
        candidate.protocol = 'https:';
        candidate.host = `${prefix}.ip.nowgg.fun`;
        const probe = await fetchNowggCandidateHtml(candidate.href);
        if (!probe.ok) {
            return { ok: false, prefix, url: candidate.href, status: probe.status, reason: `http ${probe.status}` };
        }
        if (!looksLikeResolvedNowggHtml(probe.html, candidate.href)) {
            return { ok: false, prefix, url: candidate.href, status: probe.status, reason: 'fallback html' };
        }
        return {
            ok: true,
            prefix,
            url: candidate.href,
            status: probe.status,
            finalUrl: probe.finalUrl,
        };
    };

    const prefixes = buildNowggPrefixPlan(normalized.href);
    const attempts = [];
    for (let index = 0; index < prefixes.length; index += NOWGG_RESOLVE_CONCURRENCY) {
        const batch = prefixes.slice(index, index + NOWGG_RESOLVE_CONCURRENCY);
        const results = await Promise.all(batch.map(async (prefix) => {
            try {
                return await tryCandidate(prefix);
            } catch (error) {
                return { ok: false, prefix, url: `https://${prefix}.ip.nowgg.fun${normalized.pathname}${normalized.search}`, reason: error.message || 'probe failed' };
            }
        }));

        for (const result of results) {
            attempts.push(result);
            if (!result.ok) continue;
            const resolved = {
                inputUrl: normalized.href,
                resolvedUrl: result.url,
                prefix: result.prefix,
                host: `${result.prefix}.ip.nowgg.fun`,
                cached: false,
                attempts: attempts.slice(0, 12),
            };
            nowggResolveCache.set(cacheKey, {
                expiresAt: Date.now() + NOWGG_RESOLVE_TTL_MS,
                value: resolved,
            });
            return resolved;
        }
    }

    const details = attempts.slice(0, 12).map((entry) => `${entry.prefix || '?'}:${entry.reason || entry.status || 'failed'}`).join(', ');
    throw new Error(details ? `no working now.gg session host found (${details})` : 'no working now.gg session host found');
}

async function proxyVelara(req, res, basePath, tail = '') {
    if (!ENABLE_VELARA) {
        return res.status(404).json({ error: 'velara integration disabled' });
    }
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

function normalizeGnMathHtmlPath(value) {
    const raw = String(value || '').trim();
    if (!raw) return '';

    let htmlPath = '';
    const placeholder = raw.match(/\{HTML_URL\}\/(.+?\.html?)(?:[?#].*)?$/i);
    if (placeholder && placeholder[1]) {
        htmlPath = placeholder[1];
    } else {
        try {
            const parsed = new URL(raw, GN_MATH_BASE);
            if (/^\/?html@main\//i.test(parsed.pathname)) {
                htmlPath = parsed.pathname.replace(/^\/?html@main\//i, '');
            }
        } catch {
            return '';
        }
    }

    const cleaned = htmlPath
        .replace(/^\/+/, '')
        .replace(/[?#].*$/, '')
        .replace(/\\/g, '/');
    if (!cleaned || cleaned.includes('..')) return '';
    if (!/\.html?$/i.test(cleaned)) return '';
    const file = cleaned.split('/').pop() || '';
    if (GN_MATH_BLOCKED_HTML_FILES.has(file.toLowerCase())) return '';
    return cleaned;
}

function buildGnMathCoverUrl(value) {
    const raw = String(value || '').trim();
    if (!raw) return '';
    if (raw.includes('{COVER_URL}')) {
        return raw.replace(/\{COVER_URL\}/g, GN_MATH_COVER_BASE.replace(/\/+$/, ''));
    }
    try {
        return new URL(raw, GN_MATH_COVER_BASE).href;
    } catch {
        return '';
    }
}

function encodePathForUrl(pathValue) {
    return String(pathValue || '')
        .split('/')
        .filter(Boolean)
        .map((segment) => encodeURIComponent(segment))
        .join('/');
}

function guessContentTypeFromPath(pathValue) {
    const ext = path.extname(String(pathValue || '').toLowerCase());
    switch (ext) {
        case '.html':
        case '.htm':
            return 'text/html; charset=utf-8';
        case '.js':
        case '.mjs':
            return 'application/javascript; charset=utf-8';
        case '.css':
            return 'text/css; charset=utf-8';
        case '.json':
            return 'application/json; charset=utf-8';
        case '.wasm':
            return 'application/wasm';
        case '.svg':
            return 'image/svg+xml';
        case '.png':
            return 'image/png';
        case '.jpg':
        case '.jpeg':
            return 'image/jpeg';
        case '.gif':
            return 'image/gif';
        case '.webp':
            return 'image/webp';
        case '.ico':
            return 'image/x-icon';
        case '.mp3':
            return 'audio/mpeg';
        case '.ogg':
            return 'audio/ogg';
        case '.wav':
            return 'audio/wav';
        default:
            return '';
    }
}

function normalizeTruffledCatalogHref(value) {
    const href = String(value || '').trim();
    if (!href) return '';

    let pathValue = href;
    if (/^(?:https?:)?\/\//i.test(pathValue)) {
        try {
            const parsed = new URL(pathValue.startsWith('//') ? `https:${pathValue}` : pathValue);
            if (!/(^|\.)truffled\.lol$/i.test(parsed.hostname)) return '';
            pathValue = String(parsed.pathname || '');
        } catch {
            return '';
        }
    }

    pathValue = pathValue.replace(/[?#].*$/, '').replace(/^\/+/, '');
    if (!pathValue) return '';

    try {
        pathValue = decodeURIComponent(pathValue);
    } catch {
    }

    if (!(pathValue.startsWith('games/') || pathValue.startsWith('gamefile/'))) return '';
    return pathValue;
}

function resolveTruffledMappedFile(rootMap, normalizedHref) {
    const direct = String(rootMap?.[normalizedHref] || '').trim().replace(/^\/+/, '');
    if (direct) return direct;

    const target = String(normalizedHref || '').replace(/[?#].*$/, '');
    if (!target) return '';

    for (const [rawKey, rawValue] of Object.entries(rootMap || {})) {
        const candidate = String(rawKey || '').replace(/[?#].*$/, '');
        if (candidate !== target) continue;
        const mapped = String(rawValue || '').trim().replace(/^\/+/, '');
        if (mapped) return mapped;
    }
    return '';
}

function deriveTruffledCanonicalSlug(inputHref, mappedFile = '') {
    const href = String(inputHref || '').trim().replace(/^\/+/, '').replace(/[?#].*$/, '');
    if (!href) return '';

    const gamesMatch = href.match(/^games\/([^/]+)\/index\.html$/i);
    if (gamesMatch && gamesMatch[1]) return String(gamesMatch[1]).toLowerCase();

    const gamefileMatch = href.match(/^gamefile\/(.+)\.html$/i);
    if (gamefileMatch && gamefileMatch[1]) {
        const segments = String(gamefileMatch[1]).split('/').filter(Boolean);
        const last = segments.length ? segments[segments.length - 1] : '';
        if (last) return last.toLowerCase();
    }

    const fileSlug = String(mappedFile || '').trim().replace(/\.html?$/i, '').toLowerCase();
    if (fileSlug) return fileSlug;

    return toTruffledLocalSlug(href).toLowerCase();
}

function deriveTruffledSlugCandidates(inputHref, mappedFile = '') {
    const out = new Set();
    const canonical = deriveTruffledCanonicalSlug(inputHref, mappedFile);
    if (canonical) out.add(canonical);

    const href = String(inputHref || '').trim().replace(/^\/+/, '').replace(/[?#].*$/, '');
    if (href) out.add(toTruffledLocalSlug(href).toLowerCase());

    const fileSlug = String(mappedFile || '').trim().replace(/\.html?$/i, '').toLowerCase();
    if (fileSlug) out.add(fileSlug);
    return out;
}

async function buildTruffledAliasMap() {
    let payload = null;
    try {
        const localRaw = await fs.readFile(TRUFFLED_LOCAL_JSON, 'utf8');
        payload = JSON.parse(localRaw);
    } catch {}

    if (!payload) {
        try {
            const response = await fetch(TRUFFLED_GAMES_JSON);
            if (response.ok) payload = await response.json();
        } catch {}
    }

    const rootMap = await readTruffledRootMap();
    const rows = Array.isArray(payload?.games) ? payload.games : [];
    const aliases = new Map();

    const sourceHrefs = rows.length
        ? rows.map((row) => normalizeTruffledCatalogHref(row?.url)).filter(Boolean)
        : Object.keys(rootMap).map((href) => normalizeTruffledCatalogHref(href)).filter(Boolean);

    for (const normalized of sourceHrefs) {
        const mappedFile = resolveTruffledMappedFile(rootMap, normalized);
        const targetUrl = new URL(normalized, TRUFFLED_BASE).href;
        const entry = { localFile: mappedFile, targetUrl };

        for (const rawSlug of deriveTruffledSlugCandidates(normalized, mappedFile)) {
            for (const slug of new Set([rawSlug, toLaunchSlug(rawSlug, '')])) {
                if (!slug) continue;
                const existing = aliases.get(slug);
                if (!existing || (!existing.localFile && entry.localFile)) {
                    aliases.set(slug, entry);
                }
            }
        }
    }

    return aliases;
}

async function getTruffledAliasMap() {
    const now = Date.now();
    if (truffledAliasCache.map.size > 0 && now < truffledAliasCache.expiresAt) {
        return truffledAliasCache.map;
    }

    const built = await buildTruffledAliasMap();
    truffledAliasCache = {
        map: built,
        expiresAt: now + TRUFFLED_ALIAS_CACHE_TTL_MS,
    };
    return truffledAliasCache.map;
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

function toLaunchSlug(input, fallback = 'game') {
    const slug = String(input || '')
        .trim()
        .toLowerCase()
        .replace(/\.html?$/i, '')
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');
    return slug || fallback;
}

function normalizePetezahSourceUrl(value) {
    let raw = String(value || '').trim();
    if (!raw) return '';

    if (!/^https?:\/\//i.test(raw) && /^[a-z0-9.-]+\.[a-z]{2,}(?:\/|$)/i.test(raw)) {
        raw = `https://${raw}`;
    }

    try {
        const parsed = new URL(raw, PETEZAH_BASE);
        if (!/^https?:$/i.test(parsed.protocol)) return '';

        const host = String(parsed.hostname || '').toLowerCase();
        const pathname = String(parsed.pathname || '');

        let gamePath = '';
        if (host === 'cdn.jsdelivr.net') {
            const match = pathname.match(/^\/gh\/PeteZah-Games\/PeteZahGames@[^/]+\/public\/(storage\/ag\/.+)$/i);
            if (match && match[1]) {
                gamePath = `/${match[1]}`;
            }
        } else if (host === 'petezahgames.com' || host.endsWith('.petezahgames.com')) {
            if (/^\/storage\/ag\/.+/i.test(pathname)) {
                gamePath = pathname;
            } else if (/^\/iframe\.html$/i.test(pathname)) {
                const inner = String(parsed.searchParams.get('url') || '').trim();
                if (inner) {
                    try {
                        const innerUrl = new URL(inner, PETEZAH_BASE);
                        if (/^https?:$/i.test(innerUrl.protocol)) {
                            return innerUrl.href;
                        }
                    } catch {
                    }
                }
            }
        }

        if (gamePath) {
            return new URL(gamePath, PETEZAH_BASE).href;
        }

        return parsed.href;
    } catch {
        return '';
    }
}

function normalizePetezahCoverUrl(value) {
    let raw = String(value || '').trim();
    if (!raw) return '';

    if (/^\/\//.test(raw)) raw = `https:${raw}`;
    if (!/^https?:\/\//i.test(raw) && /^[a-z0-9.-]+\.[a-z]{2,}(?:\/|$)/i.test(raw)) {
        raw = `https://${raw}`;
    }

    try {
        const parsed = new URL(raw, PETEZAH_BASE);
        if (!/^https?:$/i.test(parsed.protocol)) return '';
        return parsed.href;
    } catch {
        return '';
    }
}

function derivePetezahSlug(targetUrl, label, index) {
    let candidate = '';
    try {
        const parsed = new URL(targetUrl);
        if (/^\/iframe\.html$/i.test(String(parsed.pathname || ''))) {
            const inner = String(parsed.searchParams.get('url') || '').trim();
            if (inner) {
                try {
                    const innerParsed = new URL(inner, PETEZAH_BASE);
                    const innerSegments = String(innerParsed.pathname || '').replace(/\/+$/, '').split('/').filter(Boolean);
                    const innerLast = innerSegments.length ? innerSegments[innerSegments.length - 1] : '';
                    if (innerLast) {
                        candidate = /^index\.html?$/i.test(innerLast) && innerSegments.length > 1
                            ? String(innerSegments[innerSegments.length - 2] || '')
                            : String(innerLast).replace(/\.html?$/i, '');
                    }
                } catch {
                }
            }
        }
        const normalizedPath = String(parsed.pathname || '').replace(/\/+$/, '');
        const segments = normalizedPath.split('/').filter(Boolean);
        const last = segments.length ? segments[segments.length - 1] : '';
        if (!candidate && last) {
            if (/^index\.html?$/i.test(last) && segments.length > 1) {
                candidate = segments[segments.length - 2] || '';
            } else {
                candidate = String(last).replace(/\.html?$/i, '');
            }
        }
    } catch {
    }

    if (!candidate) candidate = String(label || '').trim();
    return toLaunchSlug(candidate, `game-${index + 1}`);
}

async function buildPetezahCatalogData() {
    let payload = null;
    let lastError = null;
    for (const sourceUrl of [PETEZAH_GAMES_JSON, PETEZAH_LEGACY_GAMES_JSON]) {
        try {
            const response = await fetch(sourceUrl);
            if (!response.ok) {
                lastError = new Error(`petezah fetch failed: ${response.status} @ ${sourceUrl}`);
                continue;
            }
            payload = await response.json();
            break;
        } catch (error) {
            lastError = error;
        }
    }
    if (!payload) {
        throw lastError || new Error('petezah fetch failed');
    }
    const rows = Array.isArray(payload?.games) ? payload.games : [];
    const items = [];
    const map = new Map();
    const usedSlugs = new Set();

    for (let index = 0; index < rows.length; index += 1) {
        const row = rows[index];
        const sourceUrl = String(row?.url || '').trim();
        const targetUrl = normalizePetezahSourceUrl(sourceUrl);
        if (!targetUrl) continue;

        const name = String(row?.label || '').trim() || `game ${index + 1}`;
        const cover = normalizePetezahCoverUrl(row?.imageUrl);
        const baseSlug = derivePetezahSlug(sourceUrl || targetUrl, name, index);
        let slug = baseSlug;
        let suffix = 2;
        while (usedSlugs.has(slug)) {
            slug = `${baseSlug}-${suffix}`;
            suffix += 1;
        }
        usedSlugs.add(slug);

        const item = {
            id: `petezah-${slug}`,
            name,
            url: `/pzlite/${encodeURIComponent(slug)}.html`,
            cover,
        };
        items.push(item);
        map.set(slug, {
            targetUrl,
            name,
            cover,
        });
    }

    items.sort((a, b) => a.name.localeCompare(b.name));
    return { items, map };
}

async function getPetezahCatalogData() {
    const now = Date.now();
    if (petezahCatalogCache.map.size > 0 && now < petezahCatalogCache.expiresAt) {
        return petezahCatalogCache;
    }

    try {
        const built = await buildPetezahCatalogData();
        petezahCatalogCache = {
            expiresAt: now + PETEZAH_CACHE_TTL_MS,
            items: built.items,
            map: built.map,
        };
        return petezahCatalogCache;
    } catch (error) {
        if (petezahCatalogCache.map.size > 0) return petezahCatalogCache;
        throw error;
    }
}

function normalizeDuckMathCatalogHref(value) {
    const href = String(value || '').trim();
    if (!href || /^javascript:/i.test(href) || /^data:/i.test(href)) return '';

    try {
        const parsed = new URL(href, DUCKMATH_BASE);
        if (!/^https?:$/i.test(parsed.protocol)) return '';
        return parsed.href;
    } catch {
        return '';
    }
}

function deriveDuckMathSlugSeed(targetUrl, name = '') {
    const fallback = toLaunchSlug(name, 'game');

    try {
        const parsed = new URL(String(targetUrl || '').trim());
        const segments = String(parsed.pathname || '')
            .split('/')
            .filter(Boolean)
            .map((segment) => {
                try {
                    return decodeURIComponent(segment);
                } catch {
                    return segment;
                }
            });
        if (!segments.length) return fallback;

        const clean = (value) => String(value || '')
            .trim()
            .toLowerCase()
            .replace(/\.[a-z0-9]+$/i, '')
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/^-+|-+$/g, '');

        const lastRaw = segments[segments.length - 1] || '';
        const prevRaw = segments.length > 1 ? segments[segments.length - 2] : '';
        const last = clean(lastRaw);
        const prev = clean(prevRaw);
        const hasExt = /\.[a-z0-9]+$/i.test(lastRaw);

        if (hasExt) {
            if (last === 'index' && prev) return `${prev}-index`;
            if (last && ['pre', 'embed', 'play', 'game'].includes(last) && prev) return `${prev}-${last}`;
            if (last) return last;
        } else {
            if (last && ['pre', 'embed', 'play', 'game'].includes(last) && prev) return `${prev}-${last}`;
            if (last && !['class', 'g4m3s'].includes(last)) return last;
            if (prev) return prev;
        }
    } catch {
    }

    return fallback;
}

function extractDuckMathBundlePath(html) {
    const source = String(html || '');
    const match = source.match(/<script[^>]*\bsrc\s*=\s*["']([^"']*\/assets\/index-[^"']+\.js)["'][^>]*>/i);
    if (!match || !match[1]) return '';
    try {
        return new URL(match[1], DUCKMATH_BASE).href;
    } catch {
        return '';
    }
}

function extractDuckMathEmbeddedGameUrl(html, pageUrl) {
    const iframeSrc = extractEmbeddedGameUrl(html, pageUrl);
    if (iframeSrc) return iframeSrc;

    const source = String(html || '');
    const patterns = [
        /<meta[^>]*http-equiv=["']refresh["'][^>]*content=["'][^"']*url=([^"';]+)[^"']*["']/i,
        /\b(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']/i,
        /\b(?:game|embed|iframe)(?:Url|URL|Src|SRC)\b[^:=]*[:=]\s*["']([^"']+)["']/i,
    ];

    for (const pattern of patterns) {
        const match = source.match(pattern);
        const candidate = String(match?.[1] || '').trim();
        if (!candidate || /^javascript:/i.test(candidate) || /^data:/i.test(candidate)) continue;
        try {
            const resolved = new URL(candidate, pageUrl).href;
            if (/^https?:\/\//i.test(resolved)) return resolved;
        } catch {
        }
    }

    return '';
}

async function resolveDuckMathLaunchTarget(pageUrl) {
    const targetPage = String(pageUrl || '').trim();
    if (!targetPage) return '';

    const now = Date.now();
    const cached = duckMathResolvedLaunchCache.get(targetPage);
    if (cached && now < Number(cached.expiresAt || 0)) {
        return String(cached.url || targetPage);
    }

    let resolved = targetPage;
    for (let i = 0; i < 2; i += 1) {
        try {
            const response = await fetch(resolved);
            if (!response.ok) break;
            const html = await response.text();
            const embedded = extractDuckMathEmbeddedGameUrl(html, resolved);
            if (!embedded || embedded === resolved) break;
            resolved = embedded;
        } catch {
            break;
        }
    }

    duckMathResolvedLaunchCache.set(targetPage, {
        url: resolved,
        expiresAt: now + DUCKMATH_RESOLVED_TTL_MS,
    });
    return resolved;
}

async function buildDuckMathCatalogData() {
    const response = await fetch(DUCKMATH_GAMES_PAGE);
    if (!response.ok) {
        throw new Error(`duckmath fetch failed: ${response.status}`);
    }

    const html = await response.text();
    const items = [];
    const map = new Map();
    const seenTargets = new Set();
    const usedSlugs = new Set();

    const pushRaw = (linkRaw, nameRaw = '', coverRaw = '') => {
        const targetUrl = normalizeDuckMathCatalogHref(linkRaw);
        if (!targetUrl) return;
        try {
            const parsed = new URL(targetUrl);
            if (/\.(mp4|webm|png|jpe?g|gif|webp|svg|mp3|wav|ogg)(?:$|\?)/i.test(parsed.pathname)) return;
        } catch {
        }
        const targetKey = targetUrl.toLowerCase();
        if (seenTargets.has(targetKey)) return;
        seenTargets.add(targetKey);

        let name = String(nameRaw || '').trim().replace(/\s+/g, ' ');
        if (!name) {
            try {
                const parsed = new URL(targetUrl);
                const last = parsed.pathname.split('/').filter(Boolean).pop() || parsed.hostname;
                name = humanizeFolderName(last.replace(/\.html?$/i, ''));
            } catch {
                name = 'DuckMath Game';
            }
        }

        let cover = '';
        const rawCover = String(coverRaw || '').trim();
        if (rawCover && !/^data:/i.test(rawCover)) {
            try {
                cover = new URL(rawCover, DUCKMATH_BASE).href;
            } catch {
                cover = '';
            }
        }

        const slugSeed = deriveDuckMathSlugSeed(targetUrl, name);
        const baseSlug = toLaunchSlug(slugSeed, toLaunchSlug(name, 'game'));
        let slug = baseSlug;
        let suffix = 2;
        while (usedSlugs.has(slug)) {
            slug = `${baseSlug}-${suffix}`;
            suffix += 1;
        }
        usedSlugs.add(slug);

        items.push({
            id: `duckmath-${slug}`,
            name,
            url: `/dkmath/${encodeURIComponent(slug)}.html`,
            cover,
        });
        map.set(slug, {
            targetUrl,
            name,
            cover,
        });
    };

    const bundlePath = extractDuckMathBundlePath(html);
    if (bundlePath) {
        try {
            const bundleResponse = await fetch(bundlePath);
            if (bundleResponse.ok) {
                const bundleText = await bundleResponse.text();
                const bundleRe = /(?:^|[,{])link:"([^"]+)"[\s\S]{0,1800}?title:"([^"]+)"[\s\S]{0,1200}?icon:"([^"]*)"/g;
                let match;
                while ((match = bundleRe.exec(bundleText)) !== null) {
                    pushRaw(match[1], match[2], match[3]);
                }
            }
        } catch {
        }
    }

    if (!items.length) {
        const htmlRe = /<a[^>]*href\s*=\s*["']([^"']+)["'][^>]*>[\s\S]*?<figcaption[^>]*>([^<]+)<\/figcaption>/gi;
        let match;
        while ((match = htmlRe.exec(html)) !== null) {
            pushRaw(match[1], match[2], '');
        }
    }

    items.sort((a, b) => a.name.localeCompare(b.name));
    return { items, map };
}

async function getDuckMathCatalogData() {
    const now = Date.now();
    if (duckMathCatalogCache.map.size > 0 && now < duckMathCatalogCache.expiresAt) {
        return duckMathCatalogCache;
    }

    try {
        const built = await buildDuckMathCatalogData();
        duckMathCatalogCache = {
            expiresAt: now + DUCKMATH_CACHE_TTL_MS,
            items: built.items,
            map: built.map,
        };
        return duckMathCatalogCache;
    } catch (error) {
        if (duckMathCatalogCache.map.size > 0) return duckMathCatalogCache;
        throw error;
    }
}

function pickCcportedCover(fileMap, dirPath) {
    const files = fileMap.get(dirPath);
    if (!files) return '';

    const preferredOrder = [
        'splash.png', 'splash.webp', 'splash.jpg', 'splash.jpeg',
        'cover.png', 'cover.webp', 'cover.jpg', 'cover.jpeg',
        'thumbnail.png', 'thumbnail.webp', 'thumbnail.jpg', 'thumbnail.jpeg',
        'icon.png', 'icon.webp', 'icon.jpg', 'icon.jpeg',
        'logo.png', 'logo.webp', 'logo.jpg', 'logo.jpeg',
    ];

    for (const name of preferredOrder) {
        const matchedPath = files.get(name);
        if (matchedPath) {
            return new URL(matchedPath, CCPORTED_RAW_BASE).href;
        }
    }

    for (const [name, matchedPath] of files.entries()) {
        if (/\.(png|jpe?g|webp|gif|ico)$/i.test(name)) {
            return new URL(matchedPath, CCPORTED_RAW_BASE).href;
        }
    }

    return '';
}

function decodeBasicHtmlEntities(value) {
    return String(value || '')
        .replace(/&amp;/gi, '&')
        .replace(/&quot;/gi, '"')
        .replace(/&#39;/gi, "'")
        .replace(/&lt;/gi, '<')
        .replace(/&gt;/gi, '>')
        .replace(/&#(\d+);/g, (_m, dec) => {
            const codePoint = Number.parseInt(dec, 10);
            if (!Number.isFinite(codePoint)) return '';
            try {
                return String.fromCodePoint(codePoint);
            } catch {
                return '';
            }
        })
        .replace(/&#x([0-9a-f]+);/gi, (_m, hex) => {
            const codePoint = Number.parseInt(hex, 16);
            if (!Number.isFinite(codePoint)) return '';
            try {
                return String.fromCodePoint(codePoint);
            } catch {
                return '';
            }
        });
}

function normalizeCcportedGameName(value) {
    let name = decodeBasicHtmlEntities(value).replace(/\s+/g, ' ').trim();
    if (!name) return '';
    name = name.replace(CCPORTED_TITLE_SUFFIX_RE, '').trim();
    name = name.replace(/^play\s+/i, '').trim();
    name = name.replace(/\s*\|\s*CCPorted\s*$/i, '').trim();
    if (!name) return '';
    if (/^(index|home|ccported)$/i.test(name)) return '';
    if (/^game[-_\s0-9a-f]+$/i.test(name)) return '';
    return name;
}

async function mapWithConcurrency(items, concurrency, mapper) {
    const list = Array.isArray(items) ? items : [];
    if (!list.length) return [];

    const safeConcurrency = Math.max(1, Math.min(Number(concurrency) || 1, list.length));
    const output = new Array(list.length);
    let cursor = 0;

    const workers = Array.from({ length: safeConcurrency }, async () => {
        while (true) {
            const index = cursor;
            cursor += 1;
            if (index >= list.length) return;
            output[index] = await mapper(list[index], index);
        }
    });
    await Promise.all(workers);
    return output;
}

async function fetchCcportedMetadataName(fileMap, dirPath) {
    const files = fileMap.get(dirPath);
    const metadataPath = files?.get('ccported_game_data.json');
    if (!metadataPath) return '';

    try {
        const response = await fetch(new URL(metadataPath, CCPORTED_RAW_BASE), {
            headers: {
                'accept': 'application/json',
                'user-agent': 'rift-ccported-catalog',
            },
        });
        if (!response.ok) return '';
        const payload = await response.json();
        if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return '';

        const candidate = payload.name || payload.title || payload.displayName || payload.game || '';
        return normalizeCcportedGameName(candidate);
    } catch {
        return '';
    }
}

async function fetchCcportedHtmlTitle(entryPath) {
    try {
        const response = await fetch(new URL(entryPath, CCPORTED_RAW_BASE), {
            headers: {
                'accept': 'text/html,application/xhtml+xml',
                'range': 'bytes=0-262143',
                'user-agent': 'rift-ccported-catalog',
            },
        });
        if (!response.ok) return '';
        const html = await response.text();
        const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
        if (!titleMatch || !titleMatch[1]) return '';
        const rawTitle = String(titleMatch[1]).replace(/<[^>]+>/g, ' ');
        return normalizeCcportedGameName(rawTitle);
    } catch {
        return '';
    }
}

async function fetchCcportedManifestName(fileMap, dirPath) {
    const files = fileMap.get(dirPath);
    if (!files) return '';

    const manifestNames = ['appmanifest.json', 'manifest.json', 'site.webmanifest'];
    for (const manifestName of manifestNames) {
        const manifestPath = files.get(manifestName);
        if (!manifestPath) continue;

        try {
            const response = await fetch(new URL(manifestPath, CCPORTED_RAW_BASE), {
                headers: {
                    'accept': 'application/json',
                    'user-agent': 'rift-ccported-catalog',
                },
            });
            if (!response.ok) continue;
            const payload = await response.json();
            if (!payload || typeof payload !== 'object' || Array.isArray(payload)) continue;

            const candidate = payload.name || payload.short_name || payload.title || payload.displayName || '';
            const normalized = normalizeCcportedGameName(candidate);
            if (normalized) return normalized;
        } catch {
            continue;
        }
    }

    return '';
}

async function resolveCcportedDisplayName(entry, fileMap) {
    const entryPath = String(entry?.entryPath || '').trim();
    const cacheKey = entryPath.toLowerCase();
    if (cacheKey && ccportedNameCache.has(cacheKey)) {
        return ccportedNameCache.get(cacheKey);
    }

    let name = await fetchCcportedMetadataName(fileMap, entry?.dirPath);
    if (!name) {
        name = await fetchCcportedHtmlTitle(entryPath);
    }
    if (!name) {
        name = await fetchCcportedManifestName(fileMap, entry?.dirPath);
    }
    if (!name) {
        const dirName = path.posix.basename(entry?.dirPath || '') || String(entry?.dirPath || '');
        name = humanizeFolderName(String(dirName || '').replace(/^game_[0-9a-f]{4}_/i, ''));
    }

    if (cacheKey) ccportedNameCache.set(cacheKey, name);
    return name;
}

async function buildCcportedCatalogData() {
    const response = await fetch(CCPORTED_TREE_API, {
        headers: {
            'accept': 'application/vnd.github+json',
            'user-agent': 'rift-ccported-catalog',
        },
    });
    if (!response.ok) {
        throw new Error(`ccported fetch failed: ${response.status}`);
    }

    const payload = await response.json();
    const rows = Array.isArray(payload?.tree) ? payload.tree : [];

    const fileMap = new Map();
    for (const row of rows) {
        if (!row || row.type !== 'blob') continue;
        const filePath = String(row.path || '').replace(/^\/+/, '').trim();
        if (!filePath || filePath.includes('..')) continue;
        const dirPath = path.posix.dirname(filePath);
        const fileName = path.posix.basename(filePath).toLowerCase();
        if (!fileMap.has(dirPath)) fileMap.set(dirPath, new Map());
        fileMap.get(dirPath).set(fileName, filePath);
    }

    const preferredEntries = new Map();
    for (const row of rows) {
        if (!row || row.type !== 'blob') continue;
        const filePath = String(row.path || '').replace(/^\/+/, '').trim();
        if (!filePath || filePath.includes('..')) continue;
        const lower = filePath.toLowerCase();
        const topLevelGameMatch = lower.match(/^([^/]+)\/game\.html$/i);
        if (topLevelGameMatch && topLevelGameMatch[1]) {
            const dirPath = topLevelGameMatch[1];
            preferredEntries.set(dirPath, {
                entryPath: filePath,
                dirPath,
                source: 'game',
            });
            continue;
        }

        const topLevelIndexMatch = lower.match(/^([^/]+)\/index\.html$/i);
        if (topLevelIndexMatch && topLevelIndexMatch[1]) {
            const dirPath = topLevelIndexMatch[1];
            if (!preferredEntries.has(dirPath)) {
                preferredEntries.set(dirPath, {
                    entryPath: filePath,
                    dirPath,
                    source: 'index',
                });
            }
        }
    }

    const gameEntries = Array.from(preferredEntries.values());
    const resolvedNames = await mapWithConcurrency(
        gameEntries,
        10,
        async (entry) => await resolveCcportedDisplayName(entry, fileMap)
    );

    const items = [];
    const map = new Map();
    const usedSlugs = new Set();
    const seenEntryPaths = new Set();

    for (let index = 0; index < gameEntries.length; index += 1) {
        const entry = gameEntries[index];
        const entryKey = String(entry.entryPath || '').toLowerCase();
        if (!entryKey || seenEntryPaths.has(entryKey)) continue;
        seenEntryPaths.add(entryKey);

        const dirName = path.posix.basename(entry.dirPath || '') || entry.dirPath;
        const fallbackName = humanizeFolderName(String(dirName || '').replace(/\.[a-z0-9]+$/i, ''));
        const name = normalizeCcportedGameName(resolvedNames[index]) || fallbackName;
        const preferredBaseSlug = toLaunchSlug(name, toLaunchSlug(dirName, 'game'));
        const legacyBaseSlug = toLaunchSlug(dirName, preferredBaseSlug);
        let slug = preferredBaseSlug;
        let suffix = 2;
        while (usedSlugs.has(slug)) {
            slug = `${preferredBaseSlug}-${suffix}`;
            suffix += 1;
        }
        usedSlugs.add(slug);

        const cover = pickCcportedCover(fileMap, entry.dirPath);
        const mappedEntry = {
            entryPath: entry.entryPath,
            dirPath: entry.dirPath,
            source: entry.source,
            name,
            cover,
        };
        items.push({
            id: `ccported-${slug}`,
            name,
            url: `/ccptd/${encodeURIComponent(slug)}.html`,
            cover,
        });
        map.set(slug, mappedEntry);
        if (legacyBaseSlug && legacyBaseSlug !== slug && !map.has(legacyBaseSlug)) {
            map.set(legacyBaseSlug, mappedEntry);
        }
    }

    items.sort((a, b) => a.name.localeCompare(b.name));
    return { items, map };
}

async function getCcportedCatalogData() {
    const now = Date.now();
    if (ccportedCatalogCache.map.size > 0 && now < ccportedCatalogCache.expiresAt) {
        return ccportedCatalogCache;
    }

    try {
        const built = await buildCcportedCatalogData();
        ccportedCatalogCache = {
            expiresAt: now + CCPORTED_CACHE_TTL_MS,
            items: built.items,
            map: built.map,
        };
        return ccportedCatalogCache;
    } catch (error) {
        if (ccportedCatalogCache.map.size > 0) return ccportedCatalogCache;
        throw error;
    }
}

function pickUgsCover(fileMap, dirPath) {
    const files = fileMap.get(dirPath);
    if (!files) return '';

    const preferredOrder = [
        'splash.png', 'splash.webp', 'splash.jpg', 'splash.jpeg',
        'cover.png', 'cover.webp', 'cover.jpg', 'cover.jpeg',
        'thumbnail.png', 'thumbnail.webp', 'thumbnail.jpg', 'thumbnail.jpeg',
        'thumb.png', 'thumb.webp', 'thumb.jpg', 'thumb.jpeg',
        'icon.png', 'icon.webp', 'icon.jpg', 'icon.jpeg',
        'logo.png', 'logo.webp', 'logo.jpg', 'logo.jpeg',
    ];

    for (const name of preferredOrder) {
        const matchedPath = files.get(name);
        if (matchedPath) {
            return new URL(matchedPath, UGS_RAW_BASE).href;
        }
    }

    for (const [name, matchedPath] of files.entries()) {
        if (/\.(png|jpe?g|webp|gif|ico)$/i.test(name)) {
            return new URL(matchedPath, UGS_RAW_BASE).href;
        }
    }

    return '';
}

async function buildUgsCatalogData() {
    const response = await fetch(UGS_TREE_API, {
        headers: {
            'accept': 'application/vnd.github+json',
            'user-agent': 'rift-ugs-catalog',
        },
    });
    if (!response.ok) {
        throw new Error(`ugs fetch failed: ${response.status}`);
    }

    const payload = await response.json();
    const rows = Array.isArray(payload?.tree) ? payload.tree : [];

    const fileMap = new Map();
    for (const row of rows) {
        if (!row || row.type !== 'blob') continue;
        const filePath = String(row.path || '').replace(/^\/+/, '').trim();
        if (!filePath || filePath.includes('..')) continue;
        const dirPath = path.posix.dirname(filePath);
        const fileName = path.posix.basename(filePath).toLowerCase();
        if (!fileMap.has(dirPath)) fileMap.set(dirPath, new Map());
        fileMap.get(dirPath).set(fileName, filePath);
    }

    const preferredEntries = new Map();
    for (const row of rows) {
        if (!row || row.type !== 'blob') continue;
        const filePath = String(row.path || '').replace(/^\/+/, '').trim();
        if (!filePath || filePath.includes('..')) continue;
        const lower = filePath.toLowerCase();
        const topLevelGameMatch = lower.match(/^([^/]+)\/game\.html$/i);
        if (topLevelGameMatch && topLevelGameMatch[1]) {
            const dirPath = topLevelGameMatch[1];
            preferredEntries.set(dirPath, {
                entryPath: filePath,
                dirPath,
                source: 'game',
            });
            continue;
        }

        const topLevelIndexMatch = lower.match(/^([^/]+)\/index\.html$/i);
        if (topLevelIndexMatch && topLevelIndexMatch[1]) {
            const dirPath = topLevelIndexMatch[1];
            if (!preferredEntries.has(dirPath)) {
                preferredEntries.set(dirPath, {
                    entryPath: filePath,
                    dirPath,
                    source: 'index',
                });
            }
        }
    }

    const items = [];
    const map = new Map();
    const usedSlugs = new Set();

    for (const entry of preferredEntries.values()) {
        const dirName = path.posix.basename(entry.dirPath || '') || entry.dirPath;
        const name = humanizeFolderName(String(dirName || '').replace(/\.[a-z0-9]+$/i, ''));
        const baseSlug = toLaunchSlug(name, toLaunchSlug(dirName, 'game'));
        let slug = baseSlug;
        let suffix = 2;
        while (usedSlugs.has(slug)) {
            slug = `${baseSlug}-${suffix}`;
            suffix += 1;
        }
        usedSlugs.add(slug);

        const cover = pickUgsCover(fileMap, entry.dirPath);
        const mappedEntry = {
            entryPath: entry.entryPath,
            dirPath: entry.dirPath,
            source: entry.source,
            name,
            cover,
        };
        items.push({
            id: `ugs-${slug}`,
            name,
            url: `/ugs/${encodeURIComponent(slug)}.html`,
            cover,
        });
        map.set(slug, mappedEntry);
    }

    items.sort((a, b) => a.name.localeCompare(b.name));
    return { items, map };
}

async function getUgsCatalogData() {
    const now = Date.now();
    if (ugsCatalogCache.map.size > 0 && now < ugsCatalogCache.expiresAt) {
        return ugsCatalogCache;
    }

    try {
        const built = await buildUgsCatalogData();
        ugsCatalogCache = {
            expiresAt: now + UGS_CACHE_TTL_MS,
            items: built.items,
            map: built.map,
        };
        return ugsCatalogCache;
    } catch (error) {
        if (ugsCatalogCache.map.size > 0) return ugsCatalogCache;
        throw error;
    }
}

function pickSeleniteCover(fileMap, dirPath) {
    const files = fileMap.get(dirPath);
    if (!files) return '';

    const preferredOrder = [
        'splash.png', 'splash.webp', 'splash.jpg', 'splash.jpeg',
        'cover.png', 'cover.webp', 'cover.jpg', 'cover.jpeg',
        'thumbnail.png', 'thumbnail.webp', 'thumbnail.jpg', 'thumbnail.jpeg',
        'thumb.png', 'thumb.webp', 'thumb.jpg', 'thumb.jpeg',
        'icon.png', 'icon.webp', 'icon.jpg', 'icon.jpeg',
        'logo.png', 'logo.webp', 'logo.jpg', 'logo.jpeg',
    ];

    for (const name of preferredOrder) {
        const matchedPath = files.get(name);
        if (matchedPath) {
            return new URL(matchedPath, SELENITE_RAW_BASE).href;
        }
    }

    for (const [name, matchedPath] of files.entries()) {
        if (/\.(png|jpe?g|webp|gif|ico)$/i.test(name)) {
            return new URL(matchedPath, SELENITE_RAW_BASE).href;
        }
    }

    return '';
}

async function buildSeleniteCatalogData() {
    const response = await fetch(SELENITE_TREE_API, {
        headers: {
            'accept': 'application/vnd.github+json',
            'user-agent': 'rift-selenite-catalog',
        },
    });
    if (!response.ok) {
        throw new Error(`selenite fetch failed: ${response.status}`);
    }

    const payload = await response.json();
    const rows = Array.isArray(payload?.tree) ? payload.tree : [];

    const fileMap = new Map();
    for (const row of rows) {
        if (!row || row.type !== 'blob') continue;
        const filePath = String(row.path || '').replace(/^\/+/, '').trim();
        if (!filePath || filePath.includes('..')) continue;
        const dirPath = path.posix.dirname(filePath);
        const fileName = path.posix.basename(filePath).toLowerCase();
        if (!fileMap.has(dirPath)) fileMap.set(dirPath, new Map());
        fileMap.get(dirPath).set(fileName, filePath);
    }

    const preferredEntries = new Map();
    for (const row of rows) {
        if (!row || row.type !== 'blob') continue;
        const filePath = String(row.path || '').replace(/^\/+/, '').trim();
        if (!filePath || filePath.includes('..')) continue;
        const lower = filePath.toLowerCase();
        const topLevelGameMatch = lower.match(/^([^/]+)\/game\.html$/i);
        if (topLevelGameMatch && topLevelGameMatch[1]) {
            const dirPath = topLevelGameMatch[1];
            preferredEntries.set(dirPath, {
                entryPath: filePath,
                dirPath,
                source: 'game',
            });
            continue;
        }

        const topLevelIndexMatch = lower.match(/^([^/]+)\/index\.html$/i);
        if (topLevelIndexMatch && topLevelIndexMatch[1]) {
            const dirPath = topLevelIndexMatch[1];
            if (!preferredEntries.has(dirPath)) {
                preferredEntries.set(dirPath, {
                    entryPath: filePath,
                    dirPath,
                    source: 'index',
                });
            }
        }
    }

    const items = [];
    const map = new Map();
    const usedSlugs = new Set();

    for (const entry of preferredEntries.values()) {
        const dirName = path.posix.basename(entry.dirPath || '') || entry.dirPath;
        const name = humanizeFolderName(String(dirName || '').replace(/\.[a-z0-9]+$/i, ''));
        const baseSlug = toLaunchSlug(name, toLaunchSlug(dirName, 'game'));
        let slug = baseSlug;
        let suffix = 2;
        while (usedSlugs.has(slug)) {
            slug = `${baseSlug}-${suffix}`;
            suffix += 1;
        }
        usedSlugs.add(slug);

        const cover = pickSeleniteCover(fileMap, entry.dirPath);
        const mappedEntry = {
            entryPath: entry.entryPath,
            dirPath: entry.dirPath,
            source: entry.source,
            name,
            cover,
        };
        items.push({
            id: `selenite-${slug}`,
            name,
            url: `/slnte/${encodeURIComponent(slug)}.html`,
            cover,
        });
        map.set(slug, mappedEntry);
    }

    items.sort((a, b) => a.name.localeCompare(b.name));
    return { items, map };
}

async function getSeleniteCatalogData() {
    const now = Date.now();
    if (seleniteCatalogCache.map.size > 0 && now < seleniteCatalogCache.expiresAt) {
        return seleniteCatalogCache;
    }

    try {
        const built = await buildSeleniteCatalogData();
        seleniteCatalogCache = {
            expiresAt: now + SELENITE_CACHE_TTL_MS,
            items: built.items,
            map: built.map,
        };
        return seleniteCatalogCache;
    } catch (error) {
        if (seleniteCatalogCache.map.size > 0) return seleniteCatalogCache;
        throw error;
    }
}

function pickRadonCover(fileMap, dirPath, imageStemMap) {
    const files = fileMap.get(dirPath);
    if (files) {
        const preferredOrder = [
            'splash.png', 'splash.webp', 'splash.jpg', 'splash.jpeg',
            'cover.png', 'cover.webp', 'cover.jpg', 'cover.jpeg',
            'thumbnail.png', 'thumbnail.webp', 'thumbnail.jpg', 'thumbnail.jpeg',
            'thumb.png', 'thumb.webp', 'thumb.jpg', 'thumb.jpeg',
            'icon.png', 'icon.webp', 'icon.jpg', 'icon.jpeg',
            'logo.png', 'logo.webp', 'logo.jpg', 'logo.jpeg',
        ];

        for (const name of preferredOrder) {
            const matchedPath = files.get(name);
            if (matchedPath) {
                return new URL(matchedPath, RADON_RAW_BASE).href;
            }
        }
    }

    const dirName = path.posix.basename(dirPath || '').toLowerCase();
    const stemCandidates = [
        dirName,
        dirName.replace(/_/g, '-'),
        dirName.replace(/-/g, '_'),
    ];
    for (const stem of stemCandidates) {
        const matchedPath = imageStemMap.get(stem);
        if (matchedPath) {
            return new URL(matchedPath, RADON_RAW_BASE).href;
        }
    }

    return '';
}

async function buildRadonCatalogData() {
    const response = await fetch(RADON_TREE_API, {
        headers: {
            'accept': 'application/vnd.github+json',
            'user-agent': 'rift-radon-catalog',
        },
    });
    if (!response.ok) {
        throw new Error(`radon fetch failed: ${response.status}`);
    }

    const payload = await response.json();
    const rows = Array.isArray(payload?.tree) ? payload.tree : [];

    const fileMap = new Map();
    const imageStemMap = new Map();
    for (const row of rows) {
        if (!row || row.type !== 'blob') continue;
        const filePath = String(row.path || '').replace(/^\/+/, '').trim();
        if (!filePath || filePath.includes('..')) continue;

        const dirPath = path.posix.dirname(filePath);
        const fileName = path.posix.basename(filePath).toLowerCase();
        if (!fileMap.has(dirPath)) fileMap.set(dirPath, new Map());
        fileMap.get(dirPath).set(fileName, filePath);

        if (/^images\/[^/]+\.(png|jpe?g|webp|gif|ico)$/i.test(filePath)) {
            const stem = path.posix.basename(filePath).replace(/\.[^.]+$/, '').toLowerCase();
            if (stem && !imageStemMap.has(stem)) {
                imageStemMap.set(stem, filePath);
            }
        }
    }

    const preferredEntries = new Map();
    for (const row of rows) {
        if (!row || row.type !== 'blob') continue;
        const filePath = String(row.path || '').replace(/^\/+/, '').trim();
        if (!filePath || filePath.includes('..')) continue;
        const lower = filePath.toLowerCase();

        const topLevelGameMatch = lower.match(/^html\/([^/]+)\/game\.html$/i);
        if (topLevelGameMatch && topLevelGameMatch[1]) {
            const folderName = topLevelGameMatch[1];
            preferredEntries.set(folderName, {
                entryPath: filePath,
                dirPath: `html/${folderName}`,
                source: 'game',
            });
            continue;
        }

        const topLevelIndexMatch = lower.match(/^html\/([^/]+)\/index\.html$/i);
        if (topLevelIndexMatch && topLevelIndexMatch[1]) {
            const folderName = topLevelIndexMatch[1];
            if (!preferredEntries.has(folderName)) {
                preferredEntries.set(folderName, {
                    entryPath: filePath,
                    dirPath: `html/${folderName}`,
                    source: 'index',
                });
            }
        }
    }

    const items = [];
    const map = new Map();
    const usedSlugs = new Set();

    for (const entry of preferredEntries.values()) {
        const dirName = path.posix.basename(entry.dirPath || '') || entry.dirPath;
        const name = humanizeFolderName(String(dirName || '').replace(/\.[a-z0-9]+$/i, ''));
        const baseSlug = toLaunchSlug(name, toLaunchSlug(dirName, 'game'));
        let slug = baseSlug;
        let suffix = 2;
        while (usedSlugs.has(slug)) {
            slug = `${baseSlug}-${suffix}`;
            suffix += 1;
        }
        usedSlugs.add(slug);

        const cover = pickRadonCover(fileMap, entry.dirPath, imageStemMap);
        const mappedEntry = {
            entryPath: entry.entryPath,
            dirPath: entry.dirPath,
            source: entry.source,
            name,
            cover,
        };
        items.push({
            id: `radon-${slug}`,
            name,
            url: `/rdn/${encodeURIComponent(slug)}.html`,
            cover,
        });
        map.set(slug, mappedEntry);
    }

    items.sort((a, b) => a.name.localeCompare(b.name));
    return { items, map };
}

async function getRadonCatalogData() {
    const now = Date.now();
    if (radonCatalogCache.map.size > 0 && now < radonCatalogCache.expiresAt) {
        return radonCatalogCache;
    }

    try {
        const built = await buildRadonCatalogData();
        radonCatalogCache = {
            expiresAt: now + RADON_CACHE_TTL_MS,
            items: built.items,
            map: built.map,
        };
        return radonCatalogCache;
    } catch (error) {
        if (radonCatalogCache.map.size > 0) return radonCatalogCache;
        throw error;
    }
}

function pickFyinxCover(fileMap, dirPath) {
    const files = fileMap.get(dirPath);
    if (!files) return '';

    const preferredOrder = [
        'splash.png', 'splash.webp', 'splash.jpg', 'splash.jpeg',
        'cover.png', 'cover.webp', 'cover.jpg', 'cover.jpeg',
        'thumbnail.png', 'thumbnail.webp', 'thumbnail.jpg', 'thumbnail.jpeg',
        'thumb.png', 'thumb.webp', 'thumb.jpg', 'thumb.jpeg',
        'icon.png', 'icon.webp', 'icon.jpg', 'icon.jpeg',
        'logo.png', 'logo.webp', 'logo.jpg', 'logo.jpeg',
    ];

    for (const name of preferredOrder) {
        const matchedPath = files.get(name);
        if (matchedPath) {
            return new URL(matchedPath, FYINX_RAW_BASE).href;
        }
    }

    for (const [name, matchedPath] of files.entries()) {
        if (/\.(png|jpe?g|webp|gif|ico)$/i.test(name)) {
            return new URL(matchedPath, FYINX_RAW_BASE).href;
        }
    }

    return '';
}

async function buildFyinxCatalogData() {
    const response = await fetch(FYINX_TREE_API, {
        headers: {
            'accept': 'application/vnd.github+json',
            'user-agent': 'rift-fyinx-catalog',
        },
    });
    if (!response.ok) {
        throw new Error(`fyinx fetch failed: ${response.status}`);
    }

    const payload = await response.json();
    const rows = Array.isArray(payload?.tree) ? payload.tree : [];

    const fileMap = new Map();
    for (const row of rows) {
        if (!row || row.type !== 'blob') continue;
        const filePath = String(row.path || '').replace(/^\/+/, '').trim();
        if (!filePath || filePath.includes('..')) continue;
        const dirPath = path.posix.dirname(filePath);
        const fileName = path.posix.basename(filePath).toLowerCase();
        if (!fileMap.has(dirPath)) fileMap.set(dirPath, new Map());
        fileMap.get(dirPath).set(fileName, filePath);
    }

    const preferredEntries = new Map();
    for (const row of rows) {
        if (!row || row.type !== 'blob') continue;
        const filePath = String(row.path || '').replace(/^\/+/, '').trim();
        if (!filePath || filePath.includes('..')) continue;
        const lower = filePath.toLowerCase();

        const topLevelGameMatch = lower.match(/^g\/([^/]+)\/game\.html$/i);
        if (topLevelGameMatch && topLevelGameMatch[1]) {
            const folderName = topLevelGameMatch[1];
            preferredEntries.set(folderName, {
                entryPath: filePath,
                dirPath: `g/${folderName}`,
                source: 'game',
            });
            continue;
        }

        const topLevelIndexMatch = lower.match(/^g\/([^/]+)\/index\.html$/i);
        if (topLevelIndexMatch && topLevelIndexMatch[1]) {
            const folderName = topLevelIndexMatch[1];
            if (!preferredEntries.has(folderName)) {
                preferredEntries.set(folderName, {
                    entryPath: filePath,
                    dirPath: `g/${folderName}`,
                    source: 'index',
                });
            }
        }
    }

    const items = [];
    const map = new Map();
    const usedSlugs = new Set();

    for (const entry of preferredEntries.values()) {
        const dirName = path.posix.basename(entry.dirPath || '') || entry.dirPath;
        const name = humanizeFolderName(String(dirName || '').replace(/\.[a-z0-9]+$/i, ''));
        const baseSlug = toLaunchSlug(name, toLaunchSlug(dirName, 'game'));
        let slug = baseSlug;
        let suffix = 2;
        while (usedSlugs.has(slug)) {
            slug = `${baseSlug}-${suffix}`;
            suffix += 1;
        }
        usedSlugs.add(slug);

        const cover = pickFyinxCover(fileMap, entry.dirPath);
        const mappedEntry = {
            entryPath: entry.entryPath,
            dirPath: entry.dirPath,
            source: entry.source,
            name,
            cover,
        };
        items.push({
            id: `fyinx-${slug}`,
            name,
            url: `/fyinx/${encodeURIComponent(slug)}.html`,
            cover,
        });
        map.set(slug, mappedEntry);
    }

    items.sort((a, b) => a.name.localeCompare(b.name));
    return { items, map };
}

async function getFyinxCatalogData() {
    const now = Date.now();
    if (fyinxCatalogCache.map.size > 0 && now < fyinxCatalogCache.expiresAt) {
        return fyinxCatalogCache;
    }

    try {
        const built = await buildFyinxCatalogData();
        fyinxCatalogCache = {
            expiresAt: now + FYINX_CACHE_TTL_MS,
            items: built.items,
            map: built.map,
        };
        return fyinxCatalogCache;
    } catch (error) {
        if (fyinxCatalogCache.map.size > 0) return fyinxCatalogCache;
        throw error;
    }
}

function asEliteHtml(raw) {
    const source = String(raw || '');
    const cdataMatch = source.match(/<content\b[^>]*>\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*<\/content>/i);
    let html = cdataMatch && cdataMatch[1] ? String(cdataMatch[1]).trim() : source.trim();

    const hasHtmlTag = /<html\b/i.test(html);
    if (!hasHtmlTag) {
        html = `<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body><pre>${html.replace(/[<&>]/g, (m) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[m] || m))}</pre></body></html>`;
    }

    if (/<head\b[^>]*>/i.test(html)) {
        const baseTag = `<base href="${ELITE_RAW_BASE}">`;
        html = html.replace(/<head\b[^>]*>/i, (match) => `${match}${baseTag}`);
    } else if (/<html\b[^>]*>/i.test(html)) {
        html = html.replace(/<html\b[^>]*>/i, (match) => `${match}<head><base href="${ELITE_RAW_BASE}"></head>`);
    }

    return html;
}

async function buildEliteCatalogData() {
    const response = await fetch(ELITE_TREE_API, {
        headers: {
            'accept': 'application/vnd.github+json',
            'user-agent': 'rift-elite-catalog',
        },
    });
    if (!response.ok) {
        throw new Error(`elite fetch failed: ${response.status}`);
    }

    const payload = await response.json();
    const rows = Array.isArray(payload?.tree) ? payload.tree : [];

    const items = [];
    const map = new Map();
    const usedSlugs = new Set();

    for (const row of rows) {
        if (!row || row.type !== 'blob') continue;
        const filePath = String(row.path || '').replace(/^\/+/, '').trim();
        if (!filePath || filePath.includes('/') || filePath.includes('..')) continue;
        const isXml = /\.xml$/i.test(filePath);
        const isNoExt = !/\.[a-z0-9]+$/i.test(filePath);
        if (!isXml && !isNoExt) continue;

        const rawName = String(filePath).replace(/\.xml$/i, '').replace(/\s+/g, ' ').trim();
        const name = rawName || `Game ${items.length + 1}`;
        const baseSlug = toLaunchSlug(rawName, `game-${items.length + 1}`);
        let slug = baseSlug;
        let suffix = 2;
        while (usedSlugs.has(slug)) {
            slug = `${baseSlug}-${suffix}`;
            suffix += 1;
        }
        usedSlugs.add(slug);

        const mappedEntry = {
            entryPath: filePath,
            name,
            cover: '',
        };
        items.push({
            id: `elite-${slug}`,
            name,
            url: `/eltgmz/${encodeURIComponent(slug)}.html`,
            cover: '',
        });
        map.set(slug, mappedEntry);
    }

    items.sort((a, b) => a.name.localeCompare(b.name));
    return { items, map };
}

async function getEliteCatalogData() {
    const now = Date.now();
    if (eliteCatalogCache.map.size > 0 && now < eliteCatalogCache.expiresAt) {
        return eliteCatalogCache;
    }

    try {
        const built = await buildEliteCatalogData();
        eliteCatalogCache = {
            expiresAt: now + ELITE_CACHE_TTL_MS,
            items: built.items,
            map: built.map,
        };
        return eliteCatalogCache;
    } catch (error) {
        if (eliteCatalogCache.map.size > 0) return eliteCatalogCache;
        throw error;
    }
}

function normalizeTotallyScienceSourceSlug(value) {
    return String(value || '')
        .trim()
        .replace(/^\.?\//, '')
        .replace(/^\/+/, '')
        .replace(/\/+$/, '')
        .replace(/\\/g, '/');
}

function extractEmbeddedGameUrl(html, pageUrl) {
    const source = String(html || '');
    const tags = source.match(/<iframe\b[^>]*>/gi) || [];
    let fallbackSrc = '';

    for (const tag of tags) {
        const srcMatch = tag.match(/\bsrc\s*=\s*["']([^"']+)["']/i);
        if (!srcMatch || !srcMatch[1]) continue;
        const srcRaw = String(srcMatch[1]).trim();
        if (!srcRaw || /^javascript:/i.test(srcRaw) || /^data:/i.test(srcRaw)) continue;

        const idMatch = tag.match(/\bid\s*=\s*["']([^"']+)["']/i);
        const idValue = String(idMatch?.[1] || '').trim().toLowerCase();
        if (!fallbackSrc) fallbackSrc = srcRaw;
        if (idValue === 'gameframe') {
            fallbackSrc = srcRaw;
            break;
        }
    }

    if (!fallbackSrc) return '';
    try {
        const resolved = new URL(fallbackSrc, pageUrl).href;
        return /^https?:\/\//i.test(resolved) ? resolved : '';
    } catch {
        return '';
    }
}

function extractTotallyScienceEmbeddedGameUrl(html, pageUrl) {
    return extractEmbeddedGameUrl(html, pageUrl);
}

function extractVelaraEmbeddedGameUrl(html, pageUrl) {
    const iframeSrc = extractEmbeddedGameUrl(html, pageUrl);
    if (iframeSrc) return iframeSrc;

    const source = String(html || '');
    const patterns = [
        /\bdata-game-url\s*=\s*["']([^"']+)["']/i,
        /\bgame(?:Url|URL)\b[^:=]*[:=]\s*["']([^"']+)["']/i,
        /\bsource(?:Url|URL)\b[^:=]*[:=]\s*["']([^"']+)["']/i,
    ];

    for (const pattern of patterns) {
        const match = source.match(pattern);
        const candidate = String(match?.[1] || '').trim();
        if (!candidate || /^javascript:/i.test(candidate) || /^data:/i.test(candidate)) continue;
        try {
            const resolved = new URL(candidate, pageUrl).href;
            if (/^https?:\/\//i.test(resolved)) return resolved;
        } catch {
        }
    }

    return '';
}

async function resolveTotallyScienceLaunchTarget(pageUrl) {
    const targetPage = String(pageUrl || '').trim();
    if (!targetPage) return '';

    const now = Date.now();
    const cached = totallyScienceResolvedLaunchCache.get(targetPage);
    if (cached && now < Number(cached.expiresAt || 0)) {
        return String(cached.url || targetPage);
    }

    let resolved = targetPage;
    try {
        const response = await fetch(targetPage);
        if (response.ok) {
            const html = await response.text();
            const embedded = extractTotallyScienceEmbeddedGameUrl(html, targetPage);
            if (embedded) resolved = embedded;
        }
    } catch {
    }

    totallyScienceResolvedLaunchCache.set(targetPage, {
        url: resolved,
        expiresAt: now + TOTALLY_SCIENCE_RESOLVED_TTL_MS,
    });
    return resolved;
}

async function resolveVelaraLaunchTarget(pageUrl) {
    const targetPage = String(pageUrl || '').trim();
    if (!targetPage) return '';

    const now = Date.now();
    const cached = velaraResolvedLaunchCache.get(targetPage);
    if (cached && now < Number(cached.expiresAt || 0)) {
        return String(cached.url || targetPage);
    }

    let resolved = targetPage;
    try {
        const response = await fetch(targetPage);
        if (response.ok) {
            const html = await response.text();
            const embedded = extractVelaraEmbeddedGameUrl(html, targetPage);
            if (embedded) resolved = embedded;
        }
    } catch {
    }

    velaraResolvedLaunchCache.set(targetPage, {
        url: resolved,
        expiresAt: now + VELARA_RESOLVED_TTL_MS,
    });
    return resolved;
}

async function buildTotallyScienceCatalogData() {
    const response = await fetch(TOTALLY_SCIENCE_BASE);
    if (!response.ok) {
        throw new Error(`totally science fetch failed: ${response.status}`);
    }

    const html = await response.text();
    const seenSources = new Set();
    const usedLaunchSlugs = new Set();
    const items = [];
    const map = new Map();

    const pushRaw = (slugRaw, nameRaw, coverRaw = '') => {
        const sourceSlug = normalizeTotallyScienceSourceSlug(slugRaw);
        const name = String(nameRaw || '').trim().replace(/\s+/g, ' ');
        if (!sourceSlug || !name) return;
        if (/^(t|tag|about|contact|privacy-policy|all-tags|new-games|recently-played-games|page)(\/|$)/i.test(sourceSlug)) return;
        const sourceKey = sourceSlug.toLowerCase();
        if (seenSources.has(sourceKey)) return;
        seenSources.add(sourceKey);

        const baseLaunchSlug = toLaunchSlug(sourceSlug, toLaunchSlug(name, 'game'));
        let launchSlug = baseLaunchSlug;
        let suffix = 2;
        while (usedLaunchSlugs.has(launchSlug)) {
            launchSlug = `${baseLaunchSlug}-${suffix}`;
            suffix += 1;
        }
        usedLaunchSlugs.add(launchSlug);

        const normalizedCover = String(coverRaw || '').trim().replace(/^\.?\//, '').replace(/^\/+/, '');
        const targetUrl = new URL(`${sourceSlug}/`, TOTALLY_SCIENCE_BASE).href;
        const cover = normalizedCover ? new URL(normalizedCover, TOTALLY_SCIENCE_BASE).href : '';

        items.push({
            id: `totalscience-${launchSlug}`,
            name,
            url: `/tllysc/${encodeURIComponent(launchSlug)}.html`,
            cover,
        });
        map.set(launchSlug, {
            targetUrl,
            name,
            cover,
        });
    };

    const cardRe = /<article[^>]*class="[^"]*\bc-card\b[^"]*"[\s\S]*?<img[^>]*src="([^"]+)"[\s\S]*?<div[^>]*class="c-card__title"[^>]*>\s*<a[^>]*href="\.\/([^"\/]+)\/"[^>]*>([^<]+)<\/a>/gi;
    let m;
    while ((m = cardRe.exec(html)) !== null) {
        pushRaw(m[2], m[3], m[1]);
    }

    const rowRe = /<div[^>]*onclick="location\.href='\/([^'\/]+)\/'"[^>]*>[\s\S]*?<img[^>]*src="([^"]+)"[\s\S]*?<h3[^>]*>([^<]+)<\/h3>/gi;
    while ((m = rowRe.exec(html)) !== null) {
        pushRaw(m[1], m[3], m[2]);
    }

    items.sort((a, b) => a.name.localeCompare(b.name));
    return { items, map };
}

async function getTotallyScienceCatalogData() {
    const now = Date.now();
    if (totallyScienceCatalogCache.map.size > 0 && now < totallyScienceCatalogCache.expiresAt) {
        return totallyScienceCatalogCache;
    }

    try {
        const built = await buildTotallyScienceCatalogData();
        totallyScienceCatalogCache = {
            expiresAt: now + TOTALLY_SCIENCE_CACHE_TTL_MS,
            items: built.items,
            map: built.map,
        };
        return totallyScienceCatalogCache;
    } catch (error) {
        if (totallyScienceCatalogCache.map.size > 0) return totallyScienceCatalogCache;
        throw error;
    }
}

async function buildVelaraCatalogData() {
    const response = await fetch(VELARA_GAMES_JSON);
    if (!response.ok) {
        throw new Error(`velara fetch failed: ${response.status}`);
    }

    const rows = await response.json();
    const items = [];
    const map = new Map();
    const seenTargetUrls = new Set();
    const usedSlugs = new Set();

    for (const row of (Array.isArray(rows) ? rows : [])) {
        const name = String(row?.title || row?.name || '').trim();
        const link = String(row?.location || row?.link || '').trim();
        const img = String(row?.image || row?.imgpath || '').trim();
        if (!name || !link) continue;

        const normalizedLink = link.startsWith('/') ? link : `/${link}`;
        const targetUrl = new URL(normalizedLink, VELARA_BASE).href;
        const targetKey = targetUrl.toLowerCase();
        if (seenTargetUrls.has(targetKey)) continue;
        seenTargetUrls.add(targetKey);

        const normalizedImg = img.startsWith('/') ? img : `/${img}`;
        const cover = img ? new URL(normalizedImg, VELARA_BASE).href : '';

        const baseSlug = toLaunchSlug(normalizedLink, toLaunchSlug(name, 'game'));
        let slug = baseSlug;
        let suffix = 2;
        while (usedSlugs.has(slug)) {
            slug = `${baseSlug}-${suffix}`;
            suffix += 1;
        }
        usedSlugs.add(slug);

        items.push({
            id: `velara-${slug}`,
            name,
            url: `/vlra/${encodeURIComponent(slug)}.html`,
            cover,
        });
        map.set(slug, {
            targetUrl,
            name,
            cover,
        });
    }

    items.sort((a, b) => a.name.localeCompare(b.name));
    return { items, map };
}

async function getVelaraCatalogData() {
    const now = Date.now();
    if (velaraCatalogCache.map.size > 0 && now < velaraCatalogCache.expiresAt) {
        return velaraCatalogCache;
    }

    try {
        const built = await buildVelaraCatalogData();
        velaraCatalogCache = {
            expiresAt: now + VELARA_CACHE_TTL_MS,
            items: built.items,
            map: built.map,
        };
        return velaraCatalogCache;
    } catch (error) {
        if (velaraCatalogCache.map.size > 0) return velaraCatalogCache;
        throw error;
    }
}

async function buildSeraphCatalogData() {
    const response = await fetch(SERAPH_GAMES_API, {
        headers: {
            'accept': 'application/vnd.github+json',
            'user-agent': 'rift-seraph-catalog',
        },
    });
    if (!response.ok) {
        throw new Error(`seraph fetch failed: ${response.status}`);
    }

    const rows = await response.json();
    const items = [];
    const map = new Map();
    const usedSlugs = new Set();

    for (const row of (Array.isArray(rows) ? rows : [])) {
        if (!row || row.type !== 'dir') continue;

        const dirName = String(row.name || '').trim();
        if (!dirName || dirName.startsWith('.')) continue;

        const label = humanizeFolderName(dirName);
        const baseSlug = toLaunchSlug(dirName, toLaunchSlug(label, 'game'));
        let slug = baseSlug;
        let suffix = 2;
        while (usedSlugs.has(slug)) {
            slug = `${baseSlug}-${suffix}`;
            suffix += 1;
        }
        usedSlugs.add(slug);

        items.push({
            id: `seraph-${slug}`,
            name: label || `Game ${items.length + 1}`,
            url: `/sph/${encodeURIComponent(slug)}.html`,
            cover: '',
        });
        map.set(slug, {
            name: label,
            dirName,
        });
    }

    items.sort((a, b) => a.name.localeCompare(b.name));
    return { items, map };
}

async function getSeraphCatalogData() {
    const now = Date.now();
    if (seraphCatalogCache.map.size > 0 && now < seraphCatalogCache.expiresAt) {
        return seraphCatalogCache;
    }

    try {
        const built = await buildSeraphCatalogData();
        seraphCatalogCache = {
            expiresAt: now + SERAPH_CACHE_TTL_MS,
            items: built.items,
            map: built.map,
        };
        return seraphCatalogCache;
    } catch (error) {
        if (seraphCatalogCache.map.size > 0) return seraphCatalogCache;
        throw error;
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

async function findSdxpBackupIndexFile() {
    const root = path.join(__dirname, '..');
    try {
        const entries = await fs.readdir(root, { withFileTypes: true });
        const candidates = entries
            .filter((entry) => entry.isDirectory() && /^\.deploy_untracked_backup_/i.test(entry.name))
            .map((entry) => path.join(root, entry.name, 'public_sdxp', 'index.html'))
            .sort()
            .reverse();

        for (const candidate of candidates) {
            try {
                await fs.access(candidate);
                return candidate;
            } catch {
            }
        }
    } catch {
    }
    return '';
}

function normalizeSdxpTail(value) {
    return String(value || '')
        .trim()
        .replace(/^[./\\]+/, '')
        .replace(/^\/+/, '')
        .replace(/\\/g, '/');
}

function buildSdxpTailCandidates(rawTail) {
    const normalized = normalizeSdxpTail(rawTail);
    if (!normalized || normalized.includes('..')) return [];

    const out = [];
    const seen = new Set();
    const add = (tail) => {
        const next = normalizeSdxpTail(tail);
        if (!next || next.includes('..')) return;
        const key = next.toLowerCase();
        if (seen.has(key)) return;
        seen.add(key);
        out.push(next);
    };

    const flatHtmlMatch = normalized.match(/^html\/([^/]+)\.html$/i);
    if (flatHtmlMatch?.[1]) {
        const slug = String(flatHtmlMatch[1]).trim();
        add(`html/${slug}/game/index.html`);
        add(`html/${slug}/index.html`);
        add(normalized);
        return out;
    }

    const folderRootMatch = normalized.match(/^html\/([^/]+)\/?$/i);
    if (folderRootMatch?.[1]) {
        const slug = String(folderRootMatch[1]).trim();
        add(`html/${slug}/game/index.html`);
        add(`html/${slug}/index.html`);
        add(normalized);
        return out;
    }

    const folderIndexMatch = normalized.match(/^html\/([^/]+)\/index\.html$/i);
    if (folderIndexMatch?.[1]) {
        const slug = String(folderIndexMatch[1]).trim();
        add(`html/${slug}/game/index.html`);
        add(normalized);
        return out;
    }

    const directGameMatch = normalized.match(/^html\/([^/]+)\/game\/index\.html$/i);
    if (directGameMatch?.[1]) {
        const slug = String(directGameMatch[1]).trim();
        add(normalized);
        add(`html/${slug}/index.html`);
        return out;
    }

    add(normalized);
    return out;
}

function sdxpCatalogUrlForTail(rawTail) {
    const tails = buildSdxpTailCandidates(rawTail);
    const launchTail = tails[0] || normalizeSdxpTail(rawTail);
    if (!launchTail) return '';
    return `/sdxp/${encodePathForUrl(launchTail)}`;
}

function stripSdxpTopRedirect(html) {
    return String(html || '').replace(
        /<script[^>]*>\s*if\s*\(\s*window\.top\s*={2,3}\s*window\.self\s*\)\s*\{\s*window\.location(?:\.href)?\s*=\s*['"][^'"]+['"]\s*;?\s*\}\s*<\/script>/gi,
        ''
    );
}

function parseSdxpCatalogCards(html) {
    const source = String(html || '');
    const items = [];
    const seen = new Set();
    const entryRe = /<a\b([^>]*)>([\s\S]*?)<\/a>/gi;
    let block;
    while ((block = entryRe.exec(source)) !== null) {
        const attrs = String(block[1] || '');
        const body = String(block[2] || '');
        const classMatch = attrs.match(/\bclass\s*=\s*["']([^"']+)["']/i);
        const classValue = String(classMatch?.[1] || '');
        if (!/\bcard\b/i.test(classValue)) continue;

        const hrefMatch = attrs.match(/\bhref\s*=\s*["']([^"']+)["']/i);
        const imgMatch = body.match(/<img[^>]*src\s*=\s*["']([^"']+)["']/i);
        const nameMatch = body.match(/<figcaption[^>]*>([\s\S]*?)<\/figcaption>/i);
        if (!hrefMatch || !nameMatch) continue;

        const hrefRaw = String(hrefMatch[1] || '').trim();
        const name = String(nameMatch[1] || '')
            .replace(/<[^>]+>/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();
        if (!hrefRaw || !name) continue;
        if (/^(?:https?:|\/\/|javascript:|data:|#)/i.test(hrefRaw)) continue;

        const rel = hrefRaw
            .replace(/^\.?\//, '')
            .replace(/^\/+/, '')
            .replace(/\\/g, '/');
        if (!rel || rel.includes('..')) continue;
        const launchUrl = sdxpCatalogUrlForTail(rel);
        if (!launchUrl) continue;
        const key = launchUrl.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);

        const relCoverRaw = String(imgMatch?.[1] || '').trim();
        const relCover = relCoverRaw
            .replace(/^\.?\//, '')
            .replace(/^\/+/, '')
            .replace(/\\/g, '/');
        const cover = relCover && !relCover.includes('..')
            ? `/sdxp/${encodePathForUrl(relCover)}`
            : '';

        items.push({
            id: `sdxp-fallback-${key.replace(/[^a-z0-9/_-]+/gi, '-')}`,
            name,
            url: launchUrl,
            cover,
        });
    }
    items.sort((a, b) => a.name.localeCompare(b.name));
    return items;
}

async function loadSdxpFallbackCatalog() {
    const backupIndex = await findSdxpBackupIndexFile();
    if (backupIndex) {
        try {
            const html = await fs.readFile(backupIndex, 'utf8');
            const parsed = parseSdxpCatalogCards(html);
            if (parsed.length) return parsed;
        } catch {
        }
    }

    try {
        const response = await fetch(SDXP_FALLBACK_BASE);
        if (response.ok) {
            const html = await response.text();
            const parsed = parseSdxpCatalogCards(html);
            if (parsed.length) return parsed;
        }
    } catch {
    }

    return [];
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

const LOGIN_RATE_WINDOW_MS = 1000 * 60 * 15; // 15 minutes
const LOGIN_RATE_MAX_ATTEMPTS = 10;
const loginAttemptMap = new Map(); // key: ip|username -> { count, resetAt }

function checkLoginRateLimit(ip, username) {
    const now = Date.now();
    const key = `${String(ip || '').trim()}|${String(username || '').trim()}`;
    const entry = loginAttemptMap.get(key);
    if (!entry || now >= entry.resetAt) {
        loginAttemptMap.set(key, { count: 1, resetAt: now + LOGIN_RATE_WINDOW_MS });
        return true;
    }
    entry.count += 1;
    if (entry.count > LOGIN_RATE_MAX_ATTEMPTS) return false;
    return true;
}

function clearLoginRateLimit(ip, username) {
    const key = `${String(ip || '').trim()}|${String(username || '').trim()}`;
    loginAttemptMap.delete(key);
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

function isSecureContext() {
    return !!(process.env.VERCEL || process.env.NODE_ENV === 'production' || process.env.HTTPS);
}

function setSessionCookie(res, token, expiresAt) {
    const expires = new Date(expiresAt).toUTCString();
    const secure = isSecureContext() ? '; Secure' : '';
    res.setHeader(
        'Set-Cookie',
        `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax${secure}; Expires=${expires}`
    );
}

function clearSessionCookie(res) {
    const secure = isSecureContext() ? '; Secure' : '';
    res.setHeader(
        'Set-Cookie',
        `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax${secure}; Expires=Thu, 01 Jan 1970 00:00:00 GMT`
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

function cloneJsonSafe(value) {
    try {
        return JSON.parse(JSON.stringify(value));
    } catch {
        return null;
    }
}

function sanitizeUsername(value) {
    return String(value || '').trim().toLowerCase();
}

function shouldPersistSessionTouch(token, now = Date.now()) {
    const key = String(token || '').trim();
    if (!key) return false;
    const lastWriteAt = Number(sessionTouchWriteMap.get(key) || 0);
    if (lastWriteAt > 0 && (now - lastWriteAt) < SESSION_TOUCH_WRITE_INTERVAL_MS) {
        return false;
    }
    sessionTouchWriteMap.set(key, now);
    return true;
}

function parseUserStatusModeInput(input) {
    const mode = String(input || '').trim().toLowerCase();
    if (!USER_STATUS_MODES.has(mode)) return '';
    return mode;
}

function normalizeUserStatusMode(input) {
    return parseUserStatusModeInput(input) || 'auto';
}

function normalizeUserStatus(input) {
    const value = String(input || '').trim().toLowerCase();
    if (value === 'online' || value === 'idle' || value === 'dnd' || value === 'offline') return value;
    return 'offline';
}

function pruneUserActivity(now = Date.now()) {
    for (const [userId, entry] of userActivityMap.entries()) {
        const lastSeenAt = Number(entry?.lastSeenAt || 0);
        if (!lastSeenAt || (now - lastSeenAt) > USER_ACTIVITY_TTL_MS) {
            userActivityMap.delete(userId);
        }
    }
}

function touchUserActivity(userId, now = Date.now()) {
    const id = String(userId || '').trim();
    if (!id) return;
    pruneUserActivity(now);
    userActivityMap.set(id, { lastSeenAt: now });
}

function getUserStatusMode(db, userId) {
    const id = String(userId || '').trim();
    if (!id) return 'auto';
    const prefs = db?.userStatusPrefs && typeof db.userStatusPrefs === 'object' ? db.userStatusPrefs : {};
    return normalizeUserStatusMode(prefs[id]?.mode);
}

function getLastActiveByUserId(db, userIds, now = Date.now()) {
    const ids = new Set(
        (Array.isArray(userIds) ? userIds : [])
            .map((entry) => String(entry || '').trim())
            .filter(Boolean)
    );
    const out = new Map();
    if (!ids.size) return out;

    pruneUserActivity(now);
    for (const userId of ids) {
        const seen = Number(userActivityMap.get(userId)?.lastSeenAt || 0);
        if (seen > 0) out.set(userId, seen);
    }

    const sessions = Array.isArray(db?.sessions) ? db.sessions : [];
    for (const session of sessions) {
        if (!session || typeof session !== 'object') continue;
        if (Number(session.expiresAt || 0) <= now) continue;
        const userId = String(session.userId || '').trim();
        if (!ids.has(userId)) continue;
        const seen = Number(session.lastSeenAt || session.createdAt || 0);
        if (seen <= 0) continue;
        if (seen > Number(out.get(userId) || 0)) {
            out.set(userId, seen);
        }
    }

    return out;
}

function computeEffectiveUserStatus(mode, lastSeenAt, now = Date.now()) {
    const seen = Number(lastSeenAt || 0);
    if (!seen || (now - seen) > USER_STATUS_OFFLINE_MS) return 'offline';
    if (mode === 'dnd') return 'dnd';
    if (mode === 'online') return 'online';
    if (mode === 'idle') return 'idle';
    return (now - seen) <= USER_STATUS_AUTO_ONLINE_MS ? 'online' : 'idle';
}

function getEffectiveUserStatus(db, userId, now = Date.now()) {
    const id = String(userId || '').trim();
    if (!id) return 'offline';
    const lastSeenByUser = getLastActiveByUserId(db, [id], now);
    const mode = getUserStatusMode(db, id);
    return computeEffectiveUserStatus(mode, lastSeenByUser.get(id), now);
}

function getEffectiveStatusesForUsers(db, userIds, now = Date.now()) {
    const ids = Array.from(new Set(
        (Array.isArray(userIds) ? userIds : [])
            .map((entry) => String(entry || '').trim())
            .filter(Boolean)
    ));
    const out = {};
    if (!ids.length) return out;

    const lastSeenByUser = getLastActiveByUserId(db, ids, now);
    for (const userId of ids) {
        const mode = getUserStatusMode(db, userId);
        out[userId] = computeEffectiveUserStatus(mode, lastSeenByUser.get(userId), now);
    }
    return out;
}

function hasUserBlockedTarget(db, blockerUserId, targetUserId) {
    const blockerId = String(blockerUserId || '').trim();
    const targetId = String(targetUserId || '').trim();
    if (!blockerId || !targetId) return false;
    const save = getUserSave(db, blockerId);
    const social = getUserSocial(save);
    return social.blocked.includes(targetId);
}

function areUsersBlockedEitherDirection(db, userIdA, userIdB) {
    const a = String(userIdA || '').trim();
    const b = String(userIdB || '').trim();
    if (!a || !b || a === b) return false;
    return hasUserBlockedTarget(db, a, b) || hasUserBlockedTarget(db, b, a);
}

function isDmRoomBlockedForUser(db, room, viewerUserId) {
    if (!isDmRoom(room)) return false;
    const viewerId = String(viewerUserId || '').trim();
    if (!viewerId) return false;
    const peerId = getDmUserIds(room).find((id) => id !== viewerId);
    if (!peerId) return false;
    return areUsersBlockedEitherDirection(db, viewerId, peerId);
}

function getFriendPayloadForUser(db, viewerUserId, now = Date.now()) {
    const viewerId = String(viewerUserId || '').trim();
    if (!viewerId) return { friends: [], blocked: [], now };
    const viewerSave = getUserSave(db, viewerId);
    const social = getUserSocial(viewerSave);
    const blockedSet = new Set(normalizeSocialUserIds(social.blocked, 500));
    const friendIds = normalizeSocialUserIds(social.friends, 500)
        .filter((id) => id !== viewerId && !blockedSet.has(id));
    const blockedIds = Array.from(blockedSet).filter((id) => id !== viewerId);
    const allIds = Array.from(new Set([...friendIds, ...blockedIds]));
    const statuses = getEffectiveStatusesForUsers(db, allIds, now);
    const lastSeenById = getLastActiveByUserId(db, allIds, now);
    const usersById = new Map((Array.isArray(db.users) ? db.users : []).map((user) => [String(user?.id || ''), user]));
    const statusRank = { online: 0, idle: 1, dnd: 2, offline: 3 };
    const toRow = (id, relation) => {
        const user = usersById.get(id);
        if (!user) return null;
        const status = normalizeUserStatus(statuses[id]);
        return {
            userId: String(user.id || id),
            username: String(user.username || 'user'),
            relation,
            status,
            lastSeenAt: Number(lastSeenById.get(id) || 0),
        };
    };
    const sortRows = (a, b) => {
        const left = statusRank[String(a?.status || 'offline')] ?? 99;
        const right = statusRank[String(b?.status || 'offline')] ?? 99;
        if (left !== right) return left - right;
        return String(a?.username || '').localeCompare(String(b?.username || ''));
    };
    const friends = friendIds.map((id) => toRow(id, 'friend')).filter(Boolean).sort(sortRows);
    const blocked = blockedIds.map((id) => toRow(id, 'blocked')).filter(Boolean).sort(sortRows);
    return { friends, blocked, now };
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
            JSON.stringify({ users: [], sessions: [], saves: {}, userStatusPrefs: {}, themePresetMarket: [] }, null, 2),
            'utf8'
        );
    }
}

async function sleep(ms) {
    return await new Promise((resolve) => setTimeout(resolve, ms));
}

async function acquireAuthDbLock(timeoutMs = AUTH_DB_LOCK_TIMEOUT_MS) {
    await fs.mkdir(path.dirname(AUTH_DB_LOCK_PATH), { recursive: true });
    const start = Date.now();

    while (true) {
        try {
            const handle = await fs.open(AUTH_DB_LOCK_PATH, 'wx');
            try {
                await handle.writeFile(`${process.pid}:${Date.now()}`, 'utf8');
            } catch {
            }
            return handle;
        } catch (error) {
            if (error?.code !== 'EEXIST') throw error;

            try {
                const stat = await fs.stat(AUTH_DB_LOCK_PATH);
                if ((Date.now() - Number(stat.mtimeMs || 0)) > AUTH_DB_LOCK_STALE_MS) {
                    await fs.unlink(AUTH_DB_LOCK_PATH);
                    continue;
                }
            } catch {
            }

            if ((Date.now() - start) > timeoutMs) {
                throw new Error('auth db lock timeout');
            }
            await sleep(25);
        }
    }
}

async function releaseAuthDbLock(handle) {
    try {
        await handle?.close();
    } catch {
    }
    try {
        await fs.unlink(AUTH_DB_LOCK_PATH);
    } catch {
    }
}

function extractFirstJsonObject(raw) {
    const text = String(raw || '');
    const start = text.indexOf('{');
    if (start < 0) return null;

    let depth = 0;
    let inString = false;
    let escaped = false;

    for (let i = start; i < text.length; i += 1) {
        const ch = text[i];

        if (inString) {
            if (escaped) {
                escaped = false;
                continue;
            }
            if (ch === '\\') {
                escaped = true;
                continue;
            }
            if (ch === '"') {
                inString = false;
            }
            continue;
        }

        if (ch === '"') {
            inString = true;
            continue;
        }
        if (ch === '{') {
            depth += 1;
            continue;
        }
        if (ch === '}') {
            depth -= 1;
            if (depth === 0) {
                return text.slice(start, i + 1);
            }
        }
    }
    return null;
}

async function parseAuthDbWithRecovery(raw) {
    const text = String(raw || '').trim();
    if (!text) return { users: [], sessions: [], saves: {}, userStatusPrefs: {}, themePresetMarket: [] };

    try {
        return JSON.parse(text);
    } catch (error) {
        const firstObject = extractFirstJsonObject(text);
        if (firstObject) {
            try {
                return JSON.parse(firstObject);
            } catch {
            }
        }
        throw error;
    }
}

async function readAuthDb() {
    await ensureAuthDb();
    let raw = await fs.readFile(AUTH_DB_PATH, 'utf8');
    let db;
    try {
        db = await parseAuthDbWithRecovery(raw);
    } catch (error) {
        // A short retry helps when another process is rewriting the file.
        try {
            await new Promise((resolve) => setTimeout(resolve, 50));
            raw = await fs.readFile(AUTH_DB_PATH, 'utf8');
            db = await parseAuthDbWithRecovery(raw);
        } catch {
            const backupPath = `${AUTH_DB_PATH}.corrupt-${Date.now()}.json`;
            try {
                await fs.writeFile(backupPath, raw, 'utf8');
            } catch {
            }
            const recovered = cloneJsonSafe(lastKnownGoodAuthDb);
            if (recovered) {
                db = recovered;
                console.error(`[auth-db] parse failed; using last known good snapshot after backup to ${backupPath}: ${error.message}`);
            } else {
                throw new Error(`[auth-db] parse failed; backup at ${backupPath}: ${error.message}`);
            }
        }
    }
    db.users = Array.isArray(db.users) ? db.users : [];
    db.sessions = Array.isArray(db.sessions) ? db.sessions : [];
    db.saves = db.saves && typeof db.saves === 'object' ? db.saves : {};
    db.userStatusPrefs = db.userStatusPrefs && typeof db.userStatusPrefs === 'object' ? db.userStatusPrefs : {};
    db.themePresetMarket = Array.isArray(db.themePresetMarket) ? db.themePresetMarket : [];
    for (const [userId, pref] of Object.entries(db.userStatusPrefs)) {
        const id = String(userId || '').trim();
        if (!id || !pref || typeof pref !== 'object') {
            delete db.userStatusPrefs[userId];
            continue;
        }
        db.userStatusPrefs[id] = {
            mode: normalizeUserStatusMode(pref.mode),
            updatedAt: Number(pref.updatedAt || Date.now()),
        };
        if (id !== userId) delete db.userStatusPrefs[userId];
    }
    pruneInactiveChatRooms(db);
    const snapshot = cloneJsonSafe(db);
    if (snapshot) {
        lastKnownGoodAuthDb = snapshot;
    }
    return db;
}

async function writeAuthDb(db) {
    await fs.mkdir(path.dirname(AUTH_DB_PATH), { recursive: true });
    const serialized = JSON.stringify(db, null, 2);
    const tempPath = `${AUTH_DB_PATH}.tmp-${process.pid}-${Date.now()}`;
    await fs.writeFile(tempPath, serialized, 'utf8');
    try {
        await fs.rename(tempPath, AUTH_DB_PATH);
    } catch (error) {
        try {
            await fs.unlink(tempPath);
        } catch {
        }
        throw error;
    }
    const snapshot = cloneJsonSafe(db);
    if (snapshot) {
        lastKnownGoodAuthDb = snapshot;
    }
}

async function updateAuthDb(mutator) {
    authWriteLock = authWriteLock
        .catch(() => {
        })
        .then(async () => {
            const lockHandle = await acquireAuthDbLock();
            try {
                const db = await readAuthDb();
                const updated = await mutator(db);
                if (updated === undefined) {
                    console.warn('[auth-db] updateAuthDb: mutator returned undefined; changes may have been lost. Ensure every code path returns db.');
                }
                await writeAuthDb(updated || db);
            } finally {
                await releaseAuthDbLock(lockHandle);
            }
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
    touchUserActivity(user.id, now);
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
        db.saves[userId] = {
            settings: {},
            games: {},
            profile: {},
            profileStyle: {},
            profilePresets: [],
            collections: [],
            achievements: {},
            partyJoins: 0,
            social: {},
            activity: {},
        };
    }
    const save = db.saves[userId];
    save.settings = save.settings && typeof save.settings === 'object' ? save.settings : {};
    save.games = save.games && typeof save.games === 'object' ? save.games : {};
    save.profile = normalizeProfileCard(save.profile);
    save.profileStyle = normalizeProfileStyle(save.profileStyle);
    save.profilePresets = normalizeSocialUserIds(save.profilePresets, 500).map((entry) => normalizePresetCode(entry)).filter(Boolean);
    save.collections = normalizeCollections(save.collections);
    save.achievements = save.achievements && typeof save.achievements === 'object' ? save.achievements : {};
    save.partyJoins = Number.isFinite(Number(save.partyJoins)) ? Number(save.partyJoins) : 0;
    save.social = save.social && typeof save.social === 'object' ? save.social : {};
    save.activity = getUserActivityState(save);
    return save;
}

function normalizeSocialUserIds(input, maxLen = 400) {
    const rows = Array.isArray(input) ? input : [];
    const out = [];
    for (const entry of rows) {
        const userId = String(entry || '').trim();
        if (!userId || out.includes(userId)) continue;
        out.push(userId);
        if (out.length >= maxLen) break;
    }
    return out;
}

function getUserSocial(save) {
    const source = save && typeof save === 'object' ? save : {};
    source.social = source.social && typeof source.social === 'object' ? source.social : {};
    source.social.friends = normalizeSocialUserIds(source.social.friends, 500);
    source.social.blocked = normalizeSocialUserIds(source.social.blocked, 500);
    return source.social;
}

function getUtcDayKey(now = Date.now()) {
    const date = new Date(Number(now || Date.now()));
    return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}-${String(date.getUTCDate()).padStart(2, '0')}`;
}

function normalizeProfileThemeId(input) {
    const value = String(input || '').trim().toLowerCase();
    const allowed = new Set(PROFILE_THEME_DEFS.map((entry) => String(entry.id || '')));
    if (allowed.has(value)) return value;
    return 'classic';
}

function normalizeProfileFrameEffect(input) {
    const value = String(input || '').trim().toLowerCase();
    return PROFILE_FRAME_EFFECTS.includes(value) ? value : 'none';
}

function normalizeProfileAccentAnimation(input) {
    const value = String(input || '').trim().toLowerCase();
    return PROFILE_ACCENT_ANIMATIONS.includes(value) ? value : 'none';
}

function normalizePresetCode(input) {
    const value = String(input || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12);
    return PROFILE_PRESET_CODE_RE.test(value) ? value : '';
}

function normalizeProfileStyle(input) {
    const raw = input && typeof input === 'object' ? input : {};
    return {
        themeId: normalizeProfileThemeId(raw.themeId),
        frameEffect: normalizeProfileFrameEffect(raw.frameEffect),
        accentAnimation: normalizeProfileAccentAnimation(raw.accentAnimation),
        presetCode: normalizePresetCode(raw.presetCode),
        updatedAt: Number(raw.updatedAt || 0),
    };
}

function getUserActivityState(save, now = Date.now()) {
    const source = save && typeof save === 'object' ? save : {};
    source.activity = source.activity && typeof source.activity === 'object' ? source.activity : {};
    const dayKey = getUtcDayKey(now);
    const currentDay = String(source.activity.dayKey || '');
    if (currentDay !== dayKey) {
        source.activity.dayKey = dayKey;
        source.activity.daily = { chatMessages: 0, gameLaunches: 0, musicActions: 0 };
    }
    source.activity.daily = source.activity.daily && typeof source.activity.daily === 'object'
        ? source.activity.daily
        : { chatMessages: 0, gameLaunches: 0, musicActions: 0 };
    source.activity.total = source.activity.total && typeof source.activity.total === 'object'
        ? source.activity.total
        : { chatMessages: 0, gameLaunches: 0, musicActions: 0 };
    for (const key of ['chatMessages', 'gameLaunches', 'musicActions']) {
        source.activity.daily[key] = Math.max(0, Number(source.activity.daily[key] || 0));
        source.activity.total[key] = Math.max(0, Number(source.activity.total[key] || 0));
    }
    return source.activity;
}

function applyActivityDelta(save, delta = {}, now = Date.now()) {
    const activity = getUserActivityState(save, now);
    for (const key of ['chatMessages', 'gameLaunches', 'musicActions']) {
        const amount = Number(delta[key] || 0);
        if (!Number.isFinite(amount) || amount <= 0) continue;
        activity.daily[key] = Number(activity.daily[key] || 0) + amount;
        activity.total[key] = Number(activity.total[key] || 0) + amount;
    }
    activity.updatedAt = Number(now || Date.now());
    return activity;
}

function getThemePresetMarket(db) {
    if (!Array.isArray(db.themePresetMarket)) db.themePresetMarket = [];
    const rows = db.themePresetMarket
        .filter((entry) => entry && typeof entry === 'object')
        .map((entry) => ({
            id: String(entry.id || crypto.randomUUID()),
            code: normalizePresetCode(entry.code),
            name: sanitizeProfileShort(entry.name || 'preset', 60),
            creatorUserId: String(entry.creatorUserId || ''),
            creatorUsername: sanitizeProfileShort(entry.creatorUsername || 'user', 32),
            style: normalizeProfileStyle(entry.style),
            accent: normalizeHexColor(entry.accent, '#8ecbff'),
            createdAt: Number(entry.createdAt || Date.now()),
        }))
        .filter((entry) => !!entry.code);
    db.themePresetMarket = rows.slice(0, PROFILE_PRESET_SHARE_LIMIT);
    return db.themePresetMarket;
}

function sanitizeProfileShort(value, maxLen = 120) {
    return String(value || '')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, maxLen);
}

function sanitizeProfileBio(value, maxLen = 360) {
    return String(value || '')
        .replace(/\r/g, '')
        .trim()
        .slice(0, maxLen);
}

function normalizeHexColor(value, fallback = '#8ecbff') {
    const raw = String(value || '').trim().toLowerCase();
    const short = raw.match(/^#([a-f0-9]{3})$/i);
    if (short) {
        const [a, b, c] = short[1].split('');
        return `#${a}${a}${b}${b}${c}${c}`;
    }
    if (/^#[a-f0-9]{6}$/i.test(raw)) return raw;
    return fallback;
}

function normalizeProfileCard(input) {
    const raw = input && typeof input === 'object' ? input : {};
    return {
        tagline: sanitizeProfileShort(raw.tagline, 80),
        bio: sanitizeProfileBio(raw.bio, 360),
        accent: normalizeHexColor(raw.accent, '#8ecbff'),
        favoriteGameId: String(raw.favoriteGameId || '').trim().slice(0, 120),
        favoriteGameName: sanitizeProfileShort(raw.favoriteGameName, 120),
        updatedAt: Number(raw.updatedAt || 0),
    };
}

function sanitizeCollectionName(value) {
    return String(value || '')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 48);
}

function normalizeCollectionId(value) {
    const id = String(value || '')
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9_-]/g, '')
        .slice(0, 64);
    return id;
}

function normalizeCollectionGameId(value) {
    return String(value || '').trim().slice(0, 140);
}

function normalizeCollections(input) {
    const rows = Array.isArray(input) ? input : [];
    const out = [];
    const seenIds = new Set();
    for (const row of rows) {
        if (!row || typeof row !== 'object') continue;
        const id = normalizeCollectionId(row.id) || `col-${crypto.randomUUID().slice(0, 12)}`;
        if (seenIds.has(id)) continue;
        seenIds.add(id);
        const name = sanitizeCollectionName(row.name) || 'collection';
        const createdAt = Number(row.createdAt || Date.now());
        const updatedAt = Number(row.updatedAt || createdAt);
        const gamesRaw = Array.isArray(row.games) ? row.games : [];
        const games = [];
        const seenGames = new Set();
        for (const entry of gamesRaw) {
            const gameId = normalizeCollectionGameId(entry?.id || entry?.gameId || '');
            if (!gameId || seenGames.has(gameId)) continue;
            seenGames.add(gameId);
            games.push({
                id: gameId,
                name: sanitizeProfileShort(entry?.name || entry?.gameName || '', 120),
                addedAt: Number(entry?.addedAt || updatedAt || Date.now()),
            });
            if (games.length >= 300) break;
        }
        out.push({ id, name, createdAt, updatedAt, games });
        if (out.length >= 80) break;
    }
    return out;
}

function getPartyMap(db) {
    if (!db.parties || typeof db.parties !== 'object') db.parties = {};
    return db.parties;
}

function sanitizePartyCode(value) {
    return String(value || '')
        .trim()
        .toUpperCase()
        .replace(/[^A-Z0-9]/g, '')
        .slice(0, 8);
}

function sanitizePartyName(value) {
    return String(value || '')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 48);
}

function sanitizePartyTrackId(value) {
    return String(value || '')
        .trim()
        .replace(/[^a-z0-9:_-]/gi, '')
        .slice(0, 140);
}

function normalizePartyMusicTrack(input) {
    if (!input || typeof input !== 'object') return null;
    const title = sanitizeProfileShort(input.title || input.name || '', 120);
    if (!title) return null;
    const artist = sanitizeProfileShort(input.artist || '', 120);
    const provider = String(input.provider || '')
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9_-]/g, '')
        .slice(0, 24);
    const trackId = sanitizePartyTrackId(input.trackId || input.id || '');
    return {
        title,
        artist,
        provider,
        trackId,
    };
}

function createPartyCode(parties) {
    const map = parties && typeof parties === 'object' ? parties : {};
    for (let i = 0; i < 50; i += 1) {
        const candidate = crypto.randomBytes(3).toString('hex').toUpperCase();
        const exists = Object.values(map).some((party) => sanitizePartyCode(party?.code) === candidate);
        if (!exists) return candidate;
    }
    return crypto.randomBytes(4).toString('hex').toUpperCase().slice(0, 8);
}

function getPartyForUser(db, userId) {
    const id = String(userId || '').trim();
    if (!id) return null;
    const parties = getPartyMap(db);
    for (const party of Object.values(parties)) {
        const members = Array.isArray(party?.members) ? party.members : [];
        if (members.some((member) => String(member?.userId || '') === id)) return party;
    }
    return null;
}

function leavePartyInternal(db, partyId, userId) {
    const id = String(userId || '').trim();
    const pid = String(partyId || '').trim();
    if (!id || !pid) return null;
    const parties = getPartyMap(db);
    const party = parties[pid];
    if (!party) return null;
    const before = Array.isArray(party.members) ? party.members : [];
    const after = before.filter((member) => String(member?.userId || '') !== id);
    if (!after.length) {
        delete parties[pid];
        return null;
    }
    party.members = after;
    if (!after.some((member) => String(member?.userId || '') === String(party.ownerUserId || ''))) {
        party.ownerUserId = String(after[0].userId || '');
        party.ownerUsername = String(after[0].username || 'user');
    }
    party.updatedAt = Date.now();
    parties[pid] = party;
    return party;
}

function computeSaveStats(save) {
    const games = save?.games && typeof save.games === 'object' ? Object.values(save.games) : [];
    let totalLaunches = 0;
    let uniqueGames = 0;
    let favoriteGames = 0;
    for (const game of games) {
        if (!game || typeof game !== 'object') continue;
        const launches = Number(game.launches || 0);
        const played = launches > 0 || Number(game.lastPlayedAt || 0) > 0;
        if (played) uniqueGames += 1;
        totalLaunches += Number.isFinite(launches) && launches > 0 ? launches : 0;
        if (game.favorite === true) favoriteGames += 1;
    }
    const collections = normalizeCollections(save?.collections);
    const hasCustomTheme = !!save?.settings?.['rift__theme-custom-v1'];
    return {
        totalLaunches,
        uniqueGames,
        favoriteGames,
        collectionCount: collections.length,
        partyJoins: Number.isFinite(Number(save?.partyJoins)) ? Number(save.partyJoins) : 0,
        hasCustomTheme,
    };
}

const LIGHT_ACHIEVEMENTS = [
    { id: 'first_launch', name: 'first launch', description: 'launch 1 game', target: 1, metric: 'totalLaunches' },
    { id: 'arcade_grinder', name: 'arcade grinder', description: 'launch 25 games total', target: 25, metric: 'totalLaunches' },
    { id: 'explorer', name: 'explorer', description: 'play 10 unique games', target: 10, metric: 'uniqueGames' },
    { id: 'collector', name: 'collector', description: 'create 3 collections', target: 3, metric: 'collectionCount' },
    { id: 'theme_editor', name: 'theme editor', description: 'save a custom theme', target: 1, metric: 'hasCustomTheme' },
    { id: 'party_up', name: 'party up', description: 'join or create a party', target: 1, metric: 'partyJoins' },
];

function ensureAchievementState(save) {
    if (!save.achievements || typeof save.achievements !== 'object') {
        save.achievements = {};
    }
    return save.achievements;
}

function evaluateAchievements(save, options = {}) {
    const now = Number(options.now || Date.now());
    const persist = !!options.persist;
    const state = ensureAchievementState(save || {});
    const stats = computeSaveStats(save || {});
    const rows = [];
    for (const def of LIGHT_ACHIEVEMENTS) {
        const rawValue = def.metric === 'hasCustomTheme'
            ? (stats.hasCustomTheme ? 1 : 0)
            : Number(stats[def.metric] || 0);
        const progress = Math.max(0, rawValue);
        const unlocked = progress >= def.target;
        let unlockedAt = Number(state[def.id]?.unlockedAt || 0);
        if (persist && unlocked && !unlockedAt) {
            unlockedAt = now;
            state[def.id] = { unlockedAt };
        }
        rows.push({
            id: def.id,
            name: def.name,
            description: def.description,
            unlocked,
            unlockedAt: unlockedAt || 0,
            progress,
            target: def.target,
        });
    }
    return rows;
}

function getUnlockedProfileThemeIds(save, now = Date.now()) {
    const achievements = evaluateAchievements(save || {}, { persist: false, now });
    const unlockedIds = new Set(
        achievements.filter((row) => !!row.unlocked).map((row) => String(row.id || ''))
    );
    const allowed = [];
    for (const def of PROFILE_THEME_DEFS) {
        const required = String(def.requiresAchievementId || '');
        if (!required || unlockedIds.has(required)) {
            allowed.push(String(def.id || 'classic'));
        }
    }
    if (!allowed.includes('classic')) allowed.unshift('classic');
    return Array.from(new Set(allowed));
}

function getCurrentSeasonEvent(now = Date.now()) {
    const value = Number(now || Date.now());
    const year = new Date(value).getUTCFullYear();
    const start = Date.UTC(year, 2, 1, 0, 0, 0, 0);
    const end = Date.UTC(year, 4, 1, 0, 0, 0, 0);
    const active = value >= start && value < end;
    return {
        id: `spring-${year}`,
        name: `spring ${year} splash`,
        active,
        startsAt: start,
        endsAt: end,
        badgeIds: ['spring_scout', 'spring_streak'],
    };
}

function computeProfileProgression(save, now = Date.now()) {
    const activity = getUserActivityState(save, now);
    const achievements = evaluateAchievements(save, { persist: false, now });
    const unlockedCount = achievements.filter((row) => !!row.unlocked).length;
    const chat = Number(activity.total?.chatMessages || 0);
    const games = Number(activity.total?.gameLaunches || 0);
    const music = Number(activity.total?.musicActions || 0);
    const xp = (chat * 5) + (games * 10) + (music * 7) + (unlockedCount * 40);
    const level = Math.max(1, Math.floor(xp / 120) + 1);
    const badges = [];
    if (xp >= 150) badges.push({ id: 'xp_rookie', name: 'xp rookie' });
    if (xp >= 600) badges.push({ id: 'xp_veteran', name: 'xp veteran' });
    if (chat >= 80) badges.push({ id: 'chat_streaker', name: 'chat streaker' });
    if (games >= 25) badges.push({ id: 'quest_gamer', name: 'quest gamer' });
    const season = getCurrentSeasonEvent(now);
    if (season.active && (chat + games + music) >= 30) badges.push({ id: 'spring_scout', name: 'spring scout' });
    if (season.active && unlockedCount >= 3) badges.push({ id: 'spring_streak', name: 'spring streak' });
    return {
        xp,
        level,
        totals: { chatMessages: chat, gameLaunches: games, musicActions: music },
        badges,
    };
}

function computeDailyQuestRows(save, now = Date.now()) {
    const activity = getUserActivityState(save, now);
    const dayKey = String(activity.dayKey || getUtcDayKey(now));
    const daily = activity.daily || {};
    return DAILY_QUEST_DEFS.map((def) => {
        const progress = Math.max(0, Number(daily[def.metric] || 0));
        return {
            id: def.id,
            name: def.name,
            metric: def.metric,
            progress,
            target: Number(def.target || 0),
            complete: progress >= Number(def.target || 0),
            xp: Number(def.xp || 0),
            dayKey,
        };
    });
}

function getProfileStyleForUser(save, now = Date.now()) {
    const style = normalizeProfileStyle(save?.profileStyle);
    const unlockedThemeIds = getUnlockedProfileThemeIds(save, now);
    const safeThemeId = unlockedThemeIds.includes(style.themeId) ? style.themeId : 'classic';
    return {
        ...style,
        themeId: safeThemeId,
        availableThemeIds: unlockedThemeIds,
    };
}

function toThemePresetPublicView(entry, options = {}) {
    const row = entry && typeof entry === 'object' ? entry : {};
    const style = normalizeProfileStyle(row.style);
    return {
        code: normalizePresetCode(row.code),
        name: sanitizeProfileShort(row.name || 'preset', 60),
        creatorUsername: sanitizeProfileShort(row.creatorUsername || 'user', 32),
        style,
        accent: normalizeHexColor(row.accent, '#8ecbff'),
        builtIn: !!row.builtIn,
        createdAt: Number(row.createdAt || 0),
        owned: !!options.owned,
    };
}

function toProfileCardPublicView(db, user, now = Date.now()) {
    const save = getUserSave(db, user.id);
    const profile = normalizeProfileCard(save.profile);
    const style = getProfileStyleForUser(save, now);
    const stats = computeSaveStats(save);
    const achievements = evaluateAchievements(save, { persist: false, now });
    const unlocked = achievements.filter((entry) => entry.unlocked);
    unlocked.sort((a, b) => Number(a.unlockedAt || 0) - Number(b.unlockedAt || 0));
    const progression = computeProfileProgression(save, now);
    const dailyQuests = computeDailyQuestRows(save, now);
    const season = getCurrentSeasonEvent(now);
    return {
        userId: String(user.id || ''),
        username: String(user.username || 'user'),
        createdAt: Number(user.createdAt || 0),
        status: getEffectiveUserStatus(db, user.id, now),
        profile,
        style,
        stats: {
            totalLaunches: stats.totalLaunches,
            uniqueGames: stats.uniqueGames,
            favoriteGames: stats.favoriteGames,
            collectionCount: stats.collectionCount,
            achievementCount: unlocked.length,
        },
        progression,
        dailyQuests,
        season,
        achievements: unlocked.slice(-6),
    };
}

function toPartyPublicView(db, party, viewerUserId = '', now = Date.now()) {
    if (!party || typeof party !== 'object') return null;
    const members = Array.isArray(party.members) ? party.members : [];
    const ids = members.map((member) => String(member?.userId || '')).filter(Boolean);
    const statuses = getEffectiveStatusesForUsers(db, ids, now);
    const musicTrack = normalizePartyMusicTrack(party.musicTrack)
        || normalizePartyMusicTrack({ title: party.gameName || '', trackId: party.gameId || '' });
    const cleanMembers = members
        .filter((member) => member && typeof member === 'object')
        .map((member) => ({
            userId: String(member.userId || ''),
            username: String(member.username || 'user'),
            joinedAt: Number(member.joinedAt || 0),
            lastSeenAt: Number(member.lastSeenAt || 0),
            status: normalizeUserStatus(statuses[String(member.userId || '')]),
        }));
    return {
        id: String(party.id || ''),
        code: sanitizePartyCode(party.code),
        name: sanitizePartyName(party.name) || 'party',
        ownerUserId: String(party.ownerUserId || ''),
        ownerUsername: String(party.ownerUsername || 'user'),
        gameId: normalizeCollectionGameId(party.gameId || ''),
        gameName: sanitizeProfileShort(party.gameName || musicTrack?.title || '', 120),
        musicTrack,
        createdAt: Number(party.createdAt || 0),
        updatedAt: Number(party.updatedAt || 0),
        memberCount: cleanMembers.length,
        isOwner: String(viewerUserId || '') === String(party.ownerUserId || ''),
        members: cleanMembers,
    };
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

function isDmRoom(room) {
    return !!(room && typeof room === 'object' && room.kind === 'dm');
}

function getDmUserIds(room) {
    if (!room || typeof room !== 'object' || !Array.isArray(room.dmUserIds)) return [];
    return room.dmUserIds.map((entry) => String(entry || '')).filter(Boolean);
}

function buildDmRoomId(userIdA, userIdB) {
    const a = String(userIdA || '').trim();
    const b = String(userIdB || '').trim();
    if (!a || !b || a === b) return '';
    const pair = [a, b].sort().join('|');
    const digest = crypto.createHash('sha1').update(pair).digest('hex').slice(0, 24);
    return `dm-${digest}`;
}

function normalizeRoomPinnedMessageIds(room) {
    if (!room || typeof room !== 'object') return [];
    const source = Array.isArray(room.pinnedMessageIds) ? room.pinnedMessageIds : [];
    const out = [];
    for (const entry of source) {
        const value = normalizeChatReplyId(entry);
        if (!value) continue;
        if (out.includes(value)) continue;
        out.push(value);
        if (out.length >= CHAT_PIN_LIMIT) break;
    }
    room.pinnedMessageIds = out;
    return out;
}

function toRoomPublicView(room, viewerUser = null, context = {}) {
    const dmUserIds = getDmUserIds(room);
    const viewerId = String(viewerUser?.id || '');
    const peerId = dmUserIds.find((id) => id !== viewerId) || '';
    const dmNames = room && room.dmUsernames && typeof room.dmUsernames === 'object'
        ? room.dmUsernames
        : {};
    const peerUsername = String(dmNames[peerId] || '');
    const isDm = isDmRoom(room);
    const statuses = context && typeof context.userStatusesById === 'object' ? context.userStatusesById : {};
    const lastSeenByUserId = context && context.lastSeenByUserId instanceof Map ? context.lastSeenByUserId : new Map();
    return {
        id: room.id,
        name: isDm ? (peerUsername || room.name || 'direct-message') : room.name,
        ownerUsername: room.ownerUsername,
        isPrivate: !!room.isPrivate,
        kind: isDm ? 'dm' : 'room',
        isDm,
        dmPeerUserId: isDm ? peerId : '',
        dmPeerUsername: isDm ? (peerUsername || '') : '',
        dmPeerStatus: isDm ? normalizeUserStatus(statuses[peerId]) : 'offline',
        dmPeerLastSeenAt: isDm ? Number(lastSeenByUserId.get(peerId) || 0) : 0,
        pinnedMessageIds: normalizeRoomPinnedMessageIds(room),
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
    if (isDmRoom(room)) {
        const userId = String(authUser?.id || '');
        if (!userId) return false;
        return getDmUserIds(room).includes(userId);
    }
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
        if (isDmRoom(room)) continue;
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
    if (a.id === 'links' && b.id !== 'lobby') return -1;
    if (b.id === 'links' && a.id !== 'lobby') return 1;
    return (b.lastMessageAt || 0) - (a.lastMessageAt || 0);
}

function canDeleteRoom(authUser, room) {
    if (!authUser || !room) return false;
    if (SYSTEM_CHAT_ROOM_IDS.has(room.id)) return false;
    if (isDmRoom(room)) return false;
    const username = sanitizeUsername(authUser.username);
    if (username === 'rift') return true;
    return room.ownerUserId === authUser.id;
}

function canPinRoom(authUser, room) {
    if (!authUser || !room) return false;
    if (isDmRoom(room)) {
        const userId = String(authUser.id || '');
        return !!userId && getDmUserIds(room).includes(userId);
    }
    return isRiftAdminUser(authUser) || room.ownerUserId === authUser.id;
}

function buildDmRoomPresenceContext(db, rooms, viewerUserId, now = Date.now()) {
    const viewerId = String(viewerUserId || '').trim();
    const candidates = Array.isArray(rooms) ? rooms : [];
    const peerIds = new Set();
    for (const room of candidates) {
        if (!isDmRoom(room)) continue;
        const peerId = getDmUserIds(room).find((id) => id !== viewerId);
        if (peerId) peerIds.add(peerId);
    }
    const ids = Array.from(peerIds);
    return {
        userStatusesById: getEffectiveStatusesForUsers(db, ids, now),
        lastSeenByUserId: getLastActiveByUserId(db, ids, now),
    };
}

function sanitizeCallSignalType(input) {
    const value = String(input || '').trim().toLowerCase();
    if (value === 'offer' || value === 'answer' || value === 'ice' || value === 'hangup') return value;
    return '';
}

function sanitizeCallSignalPayload(input) {
    if (typeof input === 'undefined') return null;
    let text = '';
    try {
        text = JSON.stringify(input);
    } catch {
        return null;
    }
    if (!text || text.length > 12000) return null;
    try {
        return JSON.parse(text);
    } catch {
        return null;
    }
}

function pruneChatCallRooms(now = Date.now()) {
    for (const [roomId, callRoom] of chatCallRooms.entries()) {
        if (!callRoom || typeof callRoom !== 'object') {
            chatCallRooms.delete(roomId);
            continue;
        }

        if (!callRoom.members || typeof callRoom.members !== 'object') callRoom.members = {};
        if (!Array.isArray(callRoom.signals)) callRoom.signals = [];

        for (const [memberId, member] of Object.entries(callRoom.members)) {
            const lastSeenAt = Number(member?.lastSeenAt || 0);
            if (lastSeenAt <= 0 || (now - lastSeenAt) > CHAT_CALL_MEMBER_TTL_MS) {
                delete callRoom.members[memberId];
            }
        }

        callRoom.signals = callRoom.signals.filter((signal) => {
            const expiresAt = Number(signal?.expiresAt || 0);
            return expiresAt > now;
        });

        const memberCount = Object.keys(callRoom.members).length;
        if (memberCount <= 0 && callRoom.signals.length <= 0) {
            chatCallRooms.delete(roomId);
        }
    }
}

function getOrCreateChatCallRoom(roomId) {
    const key = String(roomId || '');
    let room = chatCallRooms.get(key);
    if (!room || typeof room !== 'object') {
        room = {
            roomId: key,
            mode: 'voice',
            members: {},
            signals: [],
            createdAt: Date.now(),
            updatedAt: Date.now(),
        };
        chatCallRooms.set(key, room);
    }
    if (!room.members || typeof room.members !== 'object') room.members = {};
    if (!Array.isArray(room.signals)) room.signals = [];
    return room;
}

function toChatCallMembersPublicView(callRoom) {
    if (!callRoom || typeof callRoom !== 'object' || !callRoom.members || typeof callRoom.members !== 'object') {
        return [];
    }
    return Object.values(callRoom.members)
        .filter((entry) => entry && typeof entry === 'object')
        .map((entry) => ({
            userId: String(entry.userId || ''),
            username: String(entry.username || 'user'),
            clientMode: normalizeChatClientMode(entry.clientMode),
            joinedAt: Number(entry.joinedAt || Date.now()),
            wantsVideo: !!entry.wantsVideo,
        }));
}

function sanitizeChatText(input) {
    const text = String(input || '')
        .replace(/\s+/g, ' ')
        .trim();
    if (!text) return '';
    const limited = text.slice(0, 400);
    return limited.replace(/\b[a-z]{3,}\b/gi, (word) => {
        const clean = String(word || '').toLowerCase();
        if (!clean) return word;
        let isBad = CHAT_BAD_WORDS.has(clean);
        if (!isBad) {
            for (const suffix of CHAT_BAD_WORD_SUFFIXES) {
                if (!clean.endsWith(suffix) || clean.length <= suffix.length + 2) continue;
                const base = clean.slice(0, clean.length - suffix.length);
                if (CHAT_BAD_WORDS.has(base)) {
                    isBad = true;
                    break;
                }
            }
        }
        if (!isBad) return word;
        if (word.length <= 2) return word;
        return `${word[0]}${'#'.repeat(word.length - 2)}${word[word.length - 1]}`;
    });
}

function normalizeChatClientMode(input) {
    return 'rift';
}

function normalizeChatReplyId(input) {
    const value = String(input || '').trim();
    if (!value) return '';
    if (value.length > 120) return '';
    return value;
}

function normalizeChatReactionEmoji(input) {
    const value = String(input || '').trim();
    if (!value) return '';
    return CHAT_REACTION_EMOJIS.includes(value) ? value : '';
}

function normalizeMessageReactions(message) {
    if (!message || typeof message !== 'object') return {};
    const source = message.reactions && typeof message.reactions === 'object' ? message.reactions : {};
    const out = {};
    for (const emoji of CHAT_REACTION_EMOJIS) {
        const users = Array.isArray(source[emoji]) ? source[emoji] : [];
        const normalized = [];
        for (const userId of users) {
            const value = String(userId || '').trim();
            if (!value || normalized.includes(value)) continue;
            normalized.push(value);
        }
        if (normalized.length) out[emoji] = normalized;
    }
    message.reactions = out;
    return out;
}

function toChatReactionsPublicView(message, viewerUserId = '') {
    const reactions = normalizeMessageReactions(message);
    const viewerId = String(viewerUserId || '').trim();
    return CHAT_REACTION_EMOJIS
        .map((emoji) => {
            const users = Array.isArray(reactions[emoji]) ? reactions[emoji] : [];
            if (!users.length) return null;
            return {
                emoji,
                count: users.length,
                me: viewerId ? users.includes(viewerId) : false,
            };
        })
        .filter(Boolean);
}

function pruneChatTyping(now = Date.now()) {
    for (const [roomId, roomTyping] of chatTypingRooms.entries()) {
        if (!roomTyping || typeof roomTyping !== 'object') {
            chatTypingRooms.delete(roomId);
            continue;
        }
        for (const [userId, typingState] of Object.entries(roomTyping)) {
            const lastTypingAt = Number(typingState?.lastTypingAt || 0);
            if (!lastTypingAt || (now - lastTypingAt) > CHAT_TYPING_TTL_MS) {
                delete roomTyping[userId];
            }
        }
        if (!Object.keys(roomTyping).length) {
            chatTypingRooms.delete(roomId);
        }
    }
}

function setUserTypingState(roomId, user, typing, clientMode = 'rift', status = 'offline', now = Date.now()) {
    const rid = normalizeRoomName(roomId);
    const userId = String(user?.id || '').trim();
    if (!rid || !userId) return;
    pruneChatTyping(now);
    if (!typing) {
        const roomTyping = chatTypingRooms.get(rid);
        if (roomTyping) {
            delete roomTyping[userId];
            if (!Object.keys(roomTyping).length) chatTypingRooms.delete(rid);
        }
        return;
    }
    const roomTyping = chatTypingRooms.get(rid) || {};
    roomTyping[userId] = {
        userId,
        username: String(user?.username || 'user'),
        clientMode: normalizeChatClientMode(clientMode),
        status: normalizeUserStatus(status),
        lastTypingAt: now,
    };
    chatTypingRooms.set(rid, roomTyping);
}

function getRoomTypingPublicView(roomId, viewerUserId = '', now = Date.now()) {
    pruneChatTyping(now);
    const rid = normalizeRoomName(roomId);
    const roomTyping = chatTypingRooms.get(rid);
    if (!roomTyping || typeof roomTyping !== 'object') return [];
    const viewerId = String(viewerUserId || '').trim();
    return Object.values(roomTyping)
        .filter((entry) => entry && typeof entry === 'object' && String(entry.userId || '') !== viewerId)
        .sort((a, b) => Number(b.lastTypingAt || 0) - Number(a.lastTypingAt || 0))
        .map((entry) => ({
            userId: String(entry.userId || ''),
            username: String(entry.username || 'user'),
            clientMode: normalizeChatClientMode(entry.clientMode),
            status: normalizeUserStatus(entry.status),
            lastTypingAt: Number(entry.lastTypingAt || now),
        }));
}

function resolveRoomPinnedMessagesPublicView(db, room, userStatusesById, viewerUserId = '') {
    if (!room || typeof room !== 'object') return [];
    const pinnedIds = normalizeRoomPinnedMessageIds(room);
    if (!pinnedIds.length) return [];
    const rows = getRoomMessages(db, room.id);
    const byId = new Map(
        rows
            .filter((entry) => entry && typeof entry === 'object')
            .map((entry) => [String(entry.id || ''), entry])
    );
    const out = [];
    const keep = [];
    for (const messageId of pinnedIds) {
        const row = byId.get(messageId);
        if (!row) continue;
        const view = toChatMessagePublicView(row, userStatusesById, viewerUserId);
        if (!view) continue;
        keep.push(messageId);
        out.push(view);
    }
    room.pinnedMessageIds = keep.slice(0, CHAT_PIN_LIMIT);
    return out;
}

function getMessageUserStatus(message, userStatusesById) {
    const userId = String(message?.userId || '').trim();
    if (userId && userStatusesById && typeof userStatusesById === 'object' && Object.prototype.hasOwnProperty.call(userStatusesById, userId)) {
        const status = normalizeUserStatus(userStatusesById[userId]);
        if (status) return status;
    }
    return normalizeUserStatus(message?.status);
}

function collectChatUserIds(messages) {
    if (!Array.isArray(messages)) return [];
    const out = new Set();
    for (const message of messages) {
        if (!message || typeof message !== 'object') continue;
        const userId = String(message.userId || '').trim();
        if (userId) out.add(userId);
        const replyUserId = String(message.replyTo?.userId || '').trim();
        if (replyUserId) out.add(replyUserId);
    }
    return Array.from(out);
}

function toChatReplyStub(message, userStatusesById) {
    if (!message || typeof message !== 'object') return null;
    return {
        id: String(message.id || ''),
        userId: String(message.userId || ''),
        username: String(message.username || 'user'),
        text: sanitizeChatText(message.text || ''),
        createdAt: Number(message.createdAt) || Date.now(),
        clientMode: normalizeChatClientMode(message.clientMode),
        status: getMessageUserStatus(message, userStatusesById),
    };
}

function toChatMessagePublicView(message, userStatusesById, viewerUserId = '') {
    if (!message || typeof message !== 'object') return null;
    return {
        id: String(message.id || ''),
        roomId: String(message.roomId || ''),
        userId: String(message.userId || ''),
        username: String(message.username || 'user'),
        text: sanitizeChatText(message.text || ''),
        createdAt: Number(message.createdAt) || Date.now(),
        clientMode: normalizeChatClientMode(message.clientMode),
        status: getMessageUserStatus(message, userStatusesById),
        reactions: toChatReactionsPublicView(message, viewerUserId),
        replyTo: message.replyTo ? toChatReplyStub(message.replyTo, userStatusesById) : null,
    };
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
    if (
        pathname.startsWith('/assets/') ||
        pathname.startsWith('/components/') ||
        pathname.startsWith('/scramjet/') ||
        pathname.startsWith('/baremux/') ||
        pathname.startsWith('/libcurl/') ||
        pathname.startsWith('/epoxy/') ||
        pathname.startsWith('/uv/')
    ) {
        return false;
    }
    return /\.(?:js|mjs|css|json|map|png|jpe?g|webp|gif|svg|ico|woff2?|ttf|otf|eot|mp3|ogg|wav|m4a|aac|flac|wasm|unityweb|data|bin|txt|xml)(?:$|\?)/i.test(pathname);
}

async function hostnamePointsToAllowedIp(hostname) {
    if (VALIDATE_TARGET_IPS.length === 0) {
        return true;
    }

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

app.get(['/tinyjet', '/tinyjet/'], (_req, res) => {
    return res.sendFile(path.join(PUBLIC_DIR, 'tinyjet', 'index.html'));
});

app.use(express.static(PUBLIC_DIR, { redirect: false }));
app.use('/assets', express.static(path.join(__dirname, '..', 'assets')));
app.use('/components', express.static(path.join(__dirname, '..', 'components')));
app.use('/scramjet', express.static(path.join(__dirname, '..', 'node_modules', '@mercuryworkshop', 'scramjet', 'dist')));
app.use('/controller', express.static(path.join(__dirname, '..', 'node_modules', '@mercuryworkshop', 'scramjet-controller', 'dist')));
app.use('/baremux', express.static(path.join(__dirname, '..', 'node_modules', '@mercuryworkshop', 'bare-mux', 'dist')));
app.use('/libcurl', express.static(path.join(__dirname, '..', 'node_modules', '@mercuryworkshop', 'libcurl-transport', 'dist')));
app.use('/epoxy', express.static(path.join(__dirname, '..', 'node_modules', '@mercuryworkshop', 'epoxy-transport', 'dist')));
app.use('/uv', express.static(uvPath));

if (ENABLE_VELARA) {
    app.all(/^\/astra(?:\/(.*))?$/, async (req, res) => {
        const tail = req.params?.[0] || '';
        return proxyVelara(req, res, '/astra', tail);
    });

    app.all(/^\/astra-accounts(?:\/(.*))?$/, async (req, res) => {
        const tail = req.params?.[0] || '';
        return proxyVelara(req, res, '/astra-accounts', tail);
    });
}

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

        const clientIp = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').split(',')[0].trim();
        if (!checkLoginRateLimit(clientIp, username)) {
            return jsonError(res, 429, 'Too many login attempts. Please try again later.');
        }

        const db = await readAuthDb();
        const user = db.users.find((u) => u.username === username);
        if (!user) return jsonError(res, 401, 'Invalid username or password.');

        const expected = hashPassword(password, user.passwordSalt);
        if (expected !== user.passwordHash) {
            return jsonError(res, 401, 'Invalid username or password.');
        }

        clearLoginRateLimit(clientIp, username);
        const now = Date.now();
        const token = createToken();
        const expiresAt = now + SESSION_TTL_MS;
        await updateAuthDb((nextDb) => {
            nextDb.sessions = nextDb.sessions.filter((s) => s.expiresAt > now);
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
        if (shouldPersistSessionTouch(auth.token, now)) {
            await updateAuthDb((db) => {
                const session = db.sessions.find((s) => s.token === auth.token);
                if (session) {
                    session.lastSeenAt = now;
                }
                return db;
            });
        }

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
        if (shouldPersistSessionTouch(auth.token, now)) {
            await updateAuthDb((db) => {
                const session = db.sessions.find((s) => s.token === auth.token);
                if (session) session.lastSeenAt = now;
                return db;
            });
        }
        return res.json({ ok: true, authenticated: true, now });
    } catch (error) {
        return jsonError(res, 500, `Ping failed: ${error.message}`);
    }
});

app.get('/api/status/me', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const db = await readAuthDb();
        const now = Date.now();
        const mode = getUserStatusMode(db, auth.user.id);
        const status = getEffectiveUserStatus(db, auth.user.id, now);
        return res.json({ ok: true, mode, status, now });
    } catch (error) {
        return jsonError(res, 500, `Status read failed: ${error.message}`);
    }
});

app.put('/api/status/me', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const mode = parseUserStatusModeInput(req.body?.mode);
        if (!mode) return jsonError(res, 400, 'Invalid status mode');
        const now = Date.now();
        await updateAuthDb((db) => {
            if (!db.userStatusPrefs || typeof db.userStatusPrefs !== 'object') {
                db.userStatusPrefs = {};
            }
            db.userStatusPrefs[String(auth.user.id)] = {
                mode,
                updatedAt: now,
            };
            return db;
        });
        const db = await readAuthDb();
        const status = getEffectiveUserStatus(db, auth.user.id, now);
        return res.json({ ok: true, mode, status, now });
    } catch (error) {
        return jsonError(res, 500, `Status update failed: ${error.message}`);
    }
});

attachCloudControlRoutes({
    app,
    readAuthDb,
    updateAuthDb,
    getSessionFromRequest,
    jsonError,
});

app.get('/api/nowgg/resolve', async (req, res) => {
    try {
        const rawUrl = String(req.query?.url || '').trim();
        if (!rawUrl) return jsonError(res, 400, 'Missing now.gg target url');

        let targetUrl;
        try {
            targetUrl = new URL(rawUrl).href;
        } catch {
            return jsonError(res, 400, 'Invalid target url');
        }

        const parsed = new URL(targetUrl);
        if (!isResolvableNowggHost(parsed.hostname)) {
            return jsonError(res, 400, 'Unsupported now.gg host');
        }

        const resolved = await resolveNowggLaunchUrl(targetUrl);
        return res.json({
            ok: true,
            ...resolved,
        });
    } catch (error) {
        return jsonError(res, 502, `now.gg resolve failed: ${error.message}`);
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
            if (Number.isFinite(launchDelta) && launchDelta > 0) {
                applyActivityDelta(save, { gameLaunches: launchDelta }, Date.now());
            }
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

app.get('/api/profile/me', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const db = await readAuthDb();
        const user = (Array.isArray(db.users) ? db.users : []).find((entry) => entry?.id === auth.user.id) || auth.user;
        return res.json({ ok: true, profile: toProfileCardPublicView(db, user, Date.now()) });
    } catch (error) {
        return jsonError(res, 500, `Profile read failed: ${error.message}`);
    }
});

app.put('/api/profile/me', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const input = req.body?.profile && typeof req.body.profile === 'object'
            ? req.body.profile
            : (req.body && typeof req.body === 'object' ? req.body : null);
        if (!input) return jsonError(res, 400, 'profile object is required');
        const now = Date.now();
        let profileView = null;
        await updateAuthDb((db) => {
            const users = Array.isArray(db.users) ? db.users : [];
            const user = users.find((entry) => entry?.id === auth.user.id) || auth.user;
            const save = getUserSave(db, auth.user.id);
            const next = normalizeProfileCard({
                tagline: input.tagline,
                bio: input.bio,
                accent: input.accent,
                favoriteGameId: input.favoriteGameId,
                favoriteGameName: input.favoriteGameName,
                updatedAt: now,
            });
            save.profile = next;
            profileView = toProfileCardPublicView(db, user, now);
            return db;
        });
        return res.json({ ok: true, profile: profileView });
    } catch (error) {
        return jsonError(res, 500, `Profile update failed: ${error.message}`);
    }
});

app.get('/api/profile/:username', async (req, res, next) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const rawUsername = String(req.params?.username || '').trim().toLowerCase();
        if (rawUsername === 'presets' || rawUsername === 'me' || rawUsername === 'customization') {
            return next();
        }
        const username = sanitizeUsername(rawUsername);
        if (!username) return jsonError(res, 400, 'Invalid username');
        const db = await readAuthDb();
        const users = Array.isArray(db.users) ? db.users : [];
        const user = users.find((entry) => sanitizeUsername(entry?.username || '') === username);
        if (!user) return jsonError(res, 404, 'User not found');
        return res.json({ ok: true, profile: toProfileCardPublicView(db, user, Date.now()) });
    } catch (error) {
        return jsonError(res, 500, `Profile lookup failed: ${error.message}`);
    }
});

app.get('/api/achievements/me', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const now = Date.now();
        let achievements = [];
        let stats = null;
        await updateAuthDb((db) => {
            const save = getUserSave(db, auth.user.id);
            achievements = evaluateAchievements(save, { persist: true, now });
            stats = computeSaveStats(save);
            return db;
        });
        const unlocked = achievements.filter((entry) => entry.unlocked);
        return res.json({
            ok: true,
            achievements,
            summary: {
                unlocked: unlocked.length,
                total: achievements.length,
                stats,
            },
        });
    } catch (error) {
        return jsonError(res, 500, `Achievements read failed: ${error.message}`);
    }
});

app.get('/api/quests/daily/me', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const db = await readAuthDb();
        const save = getUserSave(db, auth.user.id);
        const now = Date.now();
        const quests = computeDailyQuestRows(save, now);
        const completed = quests.filter((row) => !!row.complete);
        const xpReward = completed.reduce((sum, row) => sum + Number(row.xp || 0), 0);
        return res.json({ ok: true, quests, summary: { completed: completed.length, total: quests.length, xpReward }, now });
    } catch (error) {
        return jsonError(res, 500, `Daily quests failed: ${error.message}`);
    }
});

app.get('/api/season/current', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const db = await readAuthDb();
        const save = getUserSave(db, auth.user.id);
        const now = Date.now();
        const season = getCurrentSeasonEvent(now);
        const progression = computeProfileProgression(save, now);
        return res.json({ ok: true, season, badges: progression.badges, now });
    } catch (error) {
        return jsonError(res, 500, `Season read failed: ${error.message}`);
    }
});

app.get('/api/profile/customization/me', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const db = await readAuthDb();
        const save = getUserSave(db, auth.user.id);
        const now = Date.now();
        const style = getProfileStyleForUser(save, now);
        return res.json({
            ok: true,
            style,
            themes: PROFILE_THEME_DEFS,
            frameEffects: PROFILE_FRAME_EFFECTS,
            accentAnimations: PROFILE_ACCENT_ANIMATIONS,
            now,
        });
    } catch (error) {
        return jsonError(res, 500, `Customization read failed: ${error.message}`);
    }
});

app.put('/api/profile/customization/me', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const input = req.body?.style && typeof req.body.style === 'object'
            ? req.body.style
            : (req.body && typeof req.body === 'object' ? req.body : null);
        if (!input) return jsonError(res, 400, 'style object is required');
        let styleView = null;
        await updateAuthDb((db) => {
            const save = getUserSave(db, auth.user.id);
            const now = Date.now();
            const unlockedThemes = getUnlockedProfileThemeIds(save, now);
            const next = normalizeProfileStyle({
                themeId: input.themeId,
                frameEffect: input.frameEffect,
                accentAnimation: input.accentAnimation,
                presetCode: input.presetCode,
                updatedAt: now,
            });
            if (!unlockedThemes.includes(next.themeId)) {
                throw new Error('THEME_LOCKED');
            }
            save.profileStyle = next;
            if (input.accent) {
                save.profile = normalizeProfileCard({
                    ...save.profile,
                    accent: normalizeHexColor(input.accent, save.profile?.accent || '#8ecbff'),
                    updatedAt: now,
                });
            }
            styleView = getProfileStyleForUser(save, now);
            return db;
        });
        return res.json({ ok: true, style: styleView });
    } catch (error) {
        if (error.message === 'THEME_LOCKED') return jsonError(res, 403, 'Theme is locked');
        return jsonError(res, 500, `Customization update failed: ${error.message}`);
    }
});

app.get('/api/profile/presets', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const db = await readAuthDb();
        const save = getUserSave(db, auth.user.id);
        const ownedCodes = new Set((save.profilePresets || []).map((entry) => normalizePresetCode(entry)).filter(Boolean));
        for (const builtIn of BUILTIN_PROFILE_PRESETS) {
            const code = normalizePresetCode(builtIn.code);
            if (code) ownedCodes.add(code);
        }
        const shared = getThemePresetMarket(db);
        const rows = [...BUILTIN_PROFILE_PRESETS, ...shared]
            .map((entry) => {
                const code = normalizePresetCode(entry.code);
                if (!code) return null;
                return toThemePresetPublicView(entry, { owned: ownedCodes.has(code) });
            })
            .filter(Boolean)
            .slice(0, PROFILE_PRESET_SHARE_LIMIT);
        return res.json({ ok: true, presets: rows, ownedCodes: Array.from(ownedCodes) });
    } catch (error) {
        return jsonError(res, 500, `Preset list failed: ${error.message}`);
    }
});

app.post('/api/profile/presets/share', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const name = sanitizeProfileShort(req.body?.name || '', 60);
        if (!name) return jsonError(res, 400, 'Preset name is required');
        const style = normalizeProfileStyle(req.body?.style || req.body);
        const accent = normalizeHexColor(req.body?.accent || '#8ecbff', '#8ecbff');
        let created = null;
        await updateAuthDb((db) => {
            const market = getThemePresetMarket(db);
            if (market.length >= PROFILE_PRESET_SHARE_LIMIT) {
                market.shift();
            }
            const existingCodes = new Set([
                ...BUILTIN_PROFILE_PRESETS.map((entry) => normalizePresetCode(entry.code)),
                ...market.map((entry) => normalizePresetCode(entry.code)),
            ]);
            let code = '';
            for (let i = 0; i < 20; i += 1) {
                const candidate = crypto.randomBytes(4).toString('hex').toUpperCase().slice(0, 8);
                if (existingCodes.has(candidate)) continue;
                code = candidate;
                break;
            }
            if (!code) code = crypto.randomBytes(5).toString('hex').toUpperCase().slice(0, 10);
            created = {
                id: crypto.randomUUID(),
                code,
                name,
                creatorUserId: String(auth.user.id || ''),
                creatorUsername: String(auth.user.username || 'user'),
                style,
                accent,
                createdAt: Date.now(),
            };
            market.unshift(created);
            db.themePresetMarket = market.slice(0, PROFILE_PRESET_SHARE_LIMIT);
            const save = getUserSave(db, auth.user.id);
            if (!save.profilePresets.includes(code)) save.profilePresets.push(code);
            save.profilePresets = save.profilePresets.slice(0, 500);
            return db;
        });
        return res.json({ ok: true, preset: toThemePresetPublicView(created, { owned: true }) });
    } catch (error) {
        return jsonError(res, 500, `Preset share failed: ${error.message}`);
    }
});

app.post('/api/profile/presets/import', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const code = normalizePresetCode(req.body?.code || '');
        if (!code) return jsonError(res, 400, 'Valid preset code is required');
        let preset = null;
        let style = null;
        await updateAuthDb((db) => {
            const market = getThemePresetMarket(db);
            preset = [...BUILTIN_PROFILE_PRESETS, ...market].find((entry) => normalizePresetCode(entry.code) === code) || null;
            if (!preset) throw new Error('PRESET_NOT_FOUND');
            const save = getUserSave(db, auth.user.id);
            const now = Date.now();
            const nextStyle = normalizeProfileStyle({
                ...preset.style,
                presetCode: code,
                updatedAt: now,
            });
            const unlocked = getUnlockedProfileThemeIds(save, now);
            if (!unlocked.includes(nextStyle.themeId)) {
                nextStyle.themeId = 'classic';
            }
            save.profileStyle = nextStyle;
            if (preset.accent) {
                save.profile = normalizeProfileCard({
                    ...save.profile,
                    accent: normalizeHexColor(preset.accent, save.profile?.accent || '#8ecbff'),
                    updatedAt: now,
                });
            }
            if (!save.profilePresets.includes(code)) save.profilePresets.push(code);
            save.profilePresets = save.profilePresets.slice(0, 500);
            style = getProfileStyleForUser(save, now);
            return db;
        });
        return res.json({ ok: true, code, style, preset: toThemePresetPublicView(preset, { owned: true }) });
    } catch (error) {
        if (error.message === 'PRESET_NOT_FOUND') return jsonError(res, 404, 'Preset code not found');
        return jsonError(res, 500, `Preset import failed: ${error.message}`);
    }
});

app.get('/api/games/collections', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const db = await readAuthDb();
        const save = getUserSave(db, auth.user.id);
        return res.json({ ok: true, collections: normalizeCollections(save.collections) });
    } catch (error) {
        return jsonError(res, 500, `Collection list failed: ${error.message}`);
    }
});

app.post('/api/games/collections', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const name = sanitizeCollectionName(req.body?.name);
        if (!name) return jsonError(res, 400, 'Collection name is required');
        let created = null;
        await updateAuthDb((db) => {
            const save = getUserSave(db, auth.user.id);
            const collections = normalizeCollections(save.collections);
            if (collections.length >= 80) throw new Error('COLLECTION_LIMIT');
            const now = Date.now();
            created = {
                id: `col-${crypto.randomUUID().slice(0, 12)}`,
                name,
                createdAt: now,
                updatedAt: now,
                games: [],
            };
            save.collections = [created, ...collections];
            return db;
        });
        return res.json({ ok: true, collection: created });
    } catch (error) {
        if (error.message === 'COLLECTION_LIMIT') return jsonError(res, 409, 'Collection limit reached (80)');
        return jsonError(res, 500, `Collection create failed: ${error.message}`);
    }
});

app.put('/api/games/collections/:collectionId', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const collectionId = normalizeCollectionId(req.params?.collectionId || '');
        if (!collectionId) return jsonError(res, 400, 'Invalid collection id');
        const nextName = sanitizeCollectionName(req.body?.name);
        if (!nextName) return jsonError(res, 400, 'Collection name is required');
        let updated = null;
        await updateAuthDb((db) => {
            const save = getUserSave(db, auth.user.id);
            const collections = normalizeCollections(save.collections);
            const collection = collections.find((entry) => entry.id === collectionId);
            if (!collection) throw new Error('NOT_FOUND');
            collection.name = nextName;
            collection.updatedAt = Date.now();
            save.collections = collections;
            updated = collection;
            return db;
        });
        return res.json({ ok: true, collection: updated });
    } catch (error) {
        if (error.message === 'NOT_FOUND') return jsonError(res, 404, 'Collection not found');
        return jsonError(res, 500, `Collection update failed: ${error.message}`);
    }
});

app.delete('/api/games/collections/:collectionId', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const collectionId = normalizeCollectionId(req.params?.collectionId || '');
        if (!collectionId) return jsonError(res, 400, 'Invalid collection id');
        await updateAuthDb((db) => {
            const save = getUserSave(db, auth.user.id);
            const collections = normalizeCollections(save.collections);
            const next = collections.filter((entry) => entry.id !== collectionId);
            if (next.length === collections.length) throw new Error('NOT_FOUND');
            save.collections = next;
            return db;
        });
        return res.json({ ok: true, deletedCollectionId: collectionId });
    } catch (error) {
        if (error.message === 'NOT_FOUND') return jsonError(res, 404, 'Collection not found');
        return jsonError(res, 500, `Collection delete failed: ${error.message}`);
    }
});

app.post('/api/games/collections/:collectionId/games', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const collectionId = normalizeCollectionId(req.params?.collectionId || '');
        if (!collectionId) return jsonError(res, 400, 'Invalid collection id');
        const gameId = normalizeCollectionGameId(req.body?.gameId);
        if (!gameId) return jsonError(res, 400, 'gameId is required');
        const gameName = sanitizeProfileShort(req.body?.gameName || '', 120);
        let updated = null;
        await updateAuthDb((db) => {
            const save = getUserSave(db, auth.user.id);
            const collections = normalizeCollections(save.collections);
            const collection = collections.find((entry) => entry.id === collectionId);
            if (!collection) throw new Error('NOT_FOUND');
            const now = Date.now();
            const existing = collection.games.find((entry) => entry.id === gameId);
            if (existing) {
                existing.name = gameName || existing.name || '';
                existing.addedAt = now;
            } else {
                collection.games.unshift({
                    id: gameId,
                    name: gameName || '',
                    addedAt: now,
                });
                if (collection.games.length > 300) collection.games = collection.games.slice(0, 300);
            }
            collection.updatedAt = now;
            save.collections = collections;
            updated = collection;
            return db;
        });
        return res.json({ ok: true, collection: updated });
    } catch (error) {
        if (error.message === 'NOT_FOUND') return jsonError(res, 404, 'Collection not found');
        return jsonError(res, 500, `Collection game add failed: ${error.message}`);
    }
});

app.delete('/api/games/collections/:collectionId/games/:gameId', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const collectionId = normalizeCollectionId(req.params?.collectionId || '');
        if (!collectionId) return jsonError(res, 400, 'Invalid collection id');
        const gameId = normalizeCollectionGameId(req.params?.gameId || '');
        if (!gameId) return jsonError(res, 400, 'Invalid game id');
        let updated = null;
        await updateAuthDb((db) => {
            const save = getUserSave(db, auth.user.id);
            const collections = normalizeCollections(save.collections);
            const collection = collections.find((entry) => entry.id === collectionId);
            if (!collection) throw new Error('NOT_FOUND');
            const before = collection.games.length;
            collection.games = collection.games.filter((entry) => entry.id !== gameId);
            if (before === collection.games.length) throw new Error('GAME_NOT_FOUND');
            collection.updatedAt = Date.now();
            save.collections = collections;
            updated = collection;
            return db;
        });
        return res.json({ ok: true, collection: updated, removedGameId: gameId });
    } catch (error) {
        if (error.message === 'NOT_FOUND') return jsonError(res, 404, 'Collection not found');
        if (error.message === 'GAME_NOT_FOUND') return jsonError(res, 404, 'Game not found in collection');
        return jsonError(res, 500, `Collection game remove failed: ${error.message}`);
    }
});

app.get('/api/party', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const db = await readAuthDb();
        const party = getPartyForUser(db, auth.user.id);
        const view = party ? toPartyPublicView(db, party, auth.user.id, Date.now()) : null;
        return res.json({ ok: true, party: view });
    } catch (error) {
        return jsonError(res, 500, `Party read failed: ${error.message}`);
    }
});

app.post('/api/party/create', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const name = sanitizePartyName(req.body?.name) || `${auth.user.username}'s party`;
        const gameId = normalizeCollectionGameId(req.body?.gameId || '');
        const gameName = sanitizeProfileShort(req.body?.gameName || '', 120);
        const musicTrack = normalizePartyMusicTrack(req.body?.musicTrack || req.body?.track)
            || normalizePartyMusicTrack({ title: gameName || '', trackId: gameId || '' });
        let partyView = null;
        await updateAuthDb((db) => {
            const parties = getPartyMap(db);
            const existing = getPartyForUser(db, auth.user.id);
            if (existing && existing.id) {
                leavePartyInternal(db, existing.id, auth.user.id);
            }
            const now = Date.now();
            const id = `party-${crypto.randomUUID().slice(0, 12)}`;
            const code = createPartyCode(parties);
            parties[id] = {
                id,
                code,
                name,
                ownerUserId: String(auth.user.id || ''),
                ownerUsername: String(auth.user.username || 'user'),
                gameId: gameId || '',
                gameName: gameName || '',
                musicTrack: musicTrack || null,
                createdAt: now,
                updatedAt: now,
                members: [{
                    userId: String(auth.user.id || ''),
                    username: String(auth.user.username || 'user'),
                    joinedAt: now,
                    lastSeenAt: now,
                }],
            };
            const save = getUserSave(db, auth.user.id);
            save.partyJoins = Number(save.partyJoins || 0) + 1;
            partyView = toPartyPublicView(db, parties[id], auth.user.id, now);
            return db;
        });
        return res.json({ ok: true, party: partyView });
    } catch (error) {
        return jsonError(res, 500, `Party create failed: ${error.message}`);
    }
});

app.post('/api/party/join', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const code = sanitizePartyCode(req.body?.code);
        if (!code) return jsonError(res, 400, 'Party code is required');
        let partyView = null;
        await updateAuthDb((db) => {
            const parties = getPartyMap(db);
            const target = Object.values(parties).find((party) => sanitizePartyCode(party?.code) === code);
            if (!target || !target.id) throw new Error('PARTY_NOT_FOUND');
            const now = Date.now();
            const userId = String(auth.user.id || '');
            const members = Array.isArray(target.members) ? target.members : [];
            const existingMember = members.find((member) => String(member?.userId || '') === userId);
            const current = getPartyForUser(db, userId);
            if (current && current.id && current.id !== target.id) {
                leavePartyInternal(db, current.id, userId);
            }
            if (existingMember) {
                existingMember.lastSeenAt = now;
            } else {
                if (members.length >= 24) throw new Error('PARTY_FULL');
                members.push({
                    userId,
                    username: String(auth.user.username || 'user'),
                    joinedAt: now,
                    lastSeenAt: now,
                });
                target.members = members;
                const save = getUserSave(db, auth.user.id);
                save.partyJoins = Number(save.partyJoins || 0) + 1;
            }
            target.updatedAt = now;
            parties[target.id] = target;
            partyView = toPartyPublicView(db, target, auth.user.id, now);
            return db;
        });
        return res.json({ ok: true, party: partyView });
    } catch (error) {
        if (error.message === 'PARTY_NOT_FOUND') return jsonError(res, 404, 'Party not found');
        if (error.message === 'PARTY_FULL') return jsonError(res, 409, 'Party is full');
        return jsonError(res, 500, `Party join failed: ${error.message}`);
    }
});

app.post('/api/party/leave', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        let left = false;
        await updateAuthDb((db) => {
            const current = getPartyForUser(db, auth.user.id);
            if (!current || !current.id) return db;
            left = true;
            leavePartyInternal(db, current.id, auth.user.id);
            return db;
        });
        return res.json({ ok: true, left });
    } catch (error) {
        return jsonError(res, 500, `Party leave failed: ${error.message}`);
    }
});

app.put('/api/party/music', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const clear = req.body?.clear === true;
        const musicTrack = clear
            ? null
            : normalizePartyMusicTrack(req.body?.musicTrack || req.body?.track || req.body);
        if (!clear && !musicTrack) return jsonError(res, 400, 'musicTrack.title is required');
        let partyView = null;
        await updateAuthDb((db) => {
            const current = getPartyForUser(db, auth.user.id);
            if (!current || !current.id) throw new Error('PARTY_NOT_FOUND');
            if (String(current.ownerUserId || '') !== String(auth.user.id || '')) {
                throw new Error('OWNER_ONLY');
            }
            current.musicTrack = musicTrack;
            current.gameName = sanitizeProfileShort(musicTrack?.title || '', 120);
            current.gameId = normalizeCollectionGameId(musicTrack?.trackId || '');
            current.updatedAt = Date.now();
            partyView = toPartyPublicView(db, current, auth.user.id, Date.now());
            return db;
        });
        return res.json({ ok: true, party: partyView });
    } catch (error) {
        if (error.message === 'PARTY_NOT_FOUND') return jsonError(res, 404, 'Party not found');
        if (error.message === 'OWNER_ONLY') return jsonError(res, 403, 'Only party owner can set track');
        return jsonError(res, 500, `Party track update failed: ${error.message}`);
    }
});

app.put('/api/party/game', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const gameId = normalizeCollectionGameId(req.body?.gameId || '');
        const gameName = sanitizeProfileShort(req.body?.gameName || '', 120);
        let partyView = null;
        await updateAuthDb((db) => {
            const current = getPartyForUser(db, auth.user.id);
            if (!current || !current.id) throw new Error('PARTY_NOT_FOUND');
            if (String(current.ownerUserId || '') !== String(auth.user.id || '')) {
                throw new Error('OWNER_ONLY');
            }
            current.gameId = gameId;
            current.gameName = gameName;
            current.musicTrack = normalizePartyMusicTrack({ title: gameName || '', trackId: gameId || '' });
            current.updatedAt = Date.now();
            partyView = toPartyPublicView(db, current, auth.user.id, Date.now());
            return db;
        });
        return res.json({ ok: true, party: partyView });
    } catch (error) {
        if (error.message === 'PARTY_NOT_FOUND') return jsonError(res, 404, 'Party not found');
        if (error.message === 'OWNER_ONLY') return jsonError(res, 403, 'Only party owner can set track');
        return jsonError(res, 500, `Party game update failed: ${error.message}`);
    }
});

function decodeHtmlEntities(text) {
    return String(text || '')
        .replace(/&amp;/g, '&')
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'")
        .replace(/&apos;/g, "'")
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&#(\d+);/g, (_, num) => {
            const code = Number.parseInt(num, 10);
            return Number.isFinite(code) ? String.fromCharCode(code) : '';
        });
}

function stripHtmlTags(text) {
    return decodeHtmlEntities(String(text || '').replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim();
}

function buildMyinstantsAudioProxy(url) {
    const raw = String(url || '').trim();
    if (!raw) return '';
    return `/proxy?url=${encodeURIComponent(raw)}`;
}

function extractMyinstantsCandidates(html) {
    const candidates = [];
    const seen = new Set();
    const anchorRe = /<a\b([^>]*?)href=(["'])(\/en\/instant\/[^"'?#<>]+\/?)\2([^>]*)>([\s\S]*?)<\/a>/gi;
    let match;
    while ((match = anchorRe.exec(String(html || '')))) {
        const beforeAttrs = String(match[1] || '');
        const href = String(match[3] || '').trim();
        const afterAttrs = String(match[4] || '');
        const innerHtml = String(match[5] || '');
        const absoluteUrl = new URL(href, MYINSTANTS_BASE).href;
        if (seen.has(absoluteUrl)) continue;
        seen.add(absoluteUrl);

        const titleAttr = (beforeAttrs + afterAttrs).match(/\btitle=(["'])(.*?)\1/i);
        const label = stripHtmlTags(innerHtml) || stripHtmlTags(titleAttr?.[2] || '') || href.split('/').filter(Boolean).pop() || 'instant';
        candidates.push({
            pageUrl: absoluteUrl,
            title: label,
        });
    }
    return candidates;
}

function extractMyinstantsMediaUrl(html, pageUrl) {
    const source = String(html || '');
    const patterns = [
        /href=(["'])(\/media\/sounds\/[^"'<>]+?\.(?:mp3|wav|ogg)(?:\?[^"'<>]*)?)\1/i,
        /(?:play|Play|new\s+Audio)\((["'])(\/media\/sounds\/[^"'<>]+?\.(?:mp3|wav|ogg)(?:\?[^"'<>]*)?)\1/i,
        /(?:src|data-src)=(["'])(https?:\/\/[^"'<>]+\/media\/sounds\/[^"'<>]+?\.(?:mp3|wav|ogg)(?:\?[^"'<>]*)?)\1/i,
    ];

    for (const pattern of patterns) {
        const match = source.match(pattern);
        if (!match?.[2]) continue;
        try {
            return new URL(match[2], pageUrl || MYINSTANTS_BASE).href;
        } catch {
        }
    }

    return '';
}

async function fetchMyinstantsButtons(query) {
    const trimmedQuery = String(query || '').trim().slice(0, 80);
    const sourceUrl = trimmedQuery
        ? `${MYINSTANTS_BASE}/en/search/?name=${encodeURIComponent(trimmedQuery)}`
        : `${MYINSTANTS_BASE}/en/`;

    const listingRes = await fetch(sourceUrl, {
        headers: {
            'User-Agent': 'Rift-Soundboard/1.0',
            'Accept-Language': 'en-US,en;q=0.9',
        },
    });
    if (!listingRes.ok) {
        throw new Error(`Myinstants listing failed (${listingRes.status})`);
    }

    const listingHtml = await listingRes.text();
    const candidates = extractMyinstantsCandidates(listingHtml).slice(0, MYINSTANTS_RESULT_LIMIT);
    const resolved = await Promise.allSettled(candidates.map(async (candidate, index) => {
        const pageRes = await fetch(candidate.pageUrl, {
            headers: {
                'User-Agent': 'Rift-Soundboard/1.0',
                'Accept-Language': 'en-US,en;q=0.9',
            },
        });
        if (!pageRes.ok) {
            throw new Error(`page lookup failed (${pageRes.status})`);
        }
        const pageHtml = await pageRes.text();
        const mediaUrl = extractMyinstantsMediaUrl(pageHtml, candidate.pageUrl);
        if (!mediaUrl) {
            throw new Error('no media file found');
        }
        return {
            id: `myinstants:${index}:${Buffer.from(candidate.pageUrl).toString('base64').replace(/[+=/]/g, '').slice(0, 16)}`,
            provider: 'myinstants',
            title: candidate.title,
            pageUrl: candidate.pageUrl,
            mediaUrl,
            streamUrl: buildMyinstantsAudioProxy(mediaUrl),
        };
    }));

    return resolved
        .filter((entry) => entry.status === 'fulfilled' && entry.value?.mediaUrl)
        .map((entry) => entry.value);
}

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

app.get('/api/music/soundboard/myinstants', async (req, res) => {
    try {
        const query = String(req.query?.q || '').trim().slice(0, 80);
        const clips = await fetchMyinstantsButtons(query);
        res.setHeader('Cache-Control', 'private, max-age=120');
        return res.json({
            ok: true,
            provider: 'myinstants',
            query,
            clips,
            sourceUrl: query
                ? `${MYINSTANTS_BASE}/en/search/?name=${encodeURIComponent(query)}`
                : `${MYINSTANTS_BASE}/en/`,
        });
    } catch (error) {
        return jsonError(res, 500, `Myinstants soundboard failed: ${error.message}`);
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
                    applyActivityDelta(save, { musicActions: 1 }, Date.now());
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

app.get('/api/chat/friends', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const db = await readAuthDb();
        const payload = getFriendPayloadForUser(db, auth.user.id, Date.now());
        return res.json({ ok: true, ...payload });
    } catch (error) {
        return jsonError(res, 500, `Friend list failed: ${error.message}`);
    }
});

app.post('/api/chat/friends', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const action = String(req.body?.action || '').trim().toLowerCase();
        const targetUserIdInput = String(req.body?.targetUserId || '').trim();
        const targetUsernameInput = sanitizeUsername(req.body?.targetUsername);
        if (!['add', 'remove', 'block', 'unblock'].includes(action)) {
            return jsonError(res, 400, 'Invalid action');
        }
        if (!targetUserIdInput && !targetUsernameInput) {
            return jsonError(res, 400, 'targetUserId or targetUsername is required');
        }

        await updateAuthDb((db) => {
            const users = Array.isArray(db.users) ? db.users : [];
            const targetUser = users.find((user) => {
                if (!user || typeof user !== 'object') return false;
                if (targetUserIdInput && String(user.id || '') === targetUserIdInput) return true;
                if (targetUsernameInput && sanitizeUsername(user.username) === targetUsernameInput) return true;
                return false;
            });
            if (!targetUser) throw new Error('TARGET_NOT_FOUND');

            const meId = String(auth.user?.id || '');
            const targetId = String(targetUser.id || '');
            if (!meId || !targetId || meId === targetId) throw new Error('CANNOT_TARGET_SELF');

            const meSave = getUserSave(db, meId);
            const targetSave = getUserSave(db, targetId);
            const meSocial = getUserSocial(meSave);
            const targetSocial = getUserSocial(targetSave);

            if (action === 'add') {
                if (targetSocial.blocked.includes(meId)) throw new Error('BLOCKED_BY_TARGET');
                meSocial.blocked = meSocial.blocked.filter((id) => id !== targetId);
                if (!meSocial.friends.includes(targetId)) meSocial.friends.push(targetId);
                if (!targetSocial.friends.includes(meId)) targetSocial.friends.push(meId);
                meSocial.friends = normalizeSocialUserIds(meSocial.friends, 500);
                targetSocial.friends = normalizeSocialUserIds(targetSocial.friends, 500);
                return db;
            }

            if (action === 'remove') {
                meSocial.friends = meSocial.friends.filter((id) => id !== targetId);
                targetSocial.friends = targetSocial.friends.filter((id) => id !== meId);
                return db;
            }

            if (action === 'block') {
                if (!meSocial.blocked.includes(targetId)) meSocial.blocked.push(targetId);
                meSocial.blocked = normalizeSocialUserIds(meSocial.blocked, 500);
                meSocial.friends = meSocial.friends.filter((id) => id !== targetId);
                targetSocial.friends = targetSocial.friends.filter((id) => id !== meId);
                return db;
            }

            if (action === 'unblock') {
                meSocial.blocked = meSocial.blocked.filter((id) => id !== targetId);
                return db;
            }

            return db;
        });

        const dbAfter = await readAuthDb();
        const payload = getFriendPayloadForUser(dbAfter, auth.user.id, Date.now());
        return res.json({ ok: true, action, ...payload });
    } catch (error) {
        if (error.message === 'TARGET_NOT_FOUND') return jsonError(res, 404, 'Target user not found');
        if (error.message === 'CANNOT_TARGET_SELF') return jsonError(res, 400, 'Cannot target yourself');
        if (error.message === 'BLOCKED_BY_TARGET') return jsonError(res, 403, 'That user has blocked you');
        return jsonError(res, 500, `Friend update failed: ${error.message}`);
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
        if (isDmRoomBlockedForUser(db, room, auth.user.id)) return jsonError(res, 403, 'DM is blocked');
        const rows = getRoomMessages(db, roomId);
        const filtered = since > 0 ? rows.filter((m) => Number(m.createdAt) > since) : rows;
        const tailCount = isDmRoom(room) ? 400 : 120;
        const tail = filtered.slice(-tailCount);
        const now = Date.now();
        const pinnedMessageIds = normalizeRoomPinnedMessageIds(room);
        const pinnedRows = rows.filter((entry) => pinnedMessageIds.includes(String(entry?.id || '')));
        const userStatusesById = getEffectiveStatusesForUsers(
            db,
            collectChatUserIds([...tail, ...pinnedRows]),
            now
        );
        const messages = tail.map((entry) => toChatMessagePublicView(entry, userStatusesById, auth.user.id)).filter(Boolean);
        const pins = resolveRoomPinnedMessagesPublicView(db, room, userStatusesById, auth.user.id);
        const roomPresenceContext = buildDmRoomPresenceContext(db, [room], auth.user.id, now);
        return res.json({
            ok: true,
            room: toRoomPublicView(room, auth.user, roomPresenceContext),
            messages,
            pins,
            canPin: canPinRoom(auth.user, room),
            now,
        });
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
        const clientMode = normalizeChatClientMode(req.body?.clientMode);
        const replyToId = normalizeChatReplyId(req.body?.replyToId);
        if (!text) return jsonError(res, 400, 'Message text required');
        const dbBefore = await readAuthDb();
        const roomsBefore = getChatRooms(dbBefore);
        const roomBefore = roomsBefore[roomId];
        if (!roomBefore) return jsonError(res, 404, 'Room not found');
        if (!canAccessRoom(auth.user, roomBefore, roomPassword)) return jsonError(res, 403, 'Invalid room password');
        if (isDmRoomBlockedForUser(dbBefore, roomBefore, auth.user.id)) return jsonError(res, 403, 'DM is blocked');
        let message = null;

        await updateAuthDb((db) => {
            const rooms = getChatRooms(db);
            const room = rooms[roomId];
            if (!room || !canAccessRoom(auth.user, room, roomPassword)) {
                throw new Error('ROOM_ACCESS_DENIED');
            }
            if (isDmRoomBlockedForUser(db, room, auth.user.id)) {
                throw new Error('DM_BLOCKED');
            }
            const rows = getRoomMessages(db, roomId);
            let replyTo = null;
            if (replyToId) {
                const replyTarget = rows.find((entry) => String(entry.id || '') === replyToId);
                if (!replyTarget) throw new Error('REPLY_NOT_FOUND');
                replyTo = toChatReplyStub(replyTarget);
            }
            message = {
                id: crypto.randomUUID(),
                roomId,
                userId: auth.user.id,
                username: auth.user.username,
                text,
                createdAt: Date.now(),
                clientMode,
                replyTo,
            };
            rows.push(message);
            const maxRows = isDmRoom(room) ? 5000 : 500;
            if (rows.length > maxRows) {
                getChatMessagesMap(db)[roomId] = rows.slice(-maxRows);
            }
            room.lastMessageAt = message.createdAt;
            const senderSave = getUserSave(db, auth.user.id);
            applyActivityDelta(senderSave, { chatMessages: 1 }, message.createdAt);
            return db;
        });

        const dbAfter = await readAuthDb();
        const messageUserIds = collectChatUserIds([message]);
        const userStatusesById = getEffectiveStatusesForUsers(dbAfter, messageUserIds, Date.now());
        setUserTypingState(roomId, auth.user, false, clientMode, 'offline', Date.now());
        return res.json({ ok: true, message: toChatMessagePublicView(message, userStatusesById, auth.user.id) });
    } catch (error) {
        if (error.message === 'ROOM_ACCESS_DENIED') return jsonError(res, 403, 'Invalid room password');
        if (error.message === 'DM_BLOCKED') return jsonError(res, 403, 'DM is blocked');
        if (error.message === 'REPLY_NOT_FOUND') return jsonError(res, 404, 'Reply target not found');
        return jsonError(res, 500, `Chat send failed: ${error.message}`);
    }
});

app.get('/api/chat/typing', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const roomId = normalizeRoomName(req.query?.room || 'lobby') || 'lobby';
        const roomPassword = String(req.query?.password || '');
        const db = await readAuthDb();
        const rooms = getChatRooms(db);
        const room = rooms[roomId];
        if (!room) return jsonError(res, 404, 'Room not found');
        if (!canAccessRoom(auth.user, room, roomPassword)) return jsonError(res, 403, 'Invalid room password');
        if (isDmRoomBlockedForUser(db, room, auth.user.id)) return jsonError(res, 403, 'DM is blocked');
        const typing = getRoomTypingPublicView(roomId, auth.user.id, Date.now());
        return res.json({ ok: true, typing, now: Date.now() });
    } catch (error) {
        return jsonError(res, 500, `Typing read failed: ${error.message}`);
    }
});

app.post('/api/chat/typing', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const roomId = normalizeRoomName(req.body?.room || 'lobby') || 'lobby';
        const roomPassword = String(req.body?.password || '');
        const typing = !!req.body?.typing;
        const clientMode = normalizeChatClientMode(req.body?.clientMode);
        const db = await readAuthDb();
        const rooms = getChatRooms(db);
        const room = rooms[roomId];
        if (!room) return jsonError(res, 404, 'Room not found');
        if (!canAccessRoom(auth.user, room, roomPassword)) return jsonError(res, 403, 'Invalid room password');
        if (isDmRoomBlockedForUser(db, room, auth.user.id)) return jsonError(res, 403, 'DM is blocked');
        const now = Date.now();
        const status = getEffectiveUserStatus(db, auth.user.id, now);
        setUserTypingState(roomId, auth.user, typing, clientMode, status, now);
        return res.json({ ok: true, typing, now });
    } catch (error) {
        return jsonError(res, 500, `Typing update failed: ${error.message}`);
    }
});

app.post('/api/chat/reactions', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const roomId = normalizeRoomName(req.body?.room || 'lobby') || 'lobby';
        const roomPassword = String(req.body?.password || '');
        const messageId = normalizeChatReplyId(req.body?.messageId);
        const emoji = normalizeChatReactionEmoji(req.body?.emoji);
        if (!messageId) return jsonError(res, 400, 'messageId is required');
        if (!emoji) return jsonError(res, 400, 'Invalid reaction emoji');

        const dbBefore = await readAuthDb();
        const roomsBefore = getChatRooms(dbBefore);
        const roomBefore = roomsBefore[roomId];
        if (!roomBefore) return jsonError(res, 404, 'Room not found');
        if (!canAccessRoom(auth.user, roomBefore, roomPassword)) return jsonError(res, 403, 'Invalid room password');
        if (isDmRoomBlockedForUser(dbBefore, roomBefore, auth.user.id)) return jsonError(res, 403, 'DM is blocked');
        let updatedMessage = null;

        await updateAuthDb((db) => {
            const rooms = getChatRooms(db);
            const room = rooms[roomId];
            if (!room || !canAccessRoom(auth.user, room, roomPassword)) {
                throw new Error('ROOM_ACCESS_DENIED');
            }
            const rows = getRoomMessages(db, roomId);
            const message = rows.find((entry) => String(entry?.id || '') === messageId);
            if (!message) throw new Error('MESSAGE_NOT_FOUND');
            const reactions = normalizeMessageReactions(message);
            const users = Array.isArray(reactions[emoji]) ? reactions[emoji].map((id) => String(id || '').trim()).filter(Boolean) : [];
            const meId = String(auth.user.id || '');
            if (users.includes(meId)) {
                reactions[emoji] = users.filter((id) => id !== meId);
            } else {
                reactions[emoji] = [...users, meId];
            }
            if (!reactions[emoji].length) delete reactions[emoji];
            message.reactions = reactions;
            updatedMessage = message;
            return db;
        });

        const dbAfter = await readAuthDb();
        const userStatusesById = getEffectiveStatusesForUsers(dbAfter, collectChatUserIds([updatedMessage]), Date.now());
        return res.json({ ok: true, message: toChatMessagePublicView(updatedMessage, userStatusesById, auth.user.id) });
    } catch (error) {
        if (error.message === 'ROOM_ACCESS_DENIED') return jsonError(res, 403, 'Invalid room password');
        if (error.message === 'MESSAGE_NOT_FOUND') return jsonError(res, 404, 'Message not found');
        return jsonError(res, 500, `Reaction update failed: ${error.message}`);
    }
});

app.post('/api/chat/pins', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const roomId = normalizeRoomName(req.body?.room || 'lobby') || 'lobby';
        const roomPassword = String(req.body?.password || '');
        const messageId = normalizeChatReplyId(req.body?.messageId);
        const actionRaw = String(req.body?.action || '').trim().toLowerCase();
        const action = actionRaw === 'unpin' ? 'unpin' : 'pin';
        if (!messageId) return jsonError(res, 400, 'messageId is required');

        const dbBefore = await readAuthDb();
        const roomsBefore = getChatRooms(dbBefore);
        const roomBefore = roomsBefore[roomId];
        if (!roomBefore) return jsonError(res, 404, 'Room not found');
        if (!canAccessRoom(auth.user, roomBefore, roomPassword)) return jsonError(res, 403, 'Invalid room password');
        if (isDmRoomBlockedForUser(dbBefore, roomBefore, auth.user.id)) return jsonError(res, 403, 'DM is blocked');
        if (!canPinRoom(auth.user, roomBefore)) return jsonError(res, 403, 'Not allowed to pin in this room');

        await updateAuthDb((db) => {
            const rooms = getChatRooms(db);
            const room = rooms[roomId];
            if (!room || !canAccessRoom(auth.user, room, roomPassword)) {
                throw new Error('ROOM_ACCESS_DENIED');
            }
            if (!canPinRoom(auth.user, room)) throw new Error('PIN_DENIED');
            const rows = getRoomMessages(db, roomId);
            const pins = normalizeRoomPinnedMessageIds(room);
            if (action === 'pin') {
                const messageExists = rows.some((entry) => String(entry?.id || '') === messageId);
                if (!messageExists) throw new Error('MESSAGE_NOT_FOUND');
                room.pinnedMessageIds = [messageId, ...pins.filter((id) => id !== messageId)].slice(0, CHAT_PIN_LIMIT);
            } else {
                room.pinnedMessageIds = pins.filter((id) => id !== messageId);
            }
            return db;
        });

        const dbAfter = await readAuthDb();
        const roomAfter = getChatRooms(dbAfter)[roomId];
        if (!roomAfter) return jsonError(res, 404, 'Room not found');
        const pinnedRows = getRoomMessages(dbAfter, roomId).filter((entry) => normalizeRoomPinnedMessageIds(roomAfter).includes(String(entry?.id || '')));
        const userStatusesById = getEffectiveStatusesForUsers(dbAfter, collectChatUserIds(pinnedRows), Date.now());
        const pins = resolveRoomPinnedMessagesPublicView(dbAfter, roomAfter, userStatusesById, auth.user.id);
        return res.json({ ok: true, action, pins, canPin: canPinRoom(auth.user, roomAfter), now: Date.now() });
    } catch (error) {
        if (error.message === 'ROOM_ACCESS_DENIED') return jsonError(res, 403, 'Invalid room password');
        if (error.message === 'PIN_DENIED') return jsonError(res, 403, 'Not allowed to pin in this room');
        if (error.message === 'MESSAGE_NOT_FOUND') return jsonError(res, 404, 'Message not found');
        return jsonError(res, 500, `Pin update failed: ${error.message}`);
    }
});

app.get('/api/chat/replies', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const since = Number.parseInt(String(req.query?.since || '0'), 10) || 0;
        const db = await readAuthDb();
        const rooms = getChatRooms(db);
        const messagesMap = getChatMessagesMap(db);
        const hits = [];
        const hitRows = [];

        for (const [roomId, rows] of Object.entries(messagesMap)) {
            if (!Array.isArray(rows) || !rows.length) continue;
            const room = rooms[roomId];
            if (!room) continue;
            if (isDmRoomBlockedForUser(db, room, auth.user.id)) continue;
            for (const row of rows) {
                if (!row || typeof row !== 'object') continue;
                const createdAt = Number(row.createdAt) || 0;
                if (createdAt <= since) continue;
                if (String(row.userId || '') === String(auth.user.id || '')) continue;
                const replyTo = row.replyTo && typeof row.replyTo === 'object' ? row.replyTo : null;
                if (!replyTo) continue;
                if (String(replyTo.userId || '') !== String(auth.user.id || '')) continue;

                hitRows.push(row);
                hits.push({ row, roomName: String(room.name || room.id || 'room') });
            }
        }

        const userStatusesById = getEffectiveStatusesForUsers(db, collectChatUserIds(hitRows), Date.now());
        const withMessages = hits
            .map((entry) => {
                const message = toChatMessagePublicView(entry.row, userStatusesById, auth.user.id);
                if (!message) return null;
                return {
                    ...message,
                    roomName: entry.roomName,
                };
            })
            .filter(Boolean);

        withMessages.sort((a, b) => Number(a.createdAt || 0) - Number(b.createdAt || 0));
        return res.json({ ok: true, replies: withMessages.slice(-120), now: Date.now() });
    } catch (error) {
        return jsonError(res, 500, `Reply feed failed: ${error.message}`);
    }
});

app.post('/api/chat/dm', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');

        const targetUserIdInput = String(req.body?.targetUserId || '').trim();
        const targetUsernameInput = sanitizeUsername(req.body?.targetUsername);
        if (!targetUserIdInput && !targetUsernameInput) {
            return jsonError(res, 400, 'targetUserId or targetUsername is required');
        }

        const dbBefore = await readAuthDb();
        const users = Array.isArray(dbBefore.users) ? dbBefore.users : [];
        const targetUser = users.find((user) => {
            if (!user || typeof user !== 'object') return false;
            if (targetUserIdInput && String(user.id || '') === targetUserIdInput) return true;
            if (targetUsernameInput && sanitizeUsername(user.username) === targetUsernameInput) return true;
            return false;
        });

        if (!targetUser) return jsonError(res, 404, 'Target user not found');
        if (String(targetUser.id || '') === String(auth.user.id || '')) {
            return jsonError(res, 400, 'Cannot DM yourself');
        }
        if (areUsersBlockedEitherDirection(dbBefore, auth.user.id, targetUser.id)) {
            return jsonError(res, 403, 'DM is blocked');
        }

        const roomId = buildDmRoomId(auth.user.id, targetUser.id);
        if (!roomId) return jsonError(res, 400, 'Failed to create DM room id');
        const now = Date.now();
        let room = null;

        await updateAuthDb((db) => {
            const rooms = getChatRooms(db);
            if (!rooms[roomId]) {
                rooms[roomId] = {
                    id: roomId,
                    name: `dm-${sanitizeUsername(targetUser.username)}`,
                    ownerUserId: 'system',
                    ownerUsername: 'system',
                    isPrivate: false,
                    kind: 'dm',
                    dmUserIds: [String(auth.user.id), String(targetUser.id)].sort(),
                    dmUsernames: {
                        [String(auth.user.id)]: String(auth.user.username || 'user'),
                        [String(targetUser.id)]: String(targetUser.username || 'user'),
                    },
                    createdAt: now,
                    lastMessageAt: now,
                };
                getRoomMessages(db, roomId);
            }

            const existing = rooms[roomId];
            if (!existing.kind) existing.kind = 'dm';
            if (!Array.isArray(existing.dmUserIds) || existing.dmUserIds.length < 2) {
                existing.dmUserIds = [String(auth.user.id), String(targetUser.id)].sort();
            }
            if (!existing.dmUsernames || typeof existing.dmUsernames !== 'object') {
                existing.dmUsernames = {};
            }
            existing.dmUsernames[String(auth.user.id)] = String(auth.user.username || 'user');
            existing.dmUsernames[String(targetUser.id)] = String(targetUser.username || 'user');
            room = existing;
            return db;
        });

        const roomPresenceContext = buildDmRoomPresenceContext(dbBefore, [room], auth.user.id, Date.now());
        return res.json({ ok: true, room: toRoomPublicView(room, auth.user, roomPresenceContext) });
    } catch (error) {
        return jsonError(res, 500, `DM create failed: ${error.message}`);
    }
});

app.get('/api/chat/call/state', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const roomId = normalizeRoomName(req.query?.room || '');
        const roomPassword = String(req.query?.password || '');
        if (!roomId) return jsonError(res, 400, 'Room is required');
        const rooms = getChatRooms(auth.db);
        const room = rooms[roomId];
        if (!room) return jsonError(res, 404, 'Room not found');
        if (!canAccessRoom(auth.user, room, roomPassword)) return jsonError(res, 403, 'Invalid room password');
        if (isDmRoomBlockedForUser(auth.db, room, auth.user.id)) return jsonError(res, 403, 'DM is blocked');

        pruneChatCallRooms();
        const callRoom = chatCallRooms.get(roomId);
        const members = callRoom ? toChatCallMembersPublicView(callRoom) : [];
        return res.json({
            ok: true,
            room: toRoomPublicView(room, auth.user, buildDmRoomPresenceContext(auth.db, [room], auth.user.id, Date.now())),
            call: {
                active: !!callRoom,
                mode: callRoom?.mode || 'voice',
                members,
            },
            now: Date.now(),
        });
    } catch (error) {
        return jsonError(res, 500, `Call state failed: ${error.message}`);
    }
});

app.post('/api/chat/call/join', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const roomId = normalizeRoomName(req.body?.room || '');
        const roomPassword = String(req.body?.password || '');
        const wantsVideo = Boolean(req.body?.video);
        const clientMode = normalizeChatClientMode(req.body?.clientMode);
        if (!roomId) return jsonError(res, 400, 'Room is required');

        const rooms = getChatRooms(auth.db);
        const room = rooms[roomId];
        if (!room) return jsonError(res, 404, 'Room not found');
        if (!canAccessRoom(auth.user, room, roomPassword)) return jsonError(res, 403, 'Invalid room password');
        if (isDmRoomBlockedForUser(auth.db, room, auth.user.id)) return jsonError(res, 403, 'DM is blocked');
        if (wantsVideo && !isDmRoom(room)) return jsonError(res, 400, 'Video calls are only available in DMs');

        pruneChatCallRooms();
        const now = Date.now();
        const callRoom = getOrCreateChatCallRoom(roomId);
        callRoom.members[String(auth.user.id)] = {
            userId: String(auth.user.id),
            username: String(auth.user.username || 'user'),
            clientMode,
            joinedAt: Number(callRoom.members[String(auth.user.id)]?.joinedAt || now),
            lastSeenAt: now,
            wantsVideo: wantsVideo && isDmRoom(room),
        };
        const anyVideo = Object.values(callRoom.members).some((entry) => !!entry?.wantsVideo);
        callRoom.mode = anyVideo && isDmRoom(room) ? 'video' : 'voice';
        callRoom.updatedAt = now;

        return res.json({
            ok: true,
            room: toRoomPublicView(room, auth.user, buildDmRoomPresenceContext(auth.db, [room], auth.user.id, now)),
            call: {
                active: true,
                mode: callRoom.mode,
                members: toChatCallMembersPublicView(callRoom),
            },
            now,
        });
    } catch (error) {
        return jsonError(res, 500, `Call join failed: ${error.message}`);
    }
});

app.post('/api/chat/call/ping', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const roomId = normalizeRoomName(req.body?.room || '');
        if (!roomId) return jsonError(res, 400, 'Room is required');
        pruneChatCallRooms();
        const callRoom = chatCallRooms.get(roomId);
        if (!callRoom || !callRoom.members[String(auth.user.id)]) {
            return res.json({ ok: true, joined: false, now: Date.now() });
        }
        callRoom.members[String(auth.user.id)].lastSeenAt = Date.now();
        callRoom.updatedAt = Date.now();
        return res.json({ ok: true, joined: true, now: Date.now() });
    } catch (error) {
        return jsonError(res, 500, `Call ping failed: ${error.message}`);
    }
});

app.post('/api/chat/call/leave', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const roomId = normalizeRoomName(req.body?.room || '');
        if (!roomId) return jsonError(res, 400, 'Room is required');
        pruneChatCallRooms();
        const callRoom = chatCallRooms.get(roomId);
        if (!callRoom) return res.json({ ok: true, now: Date.now() });
        delete callRoom.members[String(auth.user.id)];
        callRoom.updatedAt = Date.now();
        pruneChatCallRooms();
        return res.json({ ok: true, now: Date.now() });
    } catch (error) {
        return jsonError(res, 500, `Call leave failed: ${error.message}`);
    }
});

app.post('/api/chat/call/signal', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const roomId = normalizeRoomName(req.body?.room || '');
        const toUserId = String(req.body?.toUserId || '').trim();
        const signalType = sanitizeCallSignalType(req.body?.type);
        const payload = sanitizeCallSignalPayload(req.body?.payload);
        if (!roomId) return jsonError(res, 400, 'Room is required');
        if (!toUserId) return jsonError(res, 400, 'toUserId is required');
        if (!signalType) return jsonError(res, 400, 'Invalid signal type');
        if (!payload && signalType !== 'hangup') return jsonError(res, 400, 'Signal payload is required');

        pruneChatCallRooms();
        const callRoom = chatCallRooms.get(roomId);
        if (!callRoom) return jsonError(res, 404, 'Call room not found');
        const rooms = getChatRooms(auth.db);
        const room = rooms[roomId];
        if (!room) return jsonError(res, 404, 'Room not found');
        if (!canAccessRoom(auth.user, room, '')) return jsonError(res, 403, 'Invalid room access');
        if (isDmRoomBlockedForUser(auth.db, room, auth.user.id)) return jsonError(res, 403, 'DM is blocked');
        const fromId = String(auth.user.id || '');
        if (!callRoom.members[fromId]) return jsonError(res, 403, 'Join the call first');
        const targetInCall = !!callRoom.members[toUserId];
        const targetIsDmPeer = isDmRoom(room) && getDmUserIds(room).includes(toUserId);
        const canSignalOfflineDmPeer = targetIsDmPeer && (signalType === 'offer' || signalType === 'hangup');
        if (!targetInCall && !canSignalOfflineDmPeer) {
            return jsonError(res, 404, 'Target user is not in call');
        }

        const now = Date.now();
        callRoom.members[fromId].lastSeenAt = now;
        const signal = {
            id: crypto.randomUUID(),
            roomId,
            fromUserId: fromId,
            fromUsername: String(auth.user.username || 'user'),
            fromClientMode: normalizeChatClientMode(callRoom.members[fromId].clientMode),
            toUserId,
            type: signalType,
            payload: payload || null,
            createdAt: now,
            expiresAt: now + CHAT_CALL_SIGNAL_TTL_MS,
        };
        callRoom.signals.push(signal);
        if (callRoom.signals.length > 500) {
            callRoom.signals = callRoom.signals.slice(-500);
        }
        callRoom.updatedAt = now;

        return res.json({ ok: true, signalId: signal.id, now });
    } catch (error) {
        return jsonError(res, 500, `Call signal failed: ${error.message}`);
    }
});

app.get('/api/chat/call/incoming', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const since = Number.parseInt(String(req.query?.since || '0'), 10) || 0;
        pruneChatCallRooms();
        const rooms = getChatRooms(auth.db);
        const userId = String(auth.user.id || '');
        const hits = [];

        for (const callRoom of chatCallRooms.values()) {
            if (!callRoom || typeof callRoom !== 'object') continue;
            const roomId = String(callRoom.roomId || '');
            const room = rooms[roomId];
            if (!room) continue;
            if (!canAccessRoom(auth.user, room, '')) continue;
            if (isDmRoomBlockedForUser(auth.db, room, auth.user.id)) continue;
            const members = toChatCallMembersPublicView(callRoom);
            for (const signal of Array.isArray(callRoom.signals) ? callRoom.signals : []) {
                if (!signal || typeof signal !== 'object') continue;
                const createdAt = Number(signal.createdAt || 0);
                if (createdAt <= since) continue;
                if (String(signal.toUserId || '') !== userId) continue;
                const type = sanitizeCallSignalType(signal.type);
                if (!type) continue;
                hits.push({
                    id: String(signal.id || ''),
                    roomId,
                    room: toRoomPublicView(room, auth.user, buildDmRoomPresenceContext(auth.db, [room], auth.user.id, Date.now())),
                    fromUserId: String(signal.fromUserId || ''),
                    fromUsername: String(signal.fromUsername || 'user'),
                    fromClientMode: normalizeChatClientMode(signal.fromClientMode),
                    toUserId: userId,
                    type,
                    payload: signal.payload || null,
                    createdAt,
                    callMode: String(callRoom.mode || 'voice') === 'video' ? 'video' : 'voice',
                    callMembers: members,
                });
            }
        }

        hits.sort((a, b) => Number(a.createdAt || 0) - Number(b.createdAt || 0));
        return res.json({ ok: true, signals: hits.slice(-180), now: Date.now() });
    } catch (error) {
        return jsonError(res, 500, `Call incoming poll failed: ${error.message}`);
    }
});

app.get('/api/chat/call/signals', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const roomId = normalizeRoomName(req.query?.room || '');
        const since = Number.parseInt(String(req.query?.since || '0'), 10) || 0;
        if (!roomId) return jsonError(res, 400, 'Room is required');

        pruneChatCallRooms();
        const callRoom = chatCallRooms.get(roomId);
        if (!callRoom) return res.json({ ok: true, signals: [], now: Date.now() });
        const room = getChatRooms(auth.db)[roomId];
        if (!room) return res.json({ ok: true, signals: [], now: Date.now() });
        if (isDmRoomBlockedForUser(auth.db, room, auth.user.id)) {
            return res.json({ ok: true, signals: [], now: Date.now() });
        }
        const userId = String(auth.user.id || '');
        if (!callRoom.members[userId]) return res.json({ ok: true, signals: [], now: Date.now() });

        const signals = callRoom.signals
            .filter((signal) => {
                if (!signal || typeof signal !== 'object') return false;
                if (Number(signal.createdAt || 0) <= since) return false;
                return String(signal.toUserId || '') === userId;
            })
            .map((signal) => ({
                id: String(signal.id || ''),
                roomId: String(signal.roomId || ''),
                fromUserId: String(signal.fromUserId || ''),
                fromUsername: String(signal.fromUsername || 'user'),
                fromClientMode: normalizeChatClientMode(signal.fromClientMode),
                toUserId: String(signal.toUserId || ''),
                type: sanitizeCallSignalType(signal.type),
                payload: signal.payload || null,
                createdAt: Number(signal.createdAt || Date.now()),
            }));

        return res.json({ ok: true, signals, now: Date.now() });
    } catch (error) {
        return jsonError(res, 500, `Call signal poll failed: ${error.message}`);
    }
});

app.get('/api/chat/rooms', async (req, res) => {
    try {
        const auth = await getSessionFromRequest(req);
        if (!auth) return jsonError(res, 401, 'Unauthorized');
        const db = await readAuthDb();
        const visibleRooms = Object.values(getChatRooms(db))
            .filter((room) => {
                if (!isDmRoom(room)) return true;
                if (!canAccessRoom(auth.user, room, '')) return false;
                if (isDmRoomBlockedForUser(db, room, auth.user.id)) return false;
                return true;
            });
        const roomPresenceContext = buildDmRoomPresenceContext(db, visibleRooms, auth.user.id, Date.now());
        const rooms = visibleRooms
            .map((room) => toRoomPublicView(room, auth.user, roomPresenceContext))
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
        if (roomId.startsWith('dm-')) {
            return jsonError(res, 400, 'Room name cannot start with dm-.');
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

        return res.json({ ok: true, room: toRoomPublicView(room, auth.user) });
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

app.all('*', async (req, res, next) => {
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

    if (!isLikelyAssetPath(req.path)) {
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
            }
        }

        return next();
    } catch {
        return next();
    }
});

app.get(/^\/gn\/(.+)$/, async (req, res, next) => {
    const rawTail = String(req.params?.[0] || '').trim();
    if (!rawTail) return next();

    let tail = rawTail;
    try {
        tail = decodeURIComponent(rawTail);
    } catch {
    }
    tail = tail.replace(/^\/+/, '').replace(/\\/g, '/');
    if (!tail || tail.includes('..')) {
        return res.status(400).send('invalid gn path');
    }

    const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
    const candidates = [
        new URL(`${tail}${query}`, GN_MATH_HTML_BASE).href,
        new URL(`${tail}${query}`, GN_MATH_BASE).href,
    ];

    const attempts = [];
    for (const target of candidates) {
        try {
            const upstream = await fetch(target);
            attempts.push(`${upstream.status} ${target}`);
            if (!upstream.ok) continue;
            res.setHeader('X-Rift-GN', '1');
            const upstreamType = String(upstream.headers.get('content-type') || '').trim();
            const guessedType = guessContentTypeFromPath(tail);
            if (/\.html?$/i.test(tail)) {
                res.setHeader('Content-Type', 'text/html; charset=utf-8');
            } else if (guessedType && (!upstreamType || /^text\/plain\b/i.test(upstreamType))) {
                res.setHeader('Content-Type', guessedType);
            } else if (upstreamType) {
                res.setHeader('Content-Type', upstreamType);
            }
            const cacheControl = upstream.headers.get('cache-control');
            if (cacheControl) res.setHeader('Cache-Control', cacheControl);
            const raw = Buffer.from(await upstream.arrayBuffer());
            return res.status(upstream.status).send(raw);
        } catch (error) {
            attempts.push(`ERR ${target} :: ${error.message}`);
        }
    }

    return res.status(502).json({
        error: 'gn upstream unavailable',
        path: tail,
        attempts,
    });
});

app.get(/^\/sdxp\/(.+)$/, async (req, res, next) => {
    const rawTail = String(req.params?.[0] || '').trim();
    if (!rawTail) return next();

    let decodedTail = rawTail;
    try {
        decodedTail = decodeURIComponent(rawTail);
    } catch {
    }
    const tailCandidates = buildSdxpTailCandidates(decodedTail);
    if (!tailCandidates.length) {
        return res.status(400).send('invalid sdxp path');
    }

    const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
    const attempts = [];
    let firstFailure = null;

    for (const tail of tailCandidates) {
        const target = new URL(`${tail}${query}`, SDXP_FALLBACK_BASE).href;
        try {
            const upstream = await fetch(target);
            attempts.push(`${upstream.status} ${target}`);
            if (!upstream.ok) {
                if (!firstFailure) {
                    firstFailure = {
                        status: upstream.status,
                        target,
                    };
                }
                continue;
            }
            res.setHeader('X-Rift-SDXP', '1');
            const upstreamType = String(upstream.headers.get('content-type') || '').trim();
            const guessedType = guessContentTypeFromPath(tail);
            if (upstreamType) {
                res.setHeader('Content-Type', upstreamType);
            } else if (guessedType) {
                res.setHeader('Content-Type', guessedType);
            }
            const cacheControl = upstream.headers.get('cache-control');
            if (cacheControl) res.setHeader('Cache-Control', cacheControl);
            const shouldTreatAsHtml =
                /text\/html/i.test(upstreamType) ||
                /\.html?$/i.test(tail);
            if (shouldTreatAsHtml) {
                const html = await upstream.text();
                return res.status(upstream.status).send(stripSdxpTopRedirect(html));
            }
            const raw = Buffer.from(await upstream.arrayBuffer());
            return res.status(upstream.status).send(raw);
        } catch (error) {
            attempts.push(`ERR ${target} :: ${error.message}`);
        }
    }

    if (firstFailure) {
        return res.status(firstFailure.status).send(`sdxp upstream status ${firstFailure.status}`);
    }
    return res.status(502).json({
        error: 'sdxp upstream unavailable',
        path: normalizeSdxpTail(decodedTail),
        attempts,
    });
});

app.get(/^\/truf\/([^/]+)\.html$/i, async (req, res, next) => {
    let slug = String(req.params?.[0] || '').trim();
    try {
        slug = decodeURIComponent(slug);
    } catch {
    }
    slug = slug.toLowerCase();
    if (!/^[a-z0-9_-]+$/.test(slug)) return res.status(400).send('invalid truf slug');

    try {
        const aliasMap = await getTruffledAliasMap();
        const entry = aliasMap.get(slug);
        if (!entry) return next();

        if (entry.localFile) {
            const file = path.join(__dirname, '..', 'public', entry.localFile);
            return res.sendFile(file, (err) => {
                if (err) next();
            });
        }

        if (!entry.targetUrl) return next();

        const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
        const target = String(entry.targetUrl).includes('?')
            ? `${entry.targetUrl}${query ? `&${query.slice(1)}` : ''}`
            : `${entry.targetUrl}${query}`;
        const upstream = await fetch(target);
        if (!upstream.ok) {
            return res.status(upstream.status).send(`truf upstream status ${upstream.status}`);
        }

        const upstreamType = String(upstream.headers.get('content-type') || '').trim();
        const guessedType = guessContentTypeFromPath(target);
        res.setHeader('X-Rift-Truf', '1');
        if (upstreamType) {
            res.setHeader('Content-Type', upstreamType);
        } else if (guessedType) {
            res.setHeader('Content-Type', guessedType);
        }
        const cacheControl = upstream.headers.get('cache-control');
        if (cacheControl) res.setHeader('Cache-Control', cacheControl);
        const raw = Buffer.from(await upstream.arrayBuffer());
        return res.status(upstream.status).send(raw);
    } catch (error) {
        return res.status(502).json({ error: `truf launch failed: ${error.message}` });
    }
});

app.get(/^\/dkmath\/([^/]+)\.html$/i, async (req, res, next) => {
    let slug = String(req.params?.[0] || '').trim();
    try {
        slug = decodeURIComponent(slug);
    } catch {
    }
    slug = slug.toLowerCase();
    if (!/^[a-z0-9_-]+$/.test(slug)) return res.status(400).send('invalid dkmath slug');

    try {
        const data = await getDuckMathCatalogData();
        const entry = data.map.get(slug);
        if (!entry) return next();
        const launchTarget = await resolveDuckMathLaunchTarget(entry.targetUrl);
        const frameTarget = launchTarget || entry.targetUrl;

        const shell = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${String(entry.name || 'DuckMath')}</title><style>html,body{margin:0;padding:0;width:100%;height:100%;overflow:hidden;background:#000}iframe{width:100%;height:100%;border:none;display:block}</style></head><body><iframe id="dkmath-frame" allow="fullscreen; autoplay; clipboard-write; gamepad; microphone; camera; geolocation" referrerpolicy="strict-origin-when-cross-origin"></iframe><script>document.getElementById('dkmath-frame').src=${safeJsonForInlineScript(frameTarget)};</script></body></html>`;
        res.setHeader('X-Rift-DkMath', '1');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.status(200).send(shell);
    } catch (error) {
        return res.status(502).json({ error: `dkmath launch failed: ${error.message}` });
    }
});

app.get(/^\/ccptd\/([^/]+)\.html$/i, async (req, res, next) => {
    let slug = String(req.params?.[0] || '').trim();
    try {
        slug = decodeURIComponent(slug);
    } catch {
    }
    slug = slug.toLowerCase();
    if (!/^[a-z0-9_-]+$/.test(slug)) return res.status(400).send('invalid ccptd slug');

    try {
        const data = await getCcportedCatalogData();
        const entry = data.map.get(slug);
        if (!entry) return next();
        const frameTarget = `/ccptd/${encodeURIComponent(slug)}/game.html`;

        const shell = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${String(entry.name || 'CCPorted')}</title><style>html,body{margin:0;padding:0;width:100%;height:100%;overflow:hidden;background:#000}iframe{width:100%;height:100%;border:none;display:block}</style></head><body><iframe id="ccptd-frame" allow="fullscreen; autoplay; clipboard-write; gamepad; microphone; camera; geolocation" referrerpolicy="strict-origin-when-cross-origin"></iframe><script>document.getElementById('ccptd-frame').src=${safeJsonForInlineScript(frameTarget)};</script></body></html>`;
        res.setHeader('X-Rift-Ccptd', '1');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.status(200).send(shell);
    } catch (error) {
        return res.status(502).json({ error: `ccptd launch failed: ${error.message}` });
    }
});

app.get(/^\/ccptd\/([^/]+)\/(.+)$/i, async (req, res, next) => {
    let slug = String(req.params?.[0] || '').trim();
    let tail = String(req.params?.[1] || '').trim();
    try {
        slug = decodeURIComponent(slug);
    } catch {
    }
    try {
        tail = decodeURIComponent(tail);
    } catch {
    }
    slug = slug.toLowerCase();
    tail = tail.replace(/^\/+/, '').replace(/\\/g, '/');

    if (!/^[a-z0-9_-]+$/.test(slug)) return res.status(400).send('invalid ccptd slug');
    if (!tail || tail.includes('..')) return res.status(400).send('invalid ccptd path');

    try {
        const data = await getCcportedCatalogData();
        const entry = data.map.get(slug);
        if (!entry) return next();

        const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
        const buildTarget = (value) => {
            const safePath = String(value || '')
                .split('/')
                .filter(Boolean)
                .map((segment) => encodeURIComponent(segment))
                .join('/');
            const dirPrefix = entry.dirPath ? `${entry.dirPath.replace(/^\/+/, '')}/` : '';
            return new URL(`${dirPrefix}${safePath}${query}`, CCPORTED_RAW_BASE).href;
        };

        let target = buildTarget(tail);
        let upstream = await fetch(target);
        if ((!upstream.ok || upstream.status === 404) && /^game\.html$/i.test(tail) && entry.entryPath) {
            const fallbackTarget = new URL(`${String(entry.entryPath).replace(/^\/+/, '')}${query}`, CCPORTED_RAW_BASE).href;
            const fallback = await fetch(fallbackTarget);
            if (fallback.ok) {
                upstream = fallback;
                target = fallbackTarget;
            }
        }

        if (!upstream.ok) {
            return res.status(upstream.status).send(`ccptd upstream status ${upstream.status}`);
        }

        const upstreamType = String(upstream.headers.get('content-type') || '').trim();
        const guessedType = guessContentTypeFromPath(tail);
        if (guessedType) {
            res.setHeader('Content-Type', guessedType);
        } else if (upstreamType) {
            res.setHeader('Content-Type', upstreamType);
        }
        const cacheControl = upstream.headers.get('cache-control');
        if (cacheControl) res.setHeader('Cache-Control', cacheControl);
        res.setHeader('X-Rift-Ccptd-Asset', '1');
        const raw = Buffer.from(await upstream.arrayBuffer());
        return res.status(upstream.status).send(raw);
    } catch (error) {
        return res.status(502).json({ error: `ccptd asset failed: ${error.message}` });
    }
});

app.get(/^\/ugs\/([^/]+)\.html$/i, async (req, res, next) => {
    let slug = String(req.params?.[0] || '').trim();
    try {
        slug = decodeURIComponent(slug);
    } catch {
    }
    slug = slug.toLowerCase();
    if (!/^[a-z0-9_-]+$/.test(slug)) return res.status(400).send('invalid ugs slug');

    try {
        const data = await getUgsCatalogData();
        const entry = data.map.get(slug);
        if (!entry) return next();
        const frameTarget = `/ugs/${encodeURIComponent(slug)}/game.html`;

        const shell = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${String(entry.name || 'UGS')}</title><style>html,body{margin:0;padding:0;width:100%;height:100%;overflow:hidden;background:#000}iframe{width:100%;height:100%;border:none;display:block}</style></head><body><iframe id="ugs-frame" allow="fullscreen; autoplay; clipboard-write; gamepad; microphone; camera; geolocation" referrerpolicy="strict-origin-when-cross-origin"></iframe><script>document.getElementById('ugs-frame').src=${safeJsonForInlineScript(frameTarget)};</script></body></html>`;
        res.setHeader('X-Rift-Ugs', '1');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.status(200).send(shell);
    } catch (error) {
        return res.status(502).json({ error: `ugs launch failed: ${error.message}` });
    }
});

app.get(/^\/ugs\/([^/]+)\/(.+)$/i, async (req, res, next) => {
    let slug = String(req.params?.[0] || '').trim();
    let tail = String(req.params?.[1] || '').trim();
    try {
        slug = decodeURIComponent(slug);
    } catch {
    }
    try {
        tail = decodeURIComponent(tail);
    } catch {
    }
    slug = slug.toLowerCase();
    tail = tail.replace(/^\/+/, '').replace(/\\/g, '/');

    if (!/^[a-z0-9_-]+$/.test(slug)) return res.status(400).send('invalid ugs slug');
    if (!tail || tail.includes('..')) return res.status(400).send('invalid ugs path');

    try {
        const data = await getUgsCatalogData();
        const entry = data.map.get(slug);
        if (!entry) return next();

        const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
        const buildTarget = (value) => {
            const safePath = String(value || '')
                .split('/')
                .filter(Boolean)
                .map((segment) => encodeURIComponent(segment))
                .join('/');
            const dirPrefix = entry.dirPath ? `${entry.dirPath.replace(/^\/+/, '')}/` : '';
            return new URL(`${dirPrefix}${safePath}${query}`, UGS_RAW_BASE).href;
        };

        let target = buildTarget(tail);
        let upstream = await fetch(target);
        if ((!upstream.ok || upstream.status === 404) && /^game\.html$/i.test(tail) && entry.entryPath) {
            const fallbackTarget = new URL(`${String(entry.entryPath).replace(/^\/+/, '')}${query}`, UGS_RAW_BASE).href;
            const fallback = await fetch(fallbackTarget);
            if (fallback.ok) {
                upstream = fallback;
                target = fallbackTarget;
            }
        }

        if (!upstream.ok) {
            return res.status(upstream.status).send(`ugs upstream status ${upstream.status}`);
        }

        const upstreamType = String(upstream.headers.get('content-type') || '').trim();
        const guessedType = guessContentTypeFromPath(tail);
        if (guessedType) {
            res.setHeader('Content-Type', guessedType);
        } else if (upstreamType) {
            res.setHeader('Content-Type', upstreamType);
        }
        const cacheControl = upstream.headers.get('cache-control');
        if (cacheControl) res.setHeader('Cache-Control', cacheControl);
        res.setHeader('X-Rift-Ugs-Asset', '1');
        const raw = Buffer.from(await upstream.arrayBuffer());
        return res.status(upstream.status).send(raw);
    } catch (error) {
        return res.status(502).json({ error: `ugs asset failed: ${error.message}` });
    }
});

app.get(/^\/slnte\/([^/]+)\.html$/i, async (req, res, next) => {
    let slug = String(req.params?.[0] || '').trim();
    try {
        slug = decodeURIComponent(slug);
    } catch {
    }
    slug = slug.toLowerCase();
    if (!/^[a-z0-9_-]+$/.test(slug)) return res.status(400).send('invalid slnte slug');

    try {
        const data = await getSeleniteCatalogData();
        const entry = data.map.get(slug);
        if (!entry) return next();
        const frameTarget = `/slnte/${encodeURIComponent(slug)}/game.html`;

        const shell = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${String(entry.name || 'Selenite')}</title><style>html,body{margin:0;padding:0;width:100%;height:100%;overflow:hidden;background:#000}iframe{width:100%;height:100%;border:none;display:block}</style></head><body><iframe id="slnte-frame" allow="fullscreen; autoplay; clipboard-write; gamepad; microphone; camera; geolocation" referrerpolicy="strict-origin-when-cross-origin"></iframe><script>document.getElementById('slnte-frame').src=${safeJsonForInlineScript(frameTarget)};</script></body></html>`;
        res.setHeader('X-Rift-Slnte', '1');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.status(200).send(shell);
    } catch (error) {
        return res.status(502).json({ error: `slnte launch failed: ${error.message}` });
    }
});

app.get(/^\/slnte\/([^/]+)\/(.+)$/i, async (req, res, next) => {
    let slug = String(req.params?.[0] || '').trim();
    let tail = String(req.params?.[1] || '').trim();
    try {
        slug = decodeURIComponent(slug);
    } catch {
    }
    try {
        tail = decodeURIComponent(tail);
    } catch {
    }
    slug = slug.toLowerCase();
    tail = tail.replace(/^\/+/, '').replace(/\\/g, '/');

    if (!/^[a-z0-9_-]+$/.test(slug)) return res.status(400).send('invalid slnte slug');
    if (!tail || tail.includes('..')) return res.status(400).send('invalid slnte path');

    try {
        const data = await getSeleniteCatalogData();
        const entry = data.map.get(slug);
        if (!entry) return next();

        const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
        const buildTarget = (value) => {
            const safePath = String(value || '')
                .split('/')
                .filter(Boolean)
                .map((segment) => encodeURIComponent(segment))
                .join('/');
            const dirPrefix = entry.dirPath ? `${entry.dirPath.replace(/^\/+/, '')}/` : '';
            return new URL(`${dirPrefix}${safePath}${query}`, SELENITE_RAW_BASE).href;
        };

        let target = buildTarget(tail);
        let upstream = await fetch(target);
        if ((!upstream.ok || upstream.status === 404) && /^game\.html$/i.test(tail) && entry.entryPath) {
            const fallbackTarget = new URL(`${String(entry.entryPath).replace(/^\/+/, '')}${query}`, SELENITE_RAW_BASE).href;
            const fallback = await fetch(fallbackTarget);
            if (fallback.ok) {
                upstream = fallback;
                target = fallbackTarget;
            }
        }

        if (!upstream.ok) {
            return res.status(upstream.status).send(`slnte upstream status ${upstream.status}`);
        }

        const upstreamType = String(upstream.headers.get('content-type') || '').trim();
        const guessedType = guessContentTypeFromPath(tail);
        if (guessedType) {
            res.setHeader('Content-Type', guessedType);
        } else if (upstreamType) {
            res.setHeader('Content-Type', upstreamType);
        }
        const cacheControl = upstream.headers.get('cache-control');
        if (cacheControl) res.setHeader('Cache-Control', cacheControl);
        res.setHeader('X-Rift-Slnte-Asset', '1');
        const raw = Buffer.from(await upstream.arrayBuffer());
        return res.status(upstream.status).send(raw);
    } catch (error) {
        return res.status(502).json({ error: `slnte asset failed: ${error.message}` });
    }
});

app.get(/^\/rdn\/([^/]+)\.html$/i, async (req, res, next) => {
    let slug = String(req.params?.[0] || '').trim();
    try {
        slug = decodeURIComponent(slug);
    } catch {
    }
    slug = slug.toLowerCase();
    if (!/^[a-z0-9_-]+$/.test(slug)) return res.status(400).send('invalid rdn slug');

    try {
        const data = await getRadonCatalogData();
        const entry = data.map.get(slug);
        if (!entry) return next();
        const frameTarget = `/rdn/${encodeURIComponent(slug)}/game.html`;

        const shell = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${String(entry.name || 'Radon')}</title><style>html,body{margin:0;padding:0;width:100%;height:100%;overflow:hidden;background:#000}iframe{width:100%;height:100%;border:none;display:block}</style></head><body><iframe id="rdn-frame" allow="fullscreen; autoplay; clipboard-write; gamepad; microphone; camera; geolocation" referrerpolicy="strict-origin-when-cross-origin"></iframe><script>document.getElementById('rdn-frame').src=${safeJsonForInlineScript(frameTarget)};</script></body></html>`;
        res.setHeader('X-Rift-Rdn', '1');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.status(200).send(shell);
    } catch (error) {
        return res.status(502).json({ error: `rdn launch failed: ${error.message}` });
    }
});

app.get(/^\/rdn\/([^/]+)\/(.+)$/i, async (req, res, next) => {
    let slug = String(req.params?.[0] || '').trim();
    let tail = String(req.params?.[1] || '').trim();
    try {
        slug = decodeURIComponent(slug);
    } catch {
    }
    try {
        tail = decodeURIComponent(tail);
    } catch {
    }
    slug = slug.toLowerCase();
    tail = tail.replace(/^\/+/, '').replace(/\\/g, '/');

    if (!/^[a-z0-9_-]+$/.test(slug)) return res.status(400).send('invalid rdn slug');
    if (!tail || tail.includes('..')) return res.status(400).send('invalid rdn path');

    try {
        const data = await getRadonCatalogData();
        const entry = data.map.get(slug);
        if (!entry) return next();

        const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
        const buildTarget = (value) => {
            const safePath = String(value || '')
                .split('/')
                .filter(Boolean)
                .map((segment) => encodeURIComponent(segment))
                .join('/');
            const dirPrefix = entry.dirPath ? `${entry.dirPath.replace(/^\/+/, '')}/` : '';
            return new URL(`${dirPrefix}${safePath}${query}`, RADON_RAW_BASE).href;
        };

        let target = buildTarget(tail);
        let upstream = await fetch(target);
        if ((!upstream.ok || upstream.status === 404) && /^game\.html$/i.test(tail) && entry.entryPath) {
            const fallbackTarget = new URL(`${String(entry.entryPath).replace(/^\/+/, '')}${query}`, RADON_RAW_BASE).href;
            const fallback = await fetch(fallbackTarget);
            if (fallback.ok) {
                upstream = fallback;
                target = fallbackTarget;
            }
        }

        if (!upstream.ok) {
            return res.status(upstream.status).send(`rdn upstream status ${upstream.status}`);
        }

        const upstreamType = String(upstream.headers.get('content-type') || '').trim();
        const guessedType = guessContentTypeFromPath(tail);
        if (guessedType) {
            res.setHeader('Content-Type', guessedType);
        } else if (upstreamType) {
            res.setHeader('Content-Type', upstreamType);
        }
        const cacheControl = upstream.headers.get('cache-control');
        if (cacheControl) res.setHeader('Cache-Control', cacheControl);
        res.setHeader('X-Rift-Rdn-Asset', '1');
        const raw = Buffer.from(await upstream.arrayBuffer());
        return res.status(upstream.status).send(raw);
    } catch (error) {
        return res.status(502).json({ error: `rdn asset failed: ${error.message}` });
    }
});

app.get(/^\/fyinx\/([^/]+)\.html$/i, async (req, res, next) => {
    let slug = String(req.params?.[0] || '').trim();
    try {
        slug = decodeURIComponent(slug);
    } catch {
    }
    slug = slug.toLowerCase();
    if (!/^[a-z0-9_-]+$/.test(slug)) return res.status(400).send('invalid fyinx slug');

    try {
        const data = await getFyinxCatalogData();
        const entry = data.map.get(slug);
        if (!entry) return next();
        const frameTarget = `/fyinx/${encodeURIComponent(slug)}/game.html`;

        const shell = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${String(entry.name || 'Fyinx')}</title><style>html,body{margin:0;padding:0;width:100%;height:100%;overflow:hidden;background:#000}iframe{width:100%;height:100%;border:none;display:block}</style></head><body><iframe id="fyinx-frame" allow="fullscreen; autoplay; clipboard-write; gamepad; microphone; camera; geolocation" referrerpolicy="strict-origin-when-cross-origin"></iframe><script>document.getElementById('fyinx-frame').src=${safeJsonForInlineScript(frameTarget)};</script></body></html>`;
        res.setHeader('X-Rift-Fyinx', '1');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.status(200).send(shell);
    } catch (error) {
        return res.status(502).json({ error: `fyinx launch failed: ${error.message}` });
    }
});

app.get(/^\/fyinx\/([^/]+)\/(.+)$/i, async (req, res, next) => {
    let slug = String(req.params?.[0] || '').trim();
    let tail = String(req.params?.[1] || '').trim();
    try {
        slug = decodeURIComponent(slug);
    } catch {
    }
    try {
        tail = decodeURIComponent(tail);
    } catch {
    }
    slug = slug.toLowerCase();
    tail = tail.replace(/^\/+/, '').replace(/\\/g, '/');

    if (!/^[a-z0-9_-]+$/.test(slug)) return res.status(400).send('invalid fyinx slug');
    if (!tail || tail.includes('..')) return res.status(400).send('invalid fyinx path');

    try {
        const data = await getFyinxCatalogData();
        const entry = data.map.get(slug);
        if (!entry) return next();

        const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
        const buildTarget = (value) => {
            const safePath = String(value || '')
                .split('/')
                .filter(Boolean)
                .map((segment) => encodeURIComponent(segment))
                .join('/');
            const dirPrefix = entry.dirPath ? `${entry.dirPath.replace(/^\/+/, '')}/` : '';
            return new URL(`${dirPrefix}${safePath}${query}`, FYINX_RAW_BASE).href;
        };

        let target = buildTarget(tail);
        let upstream = await fetch(target);
        if ((!upstream.ok || upstream.status === 404) && /^game\.html$/i.test(tail) && entry.entryPath) {
            const fallbackTarget = new URL(`${String(entry.entryPath).replace(/^\/+/, '')}${query}`, FYINX_RAW_BASE).href;
            const fallback = await fetch(fallbackTarget);
            if (fallback.ok) {
                upstream = fallback;
                target = fallbackTarget;
            }
        }

        if (!upstream.ok) {
            return res.status(upstream.status).send(`fyinx upstream status ${upstream.status}`);
        }

        const upstreamType = String(upstream.headers.get('content-type') || '').trim();
        const guessedType = guessContentTypeFromPath(tail);
        if (guessedType) {
            res.setHeader('Content-Type', guessedType);
        } else if (upstreamType) {
            res.setHeader('Content-Type', upstreamType);
        }
        const cacheControl = upstream.headers.get('cache-control');
        if (cacheControl) res.setHeader('Cache-Control', cacheControl);
        res.setHeader('X-Rift-Fyinx-Asset', '1');
        const raw = Buffer.from(await upstream.arrayBuffer());
        return res.status(upstream.status).send(raw);
    } catch (error) {
        return res.status(502).json({ error: `fyinx asset failed: ${error.message}` });
    }
});

app.get(/^\/eltgmz\/([^/]+)\.html$/i, async (req, res, next) => {
    let slug = String(req.params?.[0] || '').trim();
    try {
        slug = decodeURIComponent(slug);
    } catch {
    }
    slug = slug.toLowerCase();
    if (!/^[a-z0-9_-]+$/.test(slug)) return res.status(400).send('invalid eltgmz slug');

    try {
        const data = await getEliteCatalogData();
        const entry = data.map.get(slug);
        if (!entry) return next();
        const frameTarget = `/eltgmz/${encodeURIComponent(slug)}/game.html`;

        const shell = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${String(entry.name || 'Elite')}</title><style>html,body{margin:0;padding:0;width:100%;height:100%;overflow:hidden;background:#000}iframe{width:100%;height:100%;border:none;display:block}</style></head><body><iframe id="eltgmz-frame" allow="fullscreen; autoplay; clipboard-write; gamepad; microphone; camera; geolocation" referrerpolicy="strict-origin-when-cross-origin"></iframe><script>document.getElementById('eltgmz-frame').src=${safeJsonForInlineScript(frameTarget)};</script></body></html>`;
        res.setHeader('X-Rift-Eltgmz', '1');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.status(200).send(shell);
    } catch (error) {
        return res.status(502).json({ error: `eltgmz launch failed: ${error.message}` });
    }
});

app.get(/^\/eltgmz\/([^/]+)\/(.+)$/i, async (req, res, next) => {
    let slug = String(req.params?.[0] || '').trim();
    let tail = String(req.params?.[1] || '').trim();
    try {
        slug = decodeURIComponent(slug);
    } catch {
    }
    try {
        tail = decodeURIComponent(tail);
    } catch {
    }
    slug = slug.toLowerCase();
    tail = tail.replace(/^\/+/, '').replace(/\\/g, '/');

    if (!/^[a-z0-9_-]+$/.test(slug)) return res.status(400).send('invalid eltgmz slug');
    if (!tail || tail.includes('..')) return res.status(400).send('invalid eltgmz path');

    try {
        const data = await getEliteCatalogData();
        const entry = data.map.get(slug);
        if (!entry) return next();

        const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
        if (/^game\.html$/i.test(tail) && entry.entryPath) {
            const target = new URL(`${String(entry.entryPath).replace(/^\/+/, '')}${query}`, ELITE_RAW_BASE).href;
            const upstream = await fetch(target);
            if (!upstream.ok) {
                return res.status(upstream.status).send(`eltgmz upstream status ${upstream.status}`);
            }
            const sourceText = await upstream.text();
            const html = asEliteHtml(sourceText);
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            res.setHeader('X-Rift-Eltgmz-Asset', '1');
            return res.status(200).send(html);
        }

        const safePath = String(tail || '')
            .split('/')
            .filter(Boolean)
            .map((segment) => encodeURIComponent(segment))
            .join('/');
        const target = new URL(`${safePath}${query}`, ELITE_RAW_BASE).href;
        const upstream = await fetch(target);
        if (!upstream.ok) {
            return res.status(upstream.status).send(`eltgmz upstream status ${upstream.status}`);
        }

        const upstreamType = String(upstream.headers.get('content-type') || '').trim();
        const guessedType = guessContentTypeFromPath(tail);
        if (guessedType) {
            res.setHeader('Content-Type', guessedType);
        } else if (upstreamType) {
            res.setHeader('Content-Type', upstreamType);
        }
        const cacheControl = upstream.headers.get('cache-control');
        if (cacheControl) res.setHeader('Cache-Control', cacheControl);
        res.setHeader('X-Rift-Eltgmz-Asset', '1');
        const raw = Buffer.from(await upstream.arrayBuffer());
        return res.status(upstream.status).send(raw);
    } catch (error) {
        return res.status(502).json({ error: `eltgmz asset failed: ${error.message}` });
    }
});

app.get(/^\/pzlite\/([^/]+)\.html$/i, async (req, res, next) => {
    let slug = String(req.params?.[0] || '').trim();
    try {
        slug = decodeURIComponent(slug);
    } catch {
    }
    slug = slug.toLowerCase();
    if (!/^[a-z0-9_-]+$/.test(slug)) return res.status(400).send('invalid pzlite slug');

    try {
        const data = await getPetezahCatalogData();
        const entry = data.map.get(slug);
        if (!entry) return next();

        const shell = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${String(entry.name || 'PeteZah Lite')}</title><style>html,body{margin:0;padding:0;width:100%;height:100%;overflow:hidden;background:#000}iframe{width:100%;height:100%;border:none;display:block}</style></head><body><iframe id="pzlite-frame" allow="fullscreen; autoplay; clipboard-write; gamepad; microphone; camera; geolocation" referrerpolicy="strict-origin-when-cross-origin"></iframe><script>document.getElementById('pzlite-frame').src=${safeJsonForInlineScript(entry.targetUrl)};</script></body></html>`;
        res.setHeader('X-Rift-PZLite', '1');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.status(200).send(shell);
    } catch (error) {
        return res.status(502).json({ error: `pzlite launch failed: ${error.message}` });
    }
});

app.get(/^\/tllysc\/([^/]+)\.html$/i, async (req, res, next) => {
    let slug = String(req.params?.[0] || '').trim();
    try {
        slug = decodeURIComponent(slug);
    } catch {
    }
    slug = slug.toLowerCase();
    if (!/^[a-z0-9_-]+$/.test(slug)) return res.status(400).send('invalid tllysc slug');

    try {
        const data = await getTotallyScienceCatalogData();
        const entry = data.map.get(slug);
        if (!entry) return next();
        const launchTarget = await resolveTotallyScienceLaunchTarget(entry.targetUrl);
        const frameTarget = launchTarget || entry.targetUrl;

        const shell = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${String(entry.name || 'Totally Science')}</title><style>html,body{margin:0;padding:0;width:100%;height:100%;overflow:hidden;background:#000}iframe{width:100%;height:100%;border:none;display:block}</style></head><body><iframe id="tllysc-frame" allow="fullscreen; autoplay; clipboard-write; gamepad; microphone; camera; geolocation" referrerpolicy="strict-origin-when-cross-origin"></iframe><script>document.getElementById('tllysc-frame').src=${safeJsonForInlineScript(frameTarget)};</script></body></html>`;
        res.setHeader('X-Rift-Tllysc', '1');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.status(200).send(shell);
    } catch (error) {
        return res.status(502).json({ error: `tllysc launch failed: ${error.message}` });
    }
});

app.get(/^\/vlra\/([^/]+)\.html$/i, async (req, res, next) => {
    if (!ENABLE_VELARA) return next();

    let slug = String(req.params?.[0] || '').trim();
    try {
        slug = decodeURIComponent(slug);
    } catch {
    }
    slug = slug.toLowerCase();
    if (!/^[a-z0-9_-]+$/.test(slug)) return res.status(400).send('invalid vlra slug');

    try {
        const data = await getVelaraCatalogData();
        const entry = data.map.get(slug);
        if (!entry) return next();
        const launchTarget = await resolveVelaraLaunchTarget(entry.targetUrl);
        const frameTarget = launchTarget || entry.targetUrl;

        const shell = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${String(entry.name || 'Velara')}</title><style>html,body{margin:0;padding:0;width:100%;height:100%;overflow:hidden;background:#000}iframe{width:100%;height:100%;border:none;display:block}</style></head><body><iframe id="vlra-frame" allow="fullscreen; autoplay; clipboard-write; gamepad; microphone; camera; geolocation" referrerpolicy="strict-origin-when-cross-origin"></iframe><script>document.getElementById('vlra-frame').src=${safeJsonForInlineScript(frameTarget)};</script></body></html>`;
        res.setHeader('X-Rift-Vlra', '1');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.status(200).send(shell);
    } catch (error) {
        return res.status(502).json({ error: `vlra launch failed: ${error.message}` });
    }
});

app.get(/^\/sph\/([^/]+)\.html$/i, async (req, res, next) => {
    let slug = String(req.params?.[0] || '').trim();
    try {
        slug = decodeURIComponent(slug);
    } catch {
    }
    slug = slug.toLowerCase();
    if (!/^[a-z0-9_-]+$/.test(slug)) return res.status(400).send('invalid sph slug');

    try {
        const data = await getSeraphCatalogData();
        const entry = data.map.get(slug);
        if (!entry) return next();
        const frameTarget = `/sph/${encodeURIComponent(slug)}/game.html`;

        const shell = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${String(entry.name || 'Seraph')}</title><style>html,body{margin:0;padding:0;width:100%;height:100%;overflow:hidden;background:#000}iframe{width:100%;height:100%;border:none;display:block}</style></head><body><iframe id="sph-frame" allow="fullscreen; autoplay; clipboard-write; gamepad; microphone; camera; geolocation" referrerpolicy="strict-origin-when-cross-origin"></iframe><script>document.getElementById('sph-frame').src=${safeJsonForInlineScript(frameTarget)};</script></body></html>`;
        res.setHeader('X-Rift-Sph', '1');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.status(200).send(shell);
    } catch (error) {
        return res.status(502).json({ error: `sph launch failed: ${error.message}` });
    }
});

app.get(/^\/sph\/([^/]+)\/(.+)$/i, async (req, res, next) => {
    let slug = String(req.params?.[0] || '').trim();
    let tail = String(req.params?.[1] || '').trim();
    try {
        slug = decodeURIComponent(slug);
    } catch {
    }
    try {
        tail = decodeURIComponent(tail);
    } catch {
    }
    slug = slug.toLowerCase();
    tail = tail.replace(/^\/+/, '').replace(/\\/g, '/');

    if (!/^[a-z0-9_-]+$/.test(slug)) return res.status(400).send('invalid sph slug');
    if (!tail || tail.includes('..')) return res.status(400).send('invalid sph path');

    try {
        const data = await getSeraphCatalogData();
        const entry = data.map.get(slug);
        if (!entry) return next();

        const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
        const buildTarget = (value) => {
            const safePath = String(value || '')
                .split('/')
                .filter(Boolean)
                .map((segment) => encodeURIComponent(segment))
                .join('/');
            return new URL(`games/${encodeURIComponent(entry.dirName)}/${safePath}${query}`, SERAPH_BASE).href;
        };

        let target = buildTarget(tail);
        let upstream = await fetch(target);
        if ((!upstream.ok || upstream.status === 404) && /^game\.html$/i.test(tail)) {
            const fallbackTarget = buildTarget('index.html');
            const fallback = await fetch(fallbackTarget);
            if (fallback.ok) {
                upstream = fallback;
                target = fallbackTarget;
            }
        }

        if (!upstream.ok) {
            return res.status(upstream.status).send(`sph upstream status ${upstream.status}`);
        }

        const upstreamType = String(upstream.headers.get('content-type') || '').trim();
        const guessedType = guessContentTypeFromPath(tail);
        if (guessedType) {
            res.setHeader('Content-Type', guessedType);
        } else if (upstreamType) {
            res.setHeader('Content-Type', upstreamType);
        }
        const cacheControl = upstream.headers.get('cache-control');
        if (cacheControl) res.setHeader('Cache-Control', cacheControl);
        res.setHeader('X-Rift-Sph-Asset', '1');
        const raw = Buffer.from(await upstream.arrayBuffer());
        return res.status(upstream.status).send(raw);
    } catch (error) {
        return res.status(502).json({ error: `sph asset failed: ${error.message}` });
    }
});

app.get('/:gameSlug', async (req, res, next) => {
    const slugRaw = String(req.params?.gameSlug || '').trim();
    if (!slugRaw || slugRaw.includes('.')) return next();

    const slug = slugRaw.toLowerCase();
    if (slug === 'favicon' || RESERVED_TOP_LEVEL_PATHS.has(slug)) return next();

    try {
        const aliasMap = await getTruffledAliasMap();
        const entry = aliasMap.get(slug);
        if (!entry) return next();

        if (entry.localFile) {
            const file = path.join(__dirname, '..', 'public', entry.localFile);
            return res.sendFile(file, (err) => {
                if (err) next();
            });
        }
        return next();
    } catch {
        return next();
    }
});

app.use((req, res, next) => {
    if (!req.path.includes('.')) {
        const normalizedPath = req.path.length > 1
            ? req.path.replace(/\/+$/, '')
            : req.path;

        if (normalizedPath === '/') {
            return next();
        }

        const htmlPath = `${normalizedPath.replace(/^\/+/, '')}.html`;
        const file = path.join(__dirname, '..', 'public', htmlPath);
        res.sendFile(file, (err) => {
            if (err) next();
        });
    } else {
        next();
    }
});

app.get('/gn-catalog', async (_req, res) => {
    try {
        const response = await fetch(GN_MATH_ZONES_JSON);
        if (!response.ok) {
            return res.status(502).json({ error: `gn-math fetch failed: ${response.status}` });
        }

        const rows = await response.json();
        const items = [];
        const seen = new Set();
        for (const row of (Array.isArray(rows) ? rows.slice(1) : [])) {
            const htmlPath = normalizeGnMathHtmlPath(row?.url);
            if (!htmlPath) continue;
            const key = htmlPath.toLowerCase();
            if (seen.has(key)) continue;
            seen.add(key);

            const name = String(row?.name || '').trim();
            if (!name) continue;
            const launchPath = `/gn/${encodePathForUrl(htmlPath)}`;
            const cover = buildGnMathCoverUrl(row?.cover);
            items.push({
                id: `gn-math-${key}`,
                name,
                url: launchPath,
                cover,
            });
        }

        items.sort((a, b) => a.name.localeCompare(b.name));
        return res.json(items);
    } catch (error) {
        return res.status(500).json({ error: `failed to build gn-math catalog: ${error.message}` });
    }
});

app.all('/proxy', async (req, res) => {
    let targetUrl = req.query.url;

    const unwrapNestedProxyTarget = (rawValue) => {
        let current = String(rawValue || '').trim();
        for (let i = 0; i < 4; i++) {
            if (!current) break;
            try {
                const parsed = new URL(current);
                if (parsed.pathname === '/proxy' && parsed.searchParams.get('url')) {
                    current = parsed.searchParams.get('url');
                    continue;
                }
                break;
            } catch {
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
        }
        if ((req.method || 'GET').toUpperCase() === 'GET') {
            return res.status(204).end();
        }
        return res.status(400).send('URL parameter is required');
    }

    try {
        try {
            const parsedTarget = new URL(String(targetUrl));
            if (/(^|\.)truffled\.lol$/i.test(parsedTarget.hostname) && /^\/iframe\.html$/i.test(parsedTarget.pathname)) {
                const embeddedRaw = String(parsedTarget.searchParams.get('url') || '').trim();
                if (embeddedRaw) {
                    const resolved = new URL(embeddedRaw, TRUFFLED_BASE);
                    if (!/(^|\.)truffled\.lol$/i.test(resolved.hostname) || !/^\/iframe\.html$/i.test(resolved.pathname)) {
                        return res.redirect(302, `/proxy?url=${encodeURIComponent(resolved.href)}`);
                    }
                }
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

        try {
            const target = new URL(String(targetUrl));
            if (headers.origin) headers.origin = target.origin;
            if (headers.referer) headers.referer = target.href;
            const hostname = String(target.hostname || '').toLowerCase();
            if (/(^|\.)myinstants\.com$/i.test(hostname)) {
                headers['user-agent'] = headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';
                headers.accept = headers.accept || 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8';
                headers['accept-language'] = headers['accept-language'] || 'en-US,en;q=0.9';
                headers['cache-control'] = headers['cache-control'] || 'no-cache';
                headers.pragma = headers.pragma || 'no-cache';
                headers['upgrade-insecure-requests'] = headers['upgrade-insecure-requests'] || '1';
                headers.origin = target.origin;
                headers.referer = `${target.origin}/`;
            }
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
        let rewriteBaseUrl = baseUrl;
        try {
            const baseHrefMatch = content.match(/<base[^>]*href\s*=\s*["']([^"']+)["']/i);
            const baseHref = String(baseHrefMatch?.[1] || '').trim();
            if (baseHref) {
                rewriteBaseUrl = new URL(baseHref, baseUrl);
            }
        } catch {
            rewriteBaseUrl = baseUrl;
        }
        const rewriteProxyUrl = (rawUrl) => {
            const value = String(rawUrl || '').trim();
            if (!value) return null;
            if (value.startsWith('/proxy?url=')) return null;
            if (/^(?:https?:|\/\/|data:|blob:|javascript:|mailto:|tel:|#)/i.test(value)) return null;
            try {
                return `/proxy?url=${encodeURIComponent(new URL(value, rewriteBaseUrl).href)}`;
            } catch {
                return null;
            }
        };

        // Protect inline scripts from HTML-attribute rewriting.
        // Some GN-Math pages contain JS strings like iframe[src="..."], and
        // rewriting inside script text can corrupt syntax.
        const scriptBlocks = [];
        const protectedContent = content.replace(
            /<script\b[\s\S]*?<\/script>/gi,
            (block) => {
                const token = `__RIFT_SCRIPT_BLOCK_${scriptBlocks.length}__`;
                scriptBlocks.push(block);
                return token;
            }
        );

        let modifiedContent = protectedContent.replace(
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

        modifiedContent = modifiedContent.replace(
            /__RIFT_SCRIPT_BLOCK_(\d+)__/g,
            (match, indexText) => scriptBlocks[Number(indexText)] || ''
        );

        const yaGamesShim = '<script id="rift-yagames-shim">(function(){if(window.YaGames)return;window.YaGames={init:function(){return Promise.resolve({adv:{showFullscreenAdv:function(){return Promise.resolve();},showRewardedVideo:function(){return Promise.resolve();}},features:{LoadingAPI:{ready:function(){}}}});}};})();</script>';
        if (/<head[^>]*>/i.test(modifiedContent)) {
            modifiedContent = modifiedContent.replace(/<head[^>]*>/i, `$&${yaGamesShim}`);
        } else {
            modifiedContent = yaGamesShim + modifiedContent;
        }

        try {
            const auth = await getSessionFromRequest(req);
            if (auth) {
                const scope = new URL('.', parsedTargetUrl).href;
                const storageGameId = `proxy-storage:${scope}`;
                const save = getUserSave(auth.db, auth.user.id);
                const stored = save.games?.[storageGameId]?.localStorage;
                const initialStorage = stored && typeof stored === 'object' ? stored : {};

                const storageScript = `<script id="rift-proxy-storage">(function(){try{if(window.__riftProxyStorageInit)return;window.__riftProxyStorageInit=true;var scope=${safeJsonForInlineScript(scope)};var gameId=${safeJsonForInlineScript(storageGameId)};var seed=${safeJsonForInlineScript(initialStorage)};for(var k in seed){if(Object.prototype.hasOwnProperty.call(seed,k)&&localStorage.getItem(k)===null){try{localStorage.setItem(k,String(seed[k]));}catch(_e){}}}var pending=null;var saveNow=function(){try{var out={};for(var i=0;i<localStorage.length;i++){var key=localStorage.key(i);if(key!=null){out[key]=localStorage.getItem(key);}}fetch('/api/save/games/'+encodeURIComponent(gameId),{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({progress:{localStorage:out,lastSyncedAt:Date.now(),scope:scope}})}).catch(function(){});}catch(_e){}};var schedule=function(){if(pending)clearTimeout(pending);pending=setTimeout(saveNow,600);};var sp=Storage.prototype;var _set=sp.setItem,_remove=sp.removeItem,_clear=sp.clear;sp.setItem=function(a,b){var r=_set.call(this,a,b);if(this===localStorage)schedule();return r;};sp.removeItem=function(a){var r=_remove.call(this,a);if(this===localStorage)schedule();return r;};sp.clear=function(){var r=_clear.call(this);if(this===localStorage)schedule();return r;};window.addEventListener('pagehide',saveNow);window.addEventListener('beforeunload',saveNow);}catch(_e){}})();</script>`;

                if (/<head[^>]*>/i.test(modifiedContent)) {
                    modifiedContent = modifiedContent.replace(/<head[^>]*>/i, `$&${storageScript}`);
                } else {
                    modifiedContent = storageScript + modifiedContent;
                }
            }
        } catch {
        }

        if (/^\s*</.test(modifiedContent)) {
            const cursorStyle = '<style id="rift-proxy-cursor">*,*::before,*::after{cursor:url("/assets/images/cursor.png") 16 16, auto !important;}.rift-proxy-cursor-light{position:fixed;width:150px;height:150px;border-radius:50%;background:radial-gradient(circle,rgba(255,255,255,.15) 0%,rgba(255,255,255,0) 70%);pointer-events:none;z-index:2147483647;transform:translate(-50%,-50%);mix-blend-mode:screen;}</style>';
            const cursorScript = '<script id="rift-proxy-cursor-script">(function(){if(window.__riftProxyCursorInit)return;window.__riftProxyCursorInit=true;var light=document.createElement("div");light.className="rift-proxy-cursor-light";document.documentElement.appendChild(light);document.addEventListener("mousemove",function(e){light.style.left=e.clientX+"px";light.style.top=e.clientY+"px";});document.addEventListener("mouseleave",function(){light.style.opacity="0";});document.addEventListener("mouseenter",function(){light.style.opacity="1";});})();</script>';
            if (/<head[^>]*>/i.test(modifiedContent)) {
                modifiedContent = modifiedContent.replace(/<head[^>]*>/i, `$&${cursorStyle}${cursorScript}`);
            } else {
                modifiedContent = cursorStyle + cursorScript + modifiedContent;
            }
        }

        try {
            if (/(^|\.)truffled\.lol$/i.test(parsedTargetUrl.hostname) && /^\/iframe\.html$/i.test(parsedTargetUrl.pathname)) {
                const truffledIframeFixScript = `<script id="rift-truffled-iframe-fix">(function(){try{var truffledOrigin="https://truffled.lol";function toProxy(u){return "/proxy?url="+encodeURIComponent(u);}function unwrapTarget(raw){var value=String(raw||"").trim();if(!value)return "";try{if(/^\\/proxy\\?url=/i.test(value)){var rel=new URL(value,window.location.origin);var inner=rel.searchParams.get("url");if(inner)value=inner;}}catch(_e){}try{var absolute=/^[a-z][a-z0-9+.-]*:/i.test(value)?new URL(value):new URL(value,truffledOrigin);if(/(^|\\.)truffled\\.lol$/i.test(absolute.hostname)&&/^\\/iframe\\.html$/i.test(absolute.pathname)){var nested=absolute.searchParams.get("url");if(nested){return new URL(nested,truffledOrigin).href;}}if(/(^|\\.)truffled\\.lol$/i.test(absolute.hostname)){return absolute.href;}if(!/^[a-z][a-z0-9+.-]*:/i.test(value)||value.startsWith("/")){return new URL(value,truffledOrigin).href;}}catch(_e){}return "";}function applyFrameTarget(){var frame=document.getElementById("gameframe");if(!frame)return;var outerTarget="";try{var pageUrl=new URL(window.location.href);outerTarget=pageUrl.searchParams.get("url")||"";}catch(_e){}var target=unwrapTarget(outerTarget)||unwrapTarget(frame.getAttribute("src")||frame.src||"");if(!target)return;var next=toProxy(target);var current=String(frame.getAttribute("src")||"").trim();if(current!==next){frame.setAttribute("src",next);}}document.addEventListener("DOMContentLoaded",applyFrameTarget);window.addEventListener("load",applyFrameTarget);setTimeout(applyFrameTarget,0);setTimeout(applyFrameTarget,120);setInterval(applyFrameTarget,800);var observer=new MutationObserver(function(){applyFrameTarget();});document.addEventListener("DOMContentLoaded",function(){var frame=document.getElementById("gameframe");if(frame){observer.observe(frame,{attributes:true,attributeFilter:["src"]});}});}catch(_e){}})();</script>`;
                const truffledPopoutScript = '<script id="rift-truffled-popout-link">(function(){function sync(){var btn=document.getElementById("aboutblank");var frame=document.getElementById("gameframe");if(!btn||!frame)return;var src=String(frame.src||"").trim();if(!src||/\\/404\\.html(?:$|\\?)/i.test(src))return;btn.setAttribute("href",src);btn.setAttribute("target","_blank");btn.setAttribute("rel","noopener noreferrer");}document.addEventListener("DOMContentLoaded",sync);setInterval(sync,800);})();</script>';
                if (/<\/body>/i.test(modifiedContent)) {
                    modifiedContent = modifiedContent.replace(/<\/body>/i, `${truffledIframeFixScript}${truffledPopoutScript}</body>`);
                } else {
                    modifiedContent += `${truffledIframeFixScript}${truffledPopoutScript}`;
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

app.get('/sdxp-catalog', async (_req, res) => {
    try {
        let items = [];
        try {
            await fs.access(SDXP_HTML_ROOT);
            const indexFiles = await collectIndexFiles(SDXP_HTML_ROOT);
            items = await Promise.all(indexFiles.map(async (file) => {
                const rel = path.relative(path.join(__dirname, '..', 'public', 'sdxp'), file).replace(/\\/g, '/');
                const gameFolder = path.basename(path.dirname(file));
                const cover = await pickSdxpCover(file);
                return {
                    id: `sdxp-${rel}`,
                    name: humanizeFolderName(gameFolder),
                    url: sdxpCatalogUrlForTail(rel),
                    cover,
                };
            }));
        } catch {
        }

        if (!items.length) {
            items = await loadSdxpFallbackCatalog();
        }

        items.sort((a, b) => a.name.localeCompare(b.name));
        res.json(items);
    } catch (error) {
        res.status(500).json({ error: `failed to build sdxp catalog: ${error.message}` });
    }
});

app.get('/duckmath-catalog', async (_req, res) => {
    try {
        const data = await getDuckMathCatalogData();
        return res.json(data.items);
    } catch (error) {
        return res.status(500).json({ error: `failed to build duckmath catalog: ${error.message}` });
    }
});

app.get('/ccported-catalog', async (_req, res) => {
    try {
        const data = await getCcportedCatalogData();
        return res.json(data.items);
    } catch (error) {
        return res.status(500).json({ error: `failed to build ccported catalog: ${error.message}` });
    }
});

app.get('/ugs-catalog', async (_req, res) => {
    try {
        const data = await getUgsCatalogData();
        return res.json(data.items);
    } catch (error) {
        return res.status(500).json({ error: `failed to build ugs catalog: ${error.message}` });
    }
});

app.get('/slnte-catalog', async (_req, res) => {
    try {
        const data = await getSeleniteCatalogData();
        return res.json(data.items);
    } catch (error) {
        return res.status(500).json({ error: `failed to build selenite catalog: ${error.message}` });
    }
});

app.get('/rdn-catalog', async (_req, res) => {
    try {
        const data = await getRadonCatalogData();
        return res.json(data.items);
    } catch (error) {
        return res.status(500).json({ error: `failed to build radon catalog: ${error.message}` });
    }
});

app.get('/fyinx-catalog', async (_req, res) => {
    try {
        const data = await getFyinxCatalogData();
        return res.json(data.items);
    } catch (error) {
        return res.status(500).json({ error: `failed to build fyinx catalog: ${error.message}` });
    }
});

app.get('/eltgmz-catalog', async (_req, res) => {
    try {
        const data = await getEliteCatalogData();
        return res.json(data.items);
    } catch (error) {
        return res.status(500).json({ error: `failed to build elite catalog: ${error.message}` });
    }
});

app.get('/pzlite-catalog', async (_req, res) => {
    try {
        const data = await getPetezahCatalogData();
        return res.json(data.items);
    } catch (error) {
        return res.status(500).json({ error: `failed to build pzlite catalog: ${error.message}` });
    }
});

app.get('/truffled-catalog', async (_req, res) => {
    try {
        let payload = null;
        try {
            const localRaw = await fs.readFile(TRUFFLED_LOCAL_JSON, 'utf8');
            payload = JSON.parse(localRaw);
        } catch {
        }
        if (!payload) {
            try {
                const response = await fetch(TRUFFLED_GAMES_JSON);
                if (response.ok) {
                    payload = await response.json();
                }
            } catch {
            }
        }

        const rootMap = await readTruffledRootMap();
        const rows = Array.isArray(payload?.games) ? payload.games : [];
        const items = [];
        const seen = new Set();
        const seenSlugs = new Set();

        const catalogRows = rows.length
            ? rows
            : Object.entries(rootMap).map(([href, mappedFile]) => ({
                url: `/${String(href).replace(/^\/+/, '')}`,
                name: humanizeFolderName(String(mappedFile || '').replace(/\.html?$/i, '')),
                thumbnail: '',
            }));

        for (const row of catalogRows) {
            const normalized = normalizeTruffledCatalogHref(row?.url);
            if (!normalized) continue;
            if (seen.has(normalized)) continue;
            seen.add(normalized);

            const name = String(row?.name || '').trim() || humanizeFolderName(normalized.split('/').slice(-2, -1)[0] || normalized);
            const thumbnail = String(row?.thumbnail || '').trim();
            const normalizedThumb = thumbnail.replace(/^\/+/, '');
            const mappedFile = resolveTruffledMappedFile(rootMap, normalized);
            if (!mappedFile) continue;
            try {
                await fs.access(path.join(__dirname, '..', 'public', mappedFile));
            } catch {
                continue;
            }
            const slugCandidates = [
                toLaunchSlug(deriveTruffledCanonicalSlug(normalized, mappedFile), ''),
                toLaunchSlug(toTruffledLocalSlug(normalized), ''),
            ].filter(Boolean);
            const slug = slugCandidates.find((candidate) => !seenSlugs.has(candidate)) || '';
            if (!slug) continue;
            seenSlugs.add(slug);
            const launchUrl = `/truf/${encodeURIComponent(slug)}.html`;
            items.push({
                id: `truffled-${slug}`,
                name,
                url: launchUrl,
                cover: normalizedThumb ? new URL(normalizedThumb, TRUFFLED_BASE).href : '',
            });
        }

        items.sort((a, b) => a.name.localeCompare(b.name));
        return res.json(items);
    } catch (error) {
        return res.status(500).json({ error: `failed to build truffled catalog: ${error.message}` });
    }
});

app.get('/totalscience-catalog', async (_req, res) => {
    try {
        const data = await getTotallyScienceCatalogData();
        return res.json(data.items);
    } catch (error) {
        return res.status(500).json({ error: `failed to build totally science catalog: ${error.message}` });
    }
});

app.get('/velara-catalog', async (_req, res) => {
    if (!ENABLE_VELARA) {
        return res.json([]);
    }

    try {
        const data = await getVelaraCatalogData();
        return res.json(data.items);
    } catch (error) {
        return res.status(500).json({ error: `failed to build velara catalog: ${error.message}` });
    }
});

app.get('/seraph-catalog', async (_req, res) => {
    try {
        const data = await getSeraphCatalogData();
        return res.json(data.items);
    } catch (error) {
        return res.status(500).json({ error: `failed to build seraph catalog: ${error.message}` });
    }
});

app.get('/validate', async (req, res) => {
    const domain = String(req.query.domain || '').toLowerCase().trim();

    if (!isSafeHostname(domain)) {
        return res.sendStatus(403);
    }

    const allowed = await hostnamePointsToAllowedIp(domain);
    return res.sendStatus(allowed ? 200 : 403);
});

app.get('/wisp/', (_req, res) => {
    res.status(426);
    res.setHeader('Upgrade', 'websocket');
    res.setHeader('Connection', 'Upgrade');
    return res.type('text/plain').send('Wisp websocket endpoint is available at this path via websocket upgrade.');
});

if (require.main === module) {
    const { startRiftServer } = require('./start-server');
    startRiftServer(app, { port: PORT });
}

module.exports = app;


