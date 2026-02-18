const express = require('express');
const path = require('path');
const fs = require('fs').promises;
const dns = require('dns').promises;

const app = express();
const PORT = process.env.PORT || 3000;

// Prevent stale HTML/CSS/JS from being served to clients during rapid updates.
app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
});

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
app.get('/proxy', async (req, res) => {
    const targetUrl = req.query.url;

    if (!targetUrl) {
        return res.status(400).send('URL parameter is required');
    }

    try {
        const response = await fetch(targetUrl);
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
            return res.status(response.status).send(rewrittenManifest);
        }

        // Do not rewrite non-HTML assets. Rewriting JS/CSS text can corrupt syntax.
        if (!isHtml) {
            const raw = Buffer.from(await response.arrayBuffer());
            if (contentType) {
                res.setHeader('Content-Type', contentType);
            }
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
            /\b(href|src)\s*=\s*(["'])(.*?)\2/gi,
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
        res.send(modifiedContent);
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
