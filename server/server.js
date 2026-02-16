const express = require('express');
const path = require('path');
const { createServer } = require('http');
const { hostname } = require('os');
const { server: wisp, logging } = require('@mercuryworkshop/wisp-js/server');
const { scramjetPath } = require('@mercuryworkshop/scramjet');

const app = express();
const PORT = Number.parseInt(process.env.PORT, 10) || 3000;
const rootDir = path.join(__dirname, '..');

logging.set_level(logging.NONE);
Object.assign(wisp.options, {
  allow_udp_streams: false,
  hostname_blacklist: [/example\.com/],
  dns_servers: ['1.1.1.3', '1.0.0.3']
});

const assetsPath = path.join(rootDir, 'assets');
const componentsPath = path.join(rootDir, 'components');
const libcurlPath = path.join(rootDir, 'node_modules', '@mercuryworkshop', 'libcurl-transport', 'dist');
const baremuxPath = path.join(rootDir, 'node_modules', '@mercuryworkshop', 'bare-mux', 'dist');

app.use((req, res, next) => {
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  next();
});

app.use(express.static(path.join(rootDir, 'public')));
app.use('/assets', express.static(assetsPath));
app.use('/components', express.static(componentsPath));
app.use('/scramjet', express.static(scramjetPath));
app.use('/libcurl', express.static(libcurlPath));
app.use('/baremux', express.static(baremuxPath));

app.get('/proxy', async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).send('URL parameter is required');

  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return res.status(400).send('Invalid URL');
  }

  try {
    const response = await fetch(parsed);
    const content = await response.text();

    const modifiedContent = content.replace(
      /(href|src)=["'](?!http|\/\/|#)(.*?)["']/g,
      (match, attr, url) => {
        const fullUrl = new URL(url, parsed).href;
        return `${attr}="/proxy?url=${encodeURIComponent(fullUrl)}"`;
      }
    );

    res.send(modifiedContent);
  } catch (error) {
    res.status(500).send(`Error fetching the requested URL: ${error.message}`);
  }
});

app.get('*', (req, res, next) => {
  if (req.path === '/' || req.path.includes('.') || req.path.startsWith('/wisp/')) {
    return next();
  }

  const cleanPath = req.path.replace(/\/+$/, '');
  const filePath = path.join(rootDir, 'public', `${cleanPath}.html`);
  res.sendFile(filePath, (err) => {
    if (err) next();
  });
});

app.use((req, res) => {
  res.status(404).sendFile(path.join(rootDir, 'public', '404.html'));
});

let server;

function startServer(port = PORT) {
  if (server) return server;

  server = createServer(app);
  server.on('upgrade', (req, socket, head) => {
    if (req.url.startsWith('/wisp/')) {
      wisp.routeRequest(req, socket, head);
    } else {
      socket.destroy();
    }
  });

  server.listen(port, () => {
    const address = server.address();
    const boundPort = typeof address === 'object' && address ? address.port : port;
    console.log('Rift running on:');
    console.log(`  http://localhost:${boundPort}`);
    console.log(`  http://${hostname()}:${boundPort}`);
  });

  return server;
}

if (require.main === module) {
  startServer();
}

module.exports = app;
module.exports.startServer = startServer;
