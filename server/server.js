const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files from public/, assets/, and components/
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use('/assets', express.static(path.join(__dirname, '..', 'assets')));
app.use('/components', express.static(path.join(__dirname, '..', 'components')));

// Clean URLs — serve .html files without extension
app.use((req, res, next) => {
    if (!req.path.includes('.') && req.path !== '/') {
        const file = path.join(__dirname, '..', 'public', req.path + '.html');
        res.sendFile(file, (err) => { if (err) next(); });
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
        const content = await response.text();

        const modifiedContent = content.replace(
            /(href|src)=["'](?!http|\/\/|#)(.*?)["']/g,
            (match, attr, url) => {
                const baseUrl = new URL(targetUrl);
                const fullUrl = new URL(url, baseUrl).href;
                return `${attr}="/proxy?url=${encodeURIComponent(fullUrl)}"`;
            }
        );

        res.send(modifiedContent);
    } catch (error) {
        res.status(500).send('Error fetching the requested URL: ' + error.message);
    }
});

app.listen(PORT, () => {
    console.log(`Rift running on http://localhost:${PORT}`);
});
