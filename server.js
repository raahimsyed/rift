// Basic Node.js server setup for Rift Proxy
// You'll need to install: npm install express node-fetch

const express = require('express');
const fetch = require('node-fetch');
const path = require('path');

const app = express();
const PORT = 3000;

// Serve static files
app.use(express.static(__dirname));

// Proxy endpoint
app.get('/proxy', async (req, res) => {
    const targetUrl = req.query.url;
    
    if (!targetUrl) {
        return res.status(400).send('URL parameter is required');
    }
    
    try {
        const response = await fetch(targetUrl);
        const content = await response.text();
        
        // Basic HTML rewriting to handle links
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
    console.log(`Rift Proxy running on http://localhost:${PORT}`);
});
