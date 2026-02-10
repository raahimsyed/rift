// Basic Node.js server setup for Rift Proxy
// You'll need to install: npm install express node-fetch

const express = require('express');
const fetch = require('node-fetch');
const path = require('path');

const app = express();

// Serve static files with proper MIME types
app.use(express.static(__dirname, {
    setHeaders: (res, filepath) => {
        if (filepath.endsWith('.css')) {
            res.setHeader('Content-Type', 'text/css');
        } else if (filepath.endsWith('.js')) {
            res.setHeader('Content-Type', 'application/javascript');
        } else if (filepath.endsWith('.ttf')) {
            res.setHeader('Content-Type', 'font/ttf');
        }
    }
}));

// Explicitly serve CSS file
app.get('/styles.css', (req, res) => {
    res.setHeader('Content-Type', 'text/css');
    res.sendFile(path.join(__dirname, 'styles.css'));
});

// Explicitly serve JS file
app.get('/app.js', (req, res) => {
    res.setHeader('Content-Type', 'application/javascript');
    res.sendFile(path.join(__dirname, 'app.js'));
});

// Explicitly serve font file
app.get('/RunMedium-2VJo.ttf', (req, res) => {
    res.setHeader('Content-Type', 'font/ttf');
    res.sendFile(path.join(__dirname, 'RunMedium-2VJo.ttf'));
});

// Explicitly serve background image
app.get('/background.jpg', (req, res) => {
    res.setHeader('Content-Type', 'image/jpeg');
    res.sendFile(path.join(__dirname, 'background.jpg'));
});

// Home route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
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

// Export for Vercel
module.exports = app;

// Local development
if (require.main === module) {
    const PORT = 3000;
    app.listen(PORT, () => {
        console.log(`Rift Proxy running on http://localhost:${PORT}`);
    });
}
