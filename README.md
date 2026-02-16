# Rift Proxy

A simple unblocked proxy with separated components.

## Files Structure

- `index.html` - Main HTML structure
- `styles.css` - CSS styling
- `app.js` - Client-side JavaScript
- `server.js` - Node.js backend server
- `package.json` - Dependencies

## Setup

1. Install dependencies:
```bash
npm install
```

2. Start the server:
```bash
npm start
```

3. Open your browser to:
```
http://localhost:3000
```

## Usage

Enter a URL or search term in the input field and click "Go" or press Enter.

## Vercel Production Domain Checklist

If a preview URL (like `*-git-branch-user.vercel.app`) works but the main domain (`riftedproxies.vercel.app`) does not, verify:

1. **Production Branch** is set to the branch with the latest fixes (Project → Settings → Git).
2. The latest commit is actually deployed as a **Production** deployment (Project → Deployments).
3. `riftedproxies.vercel.app` is attached to this same Vercel project (Project → Settings → Domains).
4. If needed, use **Promote to Production** on a working preview deployment.


This repository uses a catch-all rewrite in `vercel.json` to send all requests to `api/index` (which exports the Express app), so routing logic is shared between preview and production.

### Known-good `vercel.json`

Use this exact shape and do not mix legacy `builds/routes` with modern rewrites:

```json
{
  "version": 2,
  "rewrites": [
    {
      "source": "/(.*)",
      "destination": "/api/index"
    }
  ]
}

This repository uses a catch-all route in `vercel.json` to send all requests to `server/server.js`, so routing logic is shared between preview and production.


