# spotify-find

Small Express server that searches Spotify playlists using the Client Credentials flow.

Required environment variables (.env or environment):

- `SPOTIFY_CLIENT_ID`
- `SPOTIFY_CLIENT_SECRET`
- `PORT` (optional, default `3000`)

Install & run

```powershell
npm install
node server.js
```

Endpoints

- `GET /` - minimal UI to try searches
- `GET /find?name=...&owner=...&exact=true&maxResults=500` - search playlists. `exact` defaults to `true`; `maxResults` caps results (default 500, max 2000).
- `GET /tracks/:playlistId` - fetch up to 100 tracks per page from a playlist

Notes

- The server strips quotes around env var values so `.env` entries like `SPOTIFY_CLIENT_ID="id"` are tolerated.
- Network requests have short timeouts (8s) to avoid hanging.

Sanitizing before committing
 - This repository contains an `.env` used locally. Before committing, ensure your `.env` does NOT contain real credentials. The `.env.example` file shows the format. The repo's `.gitignore` excludes `.env` and logs.

Hosting the UI on GitHub Pages
 - The static UI in `docs/index.html` is suitable for GitHub Pages. It expects the API to be accessible from the same origin; if your server runs elsewhere, set the `API base` field in the UI to point to your server (e.g. `https://yourserver.example.com`).

Security notes
 - Never commit your real `SPOTIFY_CLIENT_SECRET` to a public repo. Use runtime credential entry via the UI (`Client ID`, `Client Secret`) or provide them via `.env` on a private repository only.
