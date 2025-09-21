// server.js (ESM)
import express from 'express';
import fetch from 'node-fetch';
import dotenv from 'dotenv';
import fs from 'fs';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
app.use(express.json()); // for POST /set-credentials

// Truncate previous logs on startup (if running in this workspace)
try {
  // Use Node fs to truncate logs if they exist
  const outLog = 'e:/spotify-find/server-out.log';
  const errLog = 'e:/spotify-find/server-err.log';
  try { if (fs.existsSync(outLog)) fs.truncateSync(outLog, 0); } catch (e) { /* ignore */ }
  try { if (fs.existsSync(errLog)) fs.truncateSync(errLog, 0); } catch (e) { /* ignore */ }
} catch (e) {
  // ignore if anything goes wrong truncating logs
}

// Helper to be tolerant of `.env` values that include accidental quotes
function stripQuotes(s) {
  if (!s && s !== '') return s;
  return s.toString().trim().replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1');
}

// Credentials may be provided via .env or set at runtime from the UI.
let runtimeClientId = stripQuotes(process.env.SPOTIFY_CLIENT_ID) || null;
let runtimeClientSecret = stripQuotes(process.env.SPOTIFY_CLIENT_SECRET) || null;

// In-memory log and scan buffers to show in the UI and to write to disk.
const LOG_BUFFER_MAX = 2000;
const LOG_FILE = 'e:/spotify-find/server-out.log';
const ERR_FILE = 'e:/spotify-find/server-err.log';
const logs = [];
const scans = [];

function addLog(level, message) {
  try {
    const entry = { ts: Date.now(), level, message: typeof message === 'string' ? message : JSON.stringify(message) };
    logs.push(entry);
    if (logs.length > LOG_BUFFER_MAX) logs.shift();
    // append to disk for persistence (non-blocking)
    const line = `[${new Date(entry.ts).toISOString()}] ${level.toUpperCase()} ${entry.message}\n`;
    try { fs.appendFileSync(level === 'error' ? ERR_FILE : LOG_FILE, line); } catch (e) { /* ignore */ }
    // also mirror to console for local debugging
    if (level === 'error') console.error(entry.message); else console.log(entry.message);
  } catch (e) {
    // swallow logging errors
    try { console.error('Failed to add log', e); } catch (e2) {}
  }
}

function addScan(item) {
  try {
    const entry = { ts: Date.now(), ...item };
    scans.push(entry);
    if (scans.length > LOG_BUFFER_MAX) scans.shift();
  } catch (e) {
    addLog('error', 'Failed to add scan: ' + String(e));
  }
}

// --- Simple in-memory token cache ---
let accessToken = null;
let tokenExpiresAt = 0;

async function getAccessToken() {
  const now = Date.now();
  if (accessToken && now < tokenExpiresAt - 60_000) return accessToken;
  const clientId = runtimeClientId;
  const clientSecret = runtimeClientSecret;
  if (!clientId || !clientSecret) {
    throw new Error('Missing client id/secret. Set them via .env or the UI at / (Set Credentials)');
  }
  const basic = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  const body = 'grant_type=client_credentials';
  // Use a short timeout for token requests
  const res = await fetchWithTimeout('https://accounts.spotify.com/api/token', {
    method: 'POST',
    headers: {
      Authorization: `Basic ${basic}`,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body
  }, 8000);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Token error (${res.status}): ${text}`);
  }
  const data = await res.json();
  accessToken = data.access_token;
  tokenExpiresAt = Date.now() + data.expires_in * 1000;
  addLog('info', 'Obtained new access token (expires_in=' + data.expires_in + 's)');
  return accessToken;
}

// Small helper to add timeouts to fetch (AbortController)
// Simple in-memory TTL cache
const CACHE_TTL_MS = Number(process.env.CACHE_TTL_MS ?? 5 * 60 * 1000); // default 5m
const TRACKS_CACHE_TTL_MS = Number(process.env.TRACKS_CACHE_TTL_MS ?? 10 * 60 * 1000); // default 10m
const MAX_TRACKS_CACHE_ITEMS = Number(process.env.MAX_TRACKS_CACHE_ITEMS ?? 5000);
const cache = new Map();

function cacheSet(key, value, ttlMs = CACHE_TTL_MS) {
  try {
    cache.set(key, { value, expiresAt: Date.now() + ttlMs });
  } catch (e) {
    addLog('error', 'cacheSet failed: ' + String(e));
  }
}

function cacheGet(key) {
  const e = cache.get(key);
  if (!e) return null;
  if (Date.now() > e.expiresAt) {
    cache.delete(key);
    return null;
  }
  return e.value;
}

// Fetch with timeout + retries + exponential backoff for 429/5xx/network errors
async function fetchWithTimeout(resource, options = {}, timeout = 8000, retries = 3) {
  let attempt = 0;
  while (true) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    try {
      const res = await fetch(resource, { ...options, signal: controller.signal });
      clearTimeout(id);
      if ((res.status === 429 || (res.status >= 500 && res.status < 600)) && attempt < retries) {
        const ra = res.headers.get && res.headers.get('retry-after');
        let delayMs = ra ? Number(ra) * 1000 : Math.min(1000 * 2 ** attempt, 8000);
        delayMs = delayMs + Math.floor(Math.random() * 400);
        addLog('info', `Retryable status ${res.status} from ${resource}, retrying after ${delayMs}ms (attempt ${attempt + 1})`);
        await new Promise(r => setTimeout(r, delayMs));
        attempt++;
        continue;
      }
      return res;
    } catch (e) {
      clearTimeout(id);
      if (attempt < retries) {
        const delayMs = Math.min(1000 * 2 ** attempt, 8000) + Math.floor(Math.random() * 400);
        addLog('info', `Fetch error ${e && e.name} for ${resource}, retrying after ${delayMs}ms (attempt ${attempt + 1})`);
        await new Promise(r => setTimeout(r, delayMs));
        attempt++;
        continue;
      }
      throw e;
    }
  }
}

// normalize helper used across handlers
function normalizeString(s) {
  if (!s && s !== '') return '';
  try {
    return s.toString().normalize('NFKD').replace(/\p{M}/gu, '').replace(/[^\p{L}\p{N}]+/gu, ' ').toLowerCase().trim();
  } catch (e) {
    return s.toString().toLowerCase().replace(/[^a-z0-9]+/gi, ' ').trim();
  }
}

// Helper to search users via Spotify's search API (type=user)
async function* searchUsersAllPages(q, token) {
  let url = new URL('https://api.spotify.com/v1/search');
  url.searchParams.set('q', q);
  url.searchParams.set('type', 'user');
  url.searchParams.set('limit', '50');
  while (url) {
    const res = await fetchWithTimeout(url, { headers: { Authorization: `Bearer ${token}` } }, 8000);
    if (!res.ok) throw new Error(`User search error (${res.status}): ${await res.text()}`);
    const data = await res.json();
    for (const u of data.users?.items ?? []) yield u;
    url = data.users?.next ? new URL(data.users.next) : null;
  }
}

// --- Helper: iterate all search pages ---
async function* searchPlaylistsAllPages(q, token) {
  let url = new URL('https://api.spotify.com/v1/search');
  url.searchParams.set('q', q);            // you can pass quoted or unquoted q
  url.searchParams.set('type', 'playlist');
  url.searchParams.set('limit', '50');

  while (url) {
    const res = await fetchWithTimeout(url, { headers: { Authorization: `Bearer ${token}` } }, 8000);
    if (!res.ok) throw new Error(`Search error (${res.status}): ${await res.text()}`);
    const data = await res.json();
    for (const p of data.playlists?.items ?? []) yield p;
    url = data.playlists?.next ? new URL(data.playlists.next) : null;
  }
}

// Helper: iterate all playlists for a user (pages)
async function* userPlaylistsAllPages(userId, token) {
  // Attempt to use cache by ownerId
  const cacheKey = `userPlaylists:${userId}`;
  const cached = cacheGet(cacheKey);
  if (cached) {
    addLog('info', `userPlaylistsAllPages cache hit for ${userId} (${cached.length} items)`);
    for (const p of cached) yield p;
    return;
  }

  let url = new URL(`https://api.spotify.com/v1/users/${encodeURIComponent(userId)}/playlists`);
  url.searchParams.set('limit', '50');
  const all = [];
  while (url) {
    const res = await fetchWithTimeout(url, { headers: { Authorization: `Bearer ${token}` } }, 8000);
    if (!res.ok) throw new Error(`User playlists error (${res.status}): ${await res.text()}`);
    const data = await res.json();
    for (const p of data.items ?? []) {
      all.push(p);
      yield p;
    }
    url = data.next ? new URL(data.next) : null;
  }
  try { cacheSet(cacheKey, all, CACHE_TTL_MS); } catch (e) { /* ignore cache write errors */ }
}

// --- API: GET /find?name=Everything&owner=Boo&exact=true ---
app.get('/find', async (req, res) => {
  try {
    const name = (req.query.name ?? '').toString().trim();
    const owner = (req.query.owner ?? '').toString().trim();
    const owner_id = (req.query.owner_id ?? req.query.ownerId ?? '').toString().trim();
  const exact = (req.query.exact ?? 'true').toString().toLowerCase() !== 'false'; // default exact=true
  const maxResults = Math.max(1, Math.min(Number(req.query.maxResults ?? 500), 2000)); // cap results to avoid OOM

    if (!name) return res.status(400).json({ error: 'Missing ?name=' });

    const token = await getAccessToken();

    // Use quoted query to tighten matches by default
    const q = exact ? `"${name}"` : name;

    // helper: normalize strings for comparison (remove punctuation, collapse spaces, lowercase)
    const normalize = (s) => {
      if (!s && s !== '') return '';
      try {
        // decompose accents then remove combining marks, replace non-alphanumerics with space
        return s.toString().normalize('NFKD').replace(/\p{M}/gu, '').replace(/[^\p{L}\p{N}]+/gu, ' ').toLowerCase().trim();
      } catch (e) {
        // fallback for environments without Unicode property escapes
        return s.toString().toLowerCase().replace(/[^a-z0-9]+/gi, ' ').trim();
      }
    };

    const results = [];
    let processed = 0;
    for await (const p of searchPlaylistsAllPages(q, token)) {
      processed++;
      addScan({ type: 'searchItem', idx: processed, id: p?.id ?? null, name: p?.name ?? null, owner: p?.owner?.display_name ?? null });
      const n = p?.name ?? '';
      const o = p?.owner?.display_name ?? '';

      const normName = normalize(n);
      const normQuery = normalize(name);

      const nameMatch = exact ? normName === normQuery : normName.includes(normQuery);

      let ownerMatch = true;
      if (owner_id) {
        ownerMatch = Boolean(p?.owner?.id && p.owner.id === owner_id);
      } else if (owner) {
        const normOwner = normalize(o);
        const normOwnerQuery = normalize(owner);
        ownerMatch = exact ? normOwner === normOwnerQuery : normOwner.includes(normOwnerQuery);
      }

      if (nameMatch && ownerMatch) {
        try {
          // Only return minimal fields as requested: name, playlist_id, playlist_url
          results.push({
            name: p?.name ?? null,
            playlist_id: p?.id ?? null,
            playlist_url: p?.external_urls?.spotify ?? null,
            owner_name: p?.owner?.display_name ?? null,
            owner_id: p?.owner?.id ?? null
          });
        } catch (e) {
          console.error('Skipping malformed playlist item', e && e.stack ? e.stack : e);
        }
      }

      if (results.length >= maxResults) break;
    }
    addLog('info', `Search /find completed: name=${name} owner=${owner} results=${results.length}`);
    res.json({ count: results.length, results });
  } catch (err) {
    addLog('error', 'Error in /find handler: ' + String(err && err.stack ? err.stack : err));
    res.status(500).json({ error: String(err.message || err) });
  }
});

// --- API: GET /find-by-owner-name?owner=Boo&name=Everything ---
// Best-effort: run multiple playlist searches (quoted/unquoted, with owner appended)
// and aggregate results, then filter by normalized owner/display name and playlist name.
app.get('/find-by-owner-name', async (req, res) => {
  try {
    const owner = (req.query.owner ?? '').toString().trim();
    const name = (req.query.name ?? '').toString().trim();
    const exact = (req.query.exact ?? 'true').toString().toLowerCase() !== 'false';
    const maxResults = Math.max(1, Math.min(Number(req.query.maxResults ?? 500), 2000));
    if (!owner || !name) return res.status(400).json({ error: 'Missing owner or name' });
    const token = await getAccessToken();

    const queries = [];
    const quotedName = `"${name}"`;
    // try different permutations
    queries.push(quotedName);
    queries.push(`${quotedName} ${owner}`);
    queries.push(`${name} ${owner}`);
    queries.push(name);
    queries.push(owner);

    const seen = new Set();
    const results = [];
    const normQueryName = normalizeString(name);
    const normOwnerQuery = normalizeString(owner);

    for (const q of queries) {
      for await (const p of searchPlaylistsAllPages(q, token)) {
        if (!p || !p.id) continue;
        if (seen.has(p.id)) continue;
        addScan({ type: 'ownerSearchItem', query: q, id: p.id, name: p.name, owner: p.owner?.display_name });
        // filter by normalized name and owner
        const normP = normalizeString(p?.name ?? '');
        const nameMatch = exact ? normP === normQueryName : normP.includes(normQueryName);
        const ownerDisplay = p?.owner?.display_name ?? '';
        const normOwner = normalizeString(ownerDisplay);
        const ownerMatch = exact ? normOwner === normOwnerQuery : normOwner.includes(normOwnerQuery);
        if (nameMatch && ownerMatch) {
          seen.add(p.id);
          results.push({
            name: p?.name ?? null,
            playlist_id: p?.id ?? null,
            playlist_url: p?.external_urls?.spotify ?? null,
            owner_name: ownerDisplay ?? null,
            owner_id: p?.owner?.id ?? null
          });
        }
        if (results.length >= maxResults) break;
      }
      if (results.length >= maxResults) break;
    }

    addLog('info', `find-by-owner-name completed: owner=${owner} name=${name} results=${results.length}`);
    res.json({ count: results.length, results });
  } catch (err) {
    addLog('error', 'Error in /find-by-owner-name: ' + String(err && err.stack ? err.stack : err));
    res.status(500).json({ error: String(err.message || err) });
  }
});

// --- API: GET /tracks/:playlistId  (fetches up to 100 per page; follow next yourself) ---
app.get('/tracks/:playlistId', async (req, res) => {
  try {
    const { playlistId } = req.params;
    if (!playlistId) return res.status(400).json({ error: 'Missing playlistId' });

    const token = await getAccessToken();
    const url = new URL(`https://api.spotify.com/v1/playlists/${encodeURIComponent(playlistId)}/tracks`);
    url.searchParams.set('limit', '100');

  const r = await fetchWithTimeout(url, { headers: { Authorization: `Bearer ${token}` } }, 8000);
  if (!r.ok) throw new Error(`Tracks error (${r.status}): ${await r.text()}`);
    const data = await r.json();
      addLog('info', `Fetched tracks for playlist ${playlistId} items=${(data.items ?? []).length}`);
      res.json({
        items: (data.items ?? []).map(t => ({
          added_at: t.added_at,
          track_name: t.track?.name,
          track_id: t.track?.id,
          artists: (t.track?.artists ?? []).map(a => a.name),
          album: t.track?.album?.name,
          preview_url: t.track?.preview_url,
          external_url: t.track?.external_urls?.spotify
        })),
        next: data.next
      });
  } catch (err) {
      addLog('error', 'Error in /tracks/:playlistId: ' + String(err && err.stack ? err.stack : err));
      res.status(500).json({ error: String(err.message || err) });
  }
});

// --- API: GET /playlist/:id  (lookup playlist metadata by ID) ---
app.get('/playlist/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!id) return res.status(400).json({ error: 'Missing playlist id' });
    const token = await getAccessToken();
    const url = `https://api.spotify.com/v1/playlists/${encodeURIComponent(id)}`;
    const r = await fetchWithTimeout(url, { headers: { Authorization: `Bearer ${token}` } }, 8000);
    if (!r.ok) throw new Error(`Playlist lookup error (${r.status}): ${await r.text()}`);
    const p = await r.json();
      addLog('info', `Playlist lookup /playlist/${id} ok name=${p?.name}`);
      res.json({
        id: p?.id ?? null,
        name: p?.name ?? null,
        owner_name: p?.owner?.display_name ?? null,
        owner_id: p?.owner?.id ?? null,
        external_url: p?.external_urls?.spotify ?? null,
        total_tracks: p?.tracks?.total ?? null
      });
  } catch (err) {
      addLog('error', 'Error in /playlist/:id: ' + String(err && err.stack ? err.stack : err));
    res.status(500).json({ error: String(err.message || err) });
  }
});

// also allow lookup by full url: /playlist?url=...
app.get('/playlist', async (req, res) => {
  try {
    const urlParam = req.query.url?.toString();
    if (!urlParam) return res.status(400).json({ error: 'Missing url query' });
    // extract playlist id from spotify url
    const m = urlParam.match(/playlist\/([A-Za-z0-9]+)(?:\?|$)/);
    if (!m) return res.status(400).json({ error: 'Invalid playlist url' });
    const id = m[1];
    return app.handle({ method: 'GET', url: `/playlist/${id}` }, res);
  } catch (err) {
    console.error('Error in /playlist (url)', err && err.stack ? err.stack : err);
    res.status(500).json({ error: String(err.message || err) });
  }
});

// --- API: GET /find-from-url?url=... ---
// Given a Spotify playlist URL, try to find it via the owner's playlists (more reliable than search)
app.get('/find-from-url', async (req, res) => {
  try {
    const urlParam = req.query.url?.toString();
    if (!urlParam) return res.status(400).json({ error: 'Missing url query' });
    const m = urlParam.match(/playlist\/([A-Za-z0-9]+)(?:\?|$)/);
    if (!m) return res.status(400).json({ error: 'Invalid playlist url' });
    const id = m[1];
    const token = await getAccessToken();
    // lookup playlist to get owner id
    const r = await fetchWithTimeout(`https://api.spotify.com/v1/playlists/${encodeURIComponent(id)}`, { headers: { Authorization: `Bearer ${token}` } }, 8000);
    if (!r.ok) throw new Error(`Playlist lookup error (${r.status}): ${await r.text()}`);
    const p = await r.json();
    const ownerId = p?.owner?.id;
    if (!ownerId) return res.status(404).json({ error: 'Owner not found' });

    // iterate owner's playlists and match by id
    for await (const up of userPlaylistsAllPages(ownerId, token)) {
        addScan({ type: 'ownerPlaylist', ownerId, id: up?.id, name: up?.name });
        if (up?.id === id) {
          addLog('info', `Found playlist ${id} under owner ${ownerId}`);
          return res.json({
            name: up?.name ?? null,
            playlist_id: up?.id ?? null,
            playlist_url: up?.external_urls?.spotify ?? null,
            owner_name: up?.owner?.display_name ?? null,
            owner_id: up?.owner?.id ?? null,
            total_tracks: up?.tracks?.total ?? null
          });
        }
    }

    return res.status(404).json({ error: 'Playlist not found under owner' });
  } catch (err) {
    console.error('Error in /find-from-url', err && err.stack ? err.stack : err);
    res.status(500).json({ error: String(err.message || err) });
  }
});

// --- API: GET/POST /scan-owner ---
// GET: /scan-owner?ownerId=...&name=...&songs=...&maxResults=10
// POST: JSON { ownerId, ownerUrl, name, songs }
app.all('/scan-owner', async (req, res) => {
  try {
    const isPost = req.method === 'POST';
    const ownerId = (isPost ? req.body?.ownerId || req.body?.owner_id : req.query.ownerId || req.query.owner_id) || (isPost ? req.body?.ownerUrl || req.body?.owner_url : req.query.ownerUrl || req.query.owner_url);
    const ownerUrlParam = isPost ? req.body?.ownerUrl || req.body?.owner_url : req.query.ownerUrl || req.query.owner_url;
    const name = (isPost ? req.body?.name : req.query.name) ?? '';
    const songsRaw = (isPost ? req.body?.songs : req.query.songs) ?? '';
    const maxResults = Math.max(1, Math.min(Number(isPost ? req.body?.maxResults : req.query.maxResults) || 10, 200));

    let ownerIdFinal = ownerId;
    if (!ownerIdFinal && ownerUrlParam) {
      const m = ownerUrlParam.toString().match(/user\/([A-Za-z0-9._-]+)|spotify:artist:([A-Za-z0-9._-]+)/);
      if (m) ownerIdFinal = m[1] || m[2];
    }

    if (!ownerIdFinal) return res.status(400).json({ error: 'Missing ownerId or ownerUrl' });

    const token = await getAccessToken();
    const songTerms = songsRaw ? songsRaw.split(',').map(s => s.trim()).filter(Boolean) : [];
    const normSongTerms = songTerms.map(s => normalizeString(s));

    const matches = [];
    let processed = 0;
    for await (const p of userPlaylistsAllPages(ownerIdFinal, token)) {
      processed++;
      addScan({ type: 'scanOwnerPlaylist', ownerId: ownerIdFinal, id: p?.id, name: p?.name });
      const obj = {
        id: p?.id,
        name: p?.name,
        playlist_url: p?.external_urls?.spotify,
        owner_id: ownerIdFinal,
        owner_name: p?.owner?.display_name ?? null,
        total_tracks: p?.tracks?.total ?? null,
        nameMatches: false,
        matchedSongs: []
      };

      // name match
      if (name) {
        const normP = normalizeString(p?.name ?? '');
        const normQuery = normalizeString(name);
        obj.nameMatches = normP === normQuery || normP.includes(normQuery);
      }

      // check songs if provided (scan tracks)
      if (normSongTerms.length > 0) {
        try {
          for await (const item of playlistTracksAllPages(p.id, token)) {
            const t = item.track;
            if (!t) continue;
            const tn = normalizeString(t.name ?? '');
            const an = (t.artists ?? []).map(a => normalizeString(a.name ?? '')).join(' ');
            for (const term of normSongTerms) {
              if (!term) continue;
              if (tn.includes(term) || an.includes(term)) {
                if (!obj.matchedSongs.includes(term)) obj.matchedSongs.push(term);
              }
            }
            if (obj.matchedSongs.length === normSongTerms.length) break;
          }
        } catch (e) {
          addLog('error', `Error scanning tracks for ${p.id}: ${String(e)}`);
        }
      }

      if (obj.nameMatches || obj.matchedSongs.length > 0) {
        matches.push(obj);
      }
      if (matches.length >= maxResults) break;
    }

    // rank: nameMatches first then by matchedSongs count
    matches.sort((a,b) => (b.nameMatches - a.nameMatches) || (b.matchedSongs.length - a.matchedSongs.length));
    addLog('info', `scan-owner completed owner=${ownerIdFinal} scanned=${processed} matches=${matches.length}`);
    res.json({ ownerId: ownerIdFinal, scanned: processed, matches });
  } catch (e) {
    addLog('error', 'Error in /scan-owner: ' + String(e));
    res.status(500).json({ error: String(e) });
  }
});

// Helper: iterate all tracks for a playlist (pages)
async function* playlistTracksAllPages(playlistId, token) {
  const cacheKey = `playlistTracks:${playlistId}`;
  const cached = cacheGet(cacheKey);
  if (cached) {
    addLog('info', `playlistTracksAllPages cache hit for ${playlistId} (${cached.length} items)`);
    for (const t of cached) yield t;
    return;
  }

  let url = new URL(`https://api.spotify.com/v1/playlists/${encodeURIComponent(playlistId)}/tracks`);
  url.searchParams.set('limit', '100');
  const all = [];
  while (url) {
    const res = await fetchWithTimeout(url, { headers: { Authorization: `Bearer ${token}` } }, 8000);
    if (!res.ok) throw new Error(`Playlist tracks error (${res.status}): ${await res.text()}`);
    const data = await res.json();
    for (const t of data.items ?? []) {
      all.push(t);
      yield t;
    }
    url = data.next ? new URL(data.next) : null;
  }
  try {
    // Limit cached tracks size to avoid unbounded memory growth
    if (all.length <= MAX_TRACKS_CACHE_ITEMS) cacheSet(cacheKey, all, TRACKS_CACHE_TTL_MS);
  } catch (e) {
    /* ignore cache write errors */
  }
}

// --- API: GET /advanced-search?name=&owner=&songs=comma,separated&exact=&maxResults= ---
// Performs three separate searches: by playlist name, by owner display name, and by songs list.
app.get('/advanced-search', async (req, res) => {
  try {
    const name = (req.query.name ?? '').toString().trim();
    const owner = (req.query.owner ?? '').toString().trim();
    const songsRaw = (req.query.songs ?? '').toString().trim();
    const exact = (req.query.exact ?? 'false').toString().toLowerCase() !== 'false'; // default false for broader match
    const maxResults = Math.max(1, Math.min(Number(req.query.maxResults ?? 500), 2000));

    const songTerms = songsRaw ? songsRaw.split(',').map(s => s.trim()).filter(Boolean) : [];

    const token = await getAccessToken();

    // Build candidate playlists by running playlist searches for name, owner, and each song term
    const candidateIds = new Set();
    const candidates = new Map(); // id -> playlist object

    const pushCandidate = (p) => {
      if (!p || !p.id) return;
      if (!candidateIds.has(p.id)) {
        candidateIds.add(p.id);
        candidates.set(p.id, {
          id: p.id,
          name: p.name ?? null,
          playlist_url: p.external_urls?.spotify ?? null,
          owner_name: p.owner?.display_name ?? null,
          owner_id: p.owner?.id ?? null,
          total_tracks: p.tracks?.total ?? null,
          matchedByName: false,
          matchedByOwner: false,
          matchedBySongs: false,
          matchedSongs: []
        });
      }
    };

    // helper to run playlist searches and collect candidates
    const runPlaylistQuery = async (q, markName=false, markOwner=false) => {
      for await (const p of searchPlaylistsAllPages(q, token)) {
          if (!p || !p.id) continue;
          pushCandidate(p);
          const obj = candidates.get(p.id);
          if (markName) obj.matchedByName = true;
          if (markOwner) obj.matchedByOwner = true;
          if (candidates.size >= maxResults) return;
        }
    };

    // 1) name-based search
    if (name) {
      const quoted = exact ? `"${name}"` : name;
      await runPlaylistQuery(quoted, true, false);
    }

    // 2) owner-based search (use owner as token appended)
    if (owner) {
      const q = `${owner}`;
      await runPlaylistQuery(q, false, true);
    }

    // 3) song-term searches
    for (const term of songTerms) {
      if (!term) continue;
      await runPlaylistQuery(term, false, false);
      if (candidates.size >= maxResults) break;
    }

    // Now, for each candidate playlist, fetch its tracks and check for songs
    const normSongTerms = songTerms.map(s => normalizeString(s));
    for (const [id, obj] of candidates) {
      if (songTerms.length === 0) continue;
      try {
        let foundSongs = [];
        for await (const item of playlistTracksAllPages(id, token)) {
          const track = item.track;
          if (!track) continue;
          const trackName = normalizeString(track.name ?? '');
          const artistNames = (track.artists ?? []).map(a => normalizeString(a.name ?? '')).join(' ');
          for (let i = 0; i < normSongTerms.length; i++) {
            const term = normSongTerms[i];
            if (term && (trackName.includes(term) || artistNames.includes(term))) {
              if (!foundSongs.includes(term)) foundSongs.push(term);
            }
          }
          if (foundSongs.length === normSongTerms.length) break; // all found
        }
        if (foundSongs.length > 0) {
          obj.matchedBySongs = true;
          obj.matchedSongs = foundSongs;
        }
      } catch (e) {
        // ignore track fetch errors per playlist
        console.error('Error checking tracks for playlist', id, e && e.stack ? e.stack : e);
      }
    }

    // Build final arrays: nameMatches, ownerMatches, songsMatches, combined
    const nameMatches = [];
    const ownerMatches = [];
    const songsMatches = [];
    const combined = [];

    for (const obj of candidates.values()) {
      if (obj.matchedByName) nameMatches.push(obj);
      if (obj.matchedByOwner) ownerMatches.push(obj);
      if (obj.matchedBySongs) songsMatches.push(obj);
      // combined: include flags
      combined.push(obj);
    }

    res.json({
      counts: { name: nameMatches.length, owner: ownerMatches.length, songs: songsMatches.length, combined: combined.length },
      nameMatches, ownerMatches, songsMatches, combined
    });
  } catch (err) {
    addLog('error', 'Error in /advanced-search: ' + String(err && err.stack ? err.stack : err));
    res.status(500).json({ error: String(err.message || err) });
  }
});

// --- Minimal UI for convenience ---
app.get('/', (_req, res) => {
  res.type('html').send(`
<!doctype html>
<meta charset="utf-8"/>
<title>Find Spotify Playlist</title>
<style>
  body{font-family:system-ui,Segoe UI,Arial;margin:2rem;max-width:860px}
  input,button{font:inherit;padding:.5rem .7rem}
  .row{margin:.4rem 0}
  pre{background:#f6f8fa;padding:1rem;border-radius:8px;white-space:pre-wrap}
</style>
<h1>Find Spotify Playlist</h1>
<form id="f">
  <div class="row">
    <label>Playlist name: <input name="name" value="Everything" required /></label>
  </div>
  <div class="row">
    <label>Owner (display name): <input name="owner" value="Boo" /></label>
  </div>
  <div class="row">
    <label>Client ID: <input name="client_id" id="client_id" placeholder="Optional (will override .env)" /></label>
  </div>
  <div class="row">
    <label>Client Secret: <input name="client_secret" id="client_secret" placeholder="Optional (will override .env)" type="password" /></label>
  </div>
  <div class="row">
    <label>Songs (comma-separated): <input name="songs" placeholder="song1, song2" /></label>
  </div>
  <div class="row">
    <label><input type="checkbox" name="exact" /> Exact match</label>
  </div>
  <div class="row">
    <button id="search">Search</button>
  </div>
</form>
<div style="display:flex;gap:1rem;margin-top:1rem">
  <div style="flex:1">
    <pre id="out" style="height:320px;overflow:auto;background:#111;color:#0f0;padding:1rem;border-radius:6px"></pre>
  </div>
  <div style="width:360px">
    <div style="font-weight:600">Live scans / logs</div>
    <div id="scanWindow" style="height:320px;overflow:auto;background:#fff;border:1px solid #ddd;padding:.5rem;border-radius:6px;font-family:monospace;font-size:12px"></div>
  </div>
</div>
<script>
  const f = document.getElementById('f');
  const out = document.getElementById('out');
  const scanWindow = document.getElementById('scanWindow');
  async function runAdvancedSearch() {
    const fd = new FormData(f);
    const params = new URLSearchParams();
    params.set('name', fd.get('name'));
    if (fd.get('owner')) params.set('owner', fd.get('owner'));
    if (fd.get('songs')) params.set('songs', fd.get('songs'));
    params.set('exact', fd.get('exact') ? 'true' : 'false');
    // optionally set runtime credentials (do not echo secret)
    const clientId = document.getElementById('client_id').value.trim();
    const clientSecret = document.getElementById('client_secret').value.trim();
    if (clientId && clientSecret) {
      await fetch('/set-credentials', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ client_id: clientId, client_secret: clientSecret }) });
    }
    out.textContent = 'Searching...';
    const r = await fetch('/advanced-search?' + params.toString());
    const j = await r.json();
    out.textContent = JSON.stringify(j, null, 2);
  }
  document.getElementById('search').addEventListener('click', async (e) => {
    e.preventDefault();
    await runAdvancedSearch();
  });

  // poll logs and scan items every 1s and append to the scan window, auto-scroll to caret-like behavior
  async function pollScans() {
    try {
      const r = await fetch('/_debug/scans');
      const data = await r.json();
  scanWindow.innerHTML = data.map(s => '[' + new Date(s.ts).toLocaleTimeString() + '] ' + (s.type || '') + ' ' + (s.name || '') + ' ' + (s.id || '')).join('<br>');
      // Try to follow the last cursor point by scrolling to bottom
      scanWindow.scrollTop = scanWindow.scrollHeight;
    } catch (e) {
      // ignore poll errors
    }
    setTimeout(pollScans, 1000);
  }
  pollScans();
</script>
  `);
});

// POST /set-credentials  { client_id, client_secret }
app.post('/set-credentials', (req, res) => {
  try {
    const { client_id, client_secret } = req.body || {};
    if (!client_id || !client_secret) return res.status(400).json({ error: 'Missing client_id or client_secret' });
    runtimeClientId = client_id.trim();
    runtimeClientSecret = client_secret.trim();
    // clear existing token to force a new one with these creds
    accessToken = null; tokenExpiresAt = 0;
    addLog('info', 'Runtime credentials set via UI (client id partially hidden)');
    return res.json({ ok: true });
  } catch (e) {
    addLog('error', 'Failed to set credentials: ' + String(e));
    res.status(500).json({ error: String(e) });
  }
});

// GET /_debug/logs
app.get('/_debug/logs', (_req, res) => res.json(logs));

// GET /_debug/scans
app.get('/_debug/scans', (_req, res) => res.json(scans.slice(-200)));

app.listen(PORT, () => {
  console.log(`▶ Listening on http://localhost:${PORT}`);
});
