// server.js — Halo Grunt (v2 Microsoft Identity Platform)

import express from "express";
import cors from "cors";
import crypto from "crypto";

// In Node 18+, fetch is global. If your runtime is older, uncomment next two lines:
// import fetch from "node-fetch";
// globalThis.fetch = fetch;

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ----- Env -----
const {
  PORT = "3000",

  // Admin gate for starting auth & viewing status
  ADMIN_KEY,

  // MSAL (v2) settings
  AZURE_AUTHORITY = "https://login.microsoftonline.com/consumers",
  AZURE_CLIENT_ID,
  AZURE_CLIENT_SECRET,
  AZURE_REDIRECT_URI,

  // Not required for v2, kept for compatibility / your dashboard view
  AZURE_TENANT_ID,

  // Shared secret the Worker/Wrapper will send to call /spartan
  GRUNT_SHARED_SECRET,

  // Where we forward the Spartan request (your chosen Halo stats endpoint)
  // Example we discussed:
  // HALO_ENDPOINT="https://halostats.svc.halowaypoint.com/hi/players/{gamertag}/csrs?playlist={playlistId}"
  HALO_ENDPOINT
} = process.env;

// ----- Basic validation -----
function reqEnv(name, value) {
  if (!value || String(value).trim() === "") {
    throw new Error(`Missing required env var: ${name}`);
  }
  return value;
}

reqEnv("ADMIN_KEY", ADMIN_KEY);
reqEnv("AZURE_CLIENT_ID", AZURE_CLIENT_ID);
reqEnv("AZURE_CLIENT_SECRET", AZURE_CLIENT_SECRET);
reqEnv("AZURE_REDIRECT_URI", AZURE_REDIRECT_URI);
reqEnv("GRUNT_SHARED_SECRET", GRUNT_SHARED_SECRET);
// HALO_ENDPOINT is optional at boot; /spartan will 503 if missing

// ----- Helpers -----
const v2AuthorizeUrl = `${AZURE_AUTHORITY.replace(/\/+$/, "")}/oauth2/v2.0/authorize`;
const v2TokenUrl = `${AZURE_AUTHORITY.replace(/\/+$/, "")}/oauth2/v2.0/token`;

// Memory token store (single-user flow). If you need multi-user later, key by user/state.
let tokenBundle = null; // { access_token, refresh_token, expires_at (ms), scope, id_token, ... }

// simple state store to validate /callback (avoid CSRF)
const stateSet = new Set();

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function msFromNow(seconds) {
  return Date.now() + seconds * 1000;
}

function randomState() {
  return crypto.randomBytes(16).toString("hex");
}

function urlEncode(params) {
  return new URLSearchParams(params).toString();
}

// Exchange auth code for tokens (v2)
async function exchangeCodeForToken(code) {
  const body = {
    client_id: AZURE_CLIENT_ID,
    client_secret: AZURE_CLIENT_SECRET,
    grant_type: "authorization_code",
    code,
    redirect_uri: AZURE_REDIRECT_URI
  };

  const res = await fetch(v2TokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: urlEncode(body)
  });

  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`token exchange failed: ${res.status} ${txt}`);
  }
  const json = await res.json();

  // Compute expiry timestamp
  const expires_in = Number(json.expires_in || 0);
  tokenBundle = {
    ...json,
    expires_at: msFromNow(expires_in)
  };
  return tokenBundle;
}

// Refresh token if needed (best effort)
async function ensureAccessToken() {
  if (!tokenBundle) return null;
  const soon = Date.now() + 60_000; // refresh if less than 60s left
  if (tokenBundle.expires_at > soon) {
    return tokenBundle.access_token;
  }
  if (!tokenBundle.refresh_token) {
    return tokenBundle.access_token; // nothing to refresh with
  }

  const body = {
    client_id: AZURE_CLIENT_ID,
    client_secret: AZURE_CLIENT_SECRET,
    grant_type: "refresh_token",
    refresh_token: tokenBundle.refresh_token,
    redirect_uri: AZURE_REDIRECT_URI
  };

  const res = await fetch(v2TokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: urlEncode(body)
  });

  if (!res.ok) {
    // keep old token; surface failure
    console.error("refresh failed:", res.status, await res.text());
    return tokenBundle.access_token;
  }
  const json = await res.json();
  tokenBundle = {
    ...tokenBundle,
    ...json,
    expires_at: msFromNow(Number(json.expires_in || 0))
  };
  return tokenBundle.access_token;
}

// Compose the v2 authorize URL
function buildAuthorizeUrl(state) {
  // Scopes: start simple; you can add XboxLive scopes if/when the app is configured
  const scope = [
    "openid",
    "profile",
    "offline_access"
    // "XboxLive.signin",
    // "XboxLive.offline_access"
  ].join(" ");

  const params = {
    client_id: AZURE_CLIENT_ID,
    response_type: "code",
    response_mode: "query",
    redirect_uri: AZURE_REDIRECT_URI,
    scope,
    state,
    prompt: "select_account"
  };

  return `${v2AuthorizeUrl}?${urlEncode(params)}`;
}

// ----- Routes -----

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

// Start login (admin gated)
app.get("/auth/start", (req, res) => {
  const key = req.query.key;
  if (key !== ADMIN_KEY) {
    return res.status(401).send("Unauthorized");
  }
  const state = randomState();
  stateSet.add(state);
  const url = buildAuthorizeUrl(state);
  console.log("[Grunt] Redirecting to authorize URL:", url);
  res.redirect(url);
});

// OAuth2 redirect handler
app.get("/callback", async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;

    if (error) {
      return res.status(400).send(`OAuth error: ${error}: ${error_description || ""}`);
    }
    if (!state || !stateSet.has(state)) {
      return res.status(400).send("Invalid state");
    }
    stateSet.delete(state);
    if (!code) {
      return res.status(400).send("Missing code");
    }

    await exchangeCodeForToken(code);

    res.send(
      `<html><body style="font-family:sans-serif">
        <h3>Signed in ✅</h3>
        <p>You can close this tab.</p>
        <pre>${JSON.stringify(
          { access_token: "stored", refresh_token: !!tokenBundle.refresh_token, expires_at: tokenBundle.expires_at },
          null,
          2
        )}</pre>
      </body></html>`
    );
  } catch (e) {
    console.error("callback error:", e);
    res.status(500).send("Callback failed");
  }
});

// Admin status (admin gated)
app.get("/admin/status", (req, res) => {
  const key = req.query.key;
  if (key !== ADMIN_KEY) {
    return res.status(401).send("Unauthorized");
  }

  const tokenStoreSize = tokenBundle ? 1 : 0;
  let tokenExpiresInSec = null;
  if (tokenBundle?.expires_at) {
    tokenExpiresInSec = Math.max(0, Math.floor((tokenBundle.expires_at - Date.now()) / 1000));
  }

  res.json({
    ok: true,
    usingAuthority: AZURE_AUTHORITY,
    clientIdEndsWith: (AZURE_CLIENT_ID || "").slice(-6),
    hasSecret: !!AZURE_CLIENT_SECRET,
    redirectUri: AZURE_REDIRECT_URI,
    tokenStoreSize,
    tokenExpiresInSec,
    xstsExpiresAt: null,
    spartanExpiresAt: null
  });
});

// Worker/Wrapper -> Grunt entry (requires shared secret)
// Example usage: GET /spartan?gamertag=Foo&playlist=<id>
// Sends to HALO_ENDPOINT with {gamertag} and {playlistId} placeholders if present.
app.get("/spartan", async (req, res) => {
  try {
    const hdr = req.headers["x-grunt-auth"];
    if (!hdr || hdr !== GRUNT_SHARED_SECRET) {
      return res.status(401).send("Unauthorized (missing/invalid x-grunt-auth)");
    }

    if (!HALO_ENDPOINT) {
      return res.status(503).send("HALO_ENDPOINT not configured");
    }
    if (!tokenBundle) {
      return res.status(503).send("Upstream login missing — sign in first via /auth/start");
    }

    const accessToken = await ensureAccessToken();

    // Fill placeholders if present
    let url = HALO_ENDPOINT;
    const { gamertag, playlist } = req.query;
    if (gamertag) url = url.replace("{gamertag}", encodeURIComponent(String(gamertag)));
    if (playlist) url = url.replace("{playlistId}", encodeURIComponent(String(playlist)));

    // If your endpoint expects normal query params instead of placeholders, you can:
    // const u = new URL(HALO_ENDPOINT);
    // if (gamertag) u.searchParams.set("gamertag", String(gamertag));
    // if (playlist) u.searchParams.set("playlist", String(playlist));
    // const url = u.toString();

    const upstream = await fetch(url, {
      headers: {
        // This is *your* bearer; if the upstream needs a different header
        // or an Xbox token instead, we’ll adapt here later.
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json"
      }
    });

    const text = await upstream.text();
    res.status(upstream.status).set("content-type", upstream.headers.get("content-type") || "text/plain").send(text);
  } catch (e) {
    console.error("/spartan error:", e);
    res.status(500).send("Upstream error");
  }
});

// Root
app.get("/", (_req, res) => {
  res.send("Halo Grunt (v2) up");
});

// Start
app.listen(Number(PORT), () => {
  console.log(`Halo Grunt listening on :${PORT}`);
  console.log("Health:  GET  /health");
  console.log("Login:   GET  /auth/start?key=YOUR_ADMIN_KEY");
  console.log("Status:  GET  /admin/status?key=YOUR_ADMIN_KEY");
  console.log("CSR:     GET  /spartan   (needs x-grunt-auth header)");
});
