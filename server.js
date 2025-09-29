// server.js — Grunt: Microsoft login + gated CSR proxy (no stubs)

import express from "express";
import cors from "cors";
import crypto from "crypto";
import fetch from "node-fetch";
import querystring from "querystring";

// ----- ENV -----
const {
  PORT = "3000",
  ADMIN_KEY,
  GRUNT_SHARED_SECRET,
  AZURE_CLIENT_ID,
  AZURE_CLIENT_SECRET,
  AZURE_TENANT_ID, // optional, not used for "consumers" authority
  AZURE_AUTHORITY = "https://login.microsoftonline.com/consumers",
  AZURE_REDIRECT_URI,
} = process.env;

// Basic sanity checks so failures are obvious
function must(name, value) {
  if (!value) {
    console.error(`[FATAL] Missing env ${name}`);
    process.exit(1);
  }
}
must("ADMIN_KEY", ADMIN_KEY);
must("GRUNT_SHARED_SECRET", GRUNT_SHARED_SECRET);
must("AZURE_CLIENT_ID", AZURE_CLIENT_ID);
must("AZURE_CLIENT_SECRET", AZURE_CLIENT_SECRET);
must("AZURE_REDIRECT_URI", AZURE_REDIRECT_URI);

// ----- App -----
const app = express();
app.use(cors());
app.use(express.json());

// In-memory token store (simple, one-user)
const tokenStore = {
  accessToken: null,
  refreshToken: null,
  expiresAt: 0, // epoch ms
};

function isAccessTokenValid() {
  const now = Date.now();
  return tokenStore.accessToken && tokenStore.expiresAt > now + 60_000; // 60s buffer
}

async function refreshAccessTokenIfNeeded() {
  if (isAccessTokenValid()) return;

  if (!tokenStore.refreshToken) {
    throw new Error("No refresh token; please sign in again.");
  }

  // OAuth2 token endpoint
  const tokenEndpoint = `${AZURE_AUTHORITY}/oauth2/v2.0/token`;

  const body = new URLSearchParams({
    client_id: AZURE_CLIENT_ID,
    client_secret: AZURE_CLIENT_SECRET,
    grant_type: "refresh_token",
    refresh_token: tokenStore.refreshToken,
    // scope not strictly required for refresh, but harmless if present
    scope: "XboxLive.signin offline_access openid profile",
    redirect_uri: AZURE_REDIRECT_URI,
  });

  const resp = await fetch(tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    console.error("[refreshAccessToken] error:", data);
    throw new Error("Refresh token exchange failed");
  }

  tokenStore.accessToken = data.access_token || null;
  tokenStore.refreshToken = data.refresh_token || tokenStore.refreshToken;
  tokenStore.expiresAt = Date.now() + (data.expires_in || 3600) * 1000;
}

// ----- Health -----
app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

// ----- Admin status -----
app.get("/admin/status", (req, res) => {
  const key = req.query.key;
  if (key !== ADMIN_KEY) return res.status(401).json({ ok: false, error: "Unauthorized" });

  res.json({
    ok: true,
    usingAuthority: AZURE_AUTHORITY,
    clientIdEndsWith: AZURE_CLIENT_ID.slice(-6),
    hasSecret: !!AZURE_CLIENT_SECRET,
    redirectUri: AZURE_REDIRECT_URI,
    tokenStoreSize: tokenStore.accessToken ? 1 : 0,
    tokenExpiresInSec: tokenStore.expiresAt ? Math.max(0, Math.floor((tokenStore.expiresAt - Date.now()) / 1000)) : null,
  });
});

// ----- OAuth start -----
app.get("/auth/start", (req, res) => {
  const key = req.query.key;
  if (key !== ADMIN_KEY) return res.status(401).send("Unauthorized");

  const state = crypto.randomBytes(16).toString("hex");
  const nonce = crypto.randomBytes(16).toString("hex");

  // Save in a trivial memory map for demo; normally use a session store
  stateNonceMap[state] = { nonce, createdAt: Date.now() };

  const params = {
    client_id: AZURE_CLIENT_ID,
    response_type: "code",
    redirect_uri: AZURE_REDIRECT_URI,
    response_mode: "query",
    scope: "XboxLive.signin offline_access openid profile",
    state,
    nonce,
  };

  const authUrl = `${AZURE_AUTHORITY}/oauth2/v2.0/authorize?${querystring.stringify(params)}`;
  res.redirect(authUrl);
});

const stateNonceMap = Object.create(null);

// ----- OAuth callback -----
app.get("/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    console.error("[callback] error:", error, error_description);
    return res.status(400).send(`Auth error: ${error}`);
  }
  if (!code || !state) return res.status(400).send("Missing code or state");

  const record = stateNonceMap[state];
  if (!record) return res.status(400).send("Invalid state");
  delete stateNonceMap[state];

  try {
    const tokenEndpoint = `${AZURE_AUTHORITY}/oauth2/v2.0/token`;
    const body = new URLSearchParams({
      client_id: AZURE_CLIENT_ID,
      client_secret: AZURE_CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: AZURE_REDIRECT_URI,
    });

    const resp = await fetch(tokenEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });

    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      console.error("[callback] token exchange failed:", data);
      return res.status(400).send("Token exchange failed; see logs.");
    }

    tokenStore.accessToken = data.access_token || null;
    tokenStore.refreshToken = data.refresh_token || null;
    tokenStore.expiresAt = Date.now() + (data.expires_in || 3600) * 1000;

    res.send(
      `<h3>Signed in.</h3><p>Access token stored in memory. You can close this tab.</p>`
    );
  } catch (e) {
    console.error("[callback] exception:", e);
    res.status(500).send("Unexpected error");
  }
});

// ----- Spartan/CSR endpoint (no stub) -----
// Called by your Worker/Wrapper.
// Requires header: x-grunt-auth: <GRUNT_SHARED_SECRET>
// Query: gt=<gamertag>&playlist=<playlist-id>
app.get("/spartan", async (req, res) => {
  const authHeader = req.headers["x-grunt-auth"];
  if (authHeader !== GRUNT_SHARED_SECRET) {
    return res.status(401).json({ ok: false, error: "Unauthorized (shared secret mismatch)" });
  }

  const gtRaw = (req.query.gt || "").toString().trim();
  const playlist = (req.query.playlist || "").toString().trim();

  if (!gtRaw || !playlist) {
    return res.status(400).json({ ok: false, error: "Missing gt or playlist" });
  }

  try {
    // Ensure we have a valid MS access token
    await refreshAccessTokenIfNeeded();
  } catch (e) {
    return res.status(401).json({
      ok: false,
      error: "Not signed in to Microsoft; visit /auth/start?key=YOUR_ADMIN_KEY",
      detail: e.message,
    });
  }

  // ---------- PLACEHOLDER FOR REAL HALO CALL ----------
  // At this point you have a valid Microsoft access token in tokenStore.accessToken.
  // For real CSR you must:
  // 1) Exchange MS AAD token -> XBL user token
  // 2) Exchange XBL user token -> XSTS token
  // 3) Exchange XSTS token -> Halo Spartan token
  // 4) Call the Halo Stats endpoint for CSR for (gtRaw, playlist)
  //
  // Until that chain is implemented, we refuse to return a fake stub.
  return res.status(501).json({
    ok: false,
    live: false,
    error: "Halo CSR fetch not implemented yet (no stub).",
    next: [
      "Exchange AAD access_token -> XBL user token",
      "Exchange XBL user token -> XSTS",
      "Exchange XSTS -> Spartan token",
      "Call Halo CSR endpoint for the given gamertag & playlist",
    ],
  });
});

// ----- Start -----
app.listen(Number(PORT), () => {
  console.log(`Halo Grunt listening on :${PORT}`);
  console.log(`Health:       GET  /health`);
  console.log(`Login:        GET  /auth/start?key=YOUR_ADMIN_KEY`);
  console.log(`Status:       GET  /admin/status?key=YOUR_ADMIN_KEY`);
  console.log(`CSR (worker): GET  /spartan   (needs x-grunt-auth header)`);
});

