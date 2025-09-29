// server.js — Halo Grunt (OAuth broker) — resilient v1/v2 endpoints

import express from "express";
import crypto from "crypto";

const app = express();
const PORT = process.env.PORT || 3000;

// ----- Required env -----
const ADMIN_KEY          = process.env.ADMIN_KEY;                        // your admin key
const AZURE_AUTHORITY    = process.env.AZURE_AUTHORITY;                  // e.g. https://login.microsoftonline.com/consumers
const AZURE_CLIENT_ID    = process.env.AZURE_CLIENT_ID;                  // Application (client) ID
const AZURE_CLIENT_SECRET= process.env.AZURE_CLIENT_SECRET;              // Client secret *Value*
const AZURE_REDIRECT_URI = process.env.AZURE_REDIRECT_URI;               // e.g. https://<your-service>.up.railway.app/callback

// Minimal in-memory token store (one login is fine for our flow)
let tokenStore = {
  accessToken: null,
  refreshToken: null,
  expiresAt: null,           // epoch ms
};

// Pick v1 vs v2 paths from authority
function authorizePathFor(authority) {
  return authority.includes("login.live.com")
    ? "/oauth20_authorize.srf"   // v1 Live
    : "/oauth2/v2.0/authorize";  // v2 Microsoft
}
function tokenPathFor(authority) {
  return authority.includes("login.live.com")
    ? "/oauth20_token.srf"       // v1 Live
    : "/oauth2/v2.0/token";      // v2 Microsoft
}

// Build full URLs
function buildAuthorizeUrl(state) {
  const authUrl = new URL(authorizePathFor(AZURE_AUTHORITY), AZURE_AUTHORITY);
  // v2 and v1 both accept these basics; scopes differ by usage
  const scope = [
    "openid",
    "profile",
    "offline_access",
    "XboxLive.signin",
    "XboxLive.offline_access",
  ].join(" ");

  authUrl.searchParams.set("client_id", AZURE_CLIENT_ID);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("redirect_uri", AZURE_REDIRECT_URI);
  authUrl.searchParams.set("response_mode", "query");
  authUrl.searchParams.set("scope", scope);
  authUrl.searchParams.set("state", state);
  // niceties
  authUrl.searchParams.set("prompt", "select_account");

  return authUrl.toString();
}

async function exchangeCodeForToken(code) {
  const tokenUrl = new URL(tokenPathFor(AZURE_AUTHORITY), AZURE_AUTHORITY);
  const body = new URLSearchParams();
  body.set("client_id", AZURE_CLIENT_ID);
  body.set("client_secret", AZURE_CLIENT_SECRET);
  body.set("redirect_uri", AZURE_REDIRECT_URI);
  body.set("grant_type", "authorization_code");
  body.set("code", code);

  const r = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!r.ok) {
    const txt = await r.text();
    throw new Error(`token exchange failed ${r.status}: ${txt}`);
  }
  return r.json();
}

// Admin guard
function requireAdmin(req, res, next) {
  const key = req.query.key || req.header("x-admin-key");
  if (!ADMIN_KEY || key !== ADMIN_KEY) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }
  next();
}

// Health
app.get("/health", (_req, res) => res.json({ ok: true }));

// Admin status: echo config & tokens
app.get("/admin/status", requireAdmin, (_req, res) => {
  const now = Date.now();
  const tokenExpiresInSec = tokenStore.expiresAt ? Math.max(0, Math.floor((tokenStore.expiresAt - now)/1000)) : null;

  res.json({
    ok: true,
    usingAuthority: AZURE_AUTHORITY,
    clientIdEndsWith: AZURE_CLIENT_ID?.slice(-5),
    hasSecret: !!AZURE_CLIENT_SECRET,
    redirectUri: AZURE_REDIRECT_URI,
    tokenStoreSize: tokenStore.accessToken ? 1 : 0,
    tokenExpiresInSec,
  });
});

// Start OAuth
app.get("/auth/start", requireAdmin, (req, res) => {
  const state = crypto.randomBytes(12).toString("hex");
  const url = buildAuthorizeUrl(state);
  console.log("[Grunt] Redirecting to authorize URL:", url);
  res.redirect(url);
});

// OAuth callback
app.get("/callback", async (req, res) => {
  const code = req.query.code;
  const error = req.query.error;
  if (error) {
    return res.status(400).send(`OAuth error: ${error} — ${req.query.error_description || ""}`);
  }
  if (!code) {
    return res.status(400).send("Missing authorization code");
  }
  try {
    const tokenResponse = await exchangeCodeForToken(code);
    // v2 shape: access_token, refresh_token, expires_in
    tokenStore.accessToken = tokenResponse.access_token || null;
    tokenStore.refreshToken = tokenResponse.refresh_token || null;
    tokenStore.expiresAt   = tokenResponse.expires_in ? Date.now() + (tokenResponse.expires_in * 1000) : null;

    console.log("[Grunt] Token stored. Expires in (sec):", tokenResponse.expires_in);
    res.send("Sign-in complete. You can close this tab.");
  } catch (e) {
    console.error("[Grunt] token exchange failed:", e.message);
    res.status(500).send("Token exchange failed.");
  }
});

// (placeholder) where we’ll build the full Halo header chain next
app.get("/spartan", async (req, res) => {
  return res.status(501).json({ ok: false, error: "spartan not yet wired" });
});

app.listen(PORT, () => {
  console.log(`Halo Grunt listening on :${PORT}`);
  console.log("Health: GET  /health");
  console.log("Login:  GET  /auth/start?key=YOUR_ADMIN_KEY");
  console.log("Status: GET  /admin/status?key=YOUR_ADMIN_KEY");
});

