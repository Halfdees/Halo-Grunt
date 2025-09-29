// server.js — Halo Grunt (clean replacement)
// Node 18+ (fetch available). Requires express & cors.

import express from "express";
import cors from "cors";

// ------------------------------
// Config
// ------------------------------
const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || "";
const AUTHORITY = (process.env.AZURE_AUTHORITY || "https://login.live.com/consumers").replace(/\/+$/, "");
const CLIENT_ID = process.env.AZURE_CLIENT_ID || "";
const CLIENT_SECRET = process.env.AZURE_CLIENT_SECRET || "";
const REDIRECT_URI = process.env.AZURE_REDIRECT_URI || "";
const GRUNT_SHARED_SECRET = process.env.GRUNT_SHARED_SECRET || "";

// Basic validation
function requireEnv(name, val) {
  if (!val) {
    console.error(`Missing required env ${name}`);
    process.exit(1);
  }
}
requireEnv("ADMIN_KEY", ADMIN_KEY);
requireEnv("AZURE_CLIENT_ID", CLIENT_ID);
requireEnv("AZURE_CLIENT_SECRET", CLIENT_SECRET);
requireEnv("AZURE_REDIRECT_URI", REDIRECT_URI);
requireEnv("GRUNT_SHARED_SECRET", GRUNT_SHARED_SECRET);

// ------------------------------
// Express
// ------------------------------
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ------------------------------
// In-memory token store (simple)
// ------------------------------
let tokenStore = {
  access_token: null,
  refresh_token: null,
  expires_at: 0, // epoch ms
};

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function msUntilExpiry() {
  return Math.max(0, tokenStore.expires_at * 1000 - Date.now());
}

// ------------------------------
// Helpers
// ------------------------------
function adminGuard(req, res, next) {
  if (req.query.key !== ADMIN_KEY) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }
  next();
}

function logHttpError(prefix, res, body) {
  console.error(`${prefix} failed: ${res.status}`);
  if (body) {
    try {
      const j = JSON.parse(body);
      console.error(`${prefix} body:`, JSON.stringify(j, null, 2));
    } catch {
      console.error(`${prefix} body:`, body.slice(0, 4000));
    }
  }
}

// Exchange CODE -> TOKENS or REFRESH -> TOKENS at login.live.com
async function tokenRequest(params) {
  const url = `${AUTHORITY}/oauth20_token.srf`;
  const body = new URLSearchParams(params);
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const text = await r.text();
  if (!r.ok) {
    logHttpError("oauth/token", r, text);
    throw new Error(`oauth token failed: ${r.status}`);
  }
  const json = JSON.parse(text);
  return json;
}

async function ensureAccessToken() {
  // If missing but we have refresh, refresh
  if (!tokenStore.access_token && tokenStore.refresh_token) {
    await refreshAccessToken();
  }
  // If present but expiring in <60s, refresh
  if (tokenStore.access_token && msUntilExpiry() < 60_000) {
    await refreshAccessToken();
  }
  if (!tokenStore.access_token) {
    throw new Error("No access token present; call /auth/start and sign in.");
  }
  return tokenStore.access_token;
}

async function refreshAccessToken() {
  if (!tokenStore.refresh_token) return;
  const json = await tokenRequest({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    grant_type: "refresh_token",
    refresh_token: tokenStore.refresh_token,
    redirect_uri: REDIRECT_URI,
  });
  tokenStore.access_token = json.access_token || null;
  tokenStore.refresh_token = json.refresh_token || tokenStore.refresh_token;
  // expires_in is seconds from now
  tokenStore.expires_at = nowSec() + (json.expires_in || 3600);
}

// Xbox Live chain: User → XSTS
async function getXblUserToken(msAccessToken) {
  const url = "https://user.auth.xboxlive.com/user/authenticate";
  const body = {
    RelyingParty: "http://auth.xboxlive.com",
    TokenType: "JWT",
    Properties: {
      AuthMethod: "RPS",
      SiteName: "user.auth.xboxlive.com",
      RpsTicket: `d=${msAccessToken}`,
    },
  };
  const r = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-xbl-contract-version": "1",
    },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  if (!r.ok) {
    logHttpError("xbl-user", r, text);
    throw new Error(`xbl-user failed: ${r.status}`);
  }
  return JSON.parse(text);
}

async function getXstsToken(userToken) {
  const url = "https://xsts.auth.xboxlive.com/xsts/authorize";
  const body = {
    Properties: {
      SandboxId: "RETAIL",
      UserTokens: [userToken],
    },
    RelyingParty: "http://xboxlive.com",
    TokenType: "JWT",
  };
  const r = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-xbl-contract-version": "1",
    },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  if (!r.ok) {
    logHttpError("xsts", r, text);
    throw new Error(`xsts failed: ${r.status}`);
  }
  return JSON.parse(text);
}

// Spartan token — the URL can vary by deployment. If you already had one,
// keep using it. Otherwise this placeholder will at least show the 400 body
// so we can correct it next.
const SPARTAN_TOKEN_URL =
  process.env.SPARTAN_TOKEN_URL ||
  "https://settings.svc.halowaypoint.com/spartan-token"; // placeholder

async function getSpartanToken(xstsToken, uhs) {
  // Two common header styles. We’ll try the "343 identity" header first.
  const headers = {
    "x-343-identity-provider": "xbl3",
    "x-343-authorization-spartan": `XBL3.0 x=${uhs};${xstsToken}`,
    "Content-Type": "application/json",
  };

  const r = await fetch(SPARTAN_TOKEN_URL, {
    method: "POST",
    headers,
    body: JSON.stringify({}),
  });
  const text = await r.text();
  if (!r.ok) {
    logHttpError("spartan-token", r, text);
    throw new Error(`spartan-token failed: ${r.status}`);
  }
  // Caller usually just needs OK; if there is a JSON, return it:
  try {
    return JSON.parse(text);
  } catch {
    return { ok: true };
  }
}

function buildHaloHeaders(xstsToken, uhs) {
  return {
    "x-343-identity-provider": "xbl3",
    "x-343-authorization-spartan": `XBL3.0 x=${uhs};${xstsToken}`,
  };
}

// ------------------------------
// Routes
// ------------------------------
app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

// 1) Start auth — user consents to Xbox scopes
app.get("/auth/start", (req, res) => {
  const scope = encodeURIComponent("XboxLive.signin XboxLive.offline_access openid profile");
  const url =
    `${AUTHORITY}/oauth20_authorize.srf?` +
    `client_id=${encodeURIComponent(CLIENT_ID)}` +
    `&scope=${scope}` +
    `&response_type=code` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`;
  res.redirect(url);
});

// 2) Callback — exchange code for tokens
app.get("/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("Missing code");
  try {
    const json = await tokenRequest({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: "authorization_code",
      code: code,
      redirect_uri: REDIRECT_URI,
    });
    tokenStore.access_token = json.access_token || null;
    tokenStore.refresh_token = json.refresh_token || null;
    tokenStore.expires_at = nowSec() + (json.expires_in || 3600);

    res.send(
      `<html><body><h3>Signed in!</h3><p>You can close this window.</p>` +
        `<script>setTimeout(()=>window.close(), 1000)</script></body></html>`
    );
  } catch (e) {
    res.status(500).send(String(e));
  }
});

// Admin status (token info)
app.get("/admin/status", adminGuard, (_req, res) => {
  res.json({
    ok: true,
    usingAuthority: AUTHORITY,
    clientIdEndsWith: CLIENT_ID.slice(-6),
    hasSecret: !!CLIENT_SECRET,
    redirectUri: REDIRECT_URI,
    tokenStoreSize: tokenStore.access_token ? 1 : 0,
    tokenExpiresInSec: tokenStore.access_token
      ? Math.floor(msUntilExpiry() / 1000)
      : null,
  });
});

// Diagnostic: run XBL → XSTS → Spartan and show result
app.get("/diag/spartan", adminGuard, async (_req, res) => {
  try {
    const msAccess = await ensureAccessToken();
    const user = await getXblUserToken(msAccess);
    const xsts = await getXstsToken(user.Token);
    const uhs = xsts?.DisplayClaims?.xui?.[0]?.uhs;
    const spartan = await getSpartanToken(xsts.Token, uhs);
    res.json({ ok: true, uhs, spartan: !!spartan });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// Used by the Worker wrapper; requires shared secret header.
app.get("/spartan", async (req, res) => {
  try {
    const hdr = req.headers["x-grunt-auth"];
    if (!hdr || hdr !== GRUNT_SHARED_SECRET) {
      return res.status(401).json({ ok: false, error: "unauthorized" });
    }

    const gt = req.query.gt;
    const playlist = req.query.playlist;
    if (!gt || !playlist) {
      return res.status(400).json({ ok: false, error: "missing gt or playlist" });
    }

    // Acquire chain + Spartan token; build standard Halo headers.
    const msAccess = await ensureAccessToken();
    const user = await getXblUserToken(msAccess);
    const xsts = await getXstsToken(user.Token);
    const uhs = xsts?.DisplayClaims?.xui?.[0]?.uhs;
    await getSpartanToken(xsts.Token, uhs); // mainly to verify we have one; some stacks require this hop

    const haloHeaders = buildHaloHeaders(xsts.Token, uhs);
    // TODO: call the real Halo endpoint you choose here, using haloHeaders.
    // For now we return a minimal OK with info to avoid stubbing rank:
    return res.json({ ok: true, headersReady: true });
  } catch (e) {
    return res.status(502).json({ ok: false, error: String(e) });
  }
});

// Root
app.get("/", (_req, res) => {
  res.send("Halo Grunt up");
});

// ------------------------------
app.listen(PORT, () => {
  console.log(`Halo Grunt listening on :${PORT}`);
  console.log(`Health: GET  /health`);
  console.log(`Login:  GET  /auth/start?key=YOUR_ADMIN_KEY (no key required here)`);
  console.log(`Status: GET  /admin/status?key=YOUR_ADMIN_KEY`);
  console.log(`Diag:   GET  /diag/spartan?key=YOUR_ADMIN_KEY`);
  console.log(`CSR (worker): GET  /spartan   (needs x-grunt-auth header)`);
});

