// server.js – Halo Grunt (prod-ready skeleton with CSR endpoint)

import express from "express";
import cors from "cors";
import { ConfidentialClientApplication, LogLevel } from "@azure/msal-node";
import { fetch } from "undici";

/* -------------------- ENV REQUIRED --------------------
   ADMIN_KEY                -> Your admin key (simple shared secret)
   GRUNT_SHARED_SECRET      -> Shared secret the Worker/Wrapper will send (x-grunt-auth)
   AZURE_CLIENT_ID          -> App (client) ID from Azure App Registration
   AZURE_CLIENT_SECRET      -> Client secret VALUE
   AZURE_TENANT_ID          -> Directory (tenant) ID (use 'consumers' in authority below, but we still store this for status)
   AZURE_REDIRECT_URI       -> e.g. https://<your-grunt>.up.railway.app/callback
   AZURE_AUTHORITY          -> https://login.microsoftonline.com/consumers  (for personal Microsoft accounts)
   HALO_ENDPOINT            -> default: https://halostats.svc.halowaypoint.com/hi/players/{gamertag}/csrs?playlist={playlistId}
-------------------------------------------------------- */

const {
  PORT = "3000",
  ADMIN_KEY,
  GRUNT_SHARED_SECRET,
  AZURE_CLIENT_ID,
  AZURE_CLIENT_SECRET,
  AZURE_TENANT_ID,
  AZURE_REDIRECT_URI,
  AZURE_AUTHORITY = "https://login.microsoftonline.com/consumers",
  HALO_ENDPOINT = "https://halostats.svc.halowaypoint.com/hi/players/{gamertag}/csrs?playlist={playlistId}"
} = process.env;

if (!ADMIN_KEY || !GRUNT_SHARED_SECRET || !AZURE_CLIENT_ID || !AZURE_CLIENT_SECRET || !AZURE_REDIRECT_URI) {
  console.error("Missing one or more required ENV vars. Please set ADMIN_KEY, GRUNT_SHARED_SECRET, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_REDIRECT_URI.");
  process.exit(1);
}

const app = express();
app.use(cors());
app.use(express.json());

// --------------------- MSAL Setup ---------------------
const msalConfig = {
  auth: {
    clientId: AZURE_CLIENT_ID,
    authority: AZURE_AUTHORITY,
    clientSecret: AZURE_CLIENT_SECRET,
  },
  system: {
    loggerOptions: { logLevel: LogLevel.Warning }
  }
};

const msalClient = new ConfidentialClientApplication(msalConfig);

// We'll keep a single signed-in account in memory (simple + good for single-user dummy account)
let cachedAccount = null;
let tokenStore = {
  // For debugging: last-signin
  lastSignin: null,
  // iso date expiry of XSTS/Spartan (not critical, but nice to track)
  xstsExpiresAt: null,
  spartanExpiresAt: null,
};

// Scopes sufficient to get the Xbox RPS token (the important one is xboxlive.signin)
const OAUTH_SCOPES = ["xboxlive.signin", "offline_access", "openid", "profile"];

// --------------------- Helpers ---------------------

const ok = (res, data) => res.json(data);
const bad = (res, code, msg) => res.status(code).json({ error: msg });

function mustAdmin(req, res, next) {
  const key = (req.query.key || req.headers["x-admin-key"] || "").toString().trim();
  if (!ADMIN_KEY || key !== ADMIN_KEY) return bad(res, 403, "forbidden");
  next();
}

function mustWrapper(req, res, next) {
  const h = (req.headers["x-grunt-auth"] || "").toString().trim();
  if (!GRUNT_SHARED_SECRET || h !== GRUNT_SHARED_SECRET) return bad(res, 401, "unauthorized");
  next();
}

// Build URL with params safely
function fillHaloEndpoint(template, { gamertag, playlistId }) {
  return template
    .replace("{gamertag}", encodeURIComponent(gamertag))
    .replace("{playlistId}", encodeURIComponent(playlistId));
}

// Pretty time helper
function isoPlusSecs(secs) {
  return new Date(Date.now() + secs * 1000).toISOString();
}

// --------------------- Auth Flow ---------------------

// 1) Start the OAuth code flow
app.get("/auth/start", mustAdmin, async (req, res) => {
  try {
    const url = await msalClient.getAuthCodeUrl({
      scopes: OAUTH_SCOPES,
      redirectUri: AZURE_REDIRECT_URI,
      responseMode: "query"
    });
    res.redirect(url);
  } catch (e) {
    console.error("auth/start error:", e);
    bad(res, 500, "auth_start_failed");
  }
});

// 2) OAuth redirect (Azure -> this service)
app.get("/callback", async (req, res) => {
  try {
    const tokenResp = await msalClient.acquireTokenByCode({
      code: req.query.code,
      scopes: OAUTH_SCOPES,
      redirectUri: AZURE_REDIRECT_URI
    });

    cachedAccount = tokenResp.account;
    tokenStore.lastSignin = new Date().toISOString();

    res.send("Signed in! You can close this window.");
  } catch (e) {
    console.error("callback error:", e);
    bad(res, 500, "callback_failed");
  }
});

// 3) Mint an AAD access token silently (refresh if needed)
async function acquireMsAccessToken() {
  if (!cachedAccount) throw new Error("no_account_signed_in");

  const resp = await msalClient.acquireTokenSilent({
    account: cachedAccount,
    scopes: OAUTH_SCOPES
  });
  return resp.accessToken; // This token is used as the RPS ticket in Xbox auth
}

// --------------------- Xbox / XSTS / Spartan ---------------------

// Xbox User Authenticate -> returns userToken + uhs
async function xboxUserAuthenticate(msAccessToken) {
  const payload = {
    RelyingParty: "http://auth.xboxlive.com",
    TokenType: "JWT",
    Properties: {
      AuthMethod: "RPS",
      SiteName: "user.auth.xboxlive.com",
      RpsTicket: `d=${msAccessToken}`
    }
  };

  const r = await fetch("https://user.auth.xboxlive.com/user/authenticate", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Accept": "application/json" },
    body: JSON.stringify(payload)
  });

  if (!r.ok) throw new Error(`xbox user.auth failed: ${r.status}`);
  const j = await r.json();
  const uhs = j?.DisplayClaims?.xui?.[0]?.uhs;
  if (!uhs) throw new Error("xbox user.auth missing uhs");
  return { userToken: j.Token, uhs };
}

// XSTS Authorize -> returns xstsToken
async function xboxXstsAuthorize(userToken) {
  const payload = {
    RelyingParty: "rp://api.minecraftservices.com/",
    TokenType: "JWT",
    Properties: {
      SandboxId: "RETAIL",
      UserTokens: [userToken]
    }
  };

  const r = await fetch("https://xsts.auth.xboxlive.com/xsts/authorize", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Accept": "application/json" },
    body: JSON.stringify(payload)
  });

  if (!r.ok) throw new Error(`xsts authorize failed: ${r.status}`);
  const j = await r.json();
  return j.Token;
}

// Spartan token from Waypoint (requires XBL3.0 Authorization)
async function getSpartanToken({ uhs, xstsToken }) {
  const authHeader = `XBL3.0 x=${uhs};${xstsToken}`;

  const r = await fetch("https://settings.svc.halowaypoint.com/spartan-token", {
    method: "POST",
    headers: {
      "Authorization": authHeader,
      "Accept": "application/json"
    }
  });

  if (!r.ok) throw new Error(`spartan-token failed: ${r.status}`);
  const j = await r.json(); // { spartanToken, expiresInSeconds? }
  return j;
}

// Perform whole chain & return headers needed for Waypoint stats APIs
async function buildHaloHeaders() {
  const msAccess = await acquireMsAccessToken();
  const { userToken, uhs } = await xboxUserAuthenticate(msAccess);
  const xstsToken = await xboxXstsAuthorize(userToken);
  const spartan = await getSpartanToken({ uhs, xstsToken });

  // Record expiries if present
  if (spartan?.expires_in) tokenStore.spartanExpiresAt = isoPlusSecs(Number(spartan.expires_in));
  tokenStore.xstsExpiresAt = isoPlusSecs(3600); // typical XSTS TTL

  const authHeader = `XBL3.0 x=${uhs};${xstsToken}`;

  // Some endpoints accept "Spartan-Token" (or x-343-authorization-spartan)
  return {
    Authorization: authHeader,
    "Spartan-Token": spartan?.spartanToken ?? spartan?.SpartanToken ?? "",
    "Accept": "application/json"
  };
}

// --------------------- Public/Worker Routes ---------------------

/**
 * GET /spartan?gt=<gamertag>&playlist=<playlistId>
 * headers: x-grunt-auth: <GRUNT_SHARED_SECRET>
 *
 * Returns: { csr, tier, ... } — directly from Halo CSR endpoint
 */
app.get("/spartan", mustWrapper, async (req, res) => {
  try {
    const gamertag = (req.query.gt || "").toString().trim();
    const playlistId = (req.query.playlist || "").toString().trim();

    if (!gamertag || !playlistId) {
      return bad(res, 400, "missing gt or playlist");
    }

    // Build headers (Xbox + XSTS + Spartan)
    const headers = await buildHaloHeaders();

    // Fill endpoint template
    const url = fillHaloEndpoint(HALO_ENDPOINT, { gamertag, playlistId });

    const r = await fetch(url, { headers });
    if (!r.ok) {
      const body = await r.text().catch(() => "");
      console.error("Halo CSR error", r.status, body);
      return bad(res, 502, "halo_upstream_error");
    }

    const data = await r.json();

    // For your Worker convenience you can return just {csr,tier} if present:
    // The payloads differ; this maps common shapes (adjust as needed).
    let csrValue = null, tierValue = null;

    // Example shapes (you may refine after seeing live payload)
    if (Array.isArray(data?.Result ?? data?.results)) {
      const first = (data.Result ?? data.results)[0] ?? {};
      csrValue = first?.csr ?? first?.current?.value ?? null;
      tierValue = first?.tier ?? first?.current?.tier ?? null;
    } else if (data?.csr || data?.tier) {
      csrValue = data.csr ?? null;
      tierValue = data.tier ?? null;
    }

    ok(res, { raw: data, csr: csrValue, tier: tierValue });
  } catch (e) {
    console.error("/spartan error:", e);
    bad(res, 500, "spartan_failed");
  }
});

// --------------------- Admin/Health ---------------------

app.get("/health", (req, res) => ok(res, { ok: true }));

app.get("/admin/status", mustAdmin, (req, res) => {
  ok(res, {
    ok: true,
    usingAuthority: AZURE_AUTHORITY,
    clientIdEndsWith: (AZURE_CLIENT_ID || "").slice(-6),
    hasSecret: !!AZURE_CLIENT_SECRET,
    redirectUri: AZURE_REDIRECT_URI,
    tokenStoreSize: cachedAccount ? 1 : 0,
    tokenExpiresInSec: null,
    xstsExpiresAt: tokenStore.xstsExpiresAt,
    spartanExpiresAt: tokenStore.spartanExpiresAt,
  });
});

// --------------- Server ---------------

app.listen(Number(PORT), () => {
  console.log(`Halo Grunt listening on :${PORT}`);
  console.log(`Health: GET   /health`);
  console.log(`Login:  GET   /auth/start?key=YOUR_ADMIN_KEY`);
  console.log(`Status: GET   /admin/status?key=YOUR_ADMIN_KEY`);
  console.log(`CSR (worker): GET  /spartan   (needs x-grunt-auth header)`);
});
