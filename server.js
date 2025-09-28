// server.js — Halo Grunt (Microsoft OAuth helper)

import express from "express";
import cors from "cors";
import { ConfidentialClientApplication, LogLevel } from "@azure/msal-node";

// ───────────────────────────────────────────────────────────────────────────────
// 1) Env + sanity checks
// ───────────────────────────────────────────────────────────────────────────────
const {
  ADMIN_KEY,
  AZURE_CLIENT_ID,
  AZURE_CLIENT_SECRET,
  AZURE_TENANT_ID,
  AZURE_REDIRECT_URI,
  GRUNT_SHARED_SECRET,
  PORT = 3000,
} = process.env;

const required = [
  "ADMIN_KEY",
  "AZURE_CLIENT_ID",
  "AZURE_CLIENT_SECRET",
  "AZURE_TENANT_ID",
  "AZURE_REDIRECT_URI",
  "GRUNT_SHARED_SECRET",
];
for (const k of required) {
  if (!process.env[k]) {
    console.error(`[FATAL] Missing env var ${k}`);
    process.exit(1);
  }
}

// ───────────────────────────────────────────────────────────────────────────────
// 2) MSAL configuration
// ───────────────────────────────────────────────────────────────────────────────
const authority = `https://login.microsoftonline.com/${AZURE_TENANT_ID}`;

const msalConfig = {
  auth: {
    clientId: AZURE_CLIENT_ID,
    authority,
    clientSecret: AZURE_CLIENT_SECRET,
  },
  system: {
    loggerOptions: {
      logLevel: LogLevel.Error,
      loggerCallback: (_level, _message) => { /* quiet */ },
    },
  },
};

const cca = new ConfidentialClientApplication(msalConfig);

// Scopes: include offline_access for refresh tokens; add XboxLive.signin for XBL
const SCOPES = ["offline_access", "XboxLive.signin", "User.Read"];

// We keep the active account in memory. MSAL stores tokens in its cache.
let activeAccount = null;

// ───────────────────────────────────────────────────────────────────────────────
// 3) Express app
// ───────────────────────────────────────────────────────────────────────────────
const app = express();
app.use(cors());
app.use(express.json());

// Health
app.get("/health", (_req, res) => res.json({ ok: true }));

// Utility: admin guard using a query param (?key=...)
function requireAdmin(req, res, next) {
  const key = req.query.key || req.header("x-admin-key");
  if (!key || key !== ADMIN_KEY) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// Utility: wrapper shared-secret guard (header: x-grunt-auth)
function requireWrapper(req, res, next) {
  const secret = req.header("x-grunt-auth");
  if (!secret || secret !== GRUNT_SHARED_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// ───────────────────────────────────────────────────────────────────────────────
// 4) Admin endpoints (you use these in a browser to sign in once)
// ───────────────────────────────────────────────────────────────────────────────

// Start the Microsoft login
app.get("/auth/start", requireAdmin, async (req, res) => {
  try {
    const url = await cca.getAuthCodeUrl({
      redirectUri: AZURE_REDIRECT_URI,
      scopes: SCOPES,
      prompt: "select_account",
    });
    return res.redirect(url);
  } catch (err) {
    console.error("getAuthCodeUrl error:", err);
    return res.status(500).send("Failed to start Microsoft login.");
  }
});

// OAuth redirect handler (must match AZURE_REDIRECT_URI)
app.get("/callback", async (req, res) => {
  const code = req.query.code?.toString();
  if (!code) return res.status(400).send("Missing auth code.");

  try {
    const result = await cca.acquireTokenByCode({
      code,
      redirectUri: AZURE_REDIRECT_URI,
      scopes: SCOPES,
    });

    if (!result?.account) throw new Error("No account in auth result.");
    activeAccount = result.account;

    // Simple success page
    return res.type("html").send(`
      <h1>Halo Grunt: Login successful ✅</h1>
      <p>Account: ${activeAccount.username || activeAccount.homeAccountId}</p>
      <p>You can close this tab.</p>
    `);
  } catch (err) {
    console.error("acquireTokenByCode error:", err);
    return res.status(500).send("Login failed.");
  }
});

// Check status
app.get("/admin/status", requireAdmin, async (_req, res) => {
  try {
    const cache = cca.getTokenCache();
    const accounts = await cache.getAllAccounts();
    const haveAccount = Boolean(activeAccount || accounts.length > 0);
    return res.json({
      ok: true,
      haveAccount,
      cachedAccounts: accounts.map((a) => a.username || a.homeAccountId),
      active:
        activeAccount && (activeAccount.username || activeAccount.homeAccountId),
    });
  } catch (err) {
    console.error("status error:", err);
    return res.status(500).json({ ok: false, error: "cache_error" });
  }
});

// Optional: clear active account (does not revoke tokens server-side)
app.post("/admin/logout", requireAdmin, async (_req, res) => {
  activeAccount = null;
  const cache = cca.getTokenCache();
  await cache.removeAccount(activeAccount);
  return res.json({ ok: true });
});

// ───────────────────────────────────────────────────────────────────────────────
// 5) Wrapper endpoint — called by your Worker/Wrapper (not by a browser)
//     Header: x-grunt-auth: <GRUNT_SHARED_SECRET>
// ───────────────────────────────────────────────────────────────────────────────
app.get("/spartan", requireWrapper, async (_req, res) => {
  try {
    // Ensure we have an account (i.e., you completed /auth/start once)
    if (!activeAccount) {
      // Try to recover from cache if possible
      const cache = cca.getTokenCache();
      const accounts = await cache.getAllAccounts();
      if (accounts.length > 0) activeAccount = accounts[0];
    }
    if (!activeAccount) {
      return res.status(503).json({
        ok: false,
        error: "not_authorized",
        message: "No Microsoft account connected to Grunt.",
      });
    }

    // This gives us a fresh Microsoft access token (MSAL uses the refresh token).
    const token = await cca.acquireTokenSilent({
      account: activeAccount,
      scopes: SCOPES,
    });

    if (!token?.accessToken) {
      return res.status(500).json({ ok: false, error: "no_access_token" });
    }

    // NOTE:
    //  - This is a Microsoft access token for the scopes above.
    //  - Your wrapper can now exchange this for XBL/Spartan as needed.
    return res.json({
      ok: true,
      token_type: "Bearer",
      access_token: token.accessToken,
      expires_on: token.expiresOn?.toISOString?.() || null,
      account: activeAccount.username || activeAccount.homeAccountId,
    });
  } catch (err) {
    console.error("spartan error:", err);
    return res.status(500).json({ ok: false, error: "token_error" });
  }
});

// ───────────────────────────────────────────────────────────────────────────────
// 6) Start server
// ───────────────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Halo Grunt listening on :${PORT}`);
  console.log(`Health:  GET /health`);
  console.log(`Login:   GET /auth/start?key=YOUR_ADMIN_KEY`);
  console.log(`Status:  GET /admin/status?key=YOUR_ADMIN_KEY`);
  console.log(`Wrapper: GET /spartan   (needs x-grunt-auth header)`);
});
