// server.js — Halo Grunt (auth helper) on Railway
import express from "express";
import cors from "cors";
import { ConfidentialClientApplication, LogLevel } from "@azure/msal-node";

const app = express();
app.use(cors());
app.use(express.json());

// ----------- ENV -----------
const {
  PORT = 3000,

  // security
  ADMIN_KEY,                // random admin key you generated
  GRUNT_SHARED_SECRET,      // shared secret the Wrapper must send in x-grunt-auth

  // Azure app
  AZURE_CLIENT_ID,          // Application (client) ID
  AZURE_CLIENT_SECRET,      // Client secret VALUE from Azure (not the Secret ID)
  AZURE_TENANT_ID,          // Directory (tenant) ID
  AZURE_AUTHORITY,          // optional override, e.g. https://login.microsoftonline.com/consumers
  AZURE_REDIRECT_URI,       // e.g. https://nodejs-xxxx-production.up.railway.app/callback
} = process.env;

// Prefer explicit authority, fall back to tenant-based
const authority =
  (AZURE_AUTHORITY && AZURE_AUTHORITY.trim()) ||
  `https://login.microsoftonline.com/${AZURE_TENANT_ID}`;

// MSAL (confidential client)
const msalConfig = {
  auth: {
    clientId: AZURE_CLIENT_ID,
    authority,
    clientSecret: AZURE_CLIENT_SECRET,
  },
  system: {
    loggerOptions: {
      loggerCallback(loglevel, message) {
        // Comment out if too noisy
        if (loglevel <= LogLevel.Warning) {
          console.log("[MSAL]", message);
        }
      },
      piiLoggingEnabled: false,
      logLevel: LogLevel.Warning,
    },
  },
};
const cca = new ConfidentialClientApplication(msalConfig);

// We’ll keep tokens in memory for now (per account)
const tokenStore = new Map();

// Scopes for MSA (Outlook/Live) interactive login
// openid/profile/offline_access are standard OIDC scopes; add API scopes later if needed.
const OIDC_SCOPES = ["openid", "profile", "offline_access"];

// ------------- Helpers -------------
function requireAdmin(req, res, next) {
  const key = req.query.key || req.header("x-admin-key");
  if (!ADMIN_KEY || key !== ADMIN_KEY) {
    return res.status(401).json({ error: "Unauthorized (admin)" });
  }
  next();
}

function requireWrapperSharedSecret(req, res, next) {
  const h = req.header("x-grunt-auth");
  if (!GRUNT_SHARED_SECRET || h !== GRUNT_SHARED_SECRET) {
    return res.status(401).json({ error: "Unauthorized (wrapper)" });
  }
  next();
}

// ------------- Routes -------------
app.get("/health", (req, res) => {
  res.json({ ok: true });
});

// quick status for debugging
app.get("/admin/status", requireAdmin, (req, res) => {
  res.json({
    ok: true,
    usingAuthority: authority,
    clientIdEndsWith: AZURE_CLIENT_ID?.slice(-6) || null,
    hasSecret: !!AZURE_CLIENT_SECRET,
    redirectUri: AZURE_REDIRECT_URI,
    tokenStoreSize: tokenStore.size,
  });
});

// Start interactive login (admin-only)
app.get("/auth/start", requireAdmin, async (req, res) => {
  try {
    console.log("[GRUNT] Using authority:", authority);

    const authCodeUrlParams = {
      scopes: OIDC_SCOPES,
      redirectUri: AZURE_REDIRECT_URI,
      prompt: "select_account",
    };

    const authUrl = await cca.getAuthCodeUrl(authCodeUrlParams);
    return res.redirect(authUrl);
  } catch (err) {
    console.error("[GRUNT] /auth/start error:", err);
    return res.status(500).json({ error: "auth_start_failed" });
  }
});

// OAuth redirect
app.get("/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("Missing code");

  try {
    const token = await cca.acquireTokenByCode({
      code,
      scopes: OIDC_SCOPES,
      redirectUri: AZURE_REDIRECT_URI,
    });

    if (!token?.account) {
      console.error("[GRUNT] No account in token result");
      return res.status(500).send("Login failed (no account)");
    }

    tokenStore.set(token.account.homeAccountId, token);
    console.log(
      "[GRUNT] Linked account:",
      token.account.username || token.account.homeAccountId
    );

    return res
      .status(200)
      .send(
        "<h3>Login complete.</h3><p>You can close this tab and return to Discord.</p>"
      );
  } catch (err) {
    console.error("[GRUNT] /callback error:", err);
    return res.status(500).send("Callback failed");
  }
});

// Data endpoint the Wrapper calls (still returns stub for now)
app.get("/spartan", requireWrapperSharedSecret, async (req, res) => {
  const gt = req.query.gt;
  const playlist = req.query.playlist;
  if (!gt || !playlist) {
    return res.status(400).json({ error: "Missing gt or playlist" });
  }

  // At this point, you could look up the right account in tokenStore and
  // call the real Halo/Xbox APIs. For now we return a stub.
  return res.json({
    csr: 1450,
    tier: "Diamond 2",
    source: "stub",
  });
});

// ------------- Start -------------
app.listen(PORT, () => {
  console.log(`Halo Grunt listening on :${PORT}`);
  console.log("Health: GET /health");
  console.log("Login:  GET /auth/start?key=YOUR_ADMIN_KEY");
  console.log("Status: GET /admin/status?key=YOUR_ADMIN_KEY");
  console.log("Wrapper: GET /spartan   (needs x-grunt-auth header)");
});

