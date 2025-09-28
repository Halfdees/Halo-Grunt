import express from "express";

const app = express();
const PORT = process.env.PORT || 3001;
const GRUNT_SHARED_SECRET = process.env.GRUNT_SHARED_SECRET;

// Simple health
app.get("/", (_req, res) => res.send("grunt ok"));

// Gate all API calls with a secret so only your Wrapper can call this.
function checkSecret(req, res) {
  const hdr = req.get("x-grunt-auth");
  if (!hdr || hdr !== GRUNT_SHARED_SECRET) {
    res.status(401).send("Unauthorized");
    return false;
  }
  return true;
}

// Resolve XUID from a gamertag (stub for now)
app.get("/xuid", (req, res) => {
  if (!checkSecret(req, res)) return;
  const gt = (req.query.gt || "").trim();
  if (!gt) return res.status(400).json({ error: "missing gt" });
  // TODO: replace with real lookup (Xbox Live)
  return res.json({ xuid: "2533274800000000" });
});

// Return CSR for a playlist (stub for now)
app.get("/csr", (req, res) => {
  if (!checkSecret(req, res)) return;
  const xuid = (req.query.xuid || "").trim();
  const playlist = (req.query.playlist || "").trim();
  if (!xuid || !playlist) {
    return res.status(400).json({ error: "missing xuid/playlist" });
  }
  // TODO: replace with real Halo CSR fetch via Spartan token
  return res.json({ csr: 1450, tier: "Diamond 2" });
});

app.listen(PORT, () => {
  console.log(`Grunt service listening on :${PORT}`);
});
