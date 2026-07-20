// Empire of Lech — intranet backend (MongoDB)
// Step 2: prove the DB pipe (/health) + one-time data import from Sheets.
// Logins, per-record rules, and data endpoints come next.
//
// The database key is read from a private setting (MONGODB_URI) in Render.
// It is NEVER written in this file or in GitHub.

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { MongoClient } = require("mongodb");

const app = express();
app.use(cors());
app.use(express.json({ limit: "8mb" }));

const uri = process.env.MONGODB_URI;
if (!uri) {
  console.error("Missing MONGODB_URI. Set it in Render's Environment settings.");
  process.exit(1);
}
const ADMIN_KEY = process.env.ADMIN_KEY || "";

// The two existing Sheets backends (the same public URLs already in your HTML).
const SOURCES = {
  moi: "https://script.google.com/macros/s/AKfycbxLu8jQehAZJEvMEeCLoHc9S2C4FM8o9fQh8Pp4gMzDNwwIG0S9qLJ5-1gyGM1c_InUfQ/exec",
  bk:  "https://script.google.com/macros/s/AKfycbz37c5Okp9c7PkXv38x2lq7Is3RifkJPee5ASb2KQfA7EJgsN0NwrigmiRr1a_G0E6d4Q/exec",
};

const client = new MongoClient(uri);
let db = null;

app.get("/", (req, res) => res.type("text").send("Lech backend is running. Try /health"));

app.get("/health", async (req, res) => {
  try { await db.command({ ping: 1 }); res.json({ ok: true, db: "connected" }); }
  catch (e) { res.status(500).json({ ok: false, db: "error", error: e.message }); }
});

// ── LOGIN & SESSIONS ───────────────────────────────────────────────────────────
// Verifies against the hashes carried over from the old system (salted or legacy
// unsalted SHA-256), so everyone's existing password keeps working. Issues a
// random session token stored in Mongo with a 12-hour life.
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
function sha256hex(s) { return crypto.createHash("sha256").update(String(s), "utf8").digest("hex"); }
function verifyPassword(acc, pw) {
  if (!acc || !acc.passwordHash) return false;
  if (acc.salt) return acc.passwordHash === sha256hex(acc.salt + ":" + pw);
  return acc.passwordHash === sha256hex(pw);
}
function sanitizeAccount(a) { if (!a) return a; const { passwordHash, salt, ...rest } = a; return rest; }

async function actorFromReq(req) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : (req.query.token || (req.body && req.body.token) || "");
  if (!token) return null;
  const s = await db.collection("sessions").findOne({ _id: token });
  if (!s || !s.exp || s.exp < Date.now()) { if (s) await db.collection("sessions").deleteOne({ _id: token }); return null; }
  return await db.collection("accounts").findOne({ _id: s.username });
}

app.post("/api/login", async (req, res) => {
  try {
    const u = String((req.body && req.body.username) || "").trim().toLowerCase();
    const acc = await db.collection("accounts").findOne({ _id: u });
    if (!acc || !verifyPassword(acc, String((req.body && req.body.password) || "")))
      return res.status(401).json({ ok: false, error: "ACCESS DENIED" });
    const token = crypto.randomUUID();
    await db.collection("sessions").insertOne({ _id: token, username: acc._id, exp: Date.now() + SESSION_TTL_MS });
    res.json({ ok: true, token, account: sanitizeAccount(acc) });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.post("/api/logout", async (req, res) => {
  const t = (req.body && req.body.token) || "";
  if (t) await db.collection("sessions").deleteOne({ _id: t });
  res.json({ ok: true });
});

app.get("/api/me", async (req, res) => {
  const acc = await actorFromReq(req);
  if (!acc) return res.status(401).json({ ok: false, error: "Not authenticated" });
  res.json({ ok: true, account: sanitizeAccount(acc) });
});

// ── ONE-TIME DATA IMPORT ───────────────────────────────────────────────────────
// Copies everything from both Sheets backends into MongoDB. Safe to re-run (it
// replaces the Mongo copy each time). Reads only — your Sheets are untouched.
// Guarded by ADMIN_KEY. Run MOI in compat mode (SECURE_MODE=false) first so the
// export still includes password hashes; flip it back to true afterwards.
// This whole block gets removed once the migration is done.
async function fetchAll(url) {
  const r = await fetch(url + "?action=getall");
  const d = await r.json();
  return (d && d.success) ? (d.data || {}) : {};
}
function collName(key) { return String(key).replace(/[^a-zA-Z0-9_]/g, "_"); }
async function replaceCollection(name, docs) {
  const c = db.collection(name);
  await c.deleteMany({});
  if (docs.length) await c.insertMany(docs, { ordered: false });
  return docs.length;
}

app.get("/admin/import", async (req, res) => {
  if (!ADMIN_KEY || req.query.key !== ADMIN_KEY) return res.status(403).json({ error: "Forbidden" });
  try {
    const summary = {};
    const accounts = {};   // username(lower) -> account (deduped across both stores)
    const bills = [];

    for (const src of Object.keys(SOURCES)) {
      const data = await fetchAll(SOURCES[src]);
      for (const [key, rawVal] of Object.entries(data)) {
        if (!rawVal) continue;
        let val; try { val = JSON.parse(rawVal); } catch { val = rawVal; }

        // Accounts — merge the per-row keys and the legacy blob into one set.
        if (key.startsWith("mi_acc_")) {
          if (val && val.username) { const u = String(val.username).toLowerCase(); if (!accounts[u]) accounts[u] = val; }
          continue;
        }
        if (key === "mi_accounts") {
          if (val && typeof val === "object") for (const a of Object.values(val)) {
            if (a && a.username) { const u = String(a.username).toLowerCase(); if (!accounts[u]) accounts[u] = a; }
          }
          continue;
        }
        // Bundeskongress bills — one key each — gather into a bills collection.
        if (key.startsWith("bk_bill_")) { if (val && typeof val === "object") bills.push({ _id: key, ...val }); continue; }

        // An id-keyed map becomes a collection; anything else is a single setting.
        if (val && typeof val === "object" && !Array.isArray(val) && Object.values(val).every(v => v && typeof v === "object")) {
          const docs = Object.entries(val).map(([id, rec]) => ({ _id: id, ...rec }));
          summary[collName(key)] = await replaceCollection(collName(key), docs);
        } else {
          await db.collection("singletons").replaceOne({ _id: key }, { _id: key, value: val }, { upsert: true });
          summary["singleton:" + key] = 1;
        }
      }
    }

    const accDocs = Object.values(accounts).map(a => ({ _id: String(a.username).toLowerCase(), ...a }));
    summary["accounts"] = await replaceCollection("accounts", accDocs);
    if (bills.length) { summary["bk_bills"] = await replaceCollection("bk_bills", bills); }

    res.json({ ok: true, summary });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

async function start() {
  await client.connect();
  db = client.db("lech");
  console.log("Connected to MongoDB.");
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log("Server listening on port " + port));
}
start().catch((e) => { console.error("Startup failed:", e.message); process.exit(1); });
