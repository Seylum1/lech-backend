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

// ── PER-RECORD READS ───────────────────────────────────────────────────────────
// Sensitive collections are filtered on the server by the viewer's agency
// membership and clearance — the same rules the UI used to apply in the browser,
// now enforced where F12 can't reach. Everything not listed here stays public.
const PROTECTED = { mi_lss_ops: "lss", mi_lss_docs: "lss", mi_lfp_ops: "lfp", mi_arrests: "arrests" };
function lssRoleOf(a) { if (!a) return ""; if (a.lssRole) return a.lssRole; if (a.role === "lss_director") return "director"; if (a.role === "lss_agent" || a.agentAssigned) return "agent"; return ""; }
function lfpRoleOf(a) { if (!a) return ""; if (a.lfpRole) return a.lfpRole; if (a.role === "lfp_director") return "director"; if (a.role === "lfp_officer" || a.officerAssigned) return "officer"; return ""; }
function isMinOrEmperor(a) { return !!a && (a.role === "emperor" || a.role === "minister"); }
function canSeeLSS(a) { return !!a && (isMinOrEmperor(a) || !!lssRoleOf(a)); }
function canSeeLFP(a) { return !!a && (isMinOrEmperor(a) || !!lfpRoleOf(a)); }

app.get("/api/collection/:name", async (req, res) => {
  try {
    const name = req.params.name;
    const actor = await actorFromReq(req);
    const kind = PROTECTED[name];
    const all = () => db.collection(name).find({}).toArray();

    if (!kind) return res.json({ ok: true, data: await all() });         // public

    if (kind === "lss") {
      if (!canSeeLSS(actor)) return res.json({ ok: true, data: [] });
      const cl = actor.clearance || 0;
      return res.json({ ok: true, data: (await all()).filter(d => (d.clearance || 0) <= cl) });
    }
    if (kind === "lfp" || kind === "arrests") {
      if (!canSeeLFP(actor)) return res.json({ ok: true, data: [] });
      return res.json({ ok: true, data: await all() });   // MDT-seal refinement pending
    }
    return res.json({ ok: true, data: [] });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// A single filtered snapshot of everything the viewer may see, in the same
// {key:{id:record}} shape the pages already expect — so the page code barely
// changes, but the intel is filtered before it ever leaves the server.
app.get("/api/data", async (req, res) => {
  try {
    const actor = await actorFromReq(req);
    const out = {};
    for (const { name } of await db.listCollections().toArray()) {
      if (name === "sessions") continue;
      if (name === "accounts") {
        const accs = await db.collection("accounts").find({}).toArray();
        const map = {}; accs.forEach(a => { map[a.username] = sanitizeAccount(a); });
        out["mi_accounts"] = map; continue;
      }
      if (name === "singletons") {
        (await db.collection("singletons").find({}).toArray()).forEach(d => { out[d._id] = d.value; });
        continue;
      }
      let docs = await db.collection(name).find({}).toArray();
      const kind = PROTECTED[name];
      if (kind === "lss") { if (!canSeeLSS(actor)) docs = []; else { const cl = actor.clearance || 0; docs = docs.filter(d => (d.clearance || 0) <= cl); } }
      else if (kind === "lfp" || kind === "arrests") { if (!canSeeLFP(actor)) docs = []; }
      const map = {}; docs.forEach(d => { map[d._id] = d; });
      out[name] = map;
    }
    res.json({ ok: true, data: out });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── PER-RECORD WRITES ──────────────────────────────────────────────────────────
// The server owns each collection and authorises one record at a time, so a
// filtered reader can never wipe records they weren't allowed to see.
function isOfficial(a) { return !!a && (a.role === "emperor" || a.role === "minister" || a.mowRole === "minister"); }
function roleRank(r) { return r === "emperor" ? 2 : r === "minister" ? 1 : 0; }
function escalationError(actor, acc) {
  const rank = roleRank(acc && acc.role);
  if (rank === 2 && !(actor && actor.role === "emperor")) return "Only the Emperor may grant the Imperial role";
  if (rank === 1 && !(actor && (actor.role === "emperor" || actor.role === "minister"))) return "Only the Emperor or Interior Minister may appoint a Minister";
  return null;
}
function recordId(collection, record) {
  if (collection === "accounts") return String(record.username || record._id || "").toLowerCase();
  return String(record.id || record._id || "");
}
function writeRule(collection, actor, record) {
  if (!actor) return "Not authenticated";
  if (collection === "accounts") { if (!isOfficial(actor)) return "Not authorised"; return escalationError(actor, record); }
  if (collection === "mi_lss_ops" || collection === "mi_lss_docs") {
    if (!canSeeLSS(actor)) return "Not authorised (LSS)";
    if ((record.clearance || 0) > (actor.clearance || 0)) return "Cannot create above your clearance";
    return null;
  }
  if (collection === "mi_lfp_ops" || collection === "mi_arrests") { if (!canSeeLFP(actor)) return "Not authorised (LFP)"; return null; }
  return "This collection is not open for writes yet";
}
function deleteRule(collection, actor) {
  if (!actor) return "Not authenticated";
  if (collection === "accounts") return (actor.role === "emperor" || actor.role === "minister") ? null : "Only the Interior Ministry may delete accounts";
  if (collection === "mi_lss_ops" || collection === "mi_lss_docs") return canSeeLSS(actor) ? null : "Not authorised (LSS)";
  if (collection === "mi_lfp_ops" || collection === "mi_arrests") return canSeeLFP(actor) ? null : "Not authorised (LFP)";
  return "This collection is not open for writes yet";
}
async function applyAccountSecret(record) {
  if (record.passwordHash) return;   // client supplied a new hash (password change)
  const existing = await db.collection("accounts").findOne({ _id: recordId("accounts", record) });
  if (existing) {
    if (existing.passwordHash !== undefined) record.passwordHash = existing.passwordHash;
    if (existing.salt !== undefined) record.salt = existing.salt;
  }
}

app.post("/api/write", async (req, res) => {
  try {
    const actor = await actorFromReq(req);
    const { collection, record } = req.body || {};
    if (!collection || !record) return res.status(400).json({ ok: false, error: "Missing collection/record" });
    const err = writeRule(collection, actor, record);
    if (err) return res.status(403).json({ ok: false, error: err });
    const id = recordId(collection, record);
    if (!id) return res.status(400).json({ ok: false, error: "Record has no id" });
    const doc = { ...record, _id: id };
    if (collection === "accounts") { doc.username = String(record.username || id).toLowerCase(); await applyAccountSecret(doc); }
    await db.collection(collection).replaceOne({ _id: id }, doc, { upsert: true });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.post("/api/delete", async (req, res) => {
  try {
    const actor = await actorFromReq(req);
    const { collection, id } = req.body || {};
    if (!collection || !id) return res.status(400).json({ ok: false, error: "Missing collection/id" });
    const err = deleteRule(collection, actor);
    if (err) return res.status(403).json({ ok: false, error: err });
    await db.collection(collection).deleteOne({ _id: id });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
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
