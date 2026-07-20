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
app.set("trust proxy", true);   // Render sits behind a proxy; needed for real client IPs
// Lock browser access to your site once its final URL is known: set ALLOWED_ORIGIN
// in Render (e.g. https://you.github.io, comma-separated for several). Writes need
// a token regardless, so this is defence-in-depth. Defaults to open if unset.
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*";
app.use(cors({ origin: ALLOWED_ORIGIN === "*" ? true : ALLOWED_ORIGIN.split(",").map(s => s.trim()) }));
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

// Brute-force throttle: too many wrong guesses from one IP+username locks that
// pair out for a cool-down. In-memory (resets on redeploy), which is plenty for
// slowing an online guessing attack.
const LOGIN_FAILS = new Map();
const MAX_FAILS = 8, FAIL_WINDOW_MS = 15 * 60 * 1000, LOCK_MS = 15 * 60 * 1000;
function throttleKey(req, u) { return (String(req.headers["x-forwarded-for"] || req.ip || "").split(",")[0].trim()) + "|" + u; }
function lockedFor(k) { const e = LOGIN_FAILS.get(k); return (e && e.lockUntil > Date.now()) ? Math.ceil((e.lockUntil - Date.now()) / 1000) : 0; }
function noteFail(k) {
  const now = Date.now(); let e = LOGIN_FAILS.get(k);
  if (!e || now - e.first > FAIL_WINDOW_MS) e = { count: 0, first: now, lockUntil: 0 };
  e.count++; if (e.count >= MAX_FAILS) { e.lockUntil = now + LOCK_MS; e.count = 0; e.first = now; }
  LOGIN_FAILS.set(k, e);
  if (LOGIN_FAILS.size > 5000) for (const [kk, vv] of LOGIN_FAILS) { if ((vv.lockUntil || vv.first) < now - FAIL_WINDOW_MS) LOGIN_FAILS.delete(kk); }
}

app.post("/api/login", async (req, res) => {
  try {
    const u = String((req.body && req.body.username) || "").trim().toLowerCase();
    const k = throttleKey(req, u);
    const wait = lockedFor(k);
    if (wait) return res.status(429).json({ ok: false, error: "Too many attempts. Try again in about " + Math.ceil(wait / 60) + " minute(s)." });
    const acc = await db.collection("accounts").findOne({ _id: u });
    if (!acc || !verifyPassword(acc, String((req.body && req.body.password) || ""))) {
      noteFail(k);
      return res.status(401).json({ ok: false, error: "ACCESS DENIED" });
    }
    LOGIN_FAILS.delete(k);
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
    // Never hand out the credential store or live tokens through this endpoint.
    if (name === "accounts" || name === "sessions") return res.status(403).json({ ok: false, error: "Forbidden" });
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
      if (name === "bk_bills") {   // bills were grouped on import; restore their original bk_bill_* keys
        (await db.collection("bk_bills").find({}).toArray()).forEach(d => { out[d._id] = d; });
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
function roleRank(r) { return r === "emperor" ? 2 : r === "minister" ? 1 : 0; }
function hasFinance(a) { return a.role === "emperor" || a.mofRole === "treasurer" || a.mofRole === "minister"; }
function hasWar(a) { return a.role === "emperor" || a.mowRole === "commander" || a.mowRole === "minister"; }
function hasMFA(a) { return a.role === "emperor" || !!a.mfaAccess; }
function hasJudiciary(a) { return a.role === "emperor" || a.ijAccess === "judge" || a.ijAccess === "president"; }
function hasPress(a) { return a.role === "emperor" || !!a.pressRole || !!a.pressAccess; }
function hasIMC(a) { return a.role === "emperor" || !!a.imcRole; }
function isReturningOfficer(a) { return a.role === "emperor" || a.role === "minister" || (a.clearance || 0) >= 3; }

// Governance standing: a sitting member, a Bundesherr, or an officeholder —
// verified against the live rosters, never a client's say-so.
async function hasBKStanding(actor) {
  if (actor.role === "emperor") return true;
  const u = String(actor.username || "").toLowerCase();
  const rosterHit = (docs) => docs.some(m => String(m.username || m.name || "").toLowerCase() === u);
  if (rosterHit(await db.collection("bk_members").find({}).toArray())) return true;
  if (rosterHit(await db.collection("bk_bh").find({}).toArray())) return true;
  const offDoc = await db.collection("singletons").findOne({ _id: "bk_officials" });
  const off = offDoc ? offDoc.value : null;
  if (off) {
    const names = [off.chancellor_username, off.president_bt_username, off.president_bh_username]
      .concat(Object.values(off.minister_usernames || {}));
    if (names.some(n => n && String(n).toLowerCase() === u)) return true;
  }
  return false;
}

// Which authority a data key belongs to. Keys where end-users legitimately create
// their own records are "auth" (any signed-in account). Unknown domains default
// to "auth" so nothing silently breaks — tighten as each is reviewed.
const USER_WRITABLE = new Set(["mof_businesses", "mof_expenditures", "el_voter_ids"]);
function keyDomain(key) {
  if (USER_WRITABLE.has(key)) return "auth";     // el_ballot_* is handled specially, not here
  if (key.startsWith("mof_")) return "finance";
  if (key.startsWith("mow_")) return "war";
  if (key.startsWith("mfa_")) return "mfa";
  if (key.startsWith("ij_")) return "judiciary";
  if (key.startsWith("ih_")) return "household";      // Imperial Household → Emperor only
  if (key.startsWith("press_")) return "press";
  if (key.startsWith("imc_")) return "imc";
  if (key.startsWith("el_")) return "elections";
  if (key.startsWith("bk_") || key.startsWith("bh")) return "governance";
  return "auth";                                       // eco_/exchange_/lbs_/vx_ … login required; review later
}
async function authorizeKeyWrite(actor, key) {
  if (!actor) return "Not authenticated";
  if (actor.role === "emperor") return null;
  switch (keyDomain(key)) {
    case "auth": return null;
    case "finance": return hasFinance(actor) ? null : "Requires Ministry of Finance authority";
    case "war": return hasWar(actor) ? null : "Requires Ministry of War authority";
    case "mfa": return hasMFA(actor) ? null : "Requires Foreign Affairs authority";
    case "judiciary": return hasJudiciary(actor) ? null : "Requires Judiciary authority";
    case "household": return "Reserved to the Imperial Household";
    case "press": return hasPress(actor) ? null : "Requires Imperial Press authority";
    case "imc": return hasIMC(actor) ? null : "Requires Maritime Commission authority";
    case "elections": return isReturningOfficer(actor) ? null : "Requires Returning Officer authority";
    case "governance": return (await hasBKStanding(actor)) ? null : "Requires a seat or office in the Bundeskongress";
    default: return null;
  }
}

// A ballot may be cast only for the citizen record the voter's own account owns,
// only once, and never changed. Deleting ballots is a Returning Officer act,
// handled by the normal "elections" domain rule.
async function authorizeBallot(actor, key, value) {
  if (!actor) return "Not authenticated";
  const citizenId = value && value.citizenId, elId = value && value.elId;
  if (!citizenId || !elId) return "Malformed ballot";
  if ("el_ballot_" + elId + "_" + citizenId !== key) return "Ballot does not match its key";
  const cit = await db.collection("mfa_citizens").findOne({ $or: [{ _id: citizenId }, { id: citizenId }] });
  if (!cit) return "No citizen record for this ballot";
  if (String(cit.username || "").toLowerCase() !== String(actor.username || "").toLowerCase())
    return "You may only cast your own ballot";
  if (await db.collection("singletons").findOne({ _id: key }, { projection: { _id: 1 } }))
    return "A ballot has already been cast and cannot be changed";
  return null;
}

// Account (permission) writes: the Emperor and Interior Minister manage accounts;
// a ministry head may flip ONLY their own agency's access flags and nothing else;
// only the Emperor grants the Imperial role, only Emperor/Interior appoint a
// system Minister. This is what stops sideways privilege-escalation.
async function authorizeAccountWrite(actor, incoming) {
  if (!actor) return "Not authenticated";
  const isEmperor = actor.role === "emperor";
  const isInterior = isEmperor || actor.role === "minister";
  if (roleRank(incoming.role) === 2 && !isEmperor) return "Only the Emperor may grant the Imperial role";
  if (roleRank(incoming.role) === 1 && !isInterior) return "Only the Emperor or Interior Minister may appoint a Minister";
  if (isInterior) return null;
  const existing = await db.collection("accounts").findOne({ _id: recordId("accounts", incoming) }) || {};
  const IGNORE = new Set(["_id", "_writtenBy", "_writtenAt", "passwordHash", "salt", "username", "displayName", "notes", "stateOfResidency"]);
  const changed = Object.keys({ ...existing, ...incoming })
    .filter(f => !IGNORE.has(f) && JSON.stringify(incoming[f]) !== JSON.stringify(existing[f]));
  if (actor.mowRole === "minister" && changed.every(f => ["mowAccess", "mowRole", "canSetAlert"].includes(f))) return null;
  return "You are not permitted to change this account's permissions";
}
function recordId(collection, record) {
  if (collection === "accounts") return String(record.username || record._id || "").toLowerCase();
  return String(record.id || record._id || "");
}
async function writeRule(collection, actor, record) {
  if (!actor) return "Not authenticated";
  if (collection === "accounts") return await authorizeAccountWrite(actor, record);
  if (collection === "mi_lss_ops" || collection === "mi_lss_docs") {
    if (!canSeeLSS(actor)) return "Not authorised (LSS)";
    if ((record.clearance || 0) > (actor.clearance || 0)) return "Cannot create above your clearance";
    return null;
  }
  if (collection === "mi_lfp_ops" || collection === "mi_arrests") { if (!canSeeLFP(actor)) return "Not authorised (LFP)"; return null; }
  return await authorizeKeyWrite(actor, collection);
}
async function deleteRule(collection, actor) {
  if (!actor) return "Not authenticated";
  if (collection === "accounts") return (actor.role === "emperor" || actor.role === "minister") ? null : "Only the Interior Ministry may delete accounts";
  if (collection === "mi_lss_ops" || collection === "mi_lss_docs") return canSeeLSS(actor) ? null : "Not authorised (LSS)";
  if (collection === "mi_lfp_ops" || collection === "mi_arrests") return canSeeLFP(actor) ? null : "Not authorised (LFP)";
  return await authorizeKeyWrite(actor, collection);
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
    const err = await writeRule(collection, actor, record);
    if (err) return res.status(403).json({ ok: false, error: err });
    const id = recordId(collection, record);
    if (!id) return res.status(400).json({ ok: false, error: "Record has no id" });
    const doc = { ...record, _id: id, _writtenBy: actor.username, _writtenAt: Date.now() };
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
    const err = await deleteRule(collection, actor);
    if (err) return res.status(403).json({ ok: false, error: err });
    await db.collection(collection).deleteOne({ _id: id });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── GENERIC KEY WRITES ─────────────────────────────────────────────────────────
// Preserves the old sset(key, value) / sdel(key) shape so a page can move over by
// swapping only its data layer. Any signed-in account may write these (parity
// with the old hardened backend — anonymous writes are refused); accounts and
// classified records are refused here and must go through /api/write, which
// enforces the per-record rules. Classification mirrors how the data was
// imported, so writes round-trip with /api/data.
const NON_KV = (key) => key === "mi_accounts" || key.indexOf("mi_acc_") === 0 || !!PROTECTED[key];
async function classifyKey(key, value) {
  if (SINGLETON_KEYS.has(key)) return "singleton";
  if (await db.collection("singletons").findOne({ _id: key }, { projection: { _id: 1 } })) return "singleton";
  const cn = collName(key);
  if ((await db.listCollections({ name: cn }).toArray()).length) return "collection";
  const vals = value && typeof value === "object" && !Array.isArray(value) ? Object.values(value) : null;
  if (vals && vals.length > 0 && vals.every(v => v && typeof v === "object" && !Array.isArray(v))) return "collection";
  return "singleton";
}

app.post("/api/set", async (req, res) => {
  try {
    const actor = await actorFromReq(req);
    if (!actor) return res.status(401).json({ ok: false, error: "Not authenticated" });
    const { key, value } = req.body || {};
    if (!key) return res.status(400).json({ ok: false, error: "Missing key" });
    if (NON_KV(key)) return res.status(403).json({ ok: false, error: "Use /api/write for accounts and classified records" });
    // Casting a ballot has its own ownership + one-vote rule.
    if (key.indexOf("el_ballot_") === 0) {
      const berr = await authorizeBallot(actor, key, req.body.value);
      if (berr) return res.status(403).json({ ok: false, error: berr });
      await db.collection("singletons").replaceOne({ _id: key }, { _id: key, value: req.body.value, _writtenBy: actor.username, _writtenAt: Date.now() }, { upsert: true });
      return res.json({ ok: true });
    }
    const err = await authorizeKeyWrite(actor, key);
    if (err) return res.status(403).json({ ok: false, error: err });
    const by = actor.username, at = Date.now();
    // Bills were grouped into bk_bills on import; keep new ones there too so a
    // new bk_bill_* lands alongside the rest instead of in singletons.
    if (key.indexOf("bk_bill_") === 0) {
      await db.collection("bk_bills").replaceOne({ _id: key }, { ...value, _id: key, _writtenBy: by, _writtenAt: at }, { upsert: true });
      return res.json({ ok: true });
    }
    if (await classifyKey(key, value) === "collection") {
      const cn = collName(key);
      const docs = Object.entries(value || {}).map(([id, rec]) => ({ ...rec, _id: id, _writtenBy: by, _writtenAt: at }));
      await db.collection(cn).deleteMany({});
      if (docs.length) await db.collection(cn).insertMany(docs, { ordered: false });
    } else {
      await db.collection("singletons").replaceOne({ _id: key }, { _id: key, value, _writtenBy: by, _writtenAt: at }, { upsert: true });
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.post("/api/unset", async (req, res) => {
  try {
    const actor = await actorFromReq(req);
    if (!actor) return res.status(401).json({ ok: false, error: "Not authenticated" });
    const { key } = req.body || {};
    if (!key) return res.status(400).json({ ok: false, error: "Missing key" });
    if (NON_KV(key)) return res.status(403).json({ ok: false, error: "Use /api/delete" });
    const err = await authorizeKeyWrite(actor, key);
    if (err) return res.status(403).json({ ok: false, error: err });
    if (key.indexOf("bk_bill_") === 0) { await db.collection("bk_bills").deleteOne({ _id: key }); return res.json({ ok: true }); }
    await db.collection("singletons").deleteOne({ _id: key });
    const cn = collName(key);
    if ((await db.listCollections({ name: cn }).toArray()).length) await db.collection(cn).drop().catch(() => {});
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
// Settings objects whose values happen to all be objects, so the "looks like a
// record map" heuristic would wrongly explode them into a collection. These are
// always stored as a single document.
const SINGLETON_KEYS = new Set(["bk_orgchart"]);
async function replaceCollection(name, docs) {
  const c = db.collection(name);
  await c.deleteMany({});
  if (docs.length) await c.insertMany(docs, { ordered: false });
  return docs.length;
}

app.get("/admin/import", async (req, res) => {
  // Turn this off for good once your final re-import is done: set IMPORT_ENABLED=false
  // in Render (or delete this endpoint). It rebuilds collections, so it must not
  // stay reachable in production.
  if (process.env.IMPORT_ENABLED === "false") return res.status(404).json({ error: "Not found" });
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
        const looksLikeCollection = val && typeof val === "object" && !Array.isArray(val)
          && Object.values(val).length > 0 && Object.values(val).every(v => v && typeof v === "object" && !Array.isArray(v));
        if (looksLikeCollection && !SINGLETON_KEYS.has(key)) {
          const docs = Object.entries(val).map(([id, rec]) => ({ _id: id, ...rec }));
          summary[collName(key)] = await replaceCollection(collName(key), docs);
        } else {
          await db.collection("singletons").replaceOne({ _id: key }, { _id: key, value: val }, { upsert: true });
          // Drop a stale same-named collection left by an earlier misclassified import.
          const cn = collName(key);
          if ((await db.listCollections({ name: cn }).toArray()).length) await db.collection(cn).drop().catch(() => {});
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
