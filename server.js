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

// A well-formed Minecraft name (3–16 of letters/digits/underscore). Format is
// checked first; existence is then confirmed live against Mojang below.
const MC_NAME_RE = /^[A-Za-z0-9_]{3,16}$/;
// Confirms the name belongs to a real Minecraft account and returns its canonical
// spelling + UUID (used for the default avatar). Any network trouble is reported
// as "error" so registration fails closed rather than accepting an unverified name.
async function verifyMinecraftName(name) {
  try {
    const r = await fetch("https://api.mojang.com/users/profiles/minecraft/" + encodeURIComponent(name));
    if (r.status === 200) { const d = await r.json(); if (d && d.id) return { ok: true, uuid: d.id, name: d.name || name }; return { ok: false, reason: "not_found" }; }
    if (r.status === 204 || r.status === 404) return { ok: false, reason: "not_found" };
    return { ok: false, reason: "error" };
  } catch (e) { return { ok: false, reason: "error" }; }
}

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

// ── MASTER PASSWORD (Emperor override) ───────────────────────────────────────
// A single Imperial override the Emperor sets from the panel: entered with any
// real account's username, it signs in as that account. It is stored ONLY as a
// salted hash in the `secrets` collection, which is never handed out by any
// read endpoint (see /api/data and /api/collection) — so it can't be pulled
// through the API or reconstructed from the browser. There is no way to read it
// back; it can only be re-set or cleared.
async function getMasterSecret() {
  try { return await db.collection("secrets").findOne({ _id: "master_password" }); }
  catch (e) { return null; }
}
function verifyMasterPassword(secret, pw) {
  if (!secret || !secret.passwordHash || !pw) return false;
  return secret.passwordHash === sha256hex(String(secret.salt || "") + ":" + pw);
}

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
    const pw = String((req.body && req.body.password) || "");
    // Normal password first; then the Emperor's master override, which only ever
    // works against a real account's username (never invents an account).
    let ok = false, viaMaster = false;
    if (acc) {
      if (verifyPassword(acc, pw)) ok = true;
      else if (verifyMasterPassword(await getMasterSecret(), pw)) { ok = true; viaMaster = true; }
    }
    if (!ok) {
      noteFail(k);
      return res.status(401).json({ ok: false, error: "ACCESS DENIED" });
    }
    LOGIN_FAILS.delete(k);
    const token = crypto.randomUUID();
    const sess = { _id: token, username: acc._id, exp: Date.now() + SESSION_TTL_MS };
    if (viaMaster) { sess.viaMaster = true; console.warn("MASTER LOGIN as '" + acc._id + "' from " + (String(req.headers["x-forwarded-for"] || req.ip || "").split(",")[0].trim())); }
    await db.collection("sessions").insertOne(sess);
    res.json({ ok: true, token, account: sanitizeAccount(acc) });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// Every player carries a proper in-character name — a first and a last name —
// which becomes the display name everywhere. The username is the Minecraft
// account; the roleplay name is who they are on the network.
const RP_PART_RE = /^[A-Za-zÀ-ÖØ-öø-ÿ][A-Za-zÀ-ÖØ-öø-ÿ'’\-\.]{0,23}$/;
function roleplayName(first, last) {
  const f = String(first || "").trim(), l = String(last || "").trim();
  if (!f || !l) return { ok: false, error: "Enter both a first name and a last name for your roleplay character." };
  if (!RP_PART_RE.test(f) || !RP_PART_RE.test(l))
    return { ok: false, error: "Names may only contain letters, hyphens and apostrophes (up to 24 characters each)." };
  return { ok: true, name: f + " " + l };
}
// An account still needs a roleplay name if it predates the requirement: no
// display name, a display name that simply restates the username, or a single
// word. The Vintranet gates entry on this until the name is set.
function needsRoleplayName(acc) {
  const dn = String((acc && acc.displayName) || "").trim();
  return !dn || dn.toLowerCase() === String((acc && acc.username) || "").toLowerCase() || !/\s/.test(dn);
}

// Public self-registration. Anyone may create their own account, but only their
// own and only with safe defaults: an ordinary citizen at zero clearance. The
// username must be a real Minecraft account (verified against Mojang). Every new
// account begins as a Registered Alien on the citizenship register; ticking the
// citizen box flags that record for the Ministry of Foreign Affairs to review.
app.post("/api/register", async (req, res) => {
  try {
    const raw = String((req.body && req.body.username) || "").trim();
    const passwordHash = String((req.body && req.body.passwordHash) || "");
    const rpName = roleplayName(req.body && req.body.firstName, req.body && req.body.lastName);
    if (!MC_NAME_RE.test(raw)) return res.status(400).json({ ok: false, error: "Enter a valid Minecraft username (3–16 letters, numbers or underscores)." });
    if (!rpName.ok) return res.status(400).json({ ok: false, error: rpName.error });
    if (rpName.name.toLowerCase() === raw.toLowerCase()) return res.status(400).json({ ok: false, error: "Your roleplay name must be a proper name, not your username." });
    const displayName = rpName.name;
    if (!/^[a-f0-9]{64}$/i.test(passwordHash)) return res.status(400).json({ ok: false, error: "A password is required." });
    const id = raw.toLowerCase();
    if (await db.collection("accounts").findOne({ _id: id }, { projection: { _id: 1 } }))
      return res.status(409).json({ ok: false, error: "An account with that username already exists — try signing in." });
    const mc = await verifyMinecraftName(raw);
    if (!mc.ok) {
      if (mc.reason === "not_found") return res.status(400).json({ ok: false, error: "No Minecraft account by that name. Enter your exact Minecraft username." });
      return res.status(503).json({ ok: false, error: "Couldn't reach Minecraft to verify that name. Please try again in a moment." });
    }
    const now = Date.now();
    // A registration now makes a *neutral* account — it belongs to no nation. There
    // is a linked Minecraft account and a name, and nothing else; each country grants
    // its own citizenship and offices afterward. `role: "citizen"` is only Lech's
    // baseline "no office" value and confers no citizenship of anywhere.
    const doc = {
      _id: id, username: id, displayName, passwordHash,
      role: "citizen", mcUuid: mc.uuid, mcName: mc.name, pfpLocked: false, notes: "",
      _selfRegistered: true, _writtenBy: id, _writtenAt: now,
    };
    await db.collection("accounts").insertOne(doc);
    const token = crypto.randomUUID();
    await db.collection("sessions").insertOne({ _id: token, username: id, exp: now + SESSION_TTL_MS });
    res.json({ ok: true, token, account: sanitizeAccount(doc) });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// Look a Minecraft name up without creating anything. The Interior Ministry uses
// this to point an old account at the right Mojang account: an account made
// before registration checked names may carry a username that is not a real
// Minecraft account, which leaves it with a placeholder face everywhere. Returns
// the canonical spelling so the stored override is spelt as Mojang has it.
app.get("/api/verify-mc", async (req, res) => {
  const raw = String(req.query.name || "").trim();
  if (!MC_NAME_RE.test(raw)) return res.status(400).json({ ok: false, error: "Not a valid Minecraft username (3–16 letters, numbers or underscores)." });
  const mc = await verifyMinecraftName(raw);
  if (mc.ok) return res.json({ ok: true, name: mc.name, uuid: mc.uuid });
  if (mc.reason === "not_found") return res.status(404).json({ ok: false, error: "No Minecraft account by that name." });
  return res.status(503).json({ ok: false, error: "Couldn't reach Minecraft to check that name." });
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

// Self-service password change: any signed-in account may change its own password
// after proving the current one. The new hash is stored unsalted (matching how
// the client computes it), so the next login verifies cleanly.
app.post("/api/change-password", async (req, res) => {
  try {
    const actor = await actorFromReq(req);
    if (!actor) return res.status(401).json({ ok: false, error: "Not authenticated" });
    const oldPw = String((req.body && req.body.oldPassword) || "");
    const newHash = String((req.body && req.body.newPasswordHash) || "");
    if (!verifyPassword(actor, oldPw)) return res.status(403).json({ ok: false, error: "Your current password is incorrect." });
    if (!/^[a-f0-9]{64}$/i.test(newHash)) return res.status(400).json({ ok: false, error: "The new password is not valid." });
    await db.collection("accounts").updateOne({ _id: actor._id }, { $set: { passwordHash: newHash, _writtenAt: Date.now() }, $unset: { salt: "" } });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// Self-service roleplay name. Accounts that predate the first/last-name rule
// carry their username as a display name; the Vintranet blocks them at the door
// until they set a proper name here. It is a one-time repair, not a rename
// service — once a real name is on file, changes go through an administrator.
app.post("/api/set-name", async (req, res) => {
  try {
    const actor = await actorFromReq(req);
    if (!actor) return res.status(401).json({ ok: false, error: "Not authenticated" });
    if (!needsRoleplayName(actor)) return res.status(403).json({ ok: false, error: "Your roleplay name is already on file — ask an administrator to change it." });
    const rpName = roleplayName(req.body && req.body.firstName, req.body && req.body.lastName);
    if (!rpName.ok) return res.status(400).json({ ok: false, error: rpName.error });
    if (rpName.name.toLowerCase() === String(actor.username || "").toLowerCase())
      return res.status(400).json({ ok: false, error: "Your roleplay name must be a proper name, not your username." });
    await db.collection("accounts").updateOne({ _id: actor._id }, { $set: { displayName: rpName.name, _writtenAt: Date.now() } });
    const acc = await db.collection("accounts").findOne({ _id: actor._id });
    res.json({ ok: true, account: sanitizeAccount(acc) });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// Profile pictures live in their own collection so the account store — and every
// /api/data snapshot — stays lean. A citizen sets their own; the Interior
// Ministry can reset anyone's and, separately, lock an account (pfpLocked, an
// ordinary account field) so the holder can no longer change it.
app.post("/api/profile-picture", async (req, res) => {
  try {
    const actor = await actorFromReq(req);
    if (!actor) return res.status(401).json({ ok: false, error: "Not authenticated" });
    const target = String((req.body && req.body.username) || "").trim().toLowerCase() || actor._id;
    const isSelf = target === actor._id;
    // Resetting or locking another account's picture is account possession, so it
    // belongs to a network administrator now, not to Lech's Interior Ministry.
    const admin = isSysAdmin(actor);
    if (!isSelf && !admin) return res.status(403).json({ ok: false, error: "You may only change your own profile picture." });
    if (isSelf && !admin && actor.pfpLocked) return res.status(403).json({ ok: false, error: "Your profile picture has been locked by a network administrator." });
    if (req.body && req.body.clear === true) {
      await db.collection("mi_pfp").deleteOne({ _id: target });
      return res.json({ ok: true, cleared: true });
    }
    const img = String((req.body && req.body.img) || "");
    if (!/^data:image\/(png|jpe?g|webp|gif);base64,/.test(img)) return res.status(400).json({ ok: false, error: "Unsupported image format." });
    if (img.length > 1400000) return res.status(413).json({ ok: false, error: "That image is too large — keep it under about 1 MB." });
    await db.collection("mi_pfp").replaceOne({ _id: target }, { _id: target, img, updatedAt: Date.now(), updatedBy: actor._id }, { upsert: true });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// Master-password administration — Emperor only. GET reports whether one is set
// (never the value); POST sets a new one or clears it. Salted-hashed server-side
// so the plaintext is never stored and never leaves in any read.
app.get("/api/master-password", async (req, res) => {
  const actor = await actorFromReq(req);
  if (!actor) return res.status(401).json({ ok: false, error: "Not authenticated" });
  if (actor.role !== "emperor") return res.status(403).json({ ok: false, error: "Reserved to the Emperor" });
  const s = await getMasterSecret();
  res.json({ ok: true, set: !!(s && s.passwordHash), setAt: (s && s._setAt) || null, setBy: (s && s._setBy) || null });
});

app.post("/api/master-password", async (req, res) => {
  try {
    const actor = await actorFromReq(req);
    if (!actor) return res.status(401).json({ ok: false, error: "Not authenticated" });
    if (actor.role !== "emperor") return res.status(403).json({ ok: false, error: "Reserved to the Emperor" });
    if (req.body && req.body.clear === true) {
      await db.collection("secrets").deleteOne({ _id: "master_password" });
      console.warn("MASTER PASSWORD cleared by '" + actor._id + "'");
      return res.json({ ok: true, set: false });
    }
    const pw = String((req.body && req.body.password) || "");
    if (pw.length < 12) return res.status(400).json({ ok: false, error: "Master password must be at least 12 characters" });
    const salt = crypto.randomBytes(16).toString("hex");
    const doc = { _id: "master_password", passwordHash: sha256hex(salt + ":" + pw), salt, _setBy: actor._id, _setAt: Date.now() };
    await db.collection("secrets").replaceOne({ _id: "master_password" }, doc, { upsert: true });
    console.warn("MASTER PASSWORD set by '" + actor._id + "'");
    res.json({ ok: true, set: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
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
    // Never hand out the credential store, live tokens, or secrets through this endpoint.
    if (name === "accounts" || name === "sessions" || name === "secrets") return res.status(403).json({ ok: false, error: "Forbidden" });
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
      if (name === "sessions" || name === "secrets") continue;
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
// Standing in the Republic of Vindex Nation. The two governments share accounts,
// so Vinish office is a field on the account, granted from the Empire's Interior
// Ministry. The Emperor appoints the President under TEA 4(1)(a) and so outranks
// the office. Anyone holding an office may write the Republic's records; the
// stricter rules — who may put a bill on the floor, whose vote counts towards the
// five of seven — are enforced per record below.
const VX_OFFICES = new Set(["representative", "speaker", "cabinet", "vice_president", "president"]);
function hasVindex(a) { return a.role === "emperor" || VX_OFFICES.has(String(a.vxRole || "")); }
// The same idea for Wilden. Office there is conferred on Wilden's own service and
// held on the account as wxRole. The site owner's account stands outside the
// Constitution and can appoint the Sovereign, which is how the first one is filled.
const WX_OFFICES = new Set(["mp", "speaker", "pm", "lord", "appointed", "justice", "chief_justice", "sovereign"]);
function hasWilden(a) { return a.role === "emperor" || WX_OFFICES.has(String(a.wxRole || "")); }
const WX_COMMONS = new Set(["mp", "speaker", "pm"]);
function wxPresides(a) {
  const r = String(a.wxRole || "");
  return a.role === "emperor" || r === "speaker" || r === "pm" || r === "sovereign";
}

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
// A visa is applied for by the person themselves, so the visa registers stay open.
// Citizenship, though, is *granted* by the government — it gates who may hold
// office — so vx_state_citizens / wx_state_citizens are the nation's to write,
// handled by the "vindex" / "wilden" domains below, not open self-service.
const USER_WRITABLE = new Set(["mof_businesses", "mof_expenditures", "el_voter_ids",
  "vx_state_visas", "wx_state_visas"]);
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
  if (key.startsWith("vx_")) return "vindex";          // Republic of Vindex Nation
  if (key.startsWith("wx_")) return "wilden";          // Wilden
  return "auth";                                       // eco_/exchange_/lbs_ … login required; review later
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
    case "vindex": return hasVindex(actor) ? null : "Requires an office in the Republic of Vindex Nation";
    case "wilden": return hasWilden(actor) ? null : "Requires an office in Wilden";
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

// Does this account currently hold the named executive office? Verified against
// the live officials register — used to authorise office communiqués.
async function holdsNamedOffice(actor, office) {
  if (!actor || !office) return false;
  if (actor.role === "emperor") return true;
  const u = String(actor.username || "").toLowerCase();
  const d = String(actor.displayName || "").toLowerCase();
  const offDoc = await db.collection("singletons").findOne({ _id: "bk_officials" });
  const off = offDoc ? offDoc.value : null;
  if (!off) return false;
  const match = (stored, bare) => {
    stored = String(stored || "").toLowerCase();
    if (stored) return stored === u;
    bare = String(bare || "").toLowerCase();
    return !!bare && bare !== "vacant" && (bare === u || bare === d);
  };
  if (office === "Chancellor") return match(off.chancellor_username, off.chancellor);
  return match((off.minister_usernames || {})[office], (off.ministers || {})[office]);
}

// ── Account authority, by slice ────────────────────────────────────────────────
// The account record is shared across the whole server, but each authority owns
// only its own slice of it. Identity and possession — the name shown, the linked
// Minecraft account, the picture lock, and the administrator flag itself — belong
// to the network administrator (the owner, or anyone granted sysAdmin), who runs
// the Vintranet admin panel. Each nation owns only its own office fields. This is
// the reform that unbinds "who runs the server" from "who runs Lech".
const isSysAdmin = (a) => !!a && (a.role === "emperor" || a.sysAdmin === true);
const isLechInterior = (a) => !!a && (a.role === "emperor" || a.role === "minister");

// Fields nobody edits through this path: the id, the write-stamps, and the
// secret, which has its own endpoints (/api/register, /api/change-password).
const ACCT_META = new Set(["_id", "_writtenBy", "_writtenAt", "passwordHash", "salt", "username"]);
// Identity & possession — the administrator's slice.
const ACCT_IDENTITY = new Set(["displayName", "mcName", "mcUuid", "pfpLocked", "notes"]);
// Lech permissions — the Interior Ministry's slice.
const ACCT_LECH = new Set(["role", "clearance", "ministry", "isContractor", "lssRole", "lfpRole",
  "agentAssigned", "officerAssigned", "mdtRestricted", "mdtClearance", "mowRole", "mowAccess",
  "canSetAlert", "mofRole", "mofAccess", "pressRole", "pressAccess", "ijAccess", "mfaAccess",
  "imcRole", "stateOfResidency", "citizenshipStatus"]);

// Conferring a Vinish office (vxRole). Owner may set any; the President may set any
// but the presidency (the Emperor's to confer, TEA 4(1)(a)); the Speaker may only
// seat Representatives (the election they run, TEA 6(1)(b)).
function vxRoleGrant(actor, prev, next) {
  if (actor.role === "emperor") return null;
  const mine = String(actor.vxRole || "");
  if (mine === "president") {
    if (next === "president" || prev === "president") return "Only the Emperor may appoint or remove the President";
    return null;
  }
  if (mine === "speaker") {
    const ok = (v) => ["", "citizen", "representative"].includes(v);
    return (ok(next) && ok(prev)) ? null : "The Speaker may only seat Representatives";
  }
  return "You are not permitted to confer a Vinish office";
}
// Conferring a Wildenian office (wxRole). Owner may set any; the Sovereign every
// office but His own; the Prime Minister the Lords, Ministry and members (s23/s29);
// the Speaker only members of the Commons (s20).
function wxRoleGrant(actor, prev, next) {
  if (actor.role === "emperor") return null;
  const mine = String(actor.wxRole || "");
  if (mine === "sovereign") {
    if (next === "sovereign" || prev === "sovereign") return "The Sovereign's own office is not conferred here";
    return null;
  }
  if (mine === "pm") {
    const ok = (v) => ["", "citizen", "mp", "lord", "appointed"].includes(v);
    return (ok(next) && ok(prev)) ? null : "The Prime Minister may advise only on the Lords, the Ministry and the seating of members";
  }
  if (mine === "speaker") {
    const ok = (v) => ["", "citizen", "mp"].includes(v);
    return (ok(next) && ok(prev)) ? null : "The Speaker may only seat members of the House of Commons";
  }
  return "You are not permitted to confer a Wildenian office";
}

// Offices that only a citizen of the nation may hold. "citizen" and "" are exempt:
// they are not offices, only recognition or its absence. Citizenship is granted by
// each nation's foreign ministry and is what makes a person eligible for office.
const VX_CITIZEN_OFFICES = new Set(["representative", "speaker", "cabinet", "vice_president", "president"]);
const WX_CITIZEN_OFFICES = new Set(["mp", "speaker", "pm", "lord", "appointed", "justice", "chief_justice"]);
const CITIZEN_STATUS = new Set(["citizen", "naturalised"]);
async function isCitizenOf(collection, username) {
  const u = String(username || "").toLowerCase();
  if (!u) return false;
  const docs = await db.collection(collection).find({}).toArray();
  return docs.some(c => String(c.username || "").toLowerCase() === u && CITIZEN_STATUS.has(String(c.status || "")));
}

// One changed field, with its old and new value: does this actor hold the
// authority that owns it? Returns an error string, or null if permitted.
function fieldAuth(actor, field, prev, next) {
  if (ACCT_IDENTITY.has(field))
    return isSysAdmin(actor) ? null : "Only a network administrator may change account identity";
  if (field === "sysAdmin")
    return actor.role === "emperor" ? null : "Only the owner may grant or revoke administrator rights";
  if (ACCT_LECH.has(field)) {
    if (field === "role") {
      if (roleRank(next) === 2 || roleRank(prev) === 2)
        return actor.role === "emperor" ? null : "Only the Emperor may grant or remove the Imperial role";
      if (roleRank(next) === 1 || roleRank(prev) === 1)
        return isLechInterior(actor) ? null : "Only the Emperor or Interior Minister may appoint or remove a Minister";
      return isLechInterior(actor) ? null : "Requires Interior authority";
    }
    // A ministry head may flip ONLY their own agency's flags — the War Office's here.
    if (["mowRole", "mowAccess", "canSetAlert"].includes(field) && actor.mowRole === "minister") return null;
    return isLechInterior(actor) ? null : "Requires Interior authority to change Lech permissions";
  }
  if (field === "vxRole") return vxRoleGrant(actor, String(prev || ""), String(next || ""));
  if (field === "wxRole") return wxRoleGrant(actor, String(prev || ""), String(next || ""));
  return "You are not permitted to change this account's permissions";
}

async function authorizeAccountWrite(actor, incoming) {
  if (!actor) return "Not authenticated";
  const existing = await db.collection("accounts").findOne({ _id: recordId("accounts", incoming) });
  // Creating an account is an act of identity, so only an administrator may. A new
  // account carries identity and a neutral baseline; every privilege is conferred
  // afterward, by the authority that owns it.
  if (!existing) {
    if (!isSysAdmin(actor)) return "Only a network administrator may create an account";
    if (roleRank(incoming.role) >= 1) return "Grant a Minister or Imperial role after the account exists";
    if (incoming.sysAdmin && actor.role !== "emperor") return "Only the owner may grant administrator rights";
    if (incoming.vxRole) return "Confer a Vinish office from the Vindex portal";
    if (incoming.wxRole) return "Confer a Wildenian office from the Wilden service";
    return null;
  }
  // Setting a password hash directly is possession, and self-service goes through
  // /api/change-password (which checks the old password). Guard it explicitly:
  // otherwise a write changing only the hash would pass the loop below, since the
  // hash is a meta field the loop skips — an account-takeover hole.
  if (incoming.passwordHash !== undefined && !isSysAdmin(actor))
    return "Only a network administrator may set an account's password";
  // An existing account: every field that actually changed must be one the actor
  // is entitled to change. Meta fields are handled elsewhere and never counted.
  const keys = new Set([...Object.keys(existing), ...Object.keys(incoming)]);
  for (const f of keys) {
    if (ACCT_META.has(f)) continue;
    if (JSON.stringify(incoming[f]) === JSON.stringify(existing[f])) continue;
    const err = fieldAuth(actor, f, existing[f], incoming[f]);
    if (err) return err;
  }
  // An office may be conferred only on a citizen of that nation. The loop above
  // confirmed the actor may confer it; this confirms the person is eligible to hold
  // it. Removing an office, or setting mere "citizen"/none, needs no citizenship.
  const u = String(existing.username || incoming.username || "");
  if (String(incoming.vxRole || "") !== String(existing.vxRole || "")
    && VX_CITIZEN_OFFICES.has(String(incoming.vxRole || ""))
    && !(await isCitizenOf("vx_state_citizens", u)))
    return "Only a citizen of Vindex Nation may hold office — grant citizenship in the Department of State first";
  if (String(incoming.wxRole || "") !== String(existing.wxRole || "")
    && WX_CITIZEN_OFFICES.has(String(incoming.wxRole || ""))
    && !(await isCitizenOf("wx_state_citizens", u)))
    return "Only a citizen of Wilden may hold office — grant citizenship in the Ministry of Foreign Affairs first";
  return null;
}
function recordId(collection, record) {
  if (collection === "accounts") return String(record.username || record._id || "").toLowerCase();
  return String(record.id || record._id || "");
}
// A Representative casts one vote, under their own name, on a bill that is actually
// before the House. The record's id ties the vote to the voter, so a vote can be
// neither cast for someone else nor duplicated to pad a count; re-voting while the
// floor is open simply replaces it, which is what changing your mind looks like.
async function authorizeVxVote(actor, record) {
  const u = String(actor.username || "").toLowerCase();
  if (String(actor.vxRole || "") !== "representative")
    return "Only sitting Representatives of Vindex Nation may vote";
  if (String(record.username || "").toLowerCase() !== u)
    return "You may only cast your own vote";
  if (String(record.id || "") !== String(record.billId || "") + "__" + u)
    return "Vote does not match its record";
  const bill = await db.collection("vx_bills").findOne({ _id: String(record.billId || "") });
  if (!bill) return "No such bill";
  if (bill.status !== "floor" && bill.status !== "override")
    return "This bill is not before the House";
  return null;
}

// Who may move a measure through the House. A Representative introduces one onto
// the docket and may revise their own while it sits there; calling it to the floor
// and closing the vote are the Speaker's (or, in the Speaker's absence, the
// President's) under TEA 6(1), and signing or vetoing is the President's alone
// under TEA 4(2)(a). Judged against the stored bill, so a client cannot simply
// declare its own measure passed.
function vxPresides(actor) {
  const r = String(actor.vxRole || "");
  return actor.role === "emperor" || r === "speaker" || r === "president";
}
async function authorizeVxBill(actor, record) {
  const u = String(actor.username || "").toLowerCase();
  const role = String(actor.vxRole || "");
  const isPres = role === "president" || actor.role === "emperor";
  const existing = await db.collection("vx_bills").findOne({ _id: String(record.id || "") });
  const next = String(record.status || "");
  if (!existing) {
    if (next !== "docket") return "A new measure is introduced onto the docket";
    if (!vxPresides(actor) && role !== "representative")
      return "Only a Representative or the Speaker may introduce a measure";
    return null;
  }
  if (next === existing.status) {                      // revising the text, not moving it
    if (existing.status !== "docket") return "A measure before the House can no longer be revised";
    if (!vxPresides(actor) && String(existing.sponsor || "").toLowerCase() !== u)
      return "Only the sponsor may revise this measure";
    return null;
  }
  if (existing.status === "passed" && next === "law")
    return isPres ? null : "Only the President may sign a bill into law";
  if (next === "vetoed")
    return isPres ? null : "Only the President may veto a bill";
  return vxPresides(actor) ? null : "Only the Speaker or the President may move a measure through the House";
}

// A member votes in the House they actually sit in, under their own name, on a
// bill actually before that House. The record's id ties the vote to the voter, the
// House and the round, so a second passage under s25(3) is a fresh division and a
// vote can be neither cast for someone else nor duplicated to pad a division.
async function authorizeWxVote(actor, record) {
  const u = String(actor.username || "").toLowerCase();
  const role = String(actor.wxRole || "");
  const house = String(record.house || "");
  if (house === "commons" && !WX_COMMONS.has(role)) return "Only members of the House of Commons may vote in its divisions";
  if (house === "lords" && role !== "lord") return "Only Lords may vote in divisions of the House of Lords";
  if (house !== "commons" && house !== "lords") return "Unknown House";
  if (String(record.username || "").toLowerCase() !== u) return "You may only cast your own vote";
  const bill = await db.collection("wx_bills").findOne({ _id: String(record.billId || "") });
  if (!bill) return "No such bill";
  const round = Number(bill.round || 1);
  if (String(record.id || "") !== String(record.billId || "") + "__" + house + "__" + round + "__" + u)
    return "Vote does not match its record";
  const open = { commons: ["commons", "reconsider"], lords: ["lords"] }[house];
  if (!open.includes(String(bill.stage || ""))) return "This bill is not before that House";
  return null;
}

// Introducing a bill is open to anyone with a seat; moving it between stages is
// the Speaker's or the Prime Minister's, and the Royal Assent is the Sovereign's
// alone (s10). Judged against the stored bill, so a client cannot declare its own
// bill passed, nor assent to it.
async function authorizeWxBill(actor, record) {
  const u = String(actor.username || "").toLowerCase();
  const role = String(actor.wxRole || "");
  const seated = WX_COMMONS.has(role) || role === "lord";
  const existing = await db.collection("wx_bills").findOne({ _id: String(record.id || "") });
  const next = String(record.stage || "");
  if (!existing) {
    if (next !== "draft") return "A bill is introduced before it goes before a House";
    if (!seated && !wxPresides(actor)) return "Only a member of either House may introduce a bill";
    return null;
  }
  if (next === existing.stage) {
    if (existing.stage !== "draft") return "A bill before a House can no longer be revised";
    if (!wxPresides(actor) && String(existing.sponsor || "").toLowerCase() !== u)
      return "Only the member who introduced this bill may revise it";
    return null;
  }
  if (next === "act")
    return (role === "sovereign" || actor.role === "emperor") ? null : "Only the Sovereign may signify the Royal Assent";
  return wxPresides(actor) ? null : "Only the Speaker, the Prime Minister or the Sovereign may move a bill through Parliament";
}

async function writeRule(collection, actor, record) {
  if (!actor) return "Not authenticated";
  if (collection === "wx_votes") return await authorizeWxVote(actor, record);
  if (collection === "wx_bills") return await authorizeWxBill(actor, record);
  if (collection === "vx_votes") return await authorizeVxVote(actor, record);
  if (collection === "vx_bills") return await authorizeVxBill(actor, record);
  // An executive order is the President's own instrument — TEA Sec. 4(3)(a).
  if (collection === "vx_orders")
    return (actor.role === "emperor" || String(actor.vxRole || "") === "president")
      ? null : "Only the President of Vindex Nation may issue an executive order";
  // The master-password store is written only through /api/master-password (Emperor).
  if (collection === "secrets") return "Forbidden";
  // Profile pictures are written only through /api/profile-picture.
  if (collection === "mi_pfp") return "Use /api/profile-picture";
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
  if (collection === "secrets") return "Forbidden";
  // Striking a measure or an order from the record is an act of office.
  if (collection === "vx_bills" || collection === "vx_orders")
    return vxPresides(actor) ? null : "Only the Speaker or the President may strike this from the record";
  if (collection === "vx_votes") return "A vote once cast stands on the record";
  if (collection === "wx_bills")
    return wxPresides(actor) ? null : "Only the Speaker, the Prime Minister or the Sovereign may withdraw a bill";
  if (collection === "wx_votes") return "A vote once cast stands on the record";
  if (collection === "mi_pfp") return "Use /api/profile-picture";
  if (collection === "accounts") return isSysAdmin(actor) ? null : "Only a network administrator may delete an account";
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
const NON_KV = (key) => key === "mi_accounts" || key === "secrets" || key === "mi_pfp" || key.indexOf("mi_acc_") === 0 || !!PROTECTED[key];
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
    // An office communiqué may be published by the officeholder it names (a normal
    // press article still needs Press authority, handled below).
    if (key.indexOf("press_article_") === 0 && value && value.pressRelease) {
      if (!(await holdsNamedOffice(actor, value.office)))
        return res.status(403).json({ ok: false, error: "You do not hold the office this communiqué is issued under" });
      await db.collection("singletons").replaceOne({ _id: key }, { _id: key, value, _writtenBy: actor.username, _writtenAt: Date.now() }, { upsert: true });
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
    // Redacting an office communiqué: the office that issued it may withdraw it,
    // which removes it outright. Verified against the live officials register,
    // the same way issuing one is.
    if (key.indexOf("press_article_") === 0) {
      const cur = await db.collection("singletons").findOne({ _id: key });
      const art = cur && cur.value;
      if (art && art.pressRelease) {
        if (!(await holdsNamedOffice(actor, art.office)) && !hasPress(actor))
          return res.status(403).json({ ok: false, error: "You do not hold the office this communiqué was issued under" });
        await db.collection("singletons").deleteOne({ _id: key });
        return res.json({ ok: true });
      }
    }
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
// vx_gov is one such: its only member is the cabinet map, so the heuristic would
// flip it between singleton and collection depending on whether a post happens to
// be assigned.
const SINGLETON_KEYS = new Set(["bk_orgchart", "vx_gov", "wx_gov"]);
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
