// Empire of Lech — intranet backend (MongoDB)
// Step 1 skeleton: prove the server runs and can reach the database.
// Logins, per-record rules, and data endpoints get added once this pipe works.
//
// The database key is NEVER written here. It is read from a private setting
// (environment variable) named MONGODB_URI, which you set in Render — never in
// this file, never in GitHub.

const express = require("express");
const cors = require("cors");
const { MongoClient } = require("mongodb");

const app = express();
app.use(cors());                 // tightened to your GitHub Pages origin later
app.use(express.json({ limit: "2mb" }));

const uri = process.env.MONGODB_URI;
if (!uri) {
  console.error("Missing MONGODB_URI. Set it in Render's Environment settings.");
  process.exit(1);
}

const client = new MongoClient(uri);
let db = null;

// Health check — open this in a browser to confirm the server is up and the
// database is reachable. Expected: {"ok":true,"db":"connected"}.
app.get("/health", async (req, res) => {
  try {
    await db.command({ ping: 1 });
    res.json({ ok: true, db: "connected" });
  } catch (e) {
    res.status(500).json({ ok: false, db: "error", error: e.message });
  }
});

// A friendly root page so hitting the base URL doesn't look broken.
app.get("/", (req, res) => res.type("text").send("Lech backend is running. Try /health"));

async function start() {
  await client.connect();
  db = client.db("lech");        // the database name inside your cluster
  console.log("Connected to MongoDB.");
  const port = process.env.PORT || 3000;   // Render provides PORT automatically
  app.listen(port, () => console.log("Server listening on port " + port));
}

start().catch((e) => {
  console.error("Startup failed:", e.message);
  process.exit(1);
});
