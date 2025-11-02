// index.js — One-file Roblox Licensing System (Node.js + Express + SQLite)
// --------------------------------------------------------------
import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import Database from "better-sqlite3";
import fetch from "node-fetch";
import { v4 as uuidv4 } from "uuid";
import jwt from "jsonwebtoken";
import fs from "fs";

// Environment / defaults
const PORT = process.env.PORT || 3000;
const API_SECRET = process.env.API_SECRET || "DEV_SECRET";
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "password";
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || "ADMIN_JWT";
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || "";
const DB_FILE = "./licenses.db";

// Init DB
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, "");
const db = new Database(DB_FILE);
db.exec(`
CREATE TABLE IF NOT EXISTS licenses(
 id TEXT PRIMARY KEY,
 key TEXT UNIQUE,
 owner TEXT,
 uses INTEGER DEFAULT 0,
 maxUses INTEGER DEFAULT 1,
 expiresAt INTEGER DEFAULT 0,
 revoked INTEGER DEFAULT 0,
 createdAt INTEGER
);
CREATE TABLE IF NOT EXISTS activations(
 id TEXT PRIMARY KEY,
 licenseKey TEXT,
 username TEXT,
 gameId TEXT,
 ip TEXT,
 time INTEGER
);
`);

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Helpers -------------------------------------------------------
function generateKey(prefix = "", length = 16) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let k = prefix ? prefix + "-" : "";
  for (let i = 0; i < length; i++)
    k += chars.charAt(Math.floor(Math.random() * chars.length));
  return k;
}

function webhook(title, desc) {
  if (!DISCORD_WEBHOOK_URL) return;
  fetch(DISCORD_WEBHOOK_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "License System",
      embeds: [{ title, description: desc, timestamp: new Date().toISOString() }],
    }),
  }).catch(() => {});
}

// ---------------------------------------------------------------
// Public verify endpoint (called from Roblox)
app.post("/api/verify", (req, res) => {
  const sec = req.header("x-api-secret");
  if (sec !== API_SECRET)
    return res.status(401).json({ valid: false, message: "Bad API secret" });

  const { license, username, gameId } = req.body || {};
  if (!license || !username)
    return res
      .status(400)
      .json({ valid: false, message: "license + username required" });

  const row = db.prepare("SELECT * FROM licenses WHERE key = ?").get(license);
  const now = Date.now();
  if (!row) return res.json({ valid: false, message: "License not found" });
  if (row.revoked) return res.json({ valid: false, message: "License revoked" });
  if (row.expiresAt && row.expiresAt < now)
    return res.json({ valid: false, message: "License expired" });
  if (row.uses >= row.maxUses)
    return res.json({ valid: false, message: "License uses exceeded" });

  db.prepare(
    "INSERT INTO activations (id, licenseKey, username, gameId, ip, time) VALUES (?, ?, ?, ?, ?, ?)"
  ).run(uuidv4(), license, username, gameId || "", req.ip, now);
  db.prepare("UPDATE licenses SET uses = uses + 1 WHERE key = ?").run(license);

  webhook(
    "License Verified",
    `License: ${license}\nUser: ${username}\nGame: ${gameId || "unknown"}`
  );

  res.json({ valid: true, message: "OK" });
});

// ---------------------------------------------------------------
// Admin authentication
app.post("/admin/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username !== ADMIN_USER || password !== ADMIN_PASS)
    return res.status(401).json({ ok: false, message: "Invalid credentials" });
  const token = jwt.sign({ username }, ADMIN_JWT_SECRET, { expiresIn: "12h" });
  res.json({ ok: true, token });
});

function requireAdmin(req, res, next) {
  const h = req.header("authorization");
  if (!h) return res.status(401).json({ ok: false });
  try {
    const [, token] = h.split(" ");
    jwt.verify(token, ADMIN_JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ ok: false });
  }
}

// ---------------------------------------------------------------
// Admin endpoints
app.get("/admin/licenses", requireAdmin, (req, res) => {
  res.json({
    ok: true,
    licenses: db.prepare("SELECT * FROM licenses ORDER BY createdAt DESC").all(),
  });
});

app.post("/admin/licenses/generate", requireAdmin, (req, res) => {
  const { count = 1, prefix = "", maxUses = 1, expiresInDays = 0, owner = "" } =
    req.body || {};
  const created = [];
  const stmt = db.prepare(
    "INSERT INTO licenses (id,key,owner,uses,maxUses,expiresAt,revoked,createdAt) VALUES (?,?,?,?,?,?,0,?)"
  );
  const now = Date.now();
  const exp = expiresInDays ? now + expiresInDays * 86400000 : 0;
  for (let i = 0; i < count; i++) {
    const id = uuidv4();
    const key = generateKey(prefix, 16);
    stmt.run(id, key, owner, 0, maxUses, exp, now);
    created.push(key);
  }
  res.json({ ok: true, created });
});

app.post("/admin/licenses/revoke", requireAdmin, (req, res) => {
  const { key } = req.body || {};
  db.prepare("UPDATE licenses SET revoked=1 WHERE key=?").run(key);
  res.json({ ok: true });
});

app.get("/admin/activations", requireAdmin, (req, res) => {
  res.json({
    ok: true,
    activations: db
      .prepare("SELECT * FROM activations ORDER BY time DESC LIMIT 100")
      .all(),
  });
});

// ---------------------------------------------------------------
// Minimal inline admin dashboard
const adminHTML = `
<!doctype html>
<html><head><meta charset=utf-8>
<title>License Admin</title>
<style>
body{font-family:Arial;background:#0f172a;color:#e6edf3;padding:20px}
.card{background:#111c35;padding:12px;margin-bottom:10px;border-radius:10px}
input,button{padding:6px;margin:3px;background:#1b2b4d;color:#fff;border:1px solid #314e89;border-radius:6px}
</style></head><body>
<h2>License Admin</h2>
<div id="login" class="card">
<input id="user" placeholder="user" value="admin">
<input id="pass" type="password" placeholder="pass">
<button onclick="login()">Login</button>
<div id="msg"></div></div>
<div id="panel" style="display:none">
<div class="card">
<h3>Generate</h3>
<input id="prefix" placeholder="prefix">
<input id="count" value="1" size=3>
<input id="uses" value="1" size=3>
<input id="days" value="0" size=3>
<button onclick="gen()">Generate</button>
<pre id="result"></pre></div>
<div class="card"><h3>Licenses</h3><div id="list"></div></div>
<div class="card"><h3>Activations</h3><div id="acts"></div></div>
</div>
<script>
let t=null;
async function login(){
 const r=await fetch('/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user.value,password:pass.value})});
 const j=await r.json();
 if(j.ok){t=j.token;login.style.display='none';panel.style.display='block';load();}
 else msg.innerText='Bad login';
}
async function load(){
 const L=await (await fetch('/admin/licenses',{headers:{Authorization:'Bearer '+t}})).json();
 list.innerHTML=L.licenses.map(l=>l.key+' — uses '+l.uses+'/'+l.maxUses+' — '+(l.revoked?'revoked':'ok')).join('<br>');
 const A=await (await fetch('/admin/activations',{headers:{Authorization:'Bearer '+t}})).json();
 acts.innerHTML=A.activations.map(a=>a.username+' — '+a.licenseKey+' — '+new Date(a.time).toLocaleString()).join('<br>');
}
async function gen(){
 const r=await fetch('/admin/licenses/generate',{method:'POST',headers:{Authorization:'Bearer '+t,'Content-Type':'application/json'},body:JSON.stringify({count:+count.value,prefix:prefix.value,maxUses:+uses.value,expiresInDays:+days.value})});
 const j=await r.json(); result.innerText=JSON.stringify(j.created,null,2);load();
}
</script></body></html>`;
app.get("/admin", (req, res) => res.send(adminHTML));

// ---------------------------------------------------------------
app.listen(PORT, () =>
  console.log(`✅ License system running on port ${PORT}`)
);
