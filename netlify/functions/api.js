require("dotenv").config();
const express = require("express");
const multer = require("multer");
const Anthropic = require("@anthropic-ai/sdk");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const crypto = require("crypto");
const serverless = require("serverless-http");
const { getStore } = require("@netlify/blobs");

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });
const client = new Anthropic.default({ apiKey: process.env.ANTHROPIC_API_KEY });

const JWT_SECRET = process.env.JWT_SECRET || "crochet-secret-change-in-prod";

// ── DB helpers using Netlify Blobs ───────────────────────────────
async function readDB() {
  const store = getStore("database");
  const data = await store.get("db.json", { type: "json" }).catch(() => null);
  return data || { users: [], patterns: [] };
}

async function writeDB(data) {
  const store = getStore("database");
  await store.set("db.json", JSON.stringify(data));
}

// ── Image helpers ────────────────────────────────────────────────
async function saveImage(patternId, buffer) {
  const store = getStore("images");
  await store.set(patternId, buffer, { contentType: "image/jpeg" });
}

async function getImage(patternId) {
  const store = getStore("images");
  return store.get(patternId, { type: "arrayBuffer" }).catch(() => null);
}

async function deleteImage(patternId) {
  const store = getStore("images");
  await store.delete(patternId).catch(() => null);
}

// ── Auth middleware ──────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

function optionalAuth(req, res, next) {
  const header = req.headers.authorization;
  if (header && header.startsWith("Bearer ")) {
    try { req.user = jwt.verify(header.slice(7), JWT_SECRET); } catch {}
  }
  next();
}

function requireAdmin(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) return res.status(401).json({ error: "Not authenticated" });
  try {
    const payload = jwt.verify(header.slice(7), JWT_SECRET);
    if (!payload.admin) return res.status(403).json({ error: "Forbidden" });
    req.user = payload;
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ── Password validation ──────────────────────────────────────────
function validatePassword(password) {
  if (!password || password.length < 8) return "Password must be at least 8 characters";
  if (!/[A-Z]/.test(password)) return "Password must contain at least one uppercase letter";
  if (!/[a-z]/.test(password)) return "Password must contain at least one lowercase letter";
  if (!/[0-9]/.test(password)) return "Password must contain at least one number";
  if (!/[^A-Za-z0-9]/.test(password)) return "Password must contain at least one special character (!@#$%^&* etc.)";
  return null;
}

app.use(express.json({ limit: "25mb" }));

// ── Token verify — checks JWT signature AND user exists in DB ────
app.get("/api/auth/verify", requireAuth, async (req, res) => {
  const db = await readDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(401).json({ error: "User not found" });
  res.json({ email: user.email });
});

// ── Auth routes ──────────────────────────────────────────────────
app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });
  const pwError = validatePassword(password);
  if (pwError) return res.status(400).json({ error: pwError });

  const db = await readDB();
  if (db.users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
    return res.status(409).json({ error: "An account with that email already exists" });
  }

  const hashed = await bcrypt.hash(password, 10);
  const user = { id: uuidv4(), email: email.toLowerCase(), password: hashed, createdAt: Date.now() };
  db.users.push(user);
  await writeDB(db);

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, email: user.email });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });

  const db = await readDB();
  const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Incorrect email or password" });
  }

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, email: user.email });
});

app.post("/api/auth/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  const db = await readDB();
  const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user) return res.json({ ok: true });

  const token = crypto.randomBytes(32).toString("hex");
  user.resetToken = token;
  user.resetExpiry = Date.now() + 60 * 60 * 1000;
  await writeDB(db);

  const BASE_URL = process.env.BASE_URL || process.env.URL || "https://your-site.netlify.app";
  const resetLink = `${BASE_URL}/?reset=${token}`;
  // Return link directly (no email server on Netlify without SMTP config)
  res.json({ ok: true, resetLink });
});

app.post("/api/auth/reset-password", async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: "Token and password required" });
  const pwError = validatePassword(password);
  if (pwError) return res.status(400).json({ error: pwError });

  const db = await readDB();
  const user = db.users.find(u => u.resetToken === token && u.resetExpiry > Date.now());
  if (!user) return res.status(400).json({ error: "Reset link is invalid or has expired" });

  user.password = await bcrypt.hash(password, 10);
  delete user.resetToken;
  delete user.resetExpiry;
  await writeDB(db);

  const jwtToken = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token: jwtToken, email: user.email });
});

// ── Pattern routes ───────────────────────────────────────────────
app.get("/api/patterns", requireAuth, async (req, res) => {
  const db = await readDB();
  const patterns = db.patterns
    .filter(p => p.userId === req.user.id)
    .sort((a, b) => b.createdAt - a.createdAt)
    .map(({ imageDataUrl, ...rest }) => rest);
  res.json(patterns);
});

app.post("/api/patterns", requireAuth, async (req, res) => {
  const { thumbnail, imageDataUrl, pattern } = req.body;
  if (!pattern) return res.status(400).json({ error: "Pattern text required" });

  const id = uuidv4();

  if (imageDataUrl) {
    const base64 = imageDataUrl.replace(/^data:image\/\w+;base64,/, "");
    await saveImage(id, Buffer.from(base64, "base64"));
  }

  const db = await readDB();
  db.patterns.push({ id, userId: req.user.id, createdAt: Date.now(), thumbnail, pattern });
  await writeDB(db);

  res.json({ id });
});

app.get("/api/patterns/:id/image", requireAuth, async (req, res) => {
  const db = await readDB();
  const pat = db.patterns.find(p => p.id === req.params.id && p.userId === req.user.id);
  if (!pat) return res.status(404).json({ error: "Not found" });

  const buffer = await getImage(req.params.id);
  if (!buffer) return res.status(404).json({ error: "Image not found" });

  res.setHeader("Content-Type", "image/jpeg");
  res.send(Buffer.from(buffer));
});

app.delete("/api/patterns/:id", requireAuth, async (req, res) => {
  const db = await readDB();
  const idx = db.patterns.findIndex(p => p.id === req.params.id && p.userId === req.user.id);
  if (idx === -1) return res.status(404).json({ error: "Not found" });

  db.patterns.splice(idx, 1);
  await writeDB(db);
  await deleteImage(req.params.id);

  res.json({ ok: true });
});

// ── Convert route ────────────────────────────────────────────────
app.post("/api/convert", optionalAuth, upload.single("image"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No image uploaded" });

  const imageBase64 = req.file.buffer.toString("base64");
  const mediaType = req.file.mimetype;

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  const send = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);

  try {
    const stream = client.messages.stream({
      model: "claude-opus-4-6",
      max_tokens: 4096,
      system: `You are an expert crochet pattern reverse-engineer and pattern writer specializing in US crochet terminology.
You accept two types of images and handle each accordingly:

TYPE A — Crochet chart / symbol diagram: Convert the symbols directly into a written pattern.
TYPE B — Photo of a finished crochet project (amigurumi, garment, accessory, blanket, etc.): Carefully study the texture, stitch structure, shape, and construction visible in the photo and write a complete pattern that would reproduce it.

For TYPE B photos: examine stitch height, loop placement, increases/decreases shaping, seams, color changes, and any visible construction details. Make your best assessment of yarn weight (fingering/sport/DK/worsted/bulky) and hook size based on stitch density and scale. State your assumptions clearly but keep it fun.

US Crochet Abbreviations to use:
ch = chain | sl st = slip stitch | sc = single crochet | hdc = half double crochet
dc = double crochet | tr = treble crochet | dtr = double treble | yo = yarn over
sp = space | st/sts = stitch/stitches | sk = skip | rep = repeat | beg = beginning
rnd/rnds = round/rounds | RS = right side | WS = wrong side
BLO = back loop only | FLO = front loop only | inc = increase | dec = decrease
MR = magic ring | pm = place marker | sm = slip marker | tog = together
ch-sp = chain space | * ... * = repeat section | [ ] = repeat group
inv dec = invisible decrease | sc2tog = single crochet 2 together

Format your response as:
## Description
A brief, slightly witty description of the project — give it personality! Describe what it is, what it's for, and poke a little fun at the complexity or charm. Keep it warm and fun, not mean.

## Materials
- Yarn: estimated weight and fiber suggestion
- Hook: estimated size (US and mm)
- Other: stuffing, safety eyes, stitch markers, tapestry needle, etc. as needed

## Special Stitches
List any non-standard stitches used, with definitions. Omit this section if none.

## Pattern Instructions
Row by row or round by round. Include stitch counts in parentheses at the end of each row/round. For amigurumi and 3D pieces, work in continuous rounds unless noted. For garments or flat pieces, specify turning chains.

## Finishing Notes
Assembly instructions if applicable, plus a short encouraging or humorous remark — like a coach who also crochets. Celebrate the crafter. You may lightly roast the pattern if it's particularly fiddly.

If the image is unclear or a detail is ambiguous, note your best guess and flag it — feel free to be a little dramatic, like a detective piecing together clues.`,
      messages: [{
        role: "user",
        content: [
          { type: "image", source: { type: "base64", media_type: mediaType, data: imageBase64 } },
          { type: "text", text: "Please analyze this image and write a complete crochet pattern in US crochet terminology that would reproduce what you see. It may be a crochet chart/diagram OR a photo of a finished crochet project — handle whichever it is." },
        ],
      }],
    });

    for await (const event of stream) {
      if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
        send({ type: "delta", text: event.delta.text });
      }
    }

    send({ type: "done" });
    res.end();
  } catch (err) {
    send({ type: "error", message: err.message });
    res.end();
  }
});

// ── Admin routes ─────────────────────────────────────────────────
app.post("/api/admin/login", (req, res) => {
  const { password } = req.body;
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
  if (!ADMIN_PASSWORD) return res.status(503).json({ error: "Admin access not configured. Set ADMIN_PASSWORD in environment variables." });
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: "Incorrect password" });
  const token = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: "8h" });
  res.json({ token });
});

app.get("/api/admin/stats", requireAdmin, async (req, res) => {
  const db = await readDB();
  res.json({ users: db.users.length, patterns: db.patterns.length });
});

app.get("/api/admin/users", requireAdmin, async (req, res) => {
  const db = await readDB();
  const users = db.users.map(u => ({
    id: u.id,
    email: u.email,
    createdAt: u.createdAt,
    patterns: db.patterns.filter(p => p.userId === u.id).length,
  })).sort((a, b) => b.createdAt - a.createdAt);
  res.json(users);
});

app.delete("/api/admin/users/:id", requireAdmin, async (req, res) => {
  const db = await readDB();
  const idx = db.users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "User not found" });
  db.users.splice(idx, 1);
  const userPatterns = db.patterns.filter(p => p.userId === req.params.id);
  for (const p of userPatterns) await deleteImage(p.id);
  db.patterns = db.patterns.filter(p => p.userId !== req.params.id);
  await writeDB(db);
  res.json({ ok: true });
});

app.get("/api/admin/patterns", requireAdmin, async (req, res) => {
  const db = await readDB();
  const userMap = Object.fromEntries(db.users.map(u => [u.id, u.email]));
  const patterns = db.patterns
    .map(({ imageDataUrl, ...p }) => ({ ...p, userEmail: userMap[p.userId] || "unknown" }))
    .sort((a, b) => b.createdAt - a.createdAt);
  res.json(patterns);
});

app.delete("/api/admin/patterns/:id", requireAdmin, async (req, res) => {
  const db = await readDB();
  const idx = db.patterns.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Not found" });
  db.patterns.splice(idx, 1);
  await writeDB(db);
  await deleteImage(req.params.id);
  res.json({ ok: true });
});

module.exports.handler = serverless(app);
