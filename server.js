require("dotenv").config();
const express = require("express");
const multer = require("multer");
const Anthropic = require("@anthropic-ai/sdk");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });
const client = new Anthropic.default({ apiKey: process.env.ANTHROPIC_API_KEY });

const JWT_SECRET = process.env.JWT_SECRET || "crochet-secret-change-in-prod";
const DB_PATH = path.join(__dirname, "data", "db.json");
const IMAGES_DIR = path.join(__dirname, "data", "images");

// ── Ensure data directories and db exist (never overwrite existing data) ──
fs.mkdirSync(IMAGES_DIR, { recursive: true });
if (!fs.existsSync(DB_PATH)) {
  fs.writeFileSync(DB_PATH, JSON.stringify({ users: [], patterns: [] }, null, 2));
}

app.use(express.json({ limit: "25mb" }));
app.use(express.static(path.join(__dirname, "public")));

// ── DB helpers ──────────────────────────────────────────────────
function readDB() {
  return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
}
function writeDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
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

// ── Auth routes ──────────────────────────────────────────────────
app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });
  const pwError = validatePassword(password);
  if (pwError) return res.status(400).json({ error: pwError });

  const db = readDB();
  if (db.users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
    return res.status(409).json({ error: "An account with that email already exists" });
  }

  const hashed = await bcrypt.hash(password, 10);
  const user = { id: uuidv4(), email: email.toLowerCase(), password: hashed, createdAt: Date.now() };
  db.users.push(user);
  writeDB(db);

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, email: user.email });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });

  const db = readDB();
  const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Incorrect email or password" });
  }

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, email: user.email });
});

// ── Password reset routes ────────────────────────────────────────
app.post("/api/auth/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  const db = readDB();
  const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  // Always respond success to avoid leaking whether email exists
  if (!user) return res.json({ ok: true });

  const token = crypto.randomBytes(32).toString("hex");
  user.resetToken = token;
  user.resetExpiry = Date.now() + 60 * 60 * 1000; // 1 hour
  writeDB(db);

  const BASE_URL = process.env.BASE_URL || `http://localhost:${process.env.PORT || 3001}`;
  const resetLink = `${BASE_URL}/?reset=${token}`;

  // Send email if configured, otherwise return link directly (local dev)
  if (process.env.EMAIL_HOST && process.env.EMAIL_USER) {
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: parseInt(process.env.EMAIL_PORT || "587"),
      secure: process.env.EMAIL_SECURE === "true",
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });
    await transporter.sendMail({
      from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
      to: user.email,
      subject: "Reset your Crochet Converter password",
      text: `Hi! Click the link below to reset your password. It expires in 1 hour.\n\n${resetLink}\n\nIf you didn't request this, you can ignore this email.`,
      html: `<p>Hi! Click the link below to reset your password. It expires in 1 hour.</p><p><a href="${resetLink}">${resetLink}</a></p><p>If you didn't request this, you can ignore this email.</p>`,
    });
    return res.json({ ok: true });
  }

  // No email configured — return link for local dev
  res.json({ ok: true, resetLink });
});

app.post("/api/auth/reset-password", async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: "Token and password required" });
  const pwError = validatePassword(password);
  if (pwError) return res.status(400).json({ error: pwError });

  const db = readDB();
  const user = db.users.find(u => u.resetToken === token && u.resetExpiry > Date.now());
  if (!user) return res.status(400).json({ error: "Reset link is invalid or has expired" });

  user.password = await bcrypt.hash(password, 10);
  delete user.resetToken;
  delete user.resetExpiry;
  writeDB(db);

  const jwtToken = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token: jwtToken, email: user.email });
});

// ── Pattern routes ───────────────────────────────────────────────
app.get("/api/patterns", requireAuth, (req, res) => {
  const db = readDB();
  const patterns = db.patterns
    .filter(p => p.userId === req.user.id)
    .sort((a, b) => b.createdAt - a.createdAt)
    .map(({ imageDataUrl, ...rest }) => rest);
  res.json(patterns);
});

app.post("/api/patterns", requireAuth, (req, res) => {
  const { thumbnail, imageDataUrl, pattern } = req.body;
  if (!pattern) return res.status(400).json({ error: "Pattern text required" });

  const id = uuidv4();

  if (imageDataUrl) {
    const base64 = imageDataUrl.replace(/^data:image\/\w+;base64,/, "");
    fs.writeFileSync(path.join(IMAGES_DIR, `${id}.jpg`), Buffer.from(base64, "base64"));
  }

  const db = readDB();
  db.patterns.push({ id, userId: req.user.id, createdAt: Date.now(), thumbnail, pattern });
  writeDB(db);

  res.json({ id });
});

app.get("/api/patterns/:id/image", requireAuth, (req, res) => {
  const db = readDB();
  const pat = db.patterns.find(p => p.id === req.params.id && p.userId === req.user.id);
  if (!pat) return res.status(404).json({ error: "Not found" });

  const imgPath = path.join(IMAGES_DIR, `${req.params.id}.jpg`);
  if (!fs.existsSync(imgPath)) return res.status(404).json({ error: "Image not found" });
  res.sendFile(imgPath);
});

app.delete("/api/patterns/:id", requireAuth, (req, res) => {
  const db = readDB();
  const idx = db.patterns.findIndex(p => p.id === req.params.id && p.userId === req.user.id);
  if (idx === -1) return res.status(404).json({ error: "Not found" });

  db.patterns.splice(idx, 1);
  writeDB(db);

  const imgPath = path.join(IMAGES_DIR, `${req.params.id}.jpg`);
  if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath);

  res.json({ ok: true });
});

// ── Convert route ────────────────────────────────────────────────
app.post("/api/convert", optionalAuth, upload.single("image"), async (req, res) => {
  console.log("Convert request from", req.user ? req.user.email : "guest");
  if (!req.file) return res.status(400).json({ error: "No image uploaded" });

  const imageBase64 = req.file.buffer.toString("base64");
  const mediaType = req.file.mimetype;

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

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
          { type: "text", text: "Please analyze this image and write a complete crochet pattern in US terminology that would reproduce what you see. It may be a crochet chart/diagram OR a photo of a finished crochet project — handle whichever it is." },
        ],
      }],
    });

    for await (const event of stream) {
      if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
        send({ type: "delta", text: event.delta.text });
      }
    }

    const final = await stream.finalMessage();
    console.log("Done. stop_reason:", final.stop_reason, "tokens:", final.usage.output_tokens);
    send({ type: "done" });
    res.end();
  } catch (err) {
    console.error("Convert error:", err.message);
    send({ type: "error", message: err.message });
    res.end();
  }
});

// ── Admin routes ─────────────────────────────────────────────────
app.post("/api/admin/login", (req, res) => {
  const { password } = req.body;
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
  if (!ADMIN_PASSWORD) return res.status(503).json({ error: "Admin access not configured. Set ADMIN_PASSWORD in .env" });
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: "Incorrect password" });
  const token = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: "8h" });
  res.json({ token });
});

app.get("/api/admin/stats", requireAdmin, (req, res) => {
  const db = readDB();
  res.json({
    users: db.users.length,
    patterns: db.patterns.length,
  });
});

app.get("/api/admin/users", requireAdmin, (req, res) => {
  const db = readDB();
  const users = db.users.map(u => ({
    id: u.id,
    email: u.email,
    createdAt: u.createdAt,
    patterns: db.patterns.filter(p => p.userId === u.id).length,
  })).sort((a, b) => b.createdAt - a.createdAt);
  res.json(users);
});

app.delete("/api/admin/users/:id", requireAdmin, (req, res) => {
  const db = readDB();
  const idx = db.users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "User not found" });
  db.users.splice(idx, 1);
  // Delete all their patterns and images
  const userPatterns = db.patterns.filter(p => p.userId === req.params.id);
  userPatterns.forEach(p => {
    const imgPath = path.join(IMAGES_DIR, `${p.id}.jpg`);
    if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath);
  });
  db.patterns = db.patterns.filter(p => p.userId !== req.params.id);
  writeDB(db);
  res.json({ ok: true });
});

app.get("/api/admin/patterns", requireAdmin, (req, res) => {
  const db = readDB();
  const userMap = Object.fromEntries(db.users.map(u => [u.id, u.email]));
  const patterns = db.patterns
    .map(({ imageDataUrl, ...p }) => ({ ...p, userEmail: userMap[p.userId] || "unknown" }))
    .sort((a, b) => b.createdAt - a.createdAt);
  res.json(patterns);
});

app.delete("/api/admin/patterns/:id", requireAdmin, (req, res) => {
  const db = readDB();
  const idx = db.patterns.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Not found" });
  db.patterns.splice(idx, 1);
  writeDB(db);
  const imgPath = path.join(IMAGES_DIR, `${req.params.id}.jpg`);
  if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath);
  res.json({ ok: true });
});

app.get("/api/admin/patterns/:id/image", requireAdmin, (req, res) => {
  const imgPath = path.join(IMAGES_DIR, `${req.params.id}.jpg`);
  if (!fs.existsSync(imgPath)) return res.status(404).json({ error: "Image not found" });
  res.sendFile(imgPath);
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Running at http://localhost:${PORT}`));
