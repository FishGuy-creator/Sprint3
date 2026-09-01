import "dotenv/config";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { OAuth2Client } from "google-auth-library";
import multer from "multer";
import { readDB, writeDB } from "./lib/db.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  ANTHROPIC_API_KEY,
  BACKEND_URL = "http://localhost:4000",
  FRONTEND_URL = "http://localhost:4000",
  SESSION_SECRET,
  PORT = 4000,
  NODE_ENV = "development"
} = process.env;

if (!SESSION_SECRET) {
  console.error(
    "Missing SESSION_SECRET. Copy .env.example to .env and fill it in (see README.md)."
  );
  process.exit(1);
}
const googleConfigured = Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET);
if (!googleConfigured) {
  console.warn(
    "GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET are not set — Google sign-in is disabled until you add them. See README.md."
  );
}

const anthropicConfigured = Boolean(ANTHROPIC_API_KEY);
if (!anthropicConfigured) {
  console.warn(
    "ANTHROPIC_API_KEY is not set — Nora (the AI study buddy) can't reply until you add it. See README.md."
  );
}

const oauthClient = googleConfigured
  ? new OAuth2Client(
      GOOGLE_CLIENT_ID,
      GOOGLE_CLIENT_SECRET,
      `${BACKEND_URL}/auth/google/callback`
    )
  : null;

const app = express();
app.set("trust proxy", 1);
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const COOKIE_NAME = "learnora_session";
const COOKIE_OPTS = {
  httpOnly: true,
  sameSite: "lax",
  secure: NODE_ENV === "production",
  maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
};

function publicUser(user) {
  return { name: user.name, email: user.email, picture: user.picture || null };
}

/* ------------------------- File uploads (notes) ------------------------- */
// Uploaded documents are stored on disk under data/uploads; only the
// generated on-disk filename is kept in db.json, never the raw file bytes.

const UPLOADS_DIR = process.env.UPLOADS_DIR || path.join(__dirname, "data", "uploads");
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const ALLOWED_UPLOAD_TYPES = new Set([
  "application/pdf",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.ms-powerpoint",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "text/plain",
  "image/png",
  "image/jpeg",
  "image/webp"
]);

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).slice(0, 20);
      cb(null, `${crypto.randomUUID()}${ext}`);
    }
  }),
  limits: { fileSize: 25 * 1024 * 1024 }, // 25MB
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_UPLOAD_TYPES.has(file.mimetype)) {
      return cb(new Error("unsupported_file_type"));
    }
    cb(null, true);
  }
});

// Strips the internal on-disk filename before a note is sent to the client.
function publicNote(note) {
  const { storagePath, ...rest } = note;
  return rest;
}

function signSession(user) {
  return jwt.sign(publicUser(user), SESSION_SECRET, { expiresIn: "30d" });
}

function requireAuth(req, res, next) {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return res.status(401).json({ error: "not_signed_in" });
  try {
    req.user = jwt.verify(token, SESSION_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "session_expired" });
  }
}

/* ----------------------------- Auth: Google ----------------------------- */
// Real OAuth 2.0 Authorization Code flow. Requires a Google Cloud project
// with an OAuth client (see README.md) — this route redirects the browser
// to accounts.google.com; nothing here fakes or simulates the login.

app.get("/auth/google", (req, res) => {
  if (!googleConfigured) {
    return res.status(503).send("Google sign-in is not configured on this server yet.");
  }
  const state = crypto.randomBytes(16).toString("hex");
  res.cookie("oauth_state", state, {
    httpOnly: true,
    sameSite: "lax",
    secure: NODE_ENV === "production",
    maxAge: 5 * 60 * 1000
  });
  const url = oauthClient.generateAuthUrl({
    access_type: "online",
    scope: ["openid", "email", "profile"],
    state,
    prompt: "select_account"
  });
  res.redirect(url);
});

app.get("/auth/google/callback", async (req, res) => {
  if (!googleConfigured) return res.status(503).send("Google sign-in is not configured.");
  const { code, state, error } = req.query;
  if (error) return res.redirect(`${FRONTEND_URL}/?auth_error=${encodeURIComponent(String(error))}`);
  if (!code || !state || state !== req.cookies.oauth_state) {
    return res.status(400).send("Invalid or expired sign-in attempt. Please try again.");
  }
  try {
    const { tokens } = await oauthClient.getToken({
      code: String(code),
      redirect_uri: `${BACKEND_URL}/auth/google/callback`
    });
    const ticket = await oauthClient.verifyIdToken({
      idToken: tokens.id_token,
      audience: GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    if (!payload || !payload.email_verified) {
      return res.status(403).send("Your Google account's email is not verified.");
    }
    const email = payload.email.toLowerCase();

    const db = await readDB();
    if (!db.users[email]) {
      db.users[email] = {
        email,
        name: payload.name || email.split("@")[0],
        picture: payload.picture || null,
        provider: "google",
        createdAt: new Date().toISOString()
      };
    } else if (db.users[email].provider !== "google") {
      db.users[email].provider = "google";
      db.users[email].picture = payload.picture || db.users[email].picture || null;
    }
    await writeDB(db);

    res.cookie(COOKIE_NAME, signSession(db.users[email]), COOKIE_OPTS);
    res.clearCookie("oauth_state");
    res.redirect(FRONTEND_URL);
  } catch (err) {
    console.error("Google OAuth callback failed:", err);
    res.status(500).send("Google sign-in failed. Please try again.");
  }
});

/* ------------------------- Auth: email + password ------------------------ */

app.post("/auth/register", async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) {
    return res.status(400).json({ error: "Name, email, and password are required." });
  }
  if (String(password).length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters." });
  }
  const key = String(email).trim().toLowerCase();
  if (!key.includes("@")) return res.status(400).json({ error: "Enter a valid email." });

  const db = await readDB();
  if (db.users[key]) {
    return res.status(409).json({ error: "An account with that email already exists — sign in instead." });
  }
  const passwordHash = await bcrypt.hash(password, 12);
  db.users[key] = {
    email: key,
    name: String(name).trim(),
    provider: "email",
    passwordHash,
    createdAt: new Date().toISOString()
  };
  await writeDB(db);
  res.cookie(COOKIE_NAME, signSession(db.users[key]), COOKIE_OPTS);
  res.json({ user: publicUser(db.users[key]) });
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  const key = String(email || "").trim().toLowerCase();
  const db = await readDB();
  const user = db.users[key];
  if (!user) return res.status(404).json({ error: "No account with that email — register first." });
  if (user.provider !== "email" || !user.passwordHash) {
    return res.status(400).json({ error: "That account uses Google sign-in — use 'Continue with Google'." });
  }
  const ok = await bcrypt.compare(password || "", user.passwordHash);
  if (!ok) return res.status(401).json({ error: "Incorrect password." });
  res.cookie(COOKIE_NAME, signSession(user), COOKIE_OPTS);
  res.json({ user: publicUser(user) });
});

app.post("/auth/logout", (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return res.json({ user: null });
  try {
    res.json({ user: jwt.verify(token, SESSION_SECRET) });
  } catch {
    res.json({ user: null });
  }
});

/* --------------------------------- Data API -------------------------------- */

app.get("/api/subjects", async (req, res) => {
  const db = await readDB();
  res.json(db.subjects);
});

app.post("/api/subjects", requireAuth, async (req, res) => {
  const { code, name, dept, content } = req.body || {};
  if (!code || !name || !dept) {
    return res.status(400).json({ error: "code, name, and dept are required" });
  }
  const cleanCode = String(code).trim().toUpperCase().replace(/\s+/g, "");
  if (!/^[A-Z0-9]{2,12}$/.test(cleanCode)) {
    return res.status(400).json({ error: "Subject code should be 2–12 letters/numbers, e.g. CSIT301" });
  }
  const db = await readDB();
  if (db.subjects.some((s) => s.code === cleanCode)) {
    return res.status(409).json({ error: `A subject with code ${cleanCode} already exists` });
  }
  const subject = {
    code: cleanCode,
    name: String(name).trim(),
    dept: String(dept).trim(),
    notes: 0,
    content: (content ? String(content).trim() : "") ||
      `${String(name).trim()} — no summary added yet. Upload notes or edit this subject to add study material.`
  };
  db.subjects.push(subject);
  db.notesBySubject[cleanCode] = [];
  await writeDB(db);
  res.json(subject);
});

app.get("/api/notes/:code", async (req, res) => {
  const db = await readDB();
  res.json((db.notesBySubject[req.params.code] || []).map(publicNote));
});

app.post("/api/notes/:code", requireAuth, (req, res) => {
  upload.single("file")(req, res, async (err) => {
    if (err) {
      const message =
        err.message === "unsupported_file_type"
          ? "That file type isn't supported. Upload a PDF, Word, PowerPoint, text, or image file."
          : err.code === "LIMIT_FILE_SIZE"
          ? "File is too large — the limit is 25MB."
          : "Upload failed — try again.";
      return res.status(400).json({ error: message });
    }

    const { title, type } = req.body || {};
    if (!title || !type) {
      if (req.file) await fs.promises.unlink(req.file.path).catch(() => {});
      return res.status(400).json({ error: "title and type are required" });
    }
    if (!req.file) {
      return res.status(400).json({ error: "A document is required — choose a file to upload." });
    }

    const db = await readDB();
    const code = req.params.code;
    if (!db.notesBySubject[code]) db.notesBySubject[code] = [];
    const id = `${code}-${crypto.randomUUID()}`;
    const note = {
      id,
      title: String(title).trim(),
      type,
      author: req.user.name,
      votes: 0,
      date: "just now",
      fileName: req.file.originalname,
      fileSize: req.file.size,
      fileType: req.file.mimetype,
      storagePath: req.file.filename,
      fileUrl: `/api/notes/${code}/${id}/file`
    };
    db.notesBySubject[code].unshift(note);
    const subj = db.subjects.find((s) => s.code === code);
    if (subj) subj.notes += 1;
    await writeDB(db);
    res.json(publicNote(note));
  });
});

app.get("/api/notes/:code/:noteId/file", async (req, res) => {
  const db = await readDB();
  const notes = db.notesBySubject[req.params.code] || [];
  const note = notes.find((n) => n.id === req.params.noteId);
  if (!note || !note.storagePath) return res.status(404).json({ error: "File not found" });
  const filePath = path.join(UPLOADS_DIR, note.storagePath);
  res.download(filePath, note.fileName || "document");
});

app.post("/api/notes/:code/:noteId/upvote", requireAuth, async (req, res) => {
  const db = await readDB();
  const { code, noteId } = req.params;
  const notes = db.notesBySubject[code] || [];
  const note = notes.find((n) => n.id === noteId);
  if (!note) return res.status(404).json({ error: "Note not found" });

  const email = req.user.email;
  db.votes[email] = db.votes[email] || [];
  const alreadyVoted = db.votes[email].includes(noteId);
  if (alreadyVoted) {
    db.votes[email] = db.votes[email].filter((id) => id !== noteId);
    note.votes = Math.max(0, note.votes - 1);
  } else {
    db.votes[email].push(noteId);
    note.votes += 1;
  }
  await writeDB(db);
  res.json({ note: publicNote(note), voted: !alreadyVoted });
});

app.get("/api/myvotes", requireAuth, async (req, res) => {
  const db = await readDB();
  res.json(db.votes[req.user.email] || []);
});

app.get("/api/deadlines", async (req, res) => {
  const db = await readDB();
  res.json(db.deadlines);
});

app.post("/api/deadlines", requireAuth, async (req, res) => {
  const { title, subject, type, date } = req.body || {};
  if (!title || !subject || !type || !date) {
    return res.status(400).json({ error: "title, subject, type, and date are required" });
  }
  const db = await readDB();
  const deadline = { title: String(title).trim(), subject, type, date };
  db.deadlines.push(deadline);
  await writeDB(db);
  res.json(deadline);
});

/* ------------------------------ Nora AI chat ----------------------------- */
// The frontend used to call api.anthropic.com directly from the browser,
// which can't work (no way to attach a secret API key client-side, and
// Anthropic's API doesn't allow browser CORS calls) — that's why Nora only
// ever showed "I couldn't connect". This route proxies the request through
// the server, where the key can actually live.

const NORA_SYSTEM_PROMPT =
  "You are Nora, a warm and encouraging AI study buddy inside Learnora, a notes app for college students. Give clear, well-organized study help — explanations, summaries, flashcards, quizzes, revision plans — tailored to whatever the student shares. Keep answers focused, not overly long. Use short paragraphs and '-' bullet points where useful.";

app.post("/api/chat", async (req, res) => {
  if (!anthropicConfigured) {
    return res.status(503).json({
      error: "Nora isn't set up yet — the server is missing ANTHROPIC_API_KEY. See README.md."
    });
  }
  const { messages } = req.body || {};
  const cleaned = (Array.isArray(messages) ? messages : [])
    .filter((m) => m && (m.role === "user" || m.role === "assistant") && typeof m.content === "string")
    .slice(-20)
    .map((m) => ({ role: m.role, content: m.content.slice(0, 8000) }));
  if (cleaned.length === 0) {
    return res.status(400).json({ error: "messages is required" });
  }

  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: "claude-sonnet-5",
        max_tokens: 1000,
        system: NORA_SYSTEM_PROMPT,
        messages: cleaned
      })
    });
    const data = await response.json();
    if (!response.ok) {
      console.error("Anthropic API error:", data);
      return res.status(502).json({ error: "Nora couldn't respond just now — try again in a moment." });
    }
    const reply = (data.content || []).filter((b) => b.type === "text").map((b) => b.text).join("\n");
    res.json({ reply: reply || "Sorry, I couldn't generate a response just now — try asking again." });
  } catch (err) {
    console.error("Nora chat request failed:", err);
    res.status(502).json({ error: "Nora couldn't respond just now — try again in a moment." });
  }
});

/* --------------------------------- Stats API -------------------------------- */
// Real, live counts straight from the database — not hardcoded marketing numbers.

app.get("/api/stats", async (req, res) => {
  const db = await readDB();
  const notes = Object.values(db.notesBySubject).reduce((sum, list) => sum + list.length, 0);
  res.json({ subjects: db.subjects.length, notes });
});

app.listen(PORT, () => {
  console.log(`Learnora backend listening on http://localhost:${PORT}`);
  if (!googleConfigured) console.log("  (Google sign-in disabled — see README.md)");
});
