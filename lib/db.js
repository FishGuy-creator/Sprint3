import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { seedSubjects, seedNotes, seedDeadlines } from "./seed.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "..", "data", "db.json");

// Simple write queue so concurrent requests don't clobber each other's
// writes to the JSON file (good enough for a small class-project scale
// app; swap this module for a real database like Postgres if you outgrow it).
let writeQueue = Promise.resolve();

async function ensureDB() {
  try {
    await fs.access(DB_PATH);
  } catch {
    await fs.mkdir(path.dirname(DB_PATH), { recursive: true });
    const initial = {
      users: {},
      subjects: seedSubjects,
      notesBySubject: seedNotes,
      deadlines: seedDeadlines,
      votes: {}
    };
    await fs.writeFile(DB_PATH, JSON.stringify(initial, null, 2));
  }
}

export async function readDB() {
  await ensureDB();
  const raw = await fs.readFile(DB_PATH, "utf-8");
  return JSON.parse(raw);
}

export function writeDB(db) {
  writeQueue = writeQueue.then(() =>
    fs.writeFile(DB_PATH, JSON.stringify(db, null, 2))
  );
  return writeQueue;
}
