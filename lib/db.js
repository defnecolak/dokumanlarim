const fs = require('fs');
const path = require('path');

const DEFAULT_DB_PATH = path.join(__dirname, '..', 'data', 'db.json');
const DATA_DIR = (process.env.DATA_DIR || '').trim();
const DB_PATH = DATA_DIR ? path.join(DATA_DIR, 'db.json') : DEFAULT_DB_PATH;

function ensureDbFile() {
  if (fs.existsSync(DB_PATH)) return;

  // Ensure data directory exists
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

  if (DATA_DIR) {
    // Seed dosyası varsa ilk açılışta kopyala (builtin şablonlar vb. için).
    if (fs.existsSync(DEFAULT_DB_PATH)) {
      fs.copyFileSync(DEFAULT_DB_PATH, DB_PATH);
      return;
    }
  }

  // Create empty seed DB if nothing exists
  const seed = {
    meta: { version: '1.12.0', createdAt: new Date().toISOString() },
    tenants: [],
    users: [],
    requests: [],
    audit: [],
    billing: [],
    invites: [],
    templates: [],
  };
  fs.writeFileSync(DB_PATH, JSON.stringify(seed, null, 2), 'utf-8');
}

// Ensure db.json exists at module load time.
ensureDbFile();

const REQUIRED_COLLECTIONS = ['tenants', 'users', 'requests', 'audit', 'billing', 'invites', 'templates', 'notifications'];

function readDB() {
  const raw = fs.readFileSync(DB_PATH, 'utf-8');
  const db = JSON.parse(raw);

  // Schema guard: ensure all required collections exist as arrays
  if (!db || typeof db !== 'object' || Array.isArray(db)) {
    throw new Error('DB schema invalid: root must be an object');
  }
  for (const key of REQUIRED_COLLECTIONS) {
    if (!Array.isArray(db[key])) {
      db[key] = [];
    }
  }
  if (!db.meta) db.meta = {};

  return db;
}

function writeDB(db) {
  const tmp = DB_PATH + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), 'utf-8');
  fs.renameSync(tmp, DB_PATH);
}

function withDB(mutator) {
  const db = readDB();
  const result = mutator(db);
  writeDB(db);
  return result;
}

module.exports = {
  DB_PATH,
  readDB,
  writeDB,
  withDB,
};
