const fs = require('fs');
const path = require('path');

const DEFAULT_DB_PATH = path.join(__dirname, '..', 'data', 'db.json');
const DATA_DIR = (process.env.DATA_DIR || '').trim();
const DB_PATH = DATA_DIR ? path.join(DATA_DIR, 'db.json') : DEFAULT_DB_PATH;

function ensureDbFile() {
  if (fs.existsSync(DB_PATH)) return;

  if (DATA_DIR) {
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    // Seed dosyası varsa ilk açılışta kopyala (builtin şablonlar vb. için).
    if (fs.existsSync(DEFAULT_DB_PATH)) {
      fs.copyFileSync(DEFAULT_DB_PATH, DB_PATH);
      return;
    }
  }
}


function readDB() {
  const raw = fs.readFileSync(DB_PATH, 'utf-8');
  return JSON.parse(raw);
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
