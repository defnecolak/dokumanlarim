const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, '..', 'data', 'db.json');

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
