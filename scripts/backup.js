const fs = require('fs');
const path = require('path');
const yazl = require('yazl');

function nowName() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}_${pad(d.getHours())}-${pad(d.getMinutes())}-${pad(d.getSeconds())}`;
}

function addDir(zipfile, dirPath, zipPrefix) {
  if (!fs.existsSync(dirPath)) return;
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  for (const ent of entries) {
    const full = path.join(dirPath, ent.name);
    // Zip format expects forward slashes.
    const zipPath = (zipPrefix ? `${zipPrefix}/` : '') + ent.name;

    if (ent.isDirectory()) {
      addDir(zipfile, full, zipPath);
    } else if (ent.isFile()) {
      zipfile.addFile(full, zipPath);
    }
  }
}

const root = path.join(__dirname, '..');
const backupsDir = path.join(root, 'backups');
fs.mkdirSync(backupsDir, { recursive: true });

const outPath = path.join(backupsDir, `backup_${nowName()}.zip`);
const output = fs.createWriteStream(outPath);

const zipfile = new yazl.ZipFile();
zipfile.outputStream.pipe(output);

// data + uploads
addDir(zipfile, path.join(root, 'data'), 'data');
addDir(zipfile, path.join(root, 'uploads'), 'uploads');

// .env (optional)
const envPath = path.join(root, '.env');
if (fs.existsSync(envPath)) {
  zipfile.addFile(envPath, '.env');
}

zipfile.end();

output.on('close', () => {
  try {
    const bytes = fs.statSync(outPath).size;
    console.log('✅ Backup hazır:', outPath, `(${bytes} bytes)`);
  } catch {
    console.log('✅ Backup hazır:', outPath);
  }
});
