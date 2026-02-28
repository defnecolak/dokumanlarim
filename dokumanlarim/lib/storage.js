const fs = require('fs');
const path = require('path');
const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');

function truthy(v) {
  return String(v || '').trim() === '1' || String(v || '').trim().toLowerCase() === 'true';
}

function getStorageConfig() {
  const provider = (process.env.STORAGE_PROVIDER || 'local').trim().toLowerCase();
  return {
    provider,
    localBaseDir: LOCAL_BASE_DIR,
    tmpDir: LOCAL_TMP_DIR,
    s3: {
      endpoint: (process.env.S3_ENDPOINT || '').trim() || undefined,
      region: (process.env.S3_REGION || 'auto').trim(),
      bucket: (process.env.S3_BUCKET || '').trim(),
      accessKeyId: (process.env.S3_ACCESS_KEY_ID || '').trim(),
      secretAccessKey: (process.env.S3_SECRET_ACCESS_KEY || '').trim(),
      forcePathStyle: truthy(process.env.S3_FORCE_PATH_STYLE || '0'),
    },
  };
}

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}

function createS3Client(cfg) {
  const s3cfg = cfg.s3;
  if (!s3cfg.bucket) throw new Error('S3_BUCKET missing');
  if (!s3cfg.accessKeyId || !s3cfg.secretAccessKey) throw new Error('S3 credentials missing');
  const client = new S3Client({
    region: s3cfg.region,
    endpoint: s3cfg.endpoint,
    forcePathStyle: s3cfg.forcePathStyle,
    credentials: { accessKeyId: s3cfg.accessKeyId, secretAccessKey: s3cfg.secretAccessKey },
  });
  return { client, bucket: s3cfg.bucket };
}

function makeKey(tenantId, requestId, storedName) {
  const t = String(tenantId || 't').replace(/[^a-zA-Z0-9_-]/g, '_');
  const r = String(requestId || 'r').replace(/[^a-zA-Z0-9_-]/g, '_');
  return `${t}/${r}/${storedName}`;
}

function getStorage() {
  const cfg = getStorageConfig();
  if (cfg.provider === 's3') {
    // Ensure tmp dir exists for multer
    ensureDir(cfg.tmpDir);
    const { client, bucket } = createS3Client(cfg);

    return {
      provider: 's3',
      tmpDir: cfg.tmpDir,
      // fileMeta = { key, originalName, mime, size }
      async putFromPath({ tenantId, requestId, storedName, filePath, contentType }) {
        const key = makeKey(tenantId, requestId, storedName);
        const body = fs.createReadStream(filePath);
        await client.send(new PutObjectCommand({
          Bucket: bucket,
          Key: key,
          Body: body,
          ContentType: contentType || undefined,
        }));
        return { provider: 's3', bucket, key };
      },
      async getStream(meta) {
        const out = await client.send(new GetObjectCommand({ Bucket: meta.bucket || bucket, Key: meta.key }));
        return out.Body; // stream
      },
      async delete(meta) {
        try {
          await client.send(new DeleteObjectCommand({ Bucket: meta.bucket || bucket, Key: meta.key }));
        } catch (e) {
          // ignore
        }
      },
    };
  }

  // default local
  ensureDir(cfg.localBaseDir);
  return {
    provider: 'local',
    baseDir: cfg.localBaseDir,
    tmpDir: null,
    async putFromPath({ tenantId, requestId, storedName, filePath }) {
      // file is already placed in final dir by multer in local mode
      const dir = path.join(cfg.localBaseDir, tenantId, requestId);
      ensureDir(dir);
      const dest = path.join(dir, storedName);
      // If multer already wrote there, skip move. If it's a tmp upload, move it.
      if (filePath !== dest) {
        fs.renameSync(filePath, dest);
      }
      return { provider: 'local', path: dest };
    },
    async getStream(meta) {
      return fs.createReadStream(meta.path);
    },
    async delete(meta) {
      try { fs.unlinkSync(meta.path); } catch {}
    },
  };
}

module.exports = { getStorage, getStorageConfig, makeKey };
