import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { lstat, mkdir, open, readdir, readFile, realpath, rm, stat } from 'node:fs/promises';
import { createReadStream, createWriteStream } from 'node:fs';
import { dirname, isAbsolute, parse, relative, resolve, sep } from 'node:path';
import { pipeline } from 'node:stream/promises';

const MAGIC = Buffer.from('BPC-SC022-SEALED-BUNDLE-V1\n', 'ascii');
const MANIFEST_SCHEMA = 'beta-sealed-checkpoint-payload/v1';
const HASH = /^[0-9a-f]{64}$/;
const KINDS = new Set(['database', 'evidence', 'screenshot', 'closure']);
const MAX_MANIFEST_BYTES = 16 * 1024 * 1024;

function fail(code) { throw new Error(`beta_backup_bundle_${code}`); }
function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function within(root, target) {
  const rel = relative(root, target);
  return rel === '' || (!isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`));
}
function safeRelative(value) {
  if (typeof value !== 'string' || !value || value.includes('\\') || value.includes('\0') || isAbsolute(value) ||
      /^[A-Za-z]:/.test(value) || value.split('/').some((part) => !part || part === '.' || part === '..')) fail('unsafe_path');
  return value;
}
function validateKey(key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) fail('key_invalid');
}
function aad(checkpointId) { return Buffer.concat([MAGIC, Buffer.from(checkpointId, 'ascii')]); }

async function assertPathChain(path, { allowMissingFinal = false } = {}) {
  const absolute = resolve(path);
  const root = parse(absolute).root;
  let current = root;
  const components = relative(root, absolute).split(sep).filter(Boolean);
  for (let index = 0; index < components.length; index += 1) {
    current = resolve(current, components[index]);
    let info;
    try { info = await lstat(current); }
    catch (error) {
      if (allowMissingFinal && index === components.length - 1 && error?.code === 'ENOENT') return { absolute, exists: false };
      fail('path_missing');
    }
    if (info.isSymbolicLink()) fail('path_symlink');
    if (index < components.length - 1 && !info.isDirectory()) fail('path_parent_invalid');
  }
  return { absolute, exists: true, canonicalPath: await realpath(absolute) };
}

async function listFiles(root, relativeRoot = '') {
  const entries = await readdir(resolve(root, relativeRoot), { withFileTypes: true });
  const rows = [];
  for (const entry of entries) {
    const rel = relativeRoot ? `${relativeRoot}/${entry.name}` : entry.name;
    const path = resolve(root, rel);
    const info = await lstat(path);
    if (info.isSymbolicLink()) fail('symlink');
    if (info.isDirectory()) rows.push(...await listFiles(root, rel));
    else if (info.isFile()) rows.push(rel);
    else fail('special_file');
  }
  return rows.sort();
}

async function hashFile(path) {
  const infoBefore = await lstat(path);
  if (!infoBefore.isFile() || infoBefore.isSymbolicLink()) fail('source_file_invalid');
  const hash = createHash('sha256');
  let bytes = 0;
  for await (const chunk of createReadStream(path)) { hash.update(chunk); bytes += chunk.length; }
  const infoAfter = await lstat(path);
  if (bytes !== infoAfter.size || infoBefore.size !== infoAfter.size || infoBefore.mtimeMs !== infoAfter.mtimeMs) fail('source_changed');
  return { bytes, sha256: hash.digest('hex') };
}

async function writeAll(handle, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset, null);
    if (!bytesWritten) fail('short_write');
    offset += bytesWritten;
  }
}

/** Seal every regular file under payloadRoot into one authenticated artifact. Key recovery stays external. */
export async function sealCheckpointPayload({ payloadRoot, bundleRoot, encryptedPath, checkpointId, externalKeyRecoveryPath, protectKey }) {
  if (!isAbsolute(payloadRoot ?? '') || !isAbsolute(bundleRoot ?? '') || !isAbsolute(encryptedPath ?? '') || !isAbsolute(externalKeyRecoveryPath ?? '') ||
      typeof checkpointId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(checkpointId) || typeof protectKey !== 'function') {
    fail('input_invalid');
  }
  const sourcePath = await assertPathChain(payloadRoot);
  const sourceRoot = sourcePath.canonicalPath;
  const sourceInfo = await lstat(payloadRoot);
  if (!sourceInfo.isDirectory() || sourceInfo.isSymbolicLink()) fail('payload_root_invalid');
  const bundlePath = await assertPathChain(bundleRoot);
  if (!bundlePath.exists || !(await lstat(bundlePath.canonicalPath)).isDirectory()) fail('bundle_root_invalid');
  const outputPath = resolve(encryptedPath);
  const keyPath = resolve(externalKeyRecoveryPath);
  const outputInsideBundle = within(bundlePath.canonicalPath, outputPath);
  const keyInsideBundle = within(bundlePath.canonicalPath, keyPath);
  if (!outputInsideBundle || keyInsideBundle || within(sourceRoot, keyPath) || outputPath === keyPath ||
      within(sourceRoot, outputPath) || within(outputPath, sourceRoot)) fail('path_overlap');
  await assertPathChain(dirname(outputPath));
  await assertPathChain(dirname(keyPath));
  const relativePaths = await listFiles(sourceRoot);
  if (relativePaths.length < 1) fail('payload_empty');
  const fileRows = [];
  for (const path of relativePaths) {
    const kind = path === 'database.dump' ? 'database' : path === 'operator/authoritative-closure.json' ? 'closure' :
      path.startsWith('private-data/reports/images/') ? 'screenshot' : 'evidence';
    if (!KINDS.has(kind)) fail('payload_file_kind_invalid');
    fileRows.push({ path, kind, ...(await hashFile(resolve(sourceRoot, path))) });
  }
  if (fileRows.filter((row) => row.kind === 'database').length !== 1 ||
      fileRows.some((row) => row.kind === 'screenshot' && row.bytes < 1)) fail('payload_set_invalid');
  const manifest = Buffer.from(`${JSON.stringify({ schemaVersion: MANIFEST_SCHEMA, checkpointId, files: fileRows })}\n`, 'utf8');
  if (manifest.length > MAX_MANIFEST_BYTES) fail('manifest_too_large');
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad(checkpointId));
  let output;
  let created = false;
  let keyEnvelopeCreated = false;
  try {
    output = await open(outputPath, 'wx', 0o600);
    created = true;
    await writeAll(output, MAGIC);
    await writeAll(output, iv);
    const manifestLength = Buffer.alloc(4);
    manifestLength.writeUInt32BE(manifest.length);
    const processChunk = async (chunk) => {
      const encrypted = cipher.update(chunk);
      if (encrypted.length) await writeAll(output, encrypted);
    };
    await processChunk(manifestLength);
    await processChunk(manifest);
    for (const row of fileRows) {
      const path = resolve(sourceRoot, row.path);
      const before = await lstat(path);
      const streamedHash = createHash('sha256');
      let streamedBytes = 0;
      for await (const chunk of createReadStream(path)) {
        streamedHash.update(chunk);
        streamedBytes += chunk.length;
        await processChunk(chunk);
      }
      const after = await lstat(path);
      if (streamedBytes !== row.bytes || streamedHash.digest('hex') !== row.sha256 ||
          before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ino !== after.ino) fail('source_changed_during_seal');
    }
    const finalBytes = cipher.final();
    if (finalBytes.length) await writeAll(output, finalBytes);
    await writeAll(output, cipher.getAuthTag());
    await output.sync();
    await output.close();
    output = undefined;
    const wrappingKey = Buffer.from(key);
    let keyEnvelope;
    try { keyEnvelope = await protectKey({ checkpointId, key: wrappingKey }); }
    finally { wrappingKey.fill(0); }
    if (!Buffer.isBuffer(keyEnvelope) || keyEnvelope.length < 1) fail('key_envelope_invalid');
    const keyHandle = await open(keyPath, 'wx', 0o600);
    keyEnvelopeCreated = true;
    try { await keyHandle.writeFile(keyEnvelope); await keyHandle.sync(); } finally { await keyHandle.close(); }
    const encryptedInfo = await hashFile(outputPath);
    return {
      artifact: { path: 'checkpoint.bundle.enc', kind: 'sealed_bundle', ...encryptedInfo },
      payloadManifest: { schemaVersion: MANIFEST_SCHEMA, fileCount: fileRows.length,
        databaseFiles: 1, evidenceFiles: fileRows.filter((row) => row.kind === 'evidence').length,
        screenshotFiles: fileRows.filter((row) => row.kind === 'screenshot').length,
        payloadManifestSha256: sha256(manifest), files: fileRows },
      keyRecovery: { path: keyPath, envelopeSha256: sha256(keyEnvelope), outsideBundle: true },
    };
  } catch (error) {
    if (output) await output.close().catch(() => undefined);
    if (created) await rm(outputPath, { force: true }).catch(() => undefined);
    if (keyEnvelopeCreated) await rm(keyPath, { force: true }).catch(() => undefined);
    throw error;
  } finally { key.fill(0); iv.fill(0); }
}

async function readExactly(handle, offset, length) {
  const buffer = Buffer.alloc(length);
  let readTotal = 0;
  while (readTotal < length) {
    const { bytesRead } = await handle.read(buffer, readTotal, length - readTotal, offset + readTotal);
    if (!bytesRead) fail('payload_truncated');
    readTotal += bytesRead;
  }
  return buffer;
}

function validateManifest(value, checkpointId) {
  if (!value || value.schemaVersion !== MANIFEST_SCHEMA || value.checkpointId !== checkpointId || !Array.isArray(value.files) ||
      value.files.length < 1 || value.files.filter((row) => row?.kind === 'database').length !== 1) fail('manifest_invalid');
  const seen = new Set();
  for (const row of value.files) {
    safeRelative(row.path);
    if (!KINDS.has(row.kind) || !Number.isSafeInteger(row.bytes) || row.bytes < 0 || !HASH.test(row.sha256 ?? '') || seen.has(row.path)) fail('manifest_row_invalid');
    seen.add(row.path);
  }
  return value;
}

/** Authenticate before exposing any plaintext; extraction target must be fresh and private. */
export async function openSealedCheckpointPayload({ encryptedPath, expectedEncryptedSha256, expectedEncryptedBytes,
  bundleRoot, destinationRoot, checkpointId, externalKeyRecoveryPath, recoverKey }) {
  if (!isAbsolute(encryptedPath ?? '') || !isAbsolute(destinationRoot ?? '') || !isAbsolute(externalKeyRecoveryPath ?? '') ||
      !isAbsolute(bundleRoot ?? '') || typeof checkpointId !== 'string' || typeof recoverKey !== 'function' ||
      !HASH.test(expectedEncryptedSha256 ?? '') || !Number.isSafeInteger(expectedEncryptedBytes) || expectedEncryptedBytes < 1) fail('input_invalid');
  const encryptedPathInfo = await assertPathChain(encryptedPath);
  const encrypted = encryptedPathInfo.canonicalPath;
  const bundle = await assertPathChain(bundleRoot);
  const outputRoot = resolve(destinationRoot);
  const keyPath = await assertPathChain(externalKeyRecoveryPath);
  if (!bundle.exists || !within(bundle.canonicalPath, encrypted) || within(bundle.canonicalPath, keyPath.canonicalPath) ||
      outputRoot === encrypted || within(encrypted, outputRoot) || within(outputRoot, encrypted) || keyPath.canonicalPath === encrypted) fail('path_overlap');
  const envelopeInfo = await lstat(keyPath.canonicalPath);
  if (process.platform !== 'win32' && (envelopeInfo.mode & 0o077) !== 0) fail('key_envelope_permissions');
  const outputParent = dirname(outputRoot);
  await assertPathChain(outputParent);
  await assertPathChain(outputRoot, { allowMissingFinal: true });
  const encryptedDigest = await hashFile(encrypted);
  if (encryptedDigest.sha256 !== expectedEncryptedSha256 || encryptedDigest.bytes !== expectedEncryptedBytes) fail('ciphertext_integrity');
  const keyEnvelope = await readFile(keyPath.canonicalPath);
  const returnedKey = await recoverKey({ checkpointId, envelope: keyEnvelope, externalKeyRecoveryPath: keyPath.canonicalPath });
  const key = Buffer.isBuffer(returnedKey) ? Buffer.from(returnedKey) : null;
  if (Buffer.isBuffer(returnedKey) && returnedKey !== key) returnedKey.fill(0);
  try { validateKey(key); } catch (error) { if (Buffer.isBuffer(key)) key.fill(0); throw error; }
  const tempRoot = resolve(outputParent, `.bpc-unseal-${checkpointId}-${randomBytes(6).toString('hex')}`);
  const plainPath = resolve(tempRoot, 'authenticated-payload.bin');
  let tempCreated = false;
  let outputCreated = false;
  let manifest;
  let payloadManifestSha256;
  try {
    const info = await stat(encrypted);
    const headerLength = MAGIC.length + 12;
    if (info.size < headerLength + 16) fail('ciphertext_truncated');
    const headerHandle = await open(encrypted, 'r');
    let observedMagic;
    let iv;
    let tag;
    try {
      observedMagic = await readExactly(headerHandle, 0, MAGIC.length);
      iv = await readExactly(headerHandle, MAGIC.length, 12);
      tag = await readExactly(headerHandle, info.size - 16, 16);
    } finally { await headerHandle.close(); }
    if (!observedMagic.equals(MAGIC)) fail('ciphertext_format_invalid');
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(aad(checkpointId));
    decipher.setAuthTag(tag);
    await mkdir(tempRoot, { recursive: false, mode: 0o700 });
    tempCreated = true;
    const input = createReadStream(encrypted, { start: headerLength, end: info.size - 17 });
    const output = createWriteStream(plainPath, { flags: 'wx', mode: 0o600 });
    await pipeline(input, decipher, output);

    await mkdir(outputRoot, { recursive: false, mode: 0o700 });
    outputCreated = true;
    const payloadHandle = await open(plainPath, 'r');
    try {
      const lengthBytes = await readExactly(payloadHandle, 0, 4);
      const manifestLength = lengthBytes.readUInt32BE(0);
      if (manifestLength < 2 || manifestLength > MAX_MANIFEST_BYTES) fail('manifest_length_invalid');
      const manifestBytes = await readExactly(payloadHandle, 4, manifestLength);
      try { manifest = JSON.parse(manifestBytes.toString('utf8')); } catch { fail('manifest_invalid'); }
      validateManifest(manifest, checkpointId);
      payloadManifestSha256 = sha256(manifestBytes);
      let offset = 4 + manifestLength;
      for (const row of manifest.files) {
        const target = resolve(outputRoot, ...safeRelative(row.path).split('/'));
        if (!within(outputRoot, target) || target === outputRoot) fail('extraction_path_escape');
        const parent = resolve(target, '..');
        await mkdir(parent, { recursive: true, mode: 0o700 });
        const handle = await open(target, 'wx', 0o600);
        const hash = createHash('sha256');
        let copied = 0;
        try {
          if (row.bytes > 0) {
            for await (const chunk of payloadHandle.createReadStream({ start: offset, end: offset + row.bytes - 1, autoClose: false })) {
              hash.update(chunk); copied += chunk.length; await writeAll(handle, chunk);
            }
          }
          await handle.sync();
        } finally { await handle.close(); }
        if (copied !== row.bytes || hash.digest('hex') !== row.sha256) fail('payload_file_integrity');
        offset += row.bytes;
      }
      const plainInfo = await stat(plainPath);
      if (offset !== plainInfo.size) fail('payload_trailing_bytes');
    } finally { await payloadHandle.close(); }
    await rm(tempRoot, { recursive: true, force: false });
    return { status: 'authenticated', destinationRoot: outputRoot, payloadManifestSha256,
      manifest, extractedFileCount: manifest.files.length };
  } catch (error) {
    if (outputCreated) await rm(outputRoot, { recursive: true, force: true }).catch(() => undefined);
    if (tempCreated) await rm(tempRoot, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  } finally { key.fill(0); }
}
