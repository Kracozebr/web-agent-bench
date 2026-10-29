import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { sealCheckpointPayload, openSealedCheckpointPayload } from './beta-backup-sealed-bundle.mjs';

test('sealed checkpoint keeps DB, evidence, closure, and screenshots opaque until authenticated restore', { timeout: 30_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'bpc-sealed-bundle-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const payloadRoot = join(root, 'payload');
  const bundleRoot = join(root, 'checkpoint');
  const keyRoot = join(root, 'operator');
  await mkdir(join(payloadRoot, 'evidence'), { recursive: true });
  await mkdir(join(payloadRoot, 'operator'), { recursive: true });
  await mkdir(join(payloadRoot, 'private-data', 'reports', 'images'), { recursive: true });
  await mkdir(bundleRoot);
  await mkdir(keyRoot);
  const inputs = [
    ['database.dump', 'synthetic database dump payload'],
    ['evidence/source.json', 'synthetic evidence payload'],
    ['operator/authoritative-closure.json', 'synthetic closure payload'],
    ['private-data/reports/images/10000000-0000-4000-8000-000000000001.webp', 'synthetic screenshot payload'],
  ];
  for (const [path, body] of inputs) await writeFile(join(payloadRoot, ...path.split('/')), body);
  const checkpointId = randomUUID();
  const encryptedPath = join(bundleRoot, 'checkpoint.bundle.enc');
  const externalKeyRecoveryPath = join(keyRoot, `${checkpointId}.envelope`);
  let recoveredKey;
  const sealed = await sealCheckpointPayload({ payloadRoot, bundleRoot, encryptedPath, checkpointId, externalKeyRecoveryPath,
    protectKey: async ({ key }) => { recoveredKey = Buffer.from(key); return Buffer.from('opaque synthetic recovery envelope'); } });
  const encryptedBytes = await readFile(encryptedPath);
  for (const [, body] of inputs) assert.equal(encryptedBytes.includes(Buffer.from(body)), false);
  assert.equal(sealed.payloadManifest.screenshotFiles, 1);
  assert.equal(sealed.keyRecovery.outsideBundle, true);

  const destinationRoot = join(root, 'restored-payload');
  const opened = await openSealedCheckpointPayload({ encryptedPath, expectedEncryptedSha256: sealed.artifact.sha256,
    expectedEncryptedBytes: sealed.artifact.bytes, bundleRoot, destinationRoot, checkpointId, externalKeyRecoveryPath,
    recoverKey: async () => Buffer.from(recoveredKey) });
  assert.equal(opened.status, 'authenticated');
  assert.equal(opened.extractedFileCount, inputs.length);
  for (const [path, body] of inputs) assert.equal(await readFile(join(destinationRoot, ...path.split('/')), 'utf8'), body);

  const tamperedPath = join(bundleRoot, 'tampered.bundle.enc');
  const tampered = Buffer.from(encryptedBytes);
  tampered[tampered.length - 1] ^= 0x01;
  await writeFile(tamperedPath, tampered);
  const tamperedHash = createHash('sha256').update(tampered).digest('hex');
  const rejectedOutput = join(root, 'must-not-extract');
  await assert.rejects(openSealedCheckpointPayload({ encryptedPath: tamperedPath, expectedEncryptedSha256: tamperedHash,
    expectedEncryptedBytes: tampered.length, bundleRoot, destinationRoot: rejectedOutput, checkpointId, externalKeyRecoveryPath,
    recoverKey: async () => Buffer.from(recoveredKey) }));
  await assert.rejects(readFile(rejectedOutput));
  recoveredKey.fill(0);
});
