import assert from 'node:assert/strict';
import test from 'node:test';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createEphemeralRecoveryKeyPair, decryptBridgedRecoveryMaterial,
  encryptRecoveryMaterialForRuntime, protectRecoveryMaterial } from './beta-backup-recovery-envelope.mjs';

test('operator envelope and host response bind checkpoint identity and keep recovery material encrypted', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'bpc-recovery-envelope-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const checkpointId = randomUUID();
  const operator = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 });
  const publicPath = join(root, 'operator-public.pem');
  const publicPem = operator.publicKey.export({ type: 'spki', format: 'pem' });
  const privatePem = Buffer.from(operator.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  await writeFile(publicPath, publicPem, { mode: 0o600 });
  const bundleKey = Buffer.from(Array.from({ length: 32 }, (_, index) => index + 1));
  const runtimeSecrets = { authSecret: 'synthetic-auth-secret-0123456789',
    bonusCodeVerifierSecret: 'synthetic-bonus-secret-0123456789',
    googleClientId: 'synthetic-client-id-0123456789', googleClientSecret: 'synthetic-client-secret-0123456789' };
  const envelope = await protectRecoveryMaterial({ checkpointId, bundleKey, runtimeSecrets, publicKeyPath: publicPath });
  for (const secret of Object.values(runtimeSecrets)) assert.equal(envelope.includes(Buffer.from(secret)), false);
  assert.equal(envelope.includes(Buffer.from(bundleKey.toString('base64'))), false);

  const ephemeral = createEphemeralRecoveryKeyPair();
  const bridge = encryptRecoveryMaterialForRuntime({ runtimePublicKey: ephemeral.publicKey, checkpointId,
    envelopeBytes: envelope, operatorPrivateKey: privatePem });
  for (const secret of Object.values(runtimeSecrets)) assert.equal(bridge.outputCiphertext.includes(Buffer.from(secret)), false);
  assert.equal(bridge.outputCiphertext.includes(Buffer.from(bundleKey.toString('base64'))), false);
  const recovered = decryptBridgedRecoveryMaterial({ checkpointId, encryptedMaterial: bridge.outputCiphertext,
    ephemeralPrivateKey: ephemeral.privateKey });
  assert.deepEqual(recovered.bundleKey, bundleKey);
  assert.deepEqual(recovered.runtimeSecrets, runtimeSecrets);

  const tamperedEnvelopeValue = JSON.parse(envelope.toString('utf8'));
  const ciphertext = Buffer.from(tamperedEnvelopeValue.ciphertextBase64, 'base64');
  ciphertext[0] ^= 0x01;
  tamperedEnvelopeValue.ciphertextBase64 = ciphertext.toString('base64');
  const tamperedEnvelope = Buffer.from(`${JSON.stringify(tamperedEnvelopeValue)}\n`);
  assert.throws(() => encryptRecoveryMaterialForRuntime({ runtimePublicKey: ephemeral.publicKey, checkpointId,
    envelopeBytes: tamperedEnvelope, operatorPrivateKey: privatePem }), /operator_recovery_failed/);

  const tamperedResponse = JSON.parse(bridge.outputCiphertext.toString('utf8'));
  const responseCiphertext = Buffer.from(tamperedResponse.ciphertextBase64, 'base64');
  responseCiphertext[0] ^= 0x01;
  tamperedResponse.ciphertextBase64 = responseCiphertext.toString('base64');
  assert.throws(() => decryptBridgedRecoveryMaterial({ checkpointId,
    encryptedMaterial: Buffer.from(JSON.stringify(tamperedResponse)), ephemeralPrivateKey: ephemeral.privateKey }),
  /recovery_decryption_failed/);
  bundleKey.fill(0);
  recovered.bundleKey.fill(0);
  privatePem.fill(0);
});
