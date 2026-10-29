import { createCipheriv, createDecipheriv, createHash, generateKeyPairSync, privateDecrypt, publicEncrypt, randomBytes, constants } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const SCHEMA = 'beta-backup-recovery-envelope/v1';
const HASH = /^[0-9a-f]{64}$/;

function fail(code) { throw new Error(`beta_backup_recovery_${code}`); }
function aad(checkpointId) { return Buffer.from(`${SCHEMA}\n${checkpointId}`, 'ascii'); }
function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

function validateSecrets(secrets) {
  const keys = ['authSecret', 'bonusCodeVerifierSecret', 'googleClientId', 'googleClientSecret'];
  if (!secrets || typeof secrets !== 'object' || Array.isArray(secrets) ||
      keys.some((key) => typeof secrets[key] !== 'string' || secrets[key].length < 16)) fail('runtime_secrets_invalid');
  return Object.fromEntries(keys.map((key) => [key, secrets[key]]));
}

/** Hybrid-encrypt the bundle key and runtime recovery secrets to the operator's public key. */
export async function protectRecoveryMaterial({ checkpointId, bundleKey, runtimeSecrets, publicKeyPath }) {
  if (typeof checkpointId !== 'string' || !/^[0-9a-f-]{36}$/i.test(checkpointId) ||
      !Buffer.isBuffer(bundleKey) || bundleKey.length !== 32 || typeof publicKeyPath !== 'string') fail('input_invalid');
  let publicKey;
  try { publicKey = await readFile(publicKeyPath); } catch { fail('operator_public_key_missing'); }
  const contentKey = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', contentKey, iv);
  cipher.setAAD(aad(checkpointId));
  const body = Buffer.from(JSON.stringify({ schemaVersion: SCHEMA, checkpointId,
    bundleKeyBase64: bundleKey.toString('base64'), runtimeSecrets: validateSecrets(runtimeSecrets) }), 'utf8');
  try {
    const ciphertext = Buffer.concat([cipher.update(body), cipher.final()]);
    const envelope = {
      schemaVersion: SCHEMA, checkpointId, algorithm: 'RSA-OAEP-SHA256+A256GCM',
      encryptedContentKeyBase64: publicEncrypt({ key: publicKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING }, contentKey).toString('base64'),
      ivBase64: iv.toString('base64'), ciphertextBase64: ciphertext.toString('base64'),
      tagBase64: cipher.getAuthTag().toString('base64'),
    };
    return Buffer.from(`${JSON.stringify(envelope)}\n`, 'utf8');
  } finally { contentKey.fill(0); iv.fill(0); body.fill(0); }
}

/** Recover material returned by the DPAPI host bridge; the private key never enters the runtime container. */
export function decryptBridgedRecoveryMaterial({ checkpointId, encryptedMaterial, ephemeralPrivateKey }) {
  if (typeof checkpointId !== 'string' || !Buffer.isBuffer(encryptedMaterial) || !ephemeralPrivateKey) fail('bridge_input_invalid');
  let contentKey;
  let content;
  try {
    const response = JSON.parse(encryptedMaterial.toString('utf8'));
    if (response.schemaVersion !== 'beta-backup-host-recovery-response/v1' || response.checkpointId !== checkpointId) fail('recovery_response_invalid');
    contentKey = privateDecrypt({ key: ephemeralPrivateKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING },
      Buffer.from(response.encryptedContentKeyBase64 ?? '', 'base64'));
    if (contentKey.length !== 32) fail('recovery_response_key_invalid');
    const decipher = createDecipheriv('aes-256-gcm', contentKey, Buffer.from(response.ivBase64 ?? '', 'base64'));
    decipher.setAAD(Buffer.from(`beta-backup-host-recovery-response/v1\n${checkpointId}`, 'ascii'));
    decipher.setAuthTag(Buffer.from(response.tagBase64 ?? '', 'base64'));
    content = Buffer.concat([decipher.update(Buffer.from(response.ciphertextBase64 ?? '', 'base64')), decipher.final()]);
    const parsed = JSON.parse(content.toString('utf8'));
    if (parsed.schemaVersion !== SCHEMA || parsed.checkpointId !== checkpointId ||
        typeof parsed.bundleKeyBase64 !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(parsed.bundleKeyBase64)) fail('recovered_material_invalid');
    const bundleKey = Buffer.from(parsed.bundleKeyBase64, 'base64');
    if (bundleKey.length !== 32 || bundleKey.toString('base64') !== parsed.bundleKeyBase64) fail('recovered_bundle_key_invalid');
    return { bundleKey, runtimeSecrets: validateSecrets(parsed.runtimeSecrets) };
  } catch (error) {
    if (String(error?.message ?? '').startsWith('beta_backup_recovery_')) throw error;
    fail('recovery_decryption_failed');
  } finally { if (contentKey) contentKey.fill(0); if (content) content.fill(0); }
}

/** Create an ephemeral response keypair for one host recovery request; private material stays in memory. */
export function createEphemeralRecoveryKeyPair() {
  return generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 0x10001 });
}

/** Return ciphertext for a one-time runtime public key. Used by the host PowerShell DPAPI bridge. */
export function encryptRecoveryMaterialForRuntime({ runtimePublicKey, checkpointId, envelopeBytes, operatorPrivateKey }) {
  if (!runtimePublicKey || typeof checkpointId !== 'string' || !Buffer.isBuffer(envelopeBytes) || !Buffer.isBuffer(operatorPrivateKey)) fail('host_bridge_input_invalid');
  let operatorContentKey;
  let plaintext;
  let responseKey;
  let iv;
  try {
    const envelope = JSON.parse(envelopeBytes.toString('utf8'));
    if (envelope.schemaVersion !== SCHEMA || envelope.checkpointId !== checkpointId || envelope.algorithm !== 'RSA-OAEP-SHA256+A256GCM') fail('envelope_invalid');
    operatorContentKey = privateDecrypt({ key: operatorPrivateKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING }, Buffer.from(envelope.encryptedContentKeyBase64, 'base64'));
    if (operatorContentKey.length !== 32) fail('envelope_key_invalid');
    const decipher = createDecipheriv('aes-256-gcm', operatorContentKey, Buffer.from(envelope.ivBase64, 'base64'));
    decipher.setAAD(aad(checkpointId));
    decipher.setAuthTag(Buffer.from(envelope.tagBase64, 'base64'));
    plaintext = Buffer.concat([decipher.update(Buffer.from(envelope.ciphertextBase64, 'base64')), decipher.final()]);
    responseKey = randomBytes(32);
    iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', responseKey, iv);
    cipher.setAAD(Buffer.from(`beta-backup-host-recovery-response/v1\n${checkpointId}`, 'ascii'));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const response = { schemaVersion: 'beta-backup-host-recovery-response/v1', checkpointId,
      encryptedContentKeyBase64: publicEncrypt({ key: runtimePublicKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING }, responseKey).toString('base64'),
      ivBase64: iv.toString('base64'), ciphertextBase64: ciphertext.toString('base64'), tagBase64: cipher.getAuthTag().toString('base64') };
    return { outputCiphertext: Buffer.from(`${JSON.stringify(response)}\n`, 'utf8'), materialSha256: sha256(plaintext) };
  } catch (error) {
    if (String(error?.message ?? '').startsWith('beta_backup_recovery_')) throw error;
    fail('operator_recovery_failed');
  } finally { if (operatorContentKey) operatorContentKey.fill(0); if (plaintext) plaintext.fill(0); if (responseKey) responseKey.fill(0); if (iv) iv.fill(0); }
}
