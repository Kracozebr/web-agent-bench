import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { verifyBackupFiles } from './beta-backup-inventory.mjs';

// Operator-only read-only command. Database restore and access enablement are separate gates.
const [root, inventoryFile, closureFile] = process.argv.slice(2);
if (!root || !inventoryFile || !closureFile || process.argv.length !== 5) {
  process.stderr.write('Usage: node verify-beta-backup.mjs BUNDLE_ROOT INVENTORY_JSON AUTHORITATIVE_CLOSURE_JSON\n');
  process.exitCode = 2;
} else {
  try {
    const inventory = JSON.parse(await readFile(resolve(inventoryFile), 'utf8'));
    const closure = JSON.parse(await readFile(resolve(closureFile), 'utf8'));
    if (closure.schemaVersion !== 'beta-report-closure-state/v1' ||
        (closure.betaEndedAt !== null && typeof closure.betaEndedAt !== 'string') ||
        !/^[0-9a-f]{64}$/.test(closure.sourceEvidenceSha256 ?? '')) throw new Error('beta_backup_invalid_authoritative_closure');
    const result = await verifyBackupFiles(resolve(root), inventory, { authoritativeBetaEndedAt: closure.betaEndedAt });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    // Never echo arbitrary paths, parsed documents, SQL, credentials or file content on failure.
    const reason = error instanceof Error && /^beta_backup_[a-z_]+$/.test(error.message)
      ? error.message : 'beta_backup_verification_failed';
    process.stderr.write(`${reason}\n`);
    process.exitCode = 1;
  }
}
