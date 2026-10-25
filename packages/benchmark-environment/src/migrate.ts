import { readRuntimeValue } from './config.js';
import { ensureSchema, poolFor, setupRuntimeRoles } from './db.js';
import { loadManifest } from './manifest.js';

async function main(): Promise<void> {
  const connectionString = readRuntimeValue('BEF_DATABASE_OWNER_URL', 1);
  const { manifest } = await loadManifest();
  const databaseUrl = new URL(connectionString);
  if (!['postgres:', 'postgresql:'].includes(databaseUrl.protocol)
    || databaseUrl.hostname !== manifest.local.databaseHost
    || decodeURIComponent(databaseUrl.username) !== 'bef_owner'
    || databaseUrl.pathname !== '/bef'
    || databaseUrl.search || databaseUrl.hash) {
    throw new Error('BEF_DATABASE_OWNER_URL must target the manifest-declared local PostgreSQL owner database');
  }
  const apiPassword = readRuntimeValue('BEF_DATABASE_API_PASSWORD', 32);
  const observerPassword = readRuntimeValue('BEF_DATABASE_OBSERVER_PASSWORD', 32);
  const pool = poolFor(connectionString);
  try {
    await ensureSchema(pool);
    await setupRuntimeRoles(pool, apiPassword, observerPassword);
    process.stdout.write('BEF PostgreSQL migrations and least-privilege roles are ready.\n');
  } finally {
    await pool.end();
  }
}

main().catch(() => {
  process.stderr.write('BEF PostgreSQL migration failed; runtime remains blocked.\n');
  process.exitCode = 1;
});
