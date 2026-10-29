import { readFile, writeFile, chmod, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';

// AICODE-NOTE: This provisions only the existing synthetic local BEF coordinator.
// Model actions must come through the participant MCP connection; no reference actor runs here.
export async function prepareGoogleLocalCoordinator(repoRoot, env) {
  if (repoRoot !== '/workspace' || process.platform !== 'linux') throw new Error('pinned_linux_runtime_required');
  const manifestBytes = await readFile(resolve(repoRoot, 'infrastructure/benchmark-environment/manifest.json'));
  const manifest = JSON.parse(manifestBytes);
  const manifestSha256 = createHash('sha256').update(manifestBytes).digest('hex');
  if (manifest.local?.identity !== 'private-anvil-fork' || manifest.local.chainId !== 8453 || !Array.isArray(manifest.x402?.catalog)) throw new Error('synthetic_manifest_required');
  const directory = resolve(repoRoot, '.local/owner-identity/coordinator-runtime');
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(directory, 0o700);
  const key = (await readFile('/run/secrets/bef_admin_key','utf8')).trim();
  if (key.length < 16 || key.length > 4096 || /[\r\n\0]/.test(key)) throw new Error('admin_key_invalid');
  await writeFile(resolve(directory,'bef-admin-key'),key+'\n',{ mode:0o600 });
  await chmod(resolve(directory,'bef-admin-key'),0o600);
  const local = manifest.local;
  const x402Policy = { manifestSha256, scheme:manifest.x402.scheme, network:manifest.x402.network,
    asset:manifest.x402.asset, assetTransferMethod:manifest.x402.assetTransferMethod,
    eip712Domain:manifest.x402.eip712Domain,maxTimeoutSeconds:manifest.x402.maxTimeoutSeconds??300,
    sdkVersions:{core:manifest.x402.version,evm:local.versions.x402Evm,viem:local.versions.viem},
    localAnvil:{identity:local.identity,chainId:local.chainId,anvilVersion:local.anvilVersion,
      executionNetwork:local.executionNetwork,hardFork:local.hardfork,forkBlockNumber:local.forkBlock,forkBlockHash:manifest.source.blockHash},
    resources:manifest.x402.catalog.map(item=>({resourceId:item.resourceId,resourceSha256:item.resourceSha256,
      contentType:item.contentType,...(item.dataType?{dataType:item.dataType}:{}),...(item.schema?{schema:item.schema}:{}),
      ...(item.provenance?{provenance:item.provenance}:{}),offers:item.offers})) };
  const port = (name,fallback) => {
    const value = Number(env[name] ?? fallback);
    if (!Number.isSafeInteger(value) || value<1 || value>65535) throw new Error('local_port_invalid');
    return value;
  };
  const config = { schemaVersion:'local-bef-task-coordinator-config/v1',adminKeyFile:'secrets/coordinator-runtime/bef-admin-key',
    sourceRpcUrl:'http://host.docker.internal:'+port('BEF_SOURCE_PROXY_HOST_PORT',18544),
    observationPipeline:{schemaVersion:'local-bef-training-observation/v1',database:{host:'host.docker.internal',
      port:port('BEF_DATABASE_HOST_PORT',56432),database:'bef'},passwordFile:'/run/secrets/bef_database_observer_password'},
    environments:[{envId:'bef-env-a',apiBaseUrl:'http://host.docker.internal:'+port('BEF_API_HOST_PORT',38783),
      observerRpcUrl:'http://host.docker.internal:'+port('BEF_LOCAL_RPC_A_HOST_PORT',18545),x402Policy}] };
  const path = resolve(directory,'config.json');
  await writeFile(path,JSON.stringify(config)+'\n',{mode:0o600}); await chmod(path,0o600);
  return '.local/owner-identity/coordinator-runtime/config.json';
}
