import type { RuntimeManifest } from './manifest.js';

type JsonRpcResponse = { jsonrpc?: string; id?: number; result?: unknown; error?: { code?: number; message?: string } };

export async function adminRpc(rpcUrl: string, method: string, params: unknown[] = []): Promise<unknown> {
  const response = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new Error('Private local RPC request failed');
  const body = await response.json() as JsonRpcResponse;
  if (body.id !== 1 || body.error || !Object.hasOwn(body, 'result')) throw new Error('Private local RPC returned no confirmed result');
  return body.result;
}

export async function setAnvilBalance(rpcUrl: string, address: `0x${string}`, value: string): Promise<void> {
  const result = await adminRpc(rpcUrl, 'anvil_setBalance', [address, value]);
  if (result !== null && result !== true) throw new Error('Private Anvil balance setter returned an unexpected acknowledgement');
  const observed = await adminRpc(rpcUrl, 'eth_getBalance', [address, 'latest']);
  if (typeof observed !== 'string' || !/^0x[0-9a-f]+$/i.test(observed) || BigInt(observed) !== BigInt(value)) {
    throw new Error('Private Anvil balance did not equal the declared fixture value');
  }
}

function normalizeVersion(value: string): string {
  return value.toLowerCase().replaceAll('_', '-');
}

export type AnvilIdentity = {
  clientVersion: string;
  chainId: string;
  executionNetwork: string;
  hardFork: string;
  forkBlockNumber: string;
  forkBlockHash: string;
};

export async function assertAnvilIdentity(rpcUrl: string, manifest: RuntimeManifest): Promise<AnvilIdentity> {
  const clientVersion = await adminRpc(rpcUrl, 'web3_clientVersion') as string;
  const expectedVersionNeedle = 'anvil/v' + manifest.local.anvilVersion;
  if (typeof clientVersion !== 'string' || !normalizeVersion(clientVersion).includes(normalizeVersion(expectedVersionNeedle))) {
    throw new Error('Private signer RPC is not the manifest-pinned Anvil build');
  }
  const nodeInfo = await adminRpc(rpcUrl, 'anvil_nodeInfo');
  if (!nodeInfo || typeof nodeInfo !== 'object' || Array.isArray(nodeInfo)) throw new Error('Anvil node identity metadata is unavailable');
  const info = nodeInfo as Record<string, unknown>;
  const executionNetwork = info.network;
  const hardFork = info.hardFork;
  if (typeof executionNetwork !== 'string' || executionNetwork.toLowerCase() !== manifest.local.executionNetwork
      || typeof hardFork !== 'string' || hardFork.toLowerCase() !== manifest.local.hardfork) {
    throw new Error('Private Anvil execution network or hard fork differs from the manifest');
  }
  const fork = info.forkConfig;
  if (!fork || typeof fork !== 'object' || Array.isArray(fork)) throw new Error('Anvil node is not a configured private fork');
  const forkConfig = fork as Record<string, unknown>;
  const reportedForkBlock = forkConfig.forkBlockNumber ?? forkConfig.blockNumber ?? info.forkBlockNumber;
  if (reportedForkBlock === undefined || BigInt(String(reportedForkBlock)) !== BigInt(manifest.local.forkBlock)) {
    throw new Error('Anvil fork block differs from the manifest source pin');
  }
  const chainIdValue = await adminRpc(rpcUrl, 'eth_chainId') as string;
  if (chainIdValue.toLowerCase() !== '0x' + manifest.local.chainId.toString(16)) {
    throw new Error('Private Anvil chain id differs from the manifest');
  }
  const block = await adminRpc(rpcUrl, 'eth_getBlockByNumber', [manifest.local.forkBlock, false]) as Record<string, unknown> | null;
  if (!block || typeof block.hash !== 'string' || block.hash.toLowerCase() !== manifest.source.blockHash.toLowerCase() ||
      String(block.number).toLowerCase() !== manifest.source.blockNumber.toLowerCase()) {
    throw new Error('Private Anvil fork does not expose the exact manifest-pinned source block');
  }
  return {
    clientVersion,
    chainId: chainIdValue,
    executionNetwork,
    hardFork,
    forkBlockNumber: String(block.number),
    forkBlockHash: String(block.hash),
  };
}

export async function resetAnvilFork(rpcUrl: string, sourceProxyUrl: string, manifest: RuntimeManifest): Promise<AnvilIdentity> {
  await assertAnvilIdentity(rpcUrl, manifest);
  const params = [{
    forking: {
      jsonRpcUrl: sourceProxyUrl,
      blockNumber: Number(BigInt(manifest.local.forkBlock)),
    },
  }];
  const result = await adminRpc(rpcUrl, 'anvil_reset', params);
  if (result !== null && result !== true) throw new Error('Private Anvil fork reset returned an unexpected acknowledgement');
  return assertAnvilIdentity(rpcUrl, manifest);
}

