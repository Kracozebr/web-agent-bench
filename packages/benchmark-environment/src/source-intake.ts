import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { encodeFunctionData, keccak256, parseAbi } from 'viem';
import { readRuntimeValue } from './config.js';
import { loadManifest } from './manifest.js';

const abi = {
  factory: parseAbi(['function getPool(address,address,uint24) view returns (address)']),
  pool: parseAbi([
    'function token0() view returns (address)',
    'function token1() view returns (address)',
    'function fee() view returns (uint24)',
    'function liquidity() view returns (uint128)',
    'function slot0() view returns (uint160,int24,uint16,uint16,uint16,uint8,bool)',
  ]),
  erc20: parseAbi(['function balanceOf(address) view returns (uint256)']),
};

type JsonRpcRequest = { jsonrpc: '2.0'; id: number; method: string; params: unknown[] };
type JsonRpcResponse = { jsonrpc: '2.0'; id: number; result?: unknown; error?: { code: number; message: string } };

async function main(): Promise<void> {
  const { manifest } = await loadManifest();
  const rawUrl = readRuntimeValue('BEF_SOURCE_RPC_URL');
  let endpoint: URL;
  try {
    endpoint = new URL(rawUrl);
    if (!['https:', 'http:'].includes(endpoint.protocol)) throw new Error();
  } catch {
    throw new Error('BEF_SOURCE_RPC_URL must be an HTTP(S) RPC endpoint');
  }

  const rpcRecords: Array<{ request: JsonRpcRequest; response: JsonRpcResponse }> = [];
  let nextId = 1;
  const call = async (method: string, params: unknown[]): Promise<unknown> => {
    const request: JsonRpcRequest = { jsonrpc: '2.0', id: nextId++, method, params };
    let response: JsonRpcResponse;
    try {
      const result = await fetch(rawUrl, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify(request), signal: AbortSignal.timeout(15_000),
      });
      if (!result.ok) throw new Error();
      response = await result.json() as JsonRpcResponse;
    } catch {
      throw new Error(`Read-only source intake failed at request ${request.id}`);
    }
    if (response.id !== request.id || response.error || !Object.hasOwn(response, 'result')) throw new Error(`Read-only source intake returned an unusable response at request ${request.id}`);
    rpcRecords.push({ request, response });
    return response.result;
  };
  const at = manifest.source.blockNumber;
  const contracts = manifest.contracts;
  const chainId = await call('eth_chainId', []) as string;
  const block = await call('eth_getBlockByNumber', [at, false]) as Record<string, unknown>;
  if (chainId !== '0x2105' || String(block.number).toLowerCase() !== at.toLowerCase() || String(block.hash).toLowerCase() !== manifest.source.blockHash.toLowerCase() || String(block.timestamp).toLowerCase() !== manifest.source.blockTimestamp.toLowerCase() || BigInt(String(block.baseFeePerGas)) !== BigInt(manifest.feePolicy.baseFeeWei)) {
    throw new Error('Source chain or pinned block identity differs from manifest');
  }

  const codeRows = await Promise.all(Object.entries({
    usdc: contracts.usdc.address,
    weth: contracts.weth.address,
    factory: contracts.factory.address,
    router: contracts.swapRouter02.address,
    quoter: contracts.quoterV2.address,
    pool: contracts.pool.address,
  }).map(async ([name, contractAddress]) => [name, await call('eth_getCode', [contractAddress, at])] as const));
  const code = Object.fromEntries(codeRows) as Record<string, `0x${string}`>;
  for (const [name, expected] of Object.entries({
    usdc: contracts.usdc.proxyCodeHash,
    weth: contracts.weth.codeHash,
    factory: contracts.factory.codeHash,
    router: contracts.swapRouter02.codeHash,
    quoter: contracts.quoterV2.codeHash,
    pool: contracts.pool.codeHash,
  })) {
    if (!code[name] || keccak256(code[name]).toLowerCase() !== expected.toLowerCase()) throw new Error(`Source contract code hash mismatch: ${name}`);
  }
  const poolFromFactory = await call('eth_call', [{ to: contracts.factory.address as `0x${string}`, data: encodeFunctionData({ abi: abi.factory, functionName: 'getPool', args: [contracts.weth.address as `0x${string}`, contracts.usdc.address as `0x${string}`, contracts.pool.fee] }) }, at]) as string;
  if (`0x${poolFromFactory.slice(-40)}`.toLowerCase() !== contracts.pool.address.toLowerCase()) throw new Error('Observed factory route does not match pinned pool');

  const [token0Raw, token1Raw, feeRaw, liquidityRaw, slot0Raw] = await Promise.all([
    call('eth_call', [{ to: contracts.pool.address, data: encodeFunctionData({ abi: abi.pool, functionName: 'token0' }) }, at]),
    call('eth_call', [{ to: contracts.pool.address, data: encodeFunctionData({ abi: abi.pool, functionName: 'token1' }) }, at]),
    call('eth_call', [{ to: contracts.pool.address, data: encodeFunctionData({ abi: abi.pool, functionName: 'fee' }) }, at]),
    call('eth_call', [{ to: contracts.pool.address, data: encodeFunctionData({ abi: abi.pool, functionName: 'liquidity' }) }, at]),
    call('eth_call', [{ to: contracts.pool.address, data: encodeFunctionData({ abi: abi.pool, functionName: 'slot0' }) }, at]),
  ]) as [string, string, string, string, string];
  const poolState = { token0: token0Raw, token1: token1Raw, fee: feeRaw, liquidity: liquidityRaw, slot0: slot0Raw };
  const word = (value: string, index: number) => `0x${value.slice(2 + index * 64, 2 + (index + 1) * 64)}`;
  if (`0x${poolState.token0.slice(-40)}`.toLowerCase() !== contracts.pool.token0.toLowerCase() ||
      `0x${poolState.token1.slice(-40)}`.toLowerCase() !== contracts.pool.token1.toLowerCase() ||
      BigInt(poolState.fee) !== BigInt(contracts.pool.fee) || BigInt(poolState.liquidity) === 0n ||
      word(poolState.slot0, 0).toLowerCase() !== contracts.pool.sqrtPriceX96AtSource.toLowerCase() ||
      BigInt(poolState.liquidity) !== BigInt(contracts.pool.liquidityAtSource)) {
    throw new Error('Pinned pool route, liquidity, or price differs from the source manifest');
  }

  const implementationSlot = await call('eth_getStorageAt', [contracts.usdc.address, contracts.usdc.implementationSlot, at]) as string;
  const implementationSlotRecord = rpcRecords.at(-1)!;
  if (`0x${implementationSlot.slice(-40)}`.toLowerCase() !== contracts.usdc.implementation.toLowerCase()) throw new Error('USDC proxy implementation slot does not match manifest');
  const implementationCode = await call('eth_getCode', [contracts.usdc.implementation, at]) as `0x${string}`;
  const implementationCodeRecord = rpcRecords.at(-1)!;
  if (keccak256(implementationCode).toLowerCase() !== contracts.usdc.implementationCodeHash.toLowerCase()) throw new Error('USDC implementation code hash does not match manifest');

  const fundingBalance = await call('eth_call', [{ to: contracts.usdc.address as `0x${string}`, data: encodeFunctionData({ abi: abi.erc20, functionName: 'balanceOf', args: [manifest.funding.donor as `0x${string}`] }) }, at]) as string;
  if (BigInt(fundingBalance) < BigInt(manifest.funding.maxUsdcUnitsPerGeneration)) throw new Error('Pinned USDC fixture donor cannot cover the declared private transfer');

  const sourceObservations = {
    blockNumber: at,
    blockHash: manifest.source.blockHash,
    blockTimestamp: manifest.source.blockTimestamp,
    boundary: 'read-only public Base RPC intake; no local execution',
    poolState,
    sourceRpc: endpoint.origin,
    chainId,
    sourceCalls: rpcRecords.length,
    contracts: Object.fromEntries(Object.entries(code).map(([name, bytecode]) => [name, {
      bytecodeSha256: createHash('sha256').update(bytecode).digest('hex'),
      bytecode,
      address: ({ usdc: contracts.usdc.address, weth: contracts.weth.address, factory: contracts.factory.address, router: contracts.swapRouter02.address, quoter: contracts.quoterV2.address, pool: contracts.pool.address } as Record<string, string>)[name],
      byteLength: (bytecode.length - 2) / 2,
    }])),
    observedAtUtc: new Date().toISOString(),
  };
  const fundingObservation = {
    blockNumber: at,
    privateForkFixtureMaxTransferUnits: Number(manifest.funding.maxUsdcUnitsPerGeneration),
    response: { jsonrpc: '2.0', id: nextId - 1, result: fundingBalance },
    donor: manifest.funding.donor,
    boundary: 'read-only source observations for private fork setup; source donor never impersonated externally',
    balanceUnits: BigInt(fundingBalance).toString(),
    request: rpcRecords.at(-1)!.request,
  };
  const implementationObservation = {
    request: implementationSlotRecord.request,
    response: implementationSlotRecord.response,
  };
  const implementationCodeObservation = {
    request: implementationCodeRecord.request,
    response: implementationCodeRecord.response,
  };

  const timeLabel = new Date().toISOString().replace(/[-:.]/g, '').replace('T', '-').replace('Z', 'Z');
  const outputRoot = resolve(process.cwd(), 'artifacts/runs', `bef-source-intake-${timeLabel}`);
  await mkdir(outputRoot, { recursive: false });
  const save = async (path: string, value: unknown) => {
    const target = join(outputRoot, path);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx' });
  };
  await save('source-observations.json', sourceObservations);
  await save('usdc-funding-observation.json', fundingObservation);
  await save('usdc-implementation-observation.json', implementationObservation);
  await save('usdc-implementation-code.json', implementationCodeObservation);
  for (const [index, record] of rpcRecords.entries()) await save(`rpc-${index + 1}.json`, record);
  const artifactList = ['source-observations.json', 'usdc-funding-observation.json', 'usdc-implementation-observation.json', 'usdc-implementation-code.json', ...rpcRecords.map((_, index) => `rpc-${index + 1}.json`)];
  const hashes = await Promise.all(artifactList.map(async (name) => ({ path: name, sha256: createHash('sha256').update(await readFile(join(outputRoot, name))).digest('hex') })));
  await save('intake-manifest.json', { schemaVersion: 'bef-source-intake/v1', sourceBlock: { number: at, hash: manifest.source.blockHash }, boundary: 'read-only source calls only; no external state writes', artifacts: hashes });
  process.stdout.write(`Verified ${rpcRecords.length} read-only source calls at the fixed Base block. Evidence: ${outputRoot}\n`);
}

main().catch(() => { process.stderr.write('Source intake blocked: configured RPC or pinned source observations failed validation.\n'); process.exitCode = 1; });
