import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { randomUUID, createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { planU1LocalAllocation } from '../../packages/benchmark-environment/dist/probe/task-u1-objective.js';
const require = createRequire(new URL('../../packages/benchmark-environment/package.json', import.meta.url));
const { encodeFunctionData, parseAbi, decodeFunctionResult } = require('viem');
if (process.platform !== 'linux' || process.cwd() !== '/workspace') throw new Error('Docker required');
const bytes = await readFile('infrastructure/benchmark-environment/manifest.json');
const m = JSON.parse(bytes);
const records = [];
async function rpc(method, params) {
  const request = { jsonrpc: '2.0', id: 1, method, params };
  const response = await fetch('http://host.docker.internal:18545', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(request),
    signal: AbortSignal.timeout(15000),
  });
  const body = await response.json();
  records.push({ request, httpStatus: response.status, response: body });
  if (!response.ok || body.error || body.result == null) throw new Error('local readonly quote unavailable');
  return body.result;
}
if (BigInt(await rpc('eth_chainId', [])) !== BigInt(m.local.chainId)) throw new Error('wrong local chain');
const block = await rpc('eth_getBlockByNumber', [m.local.forkBlock, false]);
if (block.hash !== m.source.blockHash) throw new Error('wrong local fork');
const abi = parseAbi(['function quoteExactInputSingle((address tokenIn,address tokenOut,uint256 amountIn,uint24 fee,uint160 sqrtPriceLimitX96) params) returns (uint256 amountOut,uint160 sqrtPriceX96After,uint32 initializedTicksCrossed,uint256 gasEstimate)']);
const amount = 1500000n;
const data = encodeFunctionData({ abi, functionName: 'quoteExactInputSingle', args: [{
  tokenIn: m.contracts.usdc.address, tokenOut: m.contracts.weth.address, amountIn: amount, fee: 3000, sqrtPriceLimitX96: 0n,
}] });
const result = await rpc('eth_call', [{ to: m.contracts.quoterV2.address, data }, m.local.forkBlock]);
const [output] = decodeFunctionResult({ abi, functionName: 'quoteExactInputSingle', data: result });
const minimum = output * BigInt(10000 - m.swap.maxSlippageBps) / 10000n;
// Fixed action count/gas ceilings: two transfers, approval, swap, unwrap, cleanup.
const maximumGas = 1000000n * (BigInt(m.feePolicy.baseFeeWei) + BigInt(m.feePolicy.priorityFeeWei));
const plan = planU1LocalAllocation({ initialUsdcUnits: m.funding.maxUsdcUnitsPerGeneration,
  initialNativeWei: m.funding.nativeEthWeiPerGeneration, paidServiceUnits: '225000', payoutUnits: ['100000', '200000'],
  swapInputUsdcUnits: amount.toString(), minimumNativeOutputWei: minimum.toString(), quotedNativeOutputWei: output.toString(),
  maximumParticipantGasWei: maximumGas.toString(), ethUsdcRateNumerator: m.feePolicy.ethUsdcRateNumerator,
  ethUsdcRateDenominator: m.feePolicy.ethUsdcRateDenominator });
const captureId = randomUUID(), directory = `artifacts/runs/bts-u1-planning/${captureId}`;
await mkdir(directory, { recursive: true });
const raw = Buffer.from(JSON.stringify({ schemaVersion: 'bts-u1-public-quote/v1',
  boundary: 'readonly local BEF Anvil proxy; no generation/reset/signing', records }, null, 2) + '\n');
await writeFile(`${directory}/public-quote.json`, raw, { flag: 'wx' });
await writeFile(`${directory}/manifest.json`, bytes, { flag: 'wx' });
const hash = (value) => createHash('sha256').update(value).digest('hex');
const capture = { captureId, classification: 'local_pre_execution_objective_plan_not_U1_acceptance',
  manifestSha256: hash(bytes), quoteSha256: hash(raw), quotedWethOutputWei: output.toString(), plan };
await writeFile(`${directory}/plan.json`, JSON.stringify(capture, null, 2) + '\n', { flag: 'wx' });
process.stdout.write(JSON.stringify({ directory, quotedWethOutputWei: output.toString(),
  minimumOutputWei: minimum.toString(), initiallySolved: plan.initiallySolved, nativeReserveWei: plan.nativeReserveWei }) + '\n');
