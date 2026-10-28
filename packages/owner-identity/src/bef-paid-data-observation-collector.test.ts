import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { collectBefPaidDataObservationCandidate, parsePaidDataBaselineState, parsePinnedRuntimeManifest, type BefPaidDataObservationCollectorDependencies } from './bef-paid-data-observation-collector.js';
import { sha256CanonicalTaskJson, type TaskCase } from './task-release.js';

const runId='30000000-0000-4000-8000-000000000003';
test('parses baseline state hashes from the producer envelope and hex block quantities',()=>{
  const projection={balances:[],allowances:[],deliveredComponentIds:[],fulfilledObligationIds:[]};
  const stateSha256=sha256CanonicalTaskJson(projection);
  const initialState={...projection,stateSha256} as TaskCase['initialState'];
  const evidence={state:{sameBlock:true,blockNumber:'0x32871b5',blockHash:`0x${'c'.repeat(64)}`,projection,reads:[]},
    stateSha256,expectedStateSha256:stateSha256};
  assert.equal('stateSha256' in evidence.state,false);
  const parsed=parsePaidDataBaselineState(evidence,initialState,stateSha256);
  assert.equal(parsed.number,BigInt('0x32871b5').toString(10));
  assert.equal(parsed.blockHash,evidence.state.blockHash);

  const nestedOnly={state:{...evidence.state,stateSha256,expectedStateSha256:stateSha256},stateSha256:undefined,expectedStateSha256:undefined};
  assert.throws(()=>parsePaidDataBaselineState(nestedOnly,initialState,stateSha256));
  const decimalBlock={...evidence,state:{...evidence.state,blockNumber:BigInt('0x32871b5').toString(10)}};
  assert.throws(()=>parsePaidDataBaselineState(decimalBlock,initialState,stateSha256));
  assert.throws(()=>parsePaidDataBaselineState(evidence,initialState,'f'.repeat(64)));
});
test('accepts the release-pinned repository manifest without rewriting its public funding and pool addresses',async()=>{
  const bytes=await readFile(new URL('../../../infrastructure/benchmark-environment/manifest.json',import.meta.url));
  const manifest=JSON.parse(bytes.toString('utf8')) as {funding:{token:string};contracts:{pool:{token0:string;token1:string}}};
  const usdc=manifest.funding.token,token0=manifest.contracts.pool.token0,token1=manifest.contracts.pool.token1;
  const weth=token0.toLowerCase()===usdc.toLowerCase()?token1:token0;
  const release={manifest:{executionIdentity:{localChainId:8453,assets:[
    {assetId:'USDC',kind:'erc20',chainId:8453,address:usdc,decimals:6,codeHash:'a'.repeat(64)},
    {assetId:'WETH',kind:'erc20',chainId:8453,address:weth,decimals:18,codeHash:'b'.repeat(64)},
    {assetId:'ETH',kind:'native',chainId:8453,address:null,decimals:18,codeHash:null}]}}} as unknown as Parameters<typeof parsePinnedRuntimeManifest>[1];
  const parsed=parsePinnedRuntimeManifest(bytes,release);
  assert.deepEqual(parsed,manifest);
});
test('permits only release-pinned public token-address fields in the scanner copy',()=>{
  const token='0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',weth='0x4200000000000000000000000000000000000006';
  const usdc={assetId:'USDC',kind:'erc20',chainId:8453,address:token,decimals:6,codeHash:'a'.repeat(64)};
  const wethAsset={assetId:'WETH',kind:'erc20',chainId:8453,address:weth,decimals:18,codeHash:'b'.repeat(64)};
  const release={manifest:{executionIdentity:{localChainId:8453,assets:[usdc,wethAsset,
    {assetId:'ETH',kind:'native',chainId:8453,address:null,decimals:18,codeHash:null}]}}} as unknown as Parameters<typeof parsePinnedRuntimeManifest>[1];
  const manifest={schemaVersion:'bef-runtime-manifest/v1',funding:{mode:'private-anvil-impersonated-transfer',token:token.toUpperCase(),ephemeralKeys:true},
    contracts:{pool:{token0:weth,token1:token},pool3000:{token0:weth,token1:token}},x402:{scheme:'exact',asset:token}};
  const bytes=Buffer.from(JSON.stringify(manifest),'utf8'),parsed=parsePinnedRuntimeManifest(bytes,release);
  assert.deepEqual(parsed,manifest);
  assert.equal((parsed.funding as Record<string,unknown>).token,token.toUpperCase());

  const wrongFunding={...manifest,funding:{...manifest.funding,token:'0x0000000000000000000000000000000000000001'}};
  assert.throws(()=>parsePinnedRuntimeManifest(Buffer.from(JSON.stringify(wrongFunding),'utf8'),release));
  const foreignPool=structuredClone(manifest);foreignPool.contracts.pool3000.token1='0x0000000000000000000000000000000000000001';
  assert.throws(()=>parsePinnedRuntimeManifest(Buffer.from(JSON.stringify(foreignPool),'utf8'),release));
  const secondTokenKey={...manifest,x402:{...manifest.x402,token}};
  assert.throws(()=>parsePinnedRuntimeManifest(Buffer.from(JSON.stringify(secondTokenKey),'utf8'),release));
  const ambiguousRelease={manifest:{executionIdentity:{localChainId:8453,assets:[usdc,{...usdc,address:weth},wethAsset]}}} as unknown as Parameters<typeof parsePinnedRuntimeManifest>[1];
  assert.throws(()=>parsePinnedRuntimeManifest(bytes,ambiguousRelease));
});
test('rejects malformed run targets before opening an owner transaction',async()=>{
  let transactions=0;
  const deps={db:{transaction:async()=>{transactions++;throw new Error('transaction must not begin')}}} as unknown as BefPaidDataObservationCollectorDependencies;
  const result=await collectBefPaidDataObservationCandidate(deps,{runId:'not-a-uuid',taskIndex:0});
  assert.deepEqual(result,{status:'unavailable',reasonCode:'invalid_target'});
  assert.equal(transactions,0);
});

test('requires an active owner task after beginning a readonly repeatable-read snapshot',async()=>{
  const statements:unknown[]=[];
  const runRow={
    owner_id:'30000000-0000-4000-8000-000000000001',agent_id:'30000000-0000-4000-8000-000000000002',
    mode:'training',task_ids:['H1'],release_identity:'fixture-release',manifest_hash:'a'.repeat(64),run_status:'running',
    cancellation_reason:null,task_id:'H1',task_status:'completed',closure_status:'closed',
    closure_id:'30000000-0000-4000-8000-000000000004',closure_operation_id:null,closure_payload_hash:'b'.repeat(64),
    closure_reason:'agent_finish',action_cutoff_sequence:'0',reconciled_action_sequence:'0',
  };
  const tx={execute:async(statement:unknown)=>{statements.push(statement);return statements.length===2?[runRow]:[]}};
  let releaseReads=0,observerReads=0,evWrites=0;
  const deps={
    db:{transaction:async(callback:(transaction:unknown)=>Promise<unknown>)=>callback(tx)},
    taskReleaseSource:{getValidatedReleaseRecord:async()=>{releaseReads++;return null}},
    repositoryRoot:'.',
    postgresByEnvironment:new Proxy({}, {get(){observerReads++;return undefined}}),
    rpcByEnvironment:new Proxy({}, {get(){observerReads++;return undefined}}),
    evidenceSink:{write:async()=>{evWrites++;throw new Error('must not write')}},
  } as unknown as BefPaidDataObservationCollectorDependencies;
  const result=await collectBefPaidDataObservationCandidate(deps,{runId,taskIndex:0});
  assert.deepEqual(result,{status:'unavailable',reasonCode:'owner_cutoff_unavailable'});
  assert.equal(statements.length,2);
  assert.equal(releaseReads,0);
  assert.equal(observerReads,0);
  assert.equal(evWrites,0);
  const first=statements[0] as {queryChunks?:unknown[]};
  assert.ok(Array.isArray(first.queryChunks));
  assert.match(JSON.stringify(first.queryChunks),/SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY/);
});

test('does not admit a task whose closure is not reconciled through its action cutoff',async()=>{
  const statements:unknown[]=[];
  const runRow={
    owner_id:'30000000-0000-4000-8000-000000000001',agent_id:'30000000-0000-4000-8000-000000000002',
    mode:'ranked',task_ids:['M2'],release_identity:'fixture-release',manifest_hash:'a'.repeat(64),run_status:'running',
    cancellation_reason:null,task_id:'M2',task_status:'active',closure_status:'closed',
    closure_id:'30000000-0000-4000-8000-000000000004',closure_operation_id:null,closure_payload_hash:'b'.repeat(64),
    closure_reason:'agent_finish',action_cutoff_sequence:'4',reconciled_action_sequence:'3',
  };
  const tx={execute:async(statement:unknown)=>{statements.push(statement);return statements.length===2?[runRow]:[]}};
  const deps={db:{transaction:async(callback:(transaction:unknown)=>Promise<unknown>)=>callback(tx)}} as unknown as BefPaidDataObservationCollectorDependencies;
  const result=await collectBefPaidDataObservationCandidate(deps,{runId,taskIndex:0});
  assert.deepEqual(result,{status:'unavailable',reasonCode:'reconciliation_pending'});
  assert.equal(statements.length,2);
});
