import assert from 'node:assert/strict';
import test from 'node:test';
import { collectBefChainTaskObservationCandidate, matchesReleaseCodeHash, observedRuntimeCodeHash, type BefChainObservationCollectorDependencies } from './bef-chain-observation-collector.js';

test('retained public runtime code hashes match the naked hash pinned in the release',()=>{
 const publicCode='0x6000';
 assert.equal(observedRuntimeCodeHash(publicCode),'07ad118d6cc8642c86c03827f276d8b791a65e5c99a3845faf186be720a1455d');
 assert.equal(observedRuntimeCodeHash(publicCode).length,64);
});

test('fee-3000 pool code hash accepts only an exact prefixed or naked release hash',()=>{
 const releaseHash='71ff5f428af7891e7cbce51d4dadacef1e8eb0c1e454342413066bbd8a0d344c';
 assert.equal(matchesReleaseCodeHash(`0x${releaseHash}`,releaseHash),true);
 assert.equal(matchesReleaseCodeHash(`0X${releaseHash.toUpperCase()}`,releaseHash),true);
 assert.equal(matchesReleaseCodeHash(`${releaseHash}00`,releaseHash),false);
 assert.equal(matchesReleaseCodeHash(`0x${releaseHash.slice(1)}`,releaseHash),false);
 assert.equal(matchesReleaseCodeHash('not-a-hash',releaseHash),false);
 assert.equal(matchesReleaseCodeHash(`0x${releaseHash}`,`0x${releaseHash.slice(0,-1)}0`),false);
});

test('chain collector rejects malformed targets before opening a transaction',async()=>{
 let transactions=0;
 const deps={db:{transaction:async()=>{transactions++;throw new Error('unexpected_transaction')}}} as unknown as BefChainObservationCollectorDependencies;
 const result=await collectBefChainTaskObservationCandidate(deps,{runId:'not-a-uuid',taskIndex:0});
 assert.deepEqual(result,{status:'unavailable',reasonCode:'invalid_target'});
 assert.equal(transactions,0);
});

test('chain collector stops after its initial owner-row lookup when no run exists',async()=>{
 const statements:unknown[]=[];
 const fakeTx={execute:async(statement:unknown)=>{statements.push(statement);return [];}};
 let transactions=0;
 const deps={db:{transaction:async<T>(callback:(tx:unknown)=>Promise<T>)=>{transactions++;return callback(fakeTx);}}} as unknown as BefChainObservationCollectorDependencies;
 const result=await collectBefChainTaskObservationCandidate(deps,{runId:'123e4567-e89b-42d3-a456-426614174000',taskIndex:0});
 assert.deepEqual(result,{status:'unavailable',reasonCode:'owner_cutoff_unavailable'});
 assert.equal(transactions,1);
 assert.equal(statements.length,1);
 assert.ok(statements[0]&&typeof statements[0]==='object');
});
