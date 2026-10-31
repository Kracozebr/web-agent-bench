import assert from 'node:assert/strict';
import test from 'node:test';
import {runBerPendingTransitionInterruption} from './ber_pending_transition_interruption.mjs';

test('interruption harness cannot stop the original Google runtime or install its test gate there',async()=>{
 let calls=0;const forbidden=async()=>{calls++;throw Error('must_not_run');};
 await assert.rejects(runBerPendingTransitionInterruption({runId:'11111111-1111-4111-8111-111111111111',phase:'evaluation',releaseReceiptFault:forbidden,
  commonCapture:{databaseUrl:'postgres://oid_owner@postgres/oid_google_local_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
   observerDatabaseUrl:'postgres://oid_observer@postgres/oid_google_local_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',repoRoot:'/must-not-read-original',stopApi:forbidden,restartApi:forbidden}}),
  error=>error?.code==='ERR_ASSERTION');
 assert.equal(calls,0);
});

test('interruption phase cannot become arbitrary SQL or a new fault boundary',async()=>{
 await assert.rejects(runBerPendingTransitionInterruption({runId:'11111111-1111-4111-8111-111111111111',phase:'evaluation; DROP TABLE oid_run_task',releaseReceiptFault:()=>{},commonCapture:{}}),
  error=>error?.code==='ERR_ASSERTION');
});
