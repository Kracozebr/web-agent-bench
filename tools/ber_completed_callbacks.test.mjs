import assert from 'node:assert/strict';
import test from 'node:test';
import {runBerCompletedCallbacks} from './ber_completed_callbacks.mjs';

const valid={databaseUrl:'postgres://oid_owner@postgres/oid_acceptance_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
 observerDatabaseUrl:'postgres://oid_observer@postgres/oid_acceptance_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
 repoRoot:'/must-not-read-original-data',runId:'11111111-1111-4111-8111-111111111111',
 ownerId:'22222222-2222-4222-8222-222222222222',agentId:'33333333-3333-4333-8333-333333333333'};

for(const[name,patch]of[
 ['original Google database',{databaseUrl:'postgres://oid_owner@postgres/oid_google_local_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',observerDatabaseUrl:'postgres://oid_observer@postgres/oid_google_local_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}],
 ['unrelated owner database',{databaseUrl:'postgres://oid_owner@postgres/owner_identity',observerDatabaseUrl:'postgres://oid_observer@postgres/owner_identity'}],
 ['observer bound to another database',{observerDatabaseUrl:'postgres://oid_observer@postgres/oid_acceptance_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'}],
 ['unexpected write role',{databaseUrl:'postgres://superuser@postgres/oid_acceptance_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}],
 ['unexpected network host',{databaseUrl:'postgres://oid_owner@example.com/oid_acceptance_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}],
])test('callback probes reject '+name+' before filesystem or database access',async()=>{
 await assert.rejects(runBerCompletedCallbacks({...valid,...patch}),error=>error?.code==='ERR_ASSERTION');
});
