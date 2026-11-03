import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {DIAGNOSTIC_HELPER_AUTHORITY_TABLES as TABLES,DIAGNOSTIC_HELPER_PG_DUMP_FLAGS,diagnosticAuthorityRestoreProof,assertDiagnosticAuthorityRestored,validateDiagnosticAuthorityPolicy} from './beta-backup-diagnostic-authority.mjs';
const canonical=v=>JSON.stringify(Array.isArray(v)?v.map(x=>JSON.parse(canonical(x))):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).sort(([a],[b])=>a<b?-1:a>b?1:0).map(([k,x])=>[k,JSON.parse(canonical(x))])):v);
const sha=v=>createHash('sha256').update(v).digest('hex');
function source(){const tableFingerprints=Object.fromEntries(['oid_ledger_entry','oid_mcp_diagnostic_event','oid_agent_access_grant',...TABLES].map((name,index)=>[name,{rowCount:index+1,sha256:sha(name)}])),sequenceSha256=sha('sequences');return {tableFingerprints,sequenceSha256,databaseTotalsSha256:sha(canonical({tableFingerprints,sequenceSha256}))};}

test('fixed helper-authority exclusion derives empty target only for three exact tables and retains full source proof',()=>{
 const original=source(),bytes=canonical(original),proof=diagnosticAuthorityRestoreProof(original);
 assert.equal(canonical(original),bytes);assert.equal(proof.policy.sourceDatabaseTotalsSha256,original.databaseTotalsSha256);assert.notEqual(proof.databaseTotalsSha256,original.databaseTotalsSha256);
 for(const name of TABLES)assert.deepEqual(proof.tableFingerprints[name],{rowCount:0,sha256:sha('')});
 for(const name of ['oid_ledger_entry','oid_mcp_diagnostic_event','oid_agent_access_grant'])assert.deepEqual(proof.tableFingerprints[name],original.tableFingerprints[name]);
 assertDiagnosticAuthorityRestored(original,{...proof,sequenceSha256:original.sequenceSha256},proof.policy);
});
test('restore policy rejects retained helper authority, changed native/business/evidence, missing proof or altered exclusions',()=>{
 const original=source(),proof=diagnosticAuthorityRestoreProof(original),actual={...proof,sequenceSha256:original.sequenceSha256};
 assert.throws(()=>assertDiagnosticAuthorityRestored(original,original,proof.policy));
 assert.throws(()=>assertDiagnosticAuthorityRestored(original,actual,undefined));
 for(const name of ['oid_ledger_entry','oid_mcp_diagnostic_event','oid_agent_access_grant',...TABLES])assert.throws(()=>assertDiagnosticAuthorityRestored(original,{...actual,tableFingerprints:{...actual.tableFingerprints,[name]:{rowCount:1,sha256:sha('tamper')}}},proof.policy));
 assert.throws(()=>validateDiagnosticAuthorityPolicy({...proof.policy,excludedTableData:[...TABLES,'oid_agent_access_grant']}));
 assert.throws(()=>validateDiagnosticAuthorityPolicy({...proof.policy,callerMayExclude:'anything'}));
 const partial=source();delete partial.tableFingerprints[TABLES[0]];assert.throws(()=>diagnosticAuthorityRestoreProof(partial));
});
test('legacy checkpoints without helper tables retain their exact fingerprint and need no policy',()=>{
 const legacy={tableFingerprints:{oid_ledger_entry:{rowCount:1,sha256:sha('legacy')}},databaseTotalsSha256:sha('original-total')};
 const proof=diagnosticAuthorityRestoreProof(legacy);assert.equal(proof.policy,undefined);assert.equal(proof.tableFingerprints,legacy.tableFingerprints);assert.equal(proof.databaseTotalsSha256,legacy.databaseTotalsSha256);
});
test('host pg_dump excludes exactly the fixed helper authority data, never native or diagnostic evidence tables',async()=>{
 const host=await readFile(new URL('./beta-backup-host.ps1',import.meta.url),'utf8');
 const flags=[...host.matchAll(/'(--exclude-table-data=public\.[a-z_]+)'/g)].map(m=>m[1]);assert.deepEqual(flags,DIAGNOSTIC_HELPER_PG_DUMP_FLAGS);
});
