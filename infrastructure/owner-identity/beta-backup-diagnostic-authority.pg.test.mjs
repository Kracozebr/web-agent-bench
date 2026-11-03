import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {DIAGNOSTIC_HELPER_AUTHORITY_TABLES as TABLES,DIAGNOSTIC_HELPER_PG_DUMP_FLAGS,diagnosticAuthorityRestoreProof,assertDiagnosticAuthorityRestored} from './beta-backup-diagnostic-authority.mjs';
const canonical=v=>JSON.stringify(Array.isArray(v)?v.map(x=>JSON.parse(canonical(x))):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).sort(([a],[b])=>a<b?-1:a>b?1:0).map(([k,x])=>[k,JSON.parse(canonical(x))])):v);
const sha=v=>createHash('sha256').update(v).digest('hex');
const compose=['compose','-f','infrastructure/owner-identity/compose.yaml','exec','-T','postgres'];
function command(args){const r=spawnSync('docker',[...compose,...args],{encoding:'utf8',timeout:60000,maxBuffer:1024*1024});assert.equal(r.status,0,'isolated PostgreSQL authority dump command failed (raw stderr deliberately not emitted)');return r.stdout;}
function sql(name,query,observer=false){assert.match(name,/^(?:owner_identity|oid_(?:authority|restore)_[a-f0-9]{32})$/);return command(['psql','-X','-U',observer?'oid_observer':'oid_owner','-d',name,'-v','ON_ERROR_STOP=1','-Atq','-c',query]).trim();}
function snapshot(name){const identity=JSON.parse(sql(name,"SELECT json_build_object('role',current_user,'readOnly',current_setting('transaction_read_only'),'database',current_database())",true));assert.equal(identity.role,'oid_observer');assert.equal(identity.readOnly,'on');assert.equal(identity.database,name);const tableFingerprints={};for(const table of ['oid_ledger_entry','oid_mcp_diagnostic_event','oid_agent_access_grant',...TABLES]){
 const raw=sql(name,`SELECT to_jsonb(t)::text FROM public.${table} t ORDER BY to_jsonb(t)::text`,true),lines=raw?raw.split('\n'):[];tableFingerprints[table]={rowCount:lines.length,sha256:sha(lines.map(r=>r+'\n').join(''))};
 }const sequences=JSON.parse(sql(name,"SELECT COALESCE(json_agg(row_to_json(s) ORDER BY schemaname,sequencename),'[]'::json) FROM (SELECT schemaname,sequencename,last_value FROM pg_sequences WHERE schemaname='public') s",true)),sequenceSha256=sha(canonical(sequences));return {tableFingerprints,sequenceSha256,databaseTotalsSha256:sha(canonical({tableFingerprints,sequenceSha256}))};}
// This is a real PostgreSQL dump/restore boundary probe using declared minimal
// synthetic table fixtures, not full unified backup/cold-restore acceptance.
test('actual pg_dump/pg_restore retains schemas, native grants and evidence while excluding only helper authority data',{skip:process.env.OID_DIAGNOSTIC_AUTHORITY_DUMP_TEST!=='1'},()=>{
 const id=randomUUID().replaceAll('-',''),source='oid_authority_'+id,target='oid_restore_'+id,path='/tmp/mcd-authority-'+id+'.dump';let sourceCreated=false,targetCreated=false;
 assert.match(path,/^\/tmp\/mcd-authority-[a-f0-9]{32}\.dump$/);
 try{
  sql('owner_identity','CREATE DATABASE '+source);sourceCreated=true;
  const tables=['oid_ledger_entry','oid_mcp_diagnostic_event','oid_agent_access_grant',...TABLES];
  sql(source,tables.map(t=>`CREATE TABLE ${t}(id integer PRIMARY KEY,payload jsonb NOT NULL); INSERT INTO ${t} VALUES(1,'{"kind":"synthetic-dump-policy-fixture"}'::jsonb);`).join(' ')+' GRANT SELECT ON ALL TABLES IN SCHEMA public TO oid_observer;');
  const before=snapshot(source);const proof=diagnosticAuthorityRestoreProof(before);
  command(['pg_dump','-U','oid_owner','-d',source,'-Fc','--no-owner','--no-acl',...DIAGNOSTIC_HELPER_PG_DUMP_FLAGS,'-f',path]);
  assert.deepEqual(snapshot(source),before,'dump may not change any source row');
  sql('owner_identity','CREATE DATABASE '+target);targetCreated=true;
  command(['pg_restore','-U','oid_owner','-d',target,'--no-owner','--no-acl','--exit-on-error',path]);
  sql(target,'GRANT SELECT ON ALL TABLES IN SCHEMA public TO oid_observer;');
  const restored=snapshot(target);assertDiagnosticAuthorityRestored(before,restored,proof.policy);
  for(const name of TABLES)assert.equal(restored.tableFingerprints[name].rowCount,0);
  assert.deepEqual(snapshot(source),before,'restore must leave source fully unchanged');
 }finally{
  if(targetCreated)sql('owner_identity','DROP DATABASE '+target+' WITH (FORCE)');
  if(sourceCreated)sql('owner_identity','DROP DATABASE '+source+' WITH (FORCE)');
  command(['rm','-f','--',path]);
 }
});
