import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import {NativeMcdObserver} from './mcd-native-observer.mjs';

// Minimal synthetic SQL fixtures qualify only the independent observer boundary,
// never the original Google database, a native model, or benchmark execution.
test('actual native observer uses seven independent hashes, repeatable read and read-only reconnections',
  {skip:process.env.OID_MCP_DIAGNOSTICS_PG_TEST!=='1'},async()=>{
  const source=new URL(process.env.OID_DATABASE_URL),observerSource=new URL(process.env.OID_OBSERVER_DATABASE_URL);
  assert.equal(source.protocol,'postgres:');assert.equal(source.hostname,'postgres');assert.equal(source.username,'oid_owner');assert.equal(source.pathname,'/owner_identity');
  assert.equal(observerSource.hostname,'postgres');assert.equal(observerSource.username,'oid_observer');
  const databaseName='oid_google_local_'+randomUUID().replaceAll('-','');assert.match(databaseName,/^oid_google_local_[a-f0-9]{32}$/);
  const target=new URL(source);target.pathname='/'+databaseName;const observerUrl=new URL(observerSource);observerUrl.pathname='/'+databaseName;observerUrl.search='';observerUrl.hash='';
  const tables={runs:'oid_benchmark_run',tasks:'oid_run_task',actions:'oid_run_task_action',receipts:'oid_run_task_action_receipt',evaluations:'oid_run_task_evaluation',ledger:'oid_ledger_entry',bonuses:'oid_bonus_grant'};
  const admin=new pg.Client({connectionString:source.href}),owner=new pg.Client({connectionString:target.href});let created=false,observer;
  await admin.connect();
  try{
    await admin.query('CREATE DATABASE '+databaseName);created=true;await owner.connect();
    await owner.query('GRANT CONNECT ON DATABASE '+databaseName+' TO oid_observer');await owner.query('GRANT USAGE ON SCHEMA public TO oid_observer');
    for(const [domain,table] of Object.entries(tables)){await owner.query('CREATE TABLE '+table+'(id uuid PRIMARY KEY,marker text NOT NULL)');await owner.query('INSERT INTO '+table+'(id,marker) VALUES($1,$2)',[randomUUID(),'synthetic-observer-fixture-'+domain]);await owner.query('GRANT SELECT ON '+table+' TO oid_observer');}
    observer=new NativeMcdObserver({url:observerUrl.href,databaseName});
    const before=await observer.business();assert.equal(before.source,'postgresql_observer');assert.deepEqual(before.observer,{role:'oid_observer',databaseName,readOnly:true});assert.deepEqual(observer.identity,before.observer);assert.deepEqual(Object.keys(before.domainHashes).sort(),Object.keys(tables).sort());
    assert.equal((await observer.query('SELECT current_user AS role'))[0].role,'oid_observer');
    assert.throws(()=>observer.setCases([]));assert.throws(()=>observer.setCases(['invalid']));
    for(const [domain,table] of Object.entries(tables)){
      const expected=(await owner.query("SELECT encode(sha256(convert_to(COALESCE(string_agg(to_jsonb(r)::text,E'\\n' ORDER BY to_jsonb(r)::text),''),'UTF8')),'hex') AS hash FROM "+table+' r')).rows[0].hash;
      assert.match(before.domainHashes[domain],/^[a-f0-9]{64}$/);assert.equal(before.domainHashes[domain],expected);
    }
    const old=(await owner.query('SELECT marker FROM oid_bonus_grant')).rows[0].marker;
    await assert.rejects(observer.read(c=>c.query("UPDATE oid_bonus_grant SET marker='forbidden-observer-write'")),error=>['25006','42501'].includes(error.code));
    assert.equal((await owner.query('SELECT marker FROM oid_bonus_grant')).rows[0].marker,old);assert.deepEqual((await observer.business()).domainHashes,before.domainHashes);
    await observer.read(async(client,identity)=>{
      assert.equal(identity.readOnly,true);assert.equal((await client.query('SHOW transaction_isolation')).rows[0].transaction_isolation,'repeatable read');
      const first=(await client.query('SELECT marker FROM oid_bonus_grant')).rows[0].marker;
      await owner.query("UPDATE oid_bonus_grant SET marker='synthetic-owner-independent-change'");
      assert.equal((await client.query('SELECT marker FROM oid_bonus_grant')).rows[0].marker,first);
    });
    assert.equal((await observer.read(c=>c.query('SELECT marker FROM oid_bonus_grant'))).rows[0].marker,'synthetic-owner-independent-change');
    await observer.close();observer=new NativeMcdObserver({url:observerUrl.href,databaseName});
    await observer.read(async(c,identity)=>{assert.equal(identity.role,'oid_observer');assert.equal(identity.databaseName,databaseName);assert.equal((await c.query('SHOW default_transaction_read_only')).rows[0].default_transaction_read_only,'on');assert.equal((await c.query('SHOW transaction_read_only')).rows[0].transaction_read_only,'on');});
    await assert.rejects(observer.read(c=>c.query("UPDATE oid_bonus_grant SET marker='forbidden-after-reconnect'")),error=>['25006','42501'].includes(error.code));
    assert.equal((await owner.query('SELECT marker FROM oid_bonus_grant')).rows[0].marker,'synthetic-owner-independent-change');
    assert.throws(()=>new NativeMcdObserver({url:target.href,databaseName}));
    const foreign=new URL(observerUrl);foreign.pathname='/owner_identity';assert.throws(()=>new NativeMcdObserver({url:foreign.href,databaseName}));
    assert.throws(()=>new NativeMcdObserver({url:observerUrl.href,databaseName:'owner_identity'}));
  }finally{
    await observer?.close().catch(()=>{});await owner.end().catch(()=>{});
    if(created){assert.match(databaseName,/^oid_google_local_[a-f0-9]{32}$/);assert.notEqual(databaseName,source.pathname.slice(1));await admin.query('DROP DATABASE '+databaseName+' WITH (FORCE)');}
    await admin.end();
  }
});
