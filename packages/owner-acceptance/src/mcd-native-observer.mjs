/** Independent observations for the explicitly selected local Google database.
 * Never uses an owner/superuser connection and never modifies database grants. */
import assert from 'node:assert/strict';
import pg from 'pg';
import {setTimeout as delay} from 'node:timers/promises';

const BUSINESS = Object.freeze({runs:'oid_benchmark_run',tasks:'oid_run_task',actions:'oid_run_task_action',
  receipts:'oid_run_task_action_receipt',evaluations:'oid_run_task_evaluation',ledger:'oid_ledger_entry',bonuses:'oid_bonus_grant'});

export function validateNativeObserverTarget(url, databaseName) {
  assert.match(databaseName,/^oid_google_local_[a-f0-9]{32}$/);
  const value=new URL(url);
  assert.equal(value.protocol,'postgres:');
  assert.equal(value.hostname,'postgres');
  assert.equal(value.username,'oid_observer');
  assert.equal(value.pathname,'/'+databaseName);
  assert.equal(value.search,'');
  assert.equal(value.hash,'');
  return databaseName;
}

export class NativeMcdObserver {
  constructor({url,databaseName}) {
    this.databaseName=validateNativeObserverTarget(url,databaseName);
    this.pool=new pg.Pool({connectionString:url,max:1,application_name:'mcd-native-independent-observer',
      options:'-c default_transaction_read_only=on -c statement_timeout=5000 -c lock_timeout=1000'});
  }
  setCases(caseIds) {
    assert(Array.isArray(caseIds)&&caseIds.length>0&&caseIds.length<=128);
    assert(caseIds.every(id=>/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(id)));
    this.caseIds=[...new Set(caseIds)];
  }
  async query(text,values=[]) {return this.read(async client=>(await client.query(text,values)).rows);}
  async read(work) {
    const client=await this.pool.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      const identity=(await client.query("SELECT current_user AS role,current_database() AS \"databaseName\",current_setting('transaction_read_only') AS mode")).rows[0];
      assert.equal(identity.role,'oid_observer');assert.equal(identity.databaseName,this.databaseName);assert.equal(identity.mode,'on');
      this.identity={role:identity.role,databaseName:identity.databaseName,readOnly:true};
      const result=await work(client,this.identity);
      await client.query('COMMIT');return result;
    } catch(error) {await client.query('ROLLBACK').catch(()=>{});throw error;}
    finally {client.release();}
  }
  async business() {
    return this.read(async(client,observer)=>{
      const domainHashes={};
      for(const [domain,table] of Object.entries(BUSINESS)) {
        domainHashes[domain]=(await client.query(`SELECT encode(sha256(convert_to(COALESCE(string_agg(to_jsonb(r)::text,E'\\n' ORDER BY to_jsonb(r)::text),''),'UTF8')),'hex') AS sha FROM ${table} r`)).rows[0].sha;
      }
      return {source:'postgresql_observer',observer,domainHashes};
    });
  }
  async diagnostics({caseIds=this.caseIds}={}) {
    assert(Array.isArray(caseIds)&&caseIds.length>0&&caseIds.length<=128);
    assert(caseIds.every(id=>/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(id)));
    return this.read(async(client,observer)=>{
      const args=[caseIds];
      const cases=(await client.query(`SELECT c.id AS "caseId",'client_diagnostics' AS kind,c.owner_id AS "ownerId",c.agent_id AS "agentId",c.connection_id AS "connectionId",c.diagnostic_session_id AS "diagnosticSessionId",c.intent_id AS "intentId",r.id AS "runId",c.report_id AS "reportId",c.created_at AS "createdAt",c.updated_at AS "updatedAt",c.capture_state AS "captureState",c.event_count AS "eventCount",c.error_count AS "errorCount" FROM oid_mcp_diagnostic_case c LEFT JOIN oid_benchmark_run r ON r.intent_id=c.intent_id WHERE c.id=ANY($1::uuid[]) ORDER BY c.id`,args)).rows;
      const events=(await client.query(`SELECT envelope,case_id AS "caseId",responsibility,attribution_reason AS "attributionReason",evidence_ids AS "evidenceIds" FROM oid_mcp_diagnostic_event WHERE case_id=ANY($1::uuid[]) ORDER BY case_id,event_id`,args)).rows.map(({envelope,...rest})=>({...envelope,...rest}));
      const reports=(await client.query(`SELECT r.id,c.id AS "caseId",c.owner_id AS "ownerId",'client_diagnostics' AS kind FROM oid_mcp_diagnostic_case c JOIN oid_support_report r ON r.id=c.report_id WHERE c.id=ANY($1::uuid[]) ORDER BY r.id`,args)).rows;
      const batches=(await client.query(`SELECT case_id AS "caseId",segment_id AS "segmentId",batch_sequence AS "batchSequence",payload_hash AS "payloadHash",completion FROM oid_mcp_diagnostic_batch WHERE case_id=ANY($1::uuid[]) ORDER BY case_id,segment_id,batch_sequence`,args)).rows;
      const audits=(await client.query(`SELECT a.report_id AS "reportId",a.event_type AS "eventType",a.revision FROM oid_support_report_audit a JOIN oid_mcp_diagnostic_case c ON c.report_id=a.report_id WHERE c.id=ANY($1::uuid[]) ORDER BY a.report_id,a.revision,a.event_type`,args)).rows;
      return JSON.parse(JSON.stringify({source:'postgresql_observer',observer,scope:{caseIds},cases,events,reports,batches,audits}));
    });
  }
  async settledDiagnostics() {
    let prior=await this.diagnostics();
    for(let attempt=0;attempt<40;attempt++) {
      await delay(50);const current=await this.diagnostics();
      if(JSON.stringify(current)===JSON.stringify(prior))return current;
      prior=current;
    }
    throw new Error('MCD_NATIVE_OBSERVATION_NOT_QUIESCENT');
  }
  async waitFor(predicate) {
    for(let attempt=0;attempt<60;attempt++) {
      const rows=await this.diagnostics();if(predicate(rows))return rows;await delay(50);
    }
    throw new Error('MCD_NATIVE_OBSERVATION_MISSING');
  }
  async close() {await this.pool.end();}
}
