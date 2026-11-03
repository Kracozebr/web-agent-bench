/** Actual PostgreSQL grammar/schema check; SELECT plans only, never execution. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import pg from 'pg';
import {BER_S1_BEF_READ_QUERIES} from './ber-admitted-actions-cases.mjs';
const enabled=process.env.OID_BER_BEF_SCHEMA_TEST==='1';
const generation='00000000-0000-4000-8000-000000000000',transaction='0x'+'0'.repeat(64);
const params={identity:[],payment_scope:['ber_schema_only',generation,transaction],delivery_scope:['ber_schema_only',generation,generation],generation_scope:['ber_schema_only',generation]};
test('all post-check helper SELECTs resolve against the actual read-only BEF schema',{skip:!enabled},async t=>{
 let password=(await readFile('/run/secrets/bef_database_observer_password','utf8')).trim();assert(password.length>=16&&!/[\r\n\u0000]/.test(password));
 const url=new URL('postgres://bef_observer@host.docker.internal:'+(process.env.BEF_DATABASE_HOST_PORT||'55432')+'/bef');url.password=password;password='';
 const pool=new pg.Pool({connectionString:url.href,max:1,options:'-c default_transaction_read_only=on -c statement_timeout=10000'});url.password='';
 t.after(()=>pool.end());
 for(const [name,query] of Object.entries(BER_S1_BEF_READ_QUERIES))await t.test(name,async()=>{
  assert.match(query.sql,/^SELECT /);assert(!query.sql.includes(';'));const c=await pool.connect();
  try{await c.query('BEGIN READ ONLY');const identity=(await c.query("SELECT current_user AS role,current_setting('transaction_read_only') AS mode")).rows[0];assert.equal(identity.role,'bef_observer');assert.equal(identity.mode,'on');const result=await c.query('EXPLAIN (FORMAT JSON) '+query.sql,params[query.parameterKind]);assert.equal(result.rows.length,1);assert(result.rows[0]['QUERY PLAN'][0].Plan);}finally{await c.query('ROLLBACK');c.release();}
 });
 await t.test('old direct delivery scope columns are rejected, so this check detects the original helper defect',async()=>{
  const c=await pool.connect();try{await c.query('BEGIN READ ONLY');await assert.rejects(c.query('EXPLAIN SELECT env_id,generation_id FROM bef_delivery'),e=>e.code==='42703');}finally{await c.query('ROLLBACK');c.release();}
 });
});
