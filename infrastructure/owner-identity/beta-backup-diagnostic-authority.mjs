import {createHash} from 'node:crypto';

// AICODE-NOTE: SC006 excludes ONLY ephemeral diagnostic-helper authority data.
// Schemas, diagnostics, native grants and every business/evidence row remain in
// the dump. Source observations always retain their unmodified full inventory.
export const DIAGNOSTIC_HELPER_AUTHORITY_TABLES=Object.freeze([
 'oid_diagnostic_oauth_request','oid_diagnostic_oauth_grant','oid_diagnostic_oauth_token'
]);
export const DIAGNOSTIC_HELPER_PG_DUMP_FLAGS=Object.freeze(DIAGNOSTIC_HELPER_AUTHORITY_TABLES.map(name=>'--exclude-table-data=public.'+name));
const canonical=v=>JSON.stringify(Array.isArray(v)?v.map(x=>JSON.parse(canonical(x))):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).sort(([a],[b])=>a<b?-1:a>b?1:0).map(([k,x])=>[k,JSON.parse(canonical(x))])):v);
const hash=value=>createHash('sha256').update(value).digest('hex');
const HEX=/^[a-f0-9]{64}$/;
const empty=()=>({rowCount:0,sha256:hash('')});
const fail=()=>{throw new Error('beta_backup_diagnostic_authority_restore_policy_invalid');};

export function validateDiagnosticAuthorityPolicy(value){
 if(value===undefined)return;
 const keys=['schemaVersion','excludedTableData','sourceTableFingerprints','restoredTableFingerprints','sourceDatabaseTotalsSha256','restorableDatabaseTotalsSha256'];
 if(!value||canonical(Object.keys(value).sort())!==canonical(keys.sort())||value.schemaVersion!=='beta-diagnostic-helper-authority-exclusion/v1'||
  canonical(value.excludedTableData)!==canonical(DIAGNOSTIC_HELPER_AUTHORITY_TABLES)||!HEX.test(value.sourceDatabaseTotalsSha256??'')||!HEX.test(value.restorableDatabaseTotalsSha256??''))fail();
 for(const map of [value.sourceTableFingerprints,value.restoredTableFingerprints]){
  if(!map||canonical(Object.keys(map).sort())!==canonical([...DIAGNOSTIC_HELPER_AUTHORITY_TABLES].sort()))fail();
  for(const row of Object.values(map))if(!row||Object.keys(row).length!==2||!Number.isSafeInteger(row.rowCount)||row.rowCount<0||!HEX.test(row.sha256??''))fail();
 }
 if(Object.values(value.restoredTableFingerprints).some(row=>canonical(row)!==canonical(empty())))fail();
}

export function diagnosticAuthorityRestoreProof(source){
 const tables=source?.tableFingerprints;if(!tables||typeof tables!=='object')fail();
 const present=DIAGNOSTIC_HELPER_AUTHORITY_TABLES.filter(name=>Object.hasOwn(tables,name));
 if(!present.length)return {policy:undefined,tableFingerprints:tables,databaseTotalsSha256:source.databaseTotalsSha256};
 if(present.length!==3||!HEX.test(source.sequenceSha256??''))fail();
 if(hash(canonical({tableFingerprints:tables,sequenceSha256:source.sequenceSha256}))!==source.databaseTotalsSha256)fail();
 const sourceTableFingerprints=Object.fromEntries(present.map(name=>[name,{...tables[name]}]));
 const restoredTableFingerprints=Object.fromEntries(present.map(name=>[name,empty()]));
 const tableFingerprints={...tables,...restoredTableFingerprints};
 const databaseTotalsSha256=hash(canonical({tableFingerprints,sequenceSha256:source.sequenceSha256}));
 const policy={schemaVersion:'beta-diagnostic-helper-authority-exclusion/v1',excludedTableData:[...DIAGNOSTIC_HELPER_AUTHORITY_TABLES],sourceTableFingerprints,restoredTableFingerprints,
  sourceDatabaseTotalsSha256:source.databaseTotalsSha256,restorableDatabaseTotalsSha256:databaseTotalsSha256};
 validateDiagnosticAuthorityPolicy(policy);return {policy,tableFingerprints,databaseTotalsSha256};
}

export function assertDiagnosticAuthorityRestored(source,actual,declaredPolicy){
 const expected=diagnosticAuthorityRestoreProof(source);validateDiagnosticAuthorityPolicy(declaredPolicy);
 if(canonical(expected.policy??null)!==canonical(declaredPolicy??null))fail();
 if(expected.policy&&(canonical(actual.tableFingerprints)!==canonical(expected.tableFingerprints)||actual.sequenceSha256!==source.sequenceSha256||actual.databaseTotalsSha256!==expected.databaseTotalsSha256))fail();
 return expected;
}
