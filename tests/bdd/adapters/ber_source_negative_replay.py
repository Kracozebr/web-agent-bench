"""Scoped read-return faults: original source bytes are never authoritative DB mutations."""
import copy,re,hashlib,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[3]))
from tests.bdd.adapters.ber_matrix_common import need,one,digest,load_ref
from tests.bdd.adapters.ber_recovery_replay import read_reference
from tests.bdd.adapters.ber_generic_recovery_replay import owner_context,verify_known_input
from tests.bdd.adapters.ber_generic_family_replay import verify_generic_family_root
from tests.bdd.adapters.ber_matrix_derived_effects import verify_derived_chain_effects
from tests.bdd.adapters.ber_matrix_support import ms
REASONS={'receipt_row_missing':'chain_family_observer_census_unavailable','receipt_hash_conflict':'chain_family_rpc_mapping_incomplete','receipt_generation_conflict':'chain_family_rpc_observation_unavailable','read_missing':'chain_family_rpc_observation_unavailable','block_missing':'paid_family_rpc_observation_unavailable','census_contradictory':'chain_family_observer_census_unavailable','census_truncated':'chain_family_observer_census_unavailable'}

def verify_query_registry(registry,repo):
 need(registry['schemaVersion']=='ber-source-query-registry/v1' and registry['source']['path']=='packages/owner-identity/src/bef-chain-observation-collector.ts','wrong source query registry')
 source=read_reference(repo,registry['source'],json_body=False).decode();need('MAX_ROWS=2048' in source and 'MAX_PACKET_BYTES=8*1024*1024' in source,'source limits drifted')
 for name,variable,table in [('costs','rawCosts','bef_transaction_cost'),('events','rawEvents','bef_selected_execution_event'),('counts','counts',None)]:
  m=re.search(r'const '+variable+r'=dbRows<J>\(await query\(`([\s\S]*?)`,\[envId,generationId\]\)\)',source);need(m,'actual registered source query absent');sql=m[1].replace('${MAX_ROWS+1}','2049').replace('${MAX_PACKET_BYTES}','8388608');need('${' not in sql,'unsupported query interpolation');columns=[re.sub(r'::text$','',x.strip()).strip() for x in sql[:sql.index('FROM public.'+table)].removeprefix('SELECT').split(',')] if table else re.findall(r' AS ([a-z_]+)',sql);expected={'name':name,'statement':sql,'sqlSha256':hashlib.sha256(' '.join(sql.split()).encode()).hexdigest(),'columns':columns};need(registry['entries'][name]==expected,'registered query/columns do not derive from actual pinned source')
 return registry['entries']

def verify_source_transformation(target,original,delivered,intervention):
 v=target['variant'];need(v in REASONS and intervention['target']==target and intervention['originalSha256']==digest(original) and intervention['deliveredSha256']==digest(delivered),'source intervention preimages or target differ')
 expected=copy.deepcopy(original)
 if v in ('read_missing','block_missing'):
  need(original['kind']=='rpc_result' and original['httpStatus']==200 and not original['body'].get('error') and original['body'].get('result') is not None,'upstream RPC was already missing/unavailable')
  method,params=original['request']['method'],original['request']['params'];need(intervention['method']==method and intervention['parametersSha256']==digest(params),'RPC intervention parameters differ')
  if v=='block_missing':need(method=='eth_getBlockByNumber' and len(params)==2 and params[1] is False and target['transactionHash'] in original['body']['result']['transactions'],'fault targets wrong block or signed/full transaction payload')
  else:need(method=='eth_call' and len(params)==2 and set(params[0])=={'to','data'} and re.fullmatch(r'0x(?:70a08231[0-9a-f]{64}|dd62ed3e[0-9a-f]{128})',params[0]['data'],re.I) and re.fullmatch(r'0x[0-9a-f]{64}',original['body']['result'],re.I),'fault is not a bounded original balance/allowance read')
  expected['body']['result']=None
 else:
  need(original['kind']=='postgres_result' and original['parameters']==[target['environmentId'],target['generationId']] and intervention['parametersSha256']==digest(original['parameters']) and intervention['querySha256']==original['querySha256'] and intervention['columns']==original['columns'],'SQL query scope/registry differs')
  rows=expected['rows'];need(all(set(r)==set(original['columns']) for r in rows),'source returned unexpected/missing columns');i=intervention['selectedRowIndex'];need(type(i)is int and 0<=i<len(rows),'missing selected original row');r=rows[i]
  if v=='census_contradictory':need(len(rows)==1 and 'costs' in r,'wrong independent count query');r['costs']=str(int(r['costs'])+1)
  else:
   need(r['operation_id']==target['befOperationId'] and r['env_id']==target['environmentId'] and r['generation_id']==target['generationId'] and r['transaction_hash']==target['transactionHash'],'selected fault row is foreign to original observed operation')
   if v in ('receipt_row_missing','census_truncated'):
    if v=='census_truncated':need(r['event_kind']=='original_tx_hash_bound','truncated row is not original transaction-bound source history')
    rows.pop(i)
   elif v=='receipt_hash_conflict':
    value=delivered['rows'][i]['receipt_block_hash'];old=r['receipt_block_hash'];need(isinstance(old,str) and re.fullmatch(r'0x[0-9a-f]{64}',value,re.I) and len(value)==len(old) and sum(a!=b for a,b in zip(value,old))==1,'receipt hash fault is not exact one-hex conflict');r['receipt_block_hash']=value
   elif v=='receipt_generation_conflict':
    value=delivered['rows'][i]['generation_id'];need(value!=r['generation_id'] and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',value),'generation fault lacks exact foreign UUID');r['generation_id']=value
 need(expected==delivered and expected!=original,'source fault omitted, broadened or altered unrelated returned data')
 return {'variant':v,'actualChangedReadReturn':True,'authoritativeDatabaseMutationClaimed':False}

def _snapshot(ref,target,repo):
 s=load_ref(repo,ref);o=s['identity'];need(o['role']=='oid_observer' and o['database_name']==target['databaseName'] and o['read_only']=='on' and o['isolation']=='repeatable read','source fault owner observer invalid');r=one(s['run'],'one original run');t=one(s['task'],'one original task');need(r['id']==t['run_id']==target['runId'] and r['task_ids']==['S1','M1','H1'] and r['mode']=='training' and t['task_id']=='S1' and t['task_index']==0,'source fault scope differs');need(ms(s['observationCompletedAt'])>=ms(o['observed_at']),'source fault completion witness precedes reads');return s

def verify_source_negative(reference,*,actor_reference,repository_root):
 repo=repository_root;proof=load_ref(repo,reference);actor=load_ref(repo,actor_reference);need(proof['schemaVersion']=='ber-source-observation-fault/v1' and proof['status']=='captured_requires_independent_replay','actual source fault capture missing');target=proof['target'];v=target['variant'];need(v in REASONS and target['taskIndex']==0 and target['taskId']=='S1' and target['mode']=='training' and target['profile']=='B' and target['databaseName']=='oid_acceptance_'+target['captureId'].replace('-',''),'invalid finite source fault target');need(actor['runId']==target['runId'] and actor['berMatrix']['profile']=='B' and actor['taskIds']==['S1','M1','H1'],'source fault actor differs')
 seam=actor['berSourceObservationFault'];need(seam['status']=='captured' and seam['evidence']==reference and seam['variant']==v,'fault not bound to original actor');before=actor['provenance']['inputHashesBefore'];need(before and before==actor['provenance']['inputHashesAfter'],'actor source drift')
 for pin in before:read_reference(repo,pin,json_body=False)
 phases=['before_finish_armed','fresh_observe_unavailable_no_evaluation','passthrough_restored','normal_known_once_and_handoff'];need([x['phase'] for x in proof['checkpoints']]==phases,'source fault lifecycle incomplete');cp=[_snapshot(x['ref'],target,repo) for x in proof['checkpoints']];first,bad,restored,known=cp
 need(first['task'][0]['closure_status']=='open' and not first['bundle'] and not first['evaluation'],'source fault armed after grade');finish=proof['actualMcpFinish'];closed=bad['task'][0];need(closed['closure_status']=='closed' and closed['closure_id']==finish['closureId'] and int(closed['action_cutoff_sequence'])==int(closed['reconciled_action_sequence'])==4 and not bad['bundle'] and not bad['evaluation'] and not bad['successorPreparations'],'unknown fault fabricated grade or progressed successor')
 for snapshot in cp:
  need(snapshot['actions']==first['actions'] and snapshot['history']==first['history'] and snapshot['money']==first['money'],'source fault changed original action/history/finance')
 for snapshot in cp[1:]:need(snapshot['task'][0]['closure_id']==closed['closure_id'] and snapshot['closures']==bad['closures'],'source fault changed original closure')
 arm=load_ref(repo,proof['armControlRef']);passthrough=load_ref(repo,proof['passthroughRestoredRef']);need(arm['schemaVersion']==passthrough['schemaVersion']=='ber-source-fault-control/v1' and arm['mode']=='armed' and passthrough['mode']=='pass' and arm['target']==passthrough['target']==target,'actual scoped arm/passthrough controls differ')
 deadline=min(ms(closed['closed_at'])+180000,ms(bad['run'][0]['overall_deadline']));progress=proof['failureProgress'];body=load_ref(repo,progress);need(body['schemaVersion']=='local-bef-task-observation-progress/v1' and body['runId']==target['runId'] and body['taskIndex']==0 and body['stage']=='observe' and body['status'] in ('blocked','unavailable') and body['reasonCode']==REASONS[v] and all(progress[k]==body[k] for k in ('stage','status','reasonCode')) and progress['sha256'] not in proof['excludedPriorProgressHashes'],'fault lacks precise fresh expected actual unknown')
 need(ms(closed['closed_at'])<=ms(progress['modifiedAt'])<=ms(proof['passthroughRestoredAt'])<=deadline,'source fault reason stale or recovery deadline reset')
 registry=verify_query_registry(load_ref(repo,proof['queryRegistryRef']),repo);interventions=proof['interventions'];need(interventions,'no actual changed source read retained');seen=set()
 causal_intervention=False
 for ref in interventions:
  item=load_ref(repo,ref);need(item['schemaVersion']=='ber-source-observation-intervention/v1','unknown intervention schema');need(ms(item['observedAt'])>=ms(closed['closed_at']) and ms(item['observedAt'])<=deadline,'actual source delivery outside original closed recovery window');causal_intervention|=ms(item['observedAt'])<=ms(progress['modifiedAt']);key=(item['originalRef']['path'],item['deliveredRef']['path']);need(key not in seen,'duplicate intervention');seen.add(key);original=load_ref(repo,item['originalRef']);verify_source_transformation(target,original,load_ref(repo,item['deliveredRef']),item)
  if item['kind']=='postgres_result':need(any(q['sqlSha256']==original['querySha256'] and q['columns']==original['columns'] for q in registry.values()),'actual SQL read is outside fixed source registry')
  w=_snapshot(item['ownerClosedWitnessRef'],target,repo);need(w['task'][0]['closure_id']==closed['closure_id'] and not w['bundle'] and not w['evaluation'],'intervention not at original closed/no-evaluation boundary')
 need(causal_intervention,'no retained source delivery precedes actual fresh unknown');need(len(known['evaluation'])==len(known['bundle'])==len(known['terminalEvents'])==1 and ms(known['evaluation'][0]['created_at'])>=ms(proof['passthroughRestoredAt']) and ms(known['evaluation'][0]['created_at'])<=deadline,'normal original evaluation missing, duplicated or outside recovery bound')
 bundle=known['bundle'][0]['bundle_json'];need(digest(bundle)==known['bundle'][0]['bundle_hash'] and bundle['cutoff']['evidence']==proof['originalRootRef'],'recovered original sealed root differs');context=owner_context(known,bundle);effects=verify_generic_family_root(proof['originalRootRef'],context,repository_root=repo);link=verify_known_input(known,bundle,actor,repo);projection=verify_derived_chain_effects(effects['children']['chain'],effects['root']['census']['entries'],effects['documents'],bundle,repo)
 chain=effects['children']['chain'];entries=effects['root']['census']['entries'];selected=entries[-1] if v in ('read_missing','block_missing') else entries[0];need(selected['actionId']==target['actionId'] and selected['ownerOperationId']==target['ownerOperationId'] and selected['transactionHash']==target['transactionHash'],'fault target not exact original fixed action');action=one([a for a in chain['ownerActions'] if a['actionId']==target['actionId']],'source target original chain action');need(action['befOperationId']==target['befOperationId'],'source target BEF operation differs')
 for ref in interventions:
  item=load_ref(repo,ref);original=load_ref(repo,item['originalRef'])
  if item['kind']=='rpc_result':need(any(h['method']==original['request']['method'] and h['paramsSha256']==digest(original['request']['params']) and h['resultSha256']==digest(original['body']['result']) for h in chain['rpc']['responseHashes']),'original upstream reply not bound to independently replayed recovered RPC source')
  elif v=='census_contradictory':
   counts=chain['bef']['before']['counts'];need(original['rows']==[{'operations':counts['operations'],'selected_executions':counts['selectedExecutions'],'selected_events':counts['selectedEvents'],'costs':counts['costs']}],'original aggregate not actual recovered independent census')
  elif v=='census_truncated':
   for row in original['rows']:
    event=one([e for e in chain['bef']['before']['selectedEvents'] if e['eventId']==row['event_id']],'original raw source event absent');need(row['env_id']==target['environmentId'] and row['generation_id']==target['generationId'] and event['eventJsonSha256']==digest(row['event_json']) and event['operationId']==row['operation_id'] and event['eventKind']==row['event_kind'] and event['transactionHash']==row['transaction_hash'] and str(event['eventSequence'])==str(row['event_sequence']),'original event preimage differs from recovered source')
  else:
   for row in original['rows']:
    cost=one([c for c in chain['bef']['before']['costs'] if c['operationId']==row['operation_id']],'original independent cost absent');camel=lambda key:'environmentId' if key=='env_id' else key.split('_')[0]+''.join(p[:1].upper()+p[1:] for p in key.split('_')[1:]);need({camel(k):val for k,val in row.items()}==cost,'original raw cost differs from recovered source')
 from tests.bdd.adapters.ber_s4_preparation_replay import verify_bef_boundary
 verify_bef_boundary(load_ref(repo,proof['befBeforeRef']),target,'active');verify_bef_boundary(load_ref(repo,proof['befAfterRef']),target,'fenced')
 need(effects['originalActionCount']==4 and effects['actualPaymentCount']==effects['actualDeliveryCount']==0,'source fault changed fixed original chain strategy')
 need(known['leases'][0]['state']=='fenced' and known['successorPreparations'] and any(t['task_index']==1 and t['status'] in ('active','completed','failed') for t in known['allTasks']),'source fault did not fence/handoff after normal recovery')
 from tests.bdd.adapters.ber_generic_recovery_replay import closure_inventory
 actual_closure=closure_inventory(proof['originalRootRef'],repo);need({r['path']:r['sha256'] for r in proof['retainedObservationClosure']}==actual_closure,'recovered source closure inventory truncated or changed')
 files={};total=0
 for ref in proof['artifactInventory']:
  need(ref['path'] not in files,'duplicate source fault artifact');raw=read_reference(repo,ref,json_body=False);need(len(raw)==ref['bytes'] and len(raw)<=8*1024*1024,'source fault artifact bound/size');total+=len(raw);files[ref['path']]=ref['sha256']
 need(total<=32*1024*1024 and all(files.get(p)==h for p,h in actual_closure.items()),'source fault artifact closure bound/inventory')
 return {'schemaVersion':'ber-source-negative-replay/v1','variant':v,'runId':target['runId'],'actualInterventions':len(interventions),'verifiedSubset':True,'originalFactsUnchanged':True,'preciseUnknownWithoutEvaluation':True,'storedEvaluatorLink':link,'independentDerivedEffects':projection,'fullBERAcceptance':False}


def main(argv=None):
 import argparse,traceback
 from tests.bdd.adapters.ber_matrix_replay import bounded_json,exact_ref,immutable_report
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--repo-root',required=True);p.add_argument('--fault-ref',required=True);p.add_argument('--actor-ref',required=True);p.add_argument('--output',required=True);a=p.parse_args(argv);repo=Path(a.repo_root).resolve()
 try:
  result=verify_source_negative(exact_ref(bounded_json(a.fault_ref)),actor_reference=exact_ref(bounded_json(a.actor_ref)),repository_root=repo);ref=immutable_report(a.output,result,repo);print(json.dumps({'status':'verified_subset','report':ref,'positive135Cells':0}));return 0
 except (AssertionError,KeyError,TypeError,ValueError,OSError) as error:
  frames=[{'file':'tests/bdd/adapters/'+Path(f.filename).name,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(error.__traceback__) if 'tests/bdd/adapters' in f.filename.replace('\\','/')][-8:]
  print(json.dumps({'status':'blocked','code':'BER_SOURCE_NEGATIVE_EVIDENCE_UNVERIFIABLE','errorClass':type(error).__name__,'frames':frames}));return 2
if __name__=='__main__':raise SystemExit(main())
