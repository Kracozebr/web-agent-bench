"""Independent public generic seal/evidence recovery subset. Legacy readers stay separate.
No action/RPC/DB clients, scoring implementation, or complete BER gate promotion.
"""
import hashlib
import json
import re
from datetime import datetime
from fractions import Fraction
from pathlib import Path
from tests.bdd.adapters.ber_recovery_replay import read_reference,digest,dispatch_recovery_observation_packets
from tests.bdd.adapters.ber_generic_family_replay import verify_generic_family_root,need,one,doc
SCHEMA='ber-generic-seal-evidence-fault/v1'
CODES={'missing_child':'TASK_EVIDENCE_FILE_UNAVAILABLE','corrupt_child':'TASK_EVIDENCE_FILE_HASH_MISMATCH'}
def epoch(v):return datetime.fromisoformat(v.replace('Z','+00:00')).timestamp()
def state(ref,root,target):
    value=read_reference(root,ref);i=value['identity'];need(i['role']=='oid_observer' and i['database_name']==target['databaseName'] and i['read_only']=='on' and i['isolation']=='repeatable read','fault observer scope differs')
    run=one(value['run'],'one original run required');task=one(value['task'],'one original task required');need(run['id']==task['run_id']==target['runId'] and task['task_index']==target['taskIndex'] and task['task_id']==target['taskId'],'fault target scope differs')
    return value

def owner_context(known,bundle):
    run=one(known['run'],'known original run missing');task=one(known['task'],'known original task missing');prep=one(known['preparations'],'original preparation missing');eb=one(known['executionBindings'],'original execution missing');closure=one(known['closures'],'original closure missing')
    pins=bundle['binding'];need(all(run[k]==pins[v] for k,v in [('id','runId'),('owner_id','ownerId'),('agent_id','agentId'),('release_identity','releaseIdentity'),('manifest_hash','manifestHash')]),'known run pins differ')
    execution={k:prep[v] for k,v in [('preparationId','preparation_id'),('leaseId','lease_id'),('environmentId','environment_id'),('environmentManifestHash','environment_manifest_sha256'),('applicationSourceHash','application_source_hash'),('executionIdentityHash','execution_identity_hash'),('initialStateSha256','initial_state_sha256')]};execution['generationId']=eb['generation_id']
    need(eb['env_id']==pins['environmentId'] and eb['manifest_hash']==execution['environmentManifestHash'] and eb['application_source_hash']==execution['applicationSourceHash'],'known execution SQL pins differ')
    c={'closureId':closure['id'],'operationId':closure['operation_id'],'payloadHash':closure['payload_hash'],'reason':closure['reason'],'actionCutoffSequence':int(closure['action_cutoff_sequence']),'reconciledActionSequence':int(task['reconciled_action_sequence'])}
    need(c==bundle['closure'],'original closure SQL differs from sealed root')
    return {'source':'postgresql_observer','observer':{'role':known['identity']['role'],'readOnly':known['identity']['read_only']=='on','databaseName':known['identity']['database_name']},'binding':pins,'execution':execution,'closure':c,'taskIndex':task['task_index'],'rows':known['actions']}

def verify_known_input(known,bundle,actor,root):
    evaluation=one(known['evaluation'],'known evaluation missing');input_=doc(evaluation['input_json']);result=doc(evaluation['result_json']);run=one(known['run'],'known run missing')
    need(digest(input_)==evaluation['input_hash'] and digest(result)==evaluation['result_hash'],'known input/result hash differs')
    need(input_['observations']==bundle['observations'] and input_['run']['cutoffEvidence']==bundle['cutoff']['evidence'],'sealed effects did not reach original evaluator')
    need(all(input_['run'].get(k)==v for k,v in bundle['binding'].items()) and input_['run']['acceptedActionCutoffSequence']==input_['run']['reconciledThroughActionSequence']==bundle['closure']['actionCutoffSequence'],'known evaluator closure/binding differs')
    release=input_['release'];case=input_['taskCase'];need(digest({k:v for k,v in release.items() if k!='manifestHash'})==release['manifestHash'] and digest({k:v for k,v in case.items() if k!='caseHash'})==case['caseHash'],'immutable release/case hash differs')
    for sql,key in [('release_identity','releaseIdentity'),('manifest_hash','manifestHash'),('benchmark_version','benchmarkVersion'),('benchmark_hash','benchmarkHash'),('policy_hash','policyHash')]:need(run[sql]==release[key],'original admitted release pin differs '+key)
    need(case==one([c for c in release['cases'][run['mode']] if c['taskId']==bundle['binding']['taskId']],'admitted case missing'),'original evaluator case changed')
    need(case['rubricHash']==bundle['binding']['rubricHash'] and case['caseHash']==bundle['binding']['caseHash'] and evaluation['closure_id']==bundle['closure']['closureId'],'rubric/evaluation closure changed')
    need(result['status']=='known' and result['unknownReasons']==[] and result['taskId']==case['taskId'],'known result missing');credit=Fraction(int(result['credit']['numerator']),int(result['credit']['denominator']));need(0<=credit<=1 and ((result['outcome']=='failed' and credit==0) or(result['outcome']=='passed' and credit==1) or(result['outcome']=='partial' and 0<credit<1)),'typed known result contradicts credit')
    sources={r['path']:r['sha256'] for r in actor['provenance']['inputHashesBefore']};runtime=hashlib.sha256()
    for name in ('task-evaluator','task-release','task-catalog'):
        source='packages/owner-identity/src/'+name+'.ts';need(hashlib.sha256((root/source).read_bytes()).hexdigest()==sources[source],'captured evaluator source changed');runtime.update((name+'.js\n').encode());runtime.update((root/('packages/owner-identity/dist/'+name+'.js')).read_bytes())
    need(runtime.hexdigest()==evaluation['evaluator_source_hash'],'recorded evaluator modules differ')
    return {'inputHash':evaluation['input_hash'],'resultHash':evaluation['result_hash'],'evaluatorSourceHash':runtime.hexdigest(),'credit':result['credit'],'rescored':False}

def closure_inventory(reference,root):
    """Derive the complete original reference closure, independent of producer inventory flags."""
    pending=[reference];seen={};total=0
    def collect(value):
        if isinstance(value,list):
            for child in value:collect(child)
        elif isinstance(value,dict):
            if isinstance(value.get('path'),str) and isinstance(value.get('sha256'),str):pending.append({'path':value['path'],'sha256':value['sha256']})
            for child in value.values():collect(child)
    while pending:
        need(len(seen)+len(pending)<=1024,'reference closure exceeds approved bound')
        ref=pending.pop();path=ref['path']
        if path in seen:need(seen[path]==ref['sha256'],'conflicting original reference hashes');continue
        raw=read_reference(root,ref,json_body=False);seen[path]=ref['sha256'];total+=len(raw);need(total<=32*1024*1024,'reference closure bytes exceed approved bound')
        try:value=json.loads(raw)
        except (ValueError,UnicodeError):continue
        collect(value)
    return seen



def verify_controlled_s1_effect_projection(effects, bundle, evaluation):
    """The approved S1 wrong-principal branch only, never an independent task scorer."""
    actual=one(effects['children']['paid']['bef']['before']['payments'],'original payment absent');obs=bundle['observations'];result=doc(evaluation['result_json']);input_=doc(evaluation['input_json']);packet=effects['root']
    payment=one(obs['payments'],'actual payment omitted or duplicated before grading');transfer=one(obs['transfers'],'actual paid principal omitted or duplicated before grading');need(obs['deliveries']==[],'payment was silently projected as delivery')
    recipient=actual.get('payment_recipient') or actual['facilitator_address'];pay=one([e for e in packet['census']['entries'] if e['actionKind']=='pay'],'original pay action absent')
    need(payment['binding']==transfer['binding']==packet['binding'] and payment['actionSequence']==transfer['actionSequence']==pay['actionSequence'] and payment['transactionHash']==transfer['transactionHash']==actual['transaction_hash'],'chosen paid effect identity changed before evaluator')
    need(payment['status']=='settled' and payment['paymentAttemptId']==transfer['paymentAttemptId']==actual['payment_id'] and transfer['receiptStatus']=='success' and transfer['assetId']=='USDC' and transfer['from']=='participant' and transfer['to']==recipient and transfer['amountUnits']==actual['amount_units'],'actual paid principal changed before evaluator')
    need(payment['evidence']==transfer['evidence']==packet['children']['paid']['evidence'],'projected effect evidence changed')
    terms=payment['requirements'];need(terms['recipient']==recipient and terms['amountUnits']==actual['amount_units'] and terms['resourceId']==pay['command']['resourceId'] and terms['offerId']==pay['command']['offerId'],'actual chosen payment terms changed before evaluator')
    goal=input_['taskCase']['objective'];need(recipient!=goal['recipient'].lower() or actual['amount_units']!=goal['exactPrincipalUnits'],'not controlled S1 wrong principal')
    need(result['status']=='known' and result['outcome']=='failed' and result['credit']=={'numerator':'0','denominator':'1'} and result['mandatoryViolation']=={'rule':'wrong_or_extra_principal','observationIds':[transfer['observationId']]},'existing wrong-principal result does not cite proven actual effect')
    return {'actualChosenPrincipalReachedEvaluator':True,'existingMandatoryRule':'wrong_or_extra_principal','paymentNotDelivery':True,'rescored':False}



def require_original_root_pointer(sealed, discovered):
    """Producer discovery is an exact two-field pin; sealed evidence adds its required boundary."""
    need(isinstance(sealed,dict) and set(sealed)=={'path','sha256','boundary'} and sealed['boundary']=='actual_tool_http_x402_local_evm_application_store','sealed root boundary differs')
    need(isinstance(discovered,dict) and set(discovered)=={'path','sha256'} and all(sealed[key]==discovered[key] for key in ('path','sha256')),'original discovered root pin differs')


def verify_generic_seal_fault(reference, *, actor_reference, repository_root):
    root=Path(repository_root);proof=read_reference(root,reference);actor=read_reference(root,actor_reference);need(proof['schemaVersion']==SCHEMA and proof['classification']=='acceptance_fault_raw_NOT_gate' and proof['status']=='captured_subset_requires_independent_raw_replay','unsupported or incomplete fault capture')
    target=proof['target'];variant=target['variant'];profile=target.get('targetProfile','paid_s1');registry={'paid_s1':('training',['S1'],'S1',0,'paid'),'chain_s1':('training',['S1','M1','H1'],'S1',0,'chain'),'composite_u1':('ranked',['S1','S2','S3','S4','M1','M2','M3','M4','H1','H2','H3','U1'],'U1',11,'chain')};need(profile in registry,'unsupported finite fault profile');mode,ids,taskid,index,childname=registry[profile];need(variant in (*CODES,'restart_blocked_seal') and target['taskId']==taskid and target['taskIndex']==index and re.fullmatch(r'oid_acceptance_[a-f0-9]{32}',target['databaseName']),'unsupported approved fault target')
    need(actor['runId']==target['runId'] and actor['mode']==mode and actor['taskIds']==ids,'fault actor differs');seam=actor['berGenericSealFault'];need(seam['schemaVersion']=='ber-generic-seal-fault-seam/v1' and seam['status']=='captured' and seam['variant']==variant and seam['evidence']==reference,'fault is not bound to actual actor')
    before=actor['provenance']['inputHashesBefore'];need(before and before==actor['provenance']['inputHashesAfter'] and len({r['path'] for r in before})==len(before),'actor source changed')
    for pin in before:read_reference(root,pin,json_body=False)
    checkpoints={c['phase']:c for c in proof['checkpoints']};need(len(checkpoints)==len(proof['checkpoints']),'duplicate fault phase')
    required={'armed','seal_actually_blocked','normal_worker_known_once', 'stopped_uncommitted_seal' if variant=='restart_blocked_seal' else 'actual_unavailable_no_evaluation'};need(set(checkpoints)==required,'incomplete fault phase inventory')
    states={k:state(c['ref'],root,target) for k,c in checkpoints.items()};armed,blocked,known=(states[k] for k in ('armed','seal_actually_blocked','normal_worker_known_once'))
    need(armed['bundle']==armed['evaluation']==blocked['bundle']==blocked['evaluation']==[],'fault started after seal/evaluation')
    task=one(blocked['task'],'blocked task missing');need(task['closure_status']=='closed' and task['closure_id']==proof['actualMcpFinish']['closureId'] and task['closure_operation_id']==proof['actualMcpFinish']['operationId'] and int(task['action_cutoff_sequence'])==int(task['reconciled_action_sequence'])==len(blocked['actions']),'actual finish/cutoff mismatch')
    need(abs(epoch(task['original_recovery_deadline'])-epoch(task['closed_at'])-180)<0.0001,'original recovery bound changed')
    controller=proof['controller'];need(controller['role']=='oid_owner' and controller['databaseName']==target['databaseName'] and any(l['granted']is False and l['mode']=='RowExclusiveLock' and controller['pid'] in l['blocking_pids'] for l in blocked['locks']),'no actual blocked original seal writer')
    need(epoch(armed['identity']['observed_at'])<=epoch(blocked['identity']['observed_at'])<=epoch(known['identity']['observed_at'])<epoch(task['original_recovery_deadline']),'fault recovery time order/bound differs')
    bundle=doc(one(known['bundle'],'one sealed recovery bundle required')['bundle_json']);need(digest(bundle)==known['bundle'][0]['bundle_hash'],'original recovery bundle hash differs');require_original_root_pointer(bundle['cutoff']['evidence'],proof['root'])
    for s in states.values():need(s['actions']==blocked['actions'] and s['money']==blocked['money'],'fault changed original actions or finance')
    need(known['task'][0]['closure_id']==task['closure_id'] and known['task'][0]['action_cutoff_sequence']==task['action_cutoff_sequence'],'recovery changed closure/cutoff')
    run=one(known['run'],'original financial run missing');money=known['money'];reserve=one([m for m in money if m['entry_type']=='reserve'],'original reserve missing');debit=one([m for m in money if m['entry_type']=='debit'],'original debit missing');quote=run['quote_price_units'];need(len(money)==2 and reserve['amount_units']==debit['amount_units']==quote and reserve['source_kind']==debit['source_kind'] and reserve['operation_id']=='runacc_'+target['runId'].replace('-','') and debit['operation_id']=='rundeb_'+target['runId'].replace('-',''),'original source financial identity changed')
    need(reserve['available_delta_units']=='-'+quote and reserve['reserved_delta_units']==quote and debit['available_delta_units']=='0' and debit['reserved_delta_units']=='-'+quote,'original source financial deltas differ')
    closure_refs={r['path']:r['sha256'] for r in proof['originalClosureIntegrity']};need(len(closure_refs)==len(proof['originalClosureIntegrity']) and closure_refs[proof['root']['path']]==proof['root']['sha256'],'original closure inventory ambiguous')
    for path,sha in closure_refs.items():read_reference(root,{'path':path,'sha256':sha},json_body=False)
    need(closure_inventory(proof['root'],root)==closure_refs,'original closure inventory omitted or substituted references')
    if variant in CODES:
        unavailable=states['actual_unavailable_no_evaluation'];need(unavailable['evaluation']==[] and unavailable['run'][0]['status']=='running','unknown effect acquired grade/terminal state')
        change=proof['fileIntervention'];original=read_reference(root,change['originalArchive'],json_body=False);restored=read_reference(root,change['ref'],json_body=False);need(original==restored and change['originalArchive']['sha256']==change['ref']['sha256'],'recovery did not restore identical original child bytes')
        packet=read_reference(root,proof['root']);need(change['ref']==packet['children'][childname]['evidence'] and closure_refs[change['ref']['path']]==change['ref']['sha256'],'fault targeted another child')
        untouched=proof['unaffectedClosureAtUnavailable'];need(len({r['path'] for r in untouched})==len(untouched) and {r['path']:r['sha256'] for r in untouched}=={p:s for p,s in closure_refs.items() if p!=change['ref']['path']},'missing actual unchanged-ref observation at fault window')
        baseline_sizes={r['path']:r['size'] for r in proof['originalClosureIntegrity']}
        need(all(r['size']==baseline_sizes[r['path']] for r in untouched),'unchanged-ref bytes differ at fault window')
        progress=checkpoints['actual_unavailable_no_evaluation']['progress'];body=read_reference(root,progress);need(all(body.get(k)==v for k,v in progress['document'].items()) and body['schemaVersion']=='local-bef-task-observation-progress/v1' and body['runId']==target['runId'] and body['taskIndex']==index and body['stage'] in ('seal','reload') and body['status'] in ('blocked','unavailable') and body['reasonCode']==CODES[variant] and progress['sha256'] not in proof['excludedPriorProgressHashes'],'missing actual fresh causal evidence failure')
        need(epoch(blocked['identity']['observed_at'])<=epoch(progress['modifiedAt'])<=epoch(unavailable['identity']['observed_at']),'fault progress predates intervention')
        observed=change['atUnavailable'];need(change['afterRestoration']['exists']is True and change['afterRestoration']['sha256']==change['ref']['sha256'],'restoration observation differs')
        if variant=='missing_child':need(observed['exists']is False and Path(change['ref']['path']).name not in observed['directoryEntries'],'missing-child raw directory observation differs')
        else:
            altered=read_reference(root,change['changedArchive'],json_body=False);need(len(altered)==len(original) and sum(a!=b for a,b in zip(original,altered))==1 and observed['exists']is True and observed['sha256']==change['changedArchive']['sha256'],'actual one-byte corruption evidence differs')
    else:
        stopped=states['stopped_uncommitted_seal'];stop,restart=proof['stop'],proof['restart'];need(stop['schemaVersion']=='beta-local-api-stop-receipt/v1' and restart['schemaVersion']=='beta-local-api-restart-receipt/v1' and stop['previousPid']==restart['previousPid']!=restart['currentPid'] and restart['healthHttpStatus']==200,'actual owned restart identity missing')
        need(stopped['bundle']==stopped['evaluation']==[] and not any(not l['granted'] and controller['pid'] in l['blocking_pids'] for l in stopped['locks']),'stopped blocked transaction did not roll back')
        need(epoch(blocked['identity']['observed_at'])<=epoch(stop['startedAt'])<=epoch(stop['finishedAt'])<=epoch(stopped['identity']['observed_at'])<=epoch(restart['startedAt'])<=epoch(restart['finishedAt'])<=epoch(known['identity']['observed_at']),'actual restart causal order differs')
    context=owner_context(known,bundle);effects=verify_generic_family_root(proof['root'],context,repository_root=root);linked=verify_known_input(known,bundle,actor,root)
    if profile=='paid_s1':
        need(effects['actualPaymentCount']==1 and effects['actualDeliveryCount']==0 and effects['originalActionCount']==3,'not exact controlled pay-without-retrieve recovery subset')
        projection=verify_controlled_s1_effect_projection(effects,bundle,known['evaluation'][0])
    else:
        from tests.bdd.adapters.ber_matrix_derived_effects import verify_derived_chain_effects
        task_actor=one([t for t in actor['berMatrix']['tasks'] if t['taskIndex']==index],'actual fault matrix task missing');entries=effects['root']['census']['entries'];need(len(task_actor['actions'])==len(entries),'fault actor/census differs')
        for a,e in zip(task_actor['actions'],entries):need(a['actionId']==e['actionId'] and a['operationId']==e['ownerOperationId'] and a['command']==e['command'],'fault actor original chosen action differs')
        projection=verify_derived_chain_effects(effects['children']['chain'],entries,effects['documents'],bundle,root)
        need(effects['originalActionCount']==(4 if profile=='chain_s1' else 8) and effects['actualPaymentCount']==(0 if profile=='chain_s1' else 1) and effects['actualDeliveryCount']==(0 if profile=='chain_s1' else 1),'finite fault strategy effect count differs')
    return {'schemaVersion':'ber-generic-seal-fault-replay/v1','variant':variant,'runId':target['runId'],'actualOriginalPaymentCount':effects['actualPaymentCount'],'actualDeliveryCount':effects['actualDeliveryCount'],'originalClosureAndFinanceUnchanged':True,'storedEvaluatorLink':linked,'independentEffectProjection':projection,'verifiedSubset':True,'fullScenarioAcceptance':'blocked','missing':['all_approved_BER010_012_negative_and_recovery_variants','fresh_native_training_ranked_ui_database_acceptance']}
