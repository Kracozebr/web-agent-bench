"""Immutable offline matrix replay CLI. Functional capture is distinct from qualified raw evidence."""
import argparse,json,sys,hashlib,os
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[3]))
from tests.bdd.adapters.ber_matrix_common import need,load_ref,source_window,digest,one
from tests.bdd.adapters.ber_matrix_core import verify_task,verify_evaluator_link,verify_readonly_task_paid_violation
from tests.bdd.adapters.ber_matrix_chain_projection import verify_chain_projection
from tests.bdd.adapters.ber_matrix_support import verify_chain_support
from tests.bdd.adapters.ber_matrix_state_effects import verify_supported_chain_effects
from tests.bdd.adapters.ber_matrix_rejection import verify_rejected_swap_task
TRAINING=['S1','M1','H1'];RANKED=['S1','S2','S3','S4','M1','M2','M3','M4','H1','H2','H3','U1'];KINDS=['inspect_catalog','inspect_offer','pay','retrieve','transfer','approve','swap','wrap','unwrap']
READER_PATHS=['tests/bdd/adapters/__init__.py', 'tests/bdd/adapters/benchmark_environment_feasibility.py', 'tests/bdd/adapters/benchmark_run_lifecycle.py', 'tests/bdd/adapters/benchmark_run_lifecycle_codex_verifier.py', 'tests/bdd/adapters/benchmark_run_lifecycle_verifier.py', 'tests/bdd/adapters/benchmark_task_suite.py', 'tests/bdd/adapters/ber_admitted_replay.py', 'tests/bdd/adapters/ber_chain_effects.py', 'tests/bdd/adapters/ber_full_replay.py', 'tests/bdd/adapters/ber_generic_family_replay.py', 'tests/bdd/adapters/ber_generic_recovery_replay.py', 'tests/bdd/adapters/ber_goal_replay.py', 'tests/bdd/adapters/ber_h1_replay.py', 'tests/bdd/adapters/ber_matrix_chain_family.py', 'tests/bdd/adapters/ber_matrix_chain_projection.py', 'tests/bdd/adapters/ber_matrix_common.py', 'tests/bdd/adapters/ber_matrix_core.py', 'tests/bdd/adapters/ber_matrix_derived_effects.py', 'tests/bdd/adapters/ber_matrix_rejection.py', 'tests/bdd/adapters/ber_matrix_replay.py', 'tests/bdd/adapters/ber_matrix_s4.py', 'tests/bdd/adapters/ber_matrix_state_effects.py', 'tests/bdd/adapters/ber_matrix_support.py', 'tests/bdd/adapters/ber_mcp_guards_replay.py', 'tests/bdd/adapters/ber_native_replay.py', 'tests/bdd/adapters/ber_recovery_replay.py', 'tests/bdd/adapters/ber_s4_preparation_replay.py', 'tests/bdd/adapters/ber_source_negative_replay.py', 'tests/bdd/adapters/beta_poc_delivery.py', 'tests/bdd/adapters/beta_poc_recovery_verifier.py', 'tests/bdd/adapters/registry.py', 'tests/bdd/adapters/sc011_resource_evidence.py', 'tools/harness_contracts.py', 'tools/replay_ber_recovery.py']

def reader_refs(repo):
 return [{'path':p,'sha256':hashlib.sha256((repo/p).read_bytes()).hexdigest()} for p in READER_PATHS]

def verify_declared_profile(profile,mode,taskid,entries,chain,documents,support=None):
 """Finite actor strategy evidence, not a new task goal or grader."""
 participant=chain['rpc']['participant'];W='1000000000000';wrap={'kind':'wrap','amountWei':'2000000000000','gasLimit':'100000'};approve={'kind':'approve','tokenAssetId':'WETH','amountUnits':W,'gasLimit':'100000'};swap={'kind':'swap','inputAssetId':'WETH','outputAssetId':'USDC','feeTier':500,'amountInUnits':W,'amountOutMinimumUnits':'1','recipient':participant,'gasLimit':'300000'};unwrap={'kind':'unwrap','amountWei':W,'gasLimit':'100000'}
 chosen=[e['command'] for e in entries];plan=profile
 if profile=='COMPOSITE_MIXED':plan='MIXED' if taskid in ('H3','U1') else 'A'
 if profile in ('NON_EOA_REJECTION','MCP_GUARDS'):plan='A'  # Its S1 denial takes the separate strict source guard path.
 if profile=='S4_RESTORED_ALLOWANCE_HISTORY':
  if taskid=='S4':return {'pattern':'separate_s4_history_control','verified':False}
  plan='A'
 def paid4(rows):
  need(len(rows)==4 and [e['actionKind'] for e in rows]==['inspect_catalog','inspect_offer','pay','retrieve'],'declared A4 paid/read/delivery union missing')
  read,pay,retrieve=rows[1:];need(rows[0]['command']=={'kind':'inspect_catalog'} and read['command']=={'kind':'inspect_offer','resourceId':pay['command']['resourceId'],'offerId':pay['command']['offerId']} and pay['command']=={'kind':'pay','resourceId':read['command']['resourceId'],'offerId':read['command']['offerId'],'offerReadActionId':read['actionId']} and retrieve['command']=={'kind':'retrieve','payActionId':pay['actionId']},'declared A4 original offer/payment/delivery references differ')
 if plan=='A':paid4(entries)
 elif plan=='B':need(chosen==[wrap,approve,swap,unwrap],'declared B4 exact chosen vector differs')
 elif plan=='C':
  need(len(chosen)==5 and chosen[:4]==[{'kind':'inspect_catalog'},wrap,approve,swap],'declared C5 conversion bootstrap differs');catalog=documents[entries[0]['actionId']]['participantToolResponse'];offers=[offer['payment'] for resource in catalog['catalog'] for offer in resource.get('offers',[])[:1] if isinstance(offer.get('payment'),dict)];need(offers,'C lacks published original payment recipient');need(chosen[4]=={'kind':'transfer','amountUnits':'1','recipient':offers[0]['payTo'],'gasLimit':'100000'},'declared C transfer does not use published payTo')
 elif plan=='MIXED':
  need(len(entries)==8,'declared composite is not A4+B4 under one cutoff');paid4(entries[:4]);need(chosen[4:]==[wrap,approve,swap,unwrap],'declared composite chain union differs');economic=[e['transactionHash'] for e in entries if e['actionKind'] in ('pay','wrap','approve','swap','unwrap')];need(len(economic)==len(set(economic))==5 and all(economic),'composite original economic transaction union differs')
 elif plan=='NOOP_REVERT_D':
  dwrap={**wrap,'amountWei':W};dswap={**swap,'amountOutMinimumUnits':str((1<<256)-1)};need(chosen==[dwrap,approve,approve,dswap] and all(e['receiptStatus']=='observed' for e in entries),'declared D4 no-op/revert chosen vector differs');txs=[one([t for t in chain['rpc']['transactions'] if t['hash']==e['transactionHash']],'D original transaction absent') for e in entries];need([t['status'] for t in txs]==['success','success','success','reverted'] and len({e['ownerOperationId'] for e in entries})==len({e['actionId'] for e in entries})==len({a['befOperationId'] for a in chain['ownerActions']})==len({t['hash'] for t in txs})==4,'D does not prove four distinct original observed/mined outcomes');need(txs[-1]['logs']==[] and int(txs[-1]['gasUsed'])>0 and int(txs[-1]['gasCostWei'])>0,'D final attempt is not a mined gas-consuming no-effect revert')
  if support is not None:
   noop=support['states'][entries[2]['actionId']];need(noop['before']['allowance.WETH']==noop['after']['allowance.WETH']==int(W),'D second original approval is not an actual no-op');last=support['states'][entries[3]['actionId']];need(all(last['before'][k]==last['after'][k] for k in last['before'] if k not in ('participant.ETH','participant.nonce')),'D reverted action has principal/allowance/pool mutation')
 else:need(False,'unknown finite declared profile')
 return {'pattern':plan,'verified':True,'secondGrader':False}

def verify_browser_results_link(actor,owner):
 run=owner['run'][0];launch=actor['launchIntent'];intent=launch['database'];need(launch['browserHttpStatus'] in (200,201) and launch['intentId']==intent['id']==run['intent_id'] and intent['owner_id']==run['owner_id'] and intent['agent_id']==run['agent_id'] and launch['mode']==intent['mode']==run['mode'] and intent['task_ids']==run['task_ids'],'browser launch does not bind original admitted owner run')
 action=one([r for r in actor['browserActionManifest'] if r['label']=='owner_run_intent_create'],'one actual browser intent mutation');need(action['method']=='POST' and action['path']=='/api/owner/runs/intents' and action['operationId']==launch['operationId'] and action['responseStatus'] in (200,201),'actual browser operation differs from original launch')
 browser=actor['browserWitness']['owner'];need(browser['schemaVersion']=='oid-browser-observation/v1','actual browser observation absent');path='/api/owner/runs/'+run['id']+'/results';need(any(r.get('method')=='GET' and r.get('path')==path for r in browser['requests']) and any(r.get('method')=='GET' and r.get('path')==path and r.get('status')==200 for r in browser['responses']),'actual browser results read absent')
 expected=[{'taskId':e['task_id'],'outcome':e['result_json']['outcome'],'credit':e['result_json']['credit']} for e in sorted(owner['evaluations'],key=lambda e:e['task_index'])];ui=actor['ownerRunResultsUi'];need(ui['browserHttpStatus']==200 and ui['runStatus']==run['status']=='completed' and ui['tasks']==expected,'actual rendered result differs from persisted evaluator')
 api=ui['resultsApi'];need(api['httpStatus']==200 and [{'taskId':t['taskId'],'outcome':t['outcome'],'credit':t['credit']} for t in api['tasks']]==expected and all(t['status']=='known' for t in api['tasks']),'actual results response differs from original UI and DB')
 return {'originalBrowserIntentOperation':launch['operationId'],'browserResultsPath':path,'actualRenderedTasksMatchDurableEvaluation':True,'producerVerifiedFlagUsed':False}

def verify_matrix(actor_ref,owner_ref,support_refs,repo):
 need(len(support_refs)<=12,'too many task support refs');actor=load_ref(repo,actor_ref);owner=load_ref(repo,owner_ref);matrix=actor['berMatrix'];mode=matrix['mode'];profile=matrix['profile'];expected=TRAINING if mode=='training' else RANKED if mode=='ranked' else None
 need(expected is not None and actor['taskIds']==expected and owner['run'][0]['id']==actor['runId'],'actor/owner full run scope differs');need(profile in ('A','B','C','NOOP_REVERT_D','COMPOSITE_MIXED','NON_EOA_REJECTION','S4_RESTORED_ALLOWANCE_HISTORY','MCP_GUARDS'),'unknown finite profile');need(profile not in ('COMPOSITE_MIXED','S4_RESTORED_ALLOWANCE_HISTORY') or mode=='ranked','control requires Ranked');need(profile not in ('NON_EOA_REJECTION','MCP_GUARDS') or mode=='training','control requires Training')
 need(len(owner['tasks'])==len(owner['evaluations'])==len(owner['bundles'])==len(matrix['tasks'])==len(expected),'run is only a partial prefix');need(owner['run'][0]['status']=='completed','original owner run not completed');terminal=actor['berMatrixQualification']['terminalMcp']['result'];need(terminal['runId']==actor['runId'] and terminal['terminal'] is True and terminal['status']=='completed','server MCP terminal not confirmed')
 browser_link=verify_browser_results_link(actor,owner);window=source_window(actor,repo);pinned={r['path']:r['sha256'] for r in actor['provenance']['inputHashesBefore']};readers=reader_refs(repo);reader_pinned=all(pinned.get(r['path'])==r['sha256'] for r in readers);complete=window['currentMatches'] and reader_pinned;reasons=[]
 if not window['currentMatches']:reasons.append('source_cohort_drift')
 if not reader_pinned:reasons.append('reader_not_pinned_in_actual_capture')
 source_control='berSourceObservationFault' in actor
 if source_control:complete=False;reasons.append('controlled_source_negative_not_positive_matrix')
 support_by_index={}
 for ref in support_refs:
  s=load_ref(repo,ref);i=s['target']['taskIndex'];need(type(i)is int and i not in support_by_index and s['target']['runId']==actor['runId'],'duplicate/foreign supporting capture');support_by_index[i]=ref
 results=[];cells=[]
 for index,taskid in enumerate(expected):
  if profile=='NON_EOA_REJECTION' and index==0:
   facts=verify_rejected_swap_task(owner,actor,index,repo);results.append({'taskId':taskid,'taskIndex':index,'rawComplete':True,'control':'deterministic_contract_recipient_rejection','facts':facts});continue
  facts=verify_task(owner,actor,index,repo);link=verify_evaluator_link(owner,actor,index,repo);row={'taskId':taskid,'taskIndex':index,'recordedCredit':facts['recordedCredit'],'evaluatorLink':link,'rawComplete':True};bundle=one([b for b in owner['bundles'] if b['task_index']==index],'original bundle missing')['bundle_json'];rootref=bundle['cutoff']['evidence'];root=load_ref(repo,rootref);chain=load_ref(repo,root['children']['chain']['evidence']);documents={e['actionId']:load_ref(repo,e['actionEvidence']) for e in root['census']['entries']};row['declaredProfile']=verify_declared_profile(profile,mode,taskid,root['census']['entries'],chain,documents)
  if taskid in ('S2','S3') and facts['paid']['actualPayments'] and facts['paid']['actualDeliveries']:row['namedViolation']=verify_readonly_task_paid_violation(owner,actor,index,repo)
  if facts['rawChainActionCount']:
   raw=verify_chain_projection(owner,actor,index,repo);row['rawReceiptAndParticipantState']=raw
   if taskid in ('S2','S3') and any(f.get('outcome')=='success' and any(int(v)!=0 for k,v in f.get('participantDeltas',{}).items() if k!='ETH') for f in raw['facts']):
    ev=one([e for e in owner['evaluations'] if e['task_index']==index],'readonly mutation evaluation');result=ev['result_json'];need(result['status']=='known' and result['credit']=={'numerator':'0','denominator':'1'} and result['mandatoryViolation']['rule']=='no_payment' and result['mandatoryViolation']['observationIds'],'actual readonly principal mutation did not reach existing mandatory zero');ids={x['observationId'] for values in ev['input_json']['observations'].values() if isinstance(values,list) for x in values if isinstance(x,dict) and 'observationId' in x};need(set(result['mandatoryViolation']['observationIds'])<=ids,'readonly mutation result references unknown observations');row['namedMutationViolation']={'existingMandatoryRule':'no_payment','actualPrincipalMutationProved':True,'knownCredit':result['credit'],'rubricRescored':False}
   if index not in support_by_index:row['rawComplete']=False;complete=False;reasons.append('per_action_direct_support_missing:'+str(index))
   else:
    support=verify_chain_support(support_by_index[index],rootref,owner,actor,index,repo);row['directStateEffects']=verify_supported_chain_effects(chain,root,bundle,support);row['declaredProfile']=verify_declared_profile(profile,mode,taskid,root['census']['entries'],chain,documents,support);row['support']={k:v for k,v in support.items() if k!='states'}
  results.append(row)
  if profile in ('A','B','C') and row['rawComplete']:
   for kind in set(facts['kinds']):cells.append({'variant':mode+':'+taskid,'kind':kind,'runId':actor['runId'],'taskIndex':index})
 if profile=='MCP_GUARDS':
  from tests.bdd.adapters.ber_mcp_guards_replay import verify_mcp_guards
  guard_facts=verify_mcp_guards(owner,actor)
 # Only a qualified actual source cohort may contribute cells; separate controls never pad135.
 if not complete:cells=[]
 return {'schemaVersion':'ber-independent-matrix-report/v1','actorRef':actor_ref,'ownerRef':owner_ref,'supportRefs':support_refs,'runId':actor['runId'],'mode':mode,'profile':profile,'functionalCaptured':True,'independentRawComplete':complete,'status':'verified_scope' if complete else 'incomplete','incompleteReasons':sorted(set(reasons)),'sourceWindow':window,'readerSources':readers,'readersPinnedInCapture':reader_pinned,'tasks':results,'browserUiAndDatabaseLink':browser_link,**({'mcpGuardFacts':guard_facts} if profile=='MCP_GUARDS' else {}),'positive135Cells':cells,'negativeControlOnly':source_control or profile not in ('A','B','C'),'full135Acceptance':False,'BER_SC009_012_complete':False,'nativeAgent':False,'rubricRescored':False}
def canonical_report_identity(value):
 # AICODE-NOTE: Matrix cells form a mathematical identity set. All other report
 # fields remain exact; normalization never permits a source/receipt/fact change.
 value=dict(value);cells=value['positive135Cells'];keys=[(c['variant'],c['kind'],c['runId'],c['taskIndex']) for c in cells]
 need(len(keys)==len(set(keys)),'duplicate report cell')
 need(all(set(c)=={'variant','kind','runId','taskIndex'} for c in cells),'unknown report cell field')
 value['positive135Cells']=sorted(cells,key=lambda c:(c['variant'],c['kind'],c['runId'],c['taskIndex']))
 return value

def collate_positive_reports(report_refs,repo):
 need(isinstance(report_refs,list) and len(report_refs)==6,'exact six A/B/C mode reports required');cells={};profiles=set();checked=[]
 for ref in report_refs:
  old=load_ref(repo,exact_ref(ref));need(old['schemaVersion']=='ber-independent-matrix-report/v1','unknown report schema');fresh=verify_matrix(old['actorRef'],old['ownerRef'],old['supportRefs'],repo);need(fresh['independentRawComplete'] and canonical_report_identity(fresh)==canonical_report_identity(old),'report no longer independently verifiable');key=(fresh['mode'],fresh['profile']);need(key not in profiles and key[1] in ('A','B','C'),'duplicate/nonpositive profile');profiles.add(key)
  for cell in fresh['positive135Cells']:cells.setdefault((cell['variant'],cell['kind']),[]).append({'runId':cell['runId'],'taskIndex':cell['taskIndex']})
  checked.append(ref)
 expected={(mode+':'+task,kind) for mode,tasks in [('training',TRAINING),('ranked',RANKED)] for task in tasks for kind in KINDS};need(set(cells)==expected and len(cells)==135,'actual positive135 coverage incomplete')
 return {'schemaVersion':'ber-independent-positive135-collation/v1','status':'verified_positive_cells','reports':checked,'actualUniqueCells':135,'cells':[{'variant':v,'kind':k,'originalRuns':runs} for (v,k),runs in sorted(cells.items())],'full135Acceptance':True,'BER_SC009_012_complete':False,'nativeAgent':False,'negativeControlsIncludedInPositiveCount':False,'rubricRescored':False}

def bounded_json(path):
 p=Path(path);need(p.is_file() and not p.is_symlink() and p.stat().st_size<=65536,'unbounded input selector');return json.loads(p.read_text(encoding='utf-8-sig'))
def exact_ref(value):need(isinstance(value,dict) and set(value)=={'path','sha256'},'selector must be exact path/hash reference');return value
def immutable_report(output,value,repo):
 p=Path(output).absolute();root=repo.resolve();need(p.is_relative_to(root/'.local') and not p.exists(),'report must be new .local artifact');cursor=p.parent
 while cursor!=root:need(not cursor.is_symlink(),'report symlink ancestor');cursor=cursor.parent
 p.parent.mkdir(parents=True,exist_ok=True)
 raw=(json.dumps(value,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode();need(len(raw)<=32*1024*1024,'report exceeds artifact bound');fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 os.chmod(p,0o400);return {'path':p.relative_to(root).as_posix(),'sha256':hashlib.sha256(raw).hexdigest()}
def main(argv=None):
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--repo-root',required=True);parser.add_argument('--actor-ref',required=True);parser.add_argument('--owner-ref',required=True);parser.add_argument('--support-refs',required=True);parser.add_argument('--output',required=True);args=parser.parse_args(argv);repo=Path(args.repo_root).resolve()
 try:
  support=bounded_json(args.support_refs);need(isinstance(support,list) and len(support)<=12,'support selector must be bounded reference array');result=verify_matrix(exact_ref(bounded_json(args.actor_ref)),exact_ref(bounded_json(args.owner_ref)),[exact_ref(r) for r in support],repo);ref=immutable_report(args.output,result,repo);print(json.dumps({'status':result['status'],'functionalCaptured':True,'independentRawComplete':result['independentRawComplete'],'report':ref}));return 0 if result['independentRawComplete'] else 2
 except (AssertionError,KeyError,ValueError,OSError,TypeError) as error:
  # Fixed public failure code. Raw exception text may contain sensitive retained input.
  import traceback
  frames=[{'file':'tests/bdd/adapters/'+Path(f.filename).name,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(error.__traceback__) if 'tests/bdd/adapters' in f.filename.replace('\\','/')][-8:]
  print(json.dumps({'status':'blocked','code':'BER_MATRIX_EVIDENCE_UNVERIFIABLE','errorClass':type(error).__name__,'frames':frames}));return 2
if __name__=='__main__':raise SystemExit(main())
