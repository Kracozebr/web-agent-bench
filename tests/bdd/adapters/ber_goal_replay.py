"""Named goal comparisons over already independently verified effects; never a grader."""
import hashlib,re
from tests.bdd.adapters.ber_matrix_common import need,load_ref,one
from tests.bdd.adapters.ber_recovery_replay import read_reference
from tests.bdd.adapters.ber_chain_effects import verify_chain_action,address
RESERVE_NAMES={
 'BER S1 semantic reserve R-1: exact principal still receives known zero with native_reserve',
 'BER S1 semantic reserve R: exact principal receives full credit',
 'BER S1 semantic reserve R+1: exact principal receives full credit',
 'BER S1 semantic reserve missing: exact principal remains unknown rather than known zero'}

def verify_semantic_capture(reference,repo):
 c=load_ref(repo,reference);need(c['schemaVersion']=='ber-rubric-semantic-test-capture/v1' and c['boundary']=='pure_existing_evaluator_synthetic_inputs_NOT_live_chain_or_owner_acceptance' and c['exitCode']==0 and c['boundExceeded'] is False,'semantic source capture missing or failed');need('--test' in c['command'] and all(x in c['command'] for x in ('tests/integration/task-evaluator.test.mjs','tests/integration/ber-s1-reserve-boundary.test.mjs')),'semantic capture did not execute both required existing/new test suites')
 pins=c['sourceInputs']['before'];need(pins and pins==c['sourceInputs']['after'],'semantic test source changed');pins={r['path']:r['sha256'] for r in pins} if isinstance(pins,list) else pins
 for path,sha in pins.items():read_reference(repo,{'path':path,'sha256':sha},json_body=False)
 required=['tests/integration/task-evaluator.test.mjs','tests/integration/ber-s1-reserve-boundary.test.mjs']+[f'packages/owner-identity/{folder}/{name}.{ext}' for folder,ext in [('src','ts'),('dist','js')] for name in ('task-evaluator','task-release','task-catalog')];need(set(required)<=set(pins),'semantic evaluator/test source closure missing')
 tap=read_reference(repo,c['stdoutRef'],json_body=False).decode('utf-8');read_reference(repo,c['stderrRef'],json_body=False);names=set(re.findall(r'^ok [0-9]+ - (.+)$',tap,re.M));need(RESERVE_NAMES<=names and re.search(r'^# fail 0$',tap,re.M) and re.search(r'^# skipped 0$',tap,re.M) and not re.search(r'^not ok ',tap,re.M),'actual TAP does not prove all four isolated numeric reserve cases')
 runtime=hashlib.sha256()
 for name in ('task-evaluator','task-release','task-catalog'):runtime.update((name+'.js\n').encode());runtime.update((repo/f'packages/owner-identity/dist/{name}.js').read_bytes())
 return {'semanticOnly':True,'actualPassingTests':len(names),'reserveNumericBoundaryNames':sorted(RESERVE_NAMES),'runtimeEvaluatorModulesHash':runtime.hexdigest(),'isolatedLiveBelowReserveClaimed':False}

def verify_s1_native_arithmetic(chain,observations):
 participant=address(chain['rpc']['participant']);balance=lambda state:int(one([b for b in state['balances'] if b['account']=='participant' and b['assetId']=='ETH'],'one participant native balance')['amountUnits']);delta=0;assets={a['assetId']:address(a['address']) for a in chain['rpc']['assets'] if a.get('address')}
 for a in chain['ownerActions']:
  tx=one([t for t in chain['rpc']['transactions'] if t['hash']==a['transactionHash']],'original chain tx');fact=verify_chain_action(a['command'],tx,participant,assets,chain['rpc']['routes'],a['approvalSpender']);delta+=int(fact.get('participantDeltas',{'ETH':'-'+fact['gasWei']})['ETH'])
 own={a['transactionHash'] for a in chain['ownerActions']}
 for cost in chain['bef']['before']['costs']:
  if cost['transactionHash'] not in own and cost['payerRole']=='participant':delta-=int(cost['gasCostWei'])
 before=balance(chain['rpc']['baseline']);after=balance(chain['rpc']['final']);need(after-before==delta,'S1 final native principal/gas does not reconcile original operations');need(balance(one(observations['finalStates'],'one S1 evaluator final state'))==after,'S1 actual final native arithmetic did not reach evaluator');return {'initialNativeWei':str(before),'finalNativeWei':str(after),'netOriginalPrincipalAndGasWei':str(delta)}

def verify_goal_controls(selector,reports,repo):
 need(set(selector)=={'semanticRef'},'goal selector must use original semantic test capture');semantic=verify_semantic_capture(selector['semanticRef'],repo);seen={'objective_read':False,'off_goal_read':False,'wrong_recipient':False,'wrong_amount':False,'wrong_route':False,'wrong_allowance':False,'s1_wrong_extra':False};s1=[]
 for report in reports:
  owner=load_ref(repo,report['ownerRef'])
  for e in owner['evaluations']:
   need(e['evaluator_source_hash']==semantic['runtimeEvaluatorModulesHash'],'semantic and actual persisted evaluator runtime differ');inp=e['input_json'];obj=inp['taskCase']['objective'];obs=inp['observations'];bundle=one([b for b in owner['bundles'] if b['task_index']==e['task_index']],'one original bundle')['bundle_json'];root=load_ref(repo,bundle['cutoff']['evidence']);chain=load_ref(repo,root['children']['chain']['evidence']);entries=root['census']['entries'];ids={x['observationId'] for values in obs.values() if isinstance(values,list) for x in values if isinstance(x,dict) and 'observationId' in x};violation=e['result_json']['mandatoryViolation']
   if violation:need(isinstance(violation['observationIds'],list) and set(violation['observationIds'])<=ids,'named result cites no independently verified actual observation')
   resources={a['command']['resourceId'] for a in entries if a['actionKind']=='inspect_offer'};goals={obj['component']['resourceId']} if 'component' in obj else {c['resourceId'] for c in obj.get('requiredComponents',[]) if 'resourceId' in c}
   if resources&goals:seen['objective_read']=True
   if resources and not resources&goals:seen['off_goal_read']=True
   if e['task_id']=='S1':
    arithmetic=verify_s1_native_arithmetic(chain,obs);reserve=int(obj['nativeReserveWei']);s1.append({'runId':report['runId'],'mode':report['mode'],'profile':report['profile'],'actualArithmetic':arithmetic,'reserveSatisfied':int(arithmetic['finalNativeWei'])>=reserve,'inputHash':e['input_hash'],'resultHash':e['result_hash']})
    for t in obs['transfers']:
     if (t['from']=='participant' or t['from']==chain['rpc']['participant']) and t['assetId']==obj['tokenAssetId']:
      seen['wrong_recipient']|=t['to'].lower()!=obj['recipient'].lower();seen['wrong_amount']|=int(t['amountUnits'])!=int(obj['exactPrincipalUnits'])
    seen['s1_wrong_extra']|=bool(violation and violation['rule']=='wrong_or_extra_principal' and bool(violation['observationIds']) and e['result_json']['credit']=={'numerator':'0','denominator':'1'})
   if 'permittedRoutes' in obj:
    allowed={r['routeId'] for r in obj['permittedRoutes']};seen['wrong_route']|=any(t['routeId'] not in allowed for t in obs['trades'])
   if e['task_id']=='S4':seen['wrong_allowance']|=any(c['tokenAssetId']!=obj['tokenAssetId'] or c['spender'].lower()!=obj['spender'].lower() for c in obs['allowanceChanges'] if c['amountBeforeUnits']!=c['amountAfterUnits'])
 need(len(s1)==6 and {(r['mode'],r['profile']) for r in s1}=={(m,p) for m in ('training','ranked') for p in ('A','B','C')},'named S1 boundary missing actual source-bound strategy mode');need(all(seen.values()),'named actual goal/read/route/allowance violation coverage incomplete')
 return {'actualGoalPredicates':seen,'S1NativeArithmeticAndInputLinks':s1,'reserveSemantic':semantic,'isolatedLiveBelowReserveClaimed':False,'existingQualificationSeparatelyRequired':True,'rubricRescored':False}
