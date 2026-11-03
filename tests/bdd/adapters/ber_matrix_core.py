"""Independent generic owner/family raw replay. Never a complete matrix gate or scoring implementation."""
import base64,copy,json
from fractions import Fraction
from tests.bdd.adapters.ber_matrix_common import need,one,digest,load_ref,decode_transfer,decimal,TRANSFER,verify_original_owner_snapshot
FAMILIES={'inspect_catalog':'read','inspect_offer':'read','pay':'payment','retrieve':'payment','transfer':'chain','approve':'chain','swap':'chain','wrap':'chain','unwrap':'chain'}

def task_owner(owner,index):
 out=copy.deepcopy(owner)
 for key in ('tasks','actions','closures','preparations','executionBindings','bundles','evaluations'):
  out[key]=[x for x in owner[key] if x['task_index']==index]
 return out

def verify_task(owner,capture,index,repo):
 own=task_owner(owner,index);stored=one(own['bundles'],'original sealed task bundle missing');bundle=stored['bundle_json'];bundle=json.loads(bundle) if isinstance(bundle,str) else bundle
 packet=load_ref(repo,bundle['cutoff']['evidence']);binding=packet['binding'];entries=packet['census']['entries'];execpins=packet['execution'];closure=packet['closure']
 need(packet['schemaVersion']=='bts-admitted-actions-observation-capture/v1' and packet['taskIndex']==index,'wrong generic root scope')
 need([e['actionSequence'] for e in entries]==list(range(1,len(entries)+1)) and closure['actionCutoffSequence']==closure['reconciledActionSequence']==len(entries),'noncontiguous closure census')
 need(len({e['actionId'] for e in entries})==len(entries) and len({e['ownerOperationId'] for e in entries})==len(entries),'duplicate original identity')
 owners=verify_original_owner_snapshot(own,packet,capture,repo)
 actor=one([t for t in capture['berMatrix']['tasks'] if t['taskIndex']==index],'actual matrix task missing');need(actor['runId']==binding['runId'] and actor['taskId']==binding['taskId'] and actor['caseHash']==binding['caseHash'],'actor task binding differs')
 need(len(actor['actions'])==len(entries),'actor admitted inventory differs')
 docs={}
 for e,a in zip(entries,actor['actions']):
  need(e['actionKind'] in FAMILIES and e['family']==FAMILIES[e['actionKind']],'wrong family partition')
  need(e['actionId']==a['actionId'] and e['ownerOperationId']==a['operationId'] and e['command']==a['command'] and e['receiptStatus']==a['receiptStatus'] and e['transactionHash']==a.get('transactionHash'),'actual actor/owner identity differs')
  d=load_ref(repo,e['actionEvidence']);docs[e['actionId']]=d
  for k,v in {'schema':'bef-task-action-observation-v1','actionId':e['actionId'],'runId':binding['runId'],'taskIndex':index,'actionSequence':str(e['actionSequence']),'ownerOperationId':e['ownerOperationId'],'actionKind':e['actionKind'],'commandSha256':e['commandSha256'],'generationId':execpins['generationId'],'environmentId':binding['environmentId'],'status':e['receiptStatus']}.items():need(d.get(k)==v,'original action evidence differs '+k)
 children={name:load_ref(repo,packet['children'][name]['evidence']) for name in ('paid','chain')}
 for name,child in children.items():
  need(child['binding']==binding and all(closure.get(k)==v for k,v in child['closure'].items()),'child root scope differs')
  need(all(child['execution'].get(k)==v for k,v in execpins.items() if k!='environmentId'),'child execution differs')
  s=child['bef']['session'];need(s['sessionUser']==s['currentUser']=='bef_observer' and s['transactionReadOnly']=='on' and s['transactionIsolation']=='repeatable read' and s['superuser']is False and s['bypassRls']is False,'family observer is not readonly')
  need(child['bef']['before']==child['bef']['after'] and digest(child['bef']['before'])==child['bef']['censusSha256'],'family observation snapshot changed')
  boundary=packet['children'][name]['boundary'];need(boundary['actionCutoffSequence']==len(entries),'family cutoff differs')
 paid=children['paid'];chain=children['chain'];expected_paid=[e for e in entries if e['family']!='chain'];expected_chain=[e for e in entries if e['family']=='chain']
 for original,wanted in [(paid['ownerActions'],expected_paid),(chain['ownerActions'],expected_chain),(chain['externalActions'],expected_paid)]:
  need(len(original)==len(wanted),'family census omitted or duplicated chosen action')
  for row,e in zip(original,wanted):
   keys=('actionId','actionSequence','ownerOperationId','actionKind','commandSha256','transactionHash','actionEvidence')
   need(all(row.get(k)==e.get(k) for k in keys),'family original receipt differs')
   if e['family']!='chain':need(row.get('receiptStatus')==e['receiptStatus'],'paid family receipt status differs')
 manifest=load_ref(repo,chain['technicalScope']['manifest']);need(chain['technicalScope']['manifest']['sha256']==execpins['environmentManifestHash'],'technical source pin differs')
 need(chain['rpc']['baseline']['blockHash']==paid['rpc']['baselineBlock']['hash'] and chain['rpc']['final']['blockHash']==paid['rpc']['finalBlock']['hash'],'family RPC boundaries differ')
 asset=one([a for a in chain['rpc']['assets'] if a['assetId']=='USDC'],'USDC identity missing')['address'];need(asset==manifest['contracts']['usdc']['address'].lower(),'USDC differs from pinned source')
 paidfacts=verify_paid(entries,docs,paid,chain,asset)
 paidfacts['sealedProjection']=verify_paid_projection(bundle,packet,docs,paid,chain)
 final=one(bundle['observations']['finalStates'],'one final state projection required');need(final['binding']==binding and final['balances']==chain['rpc']['final']['balances'] and final['allowances']==chain['rpc']['final']['allowances'],'actual independent final state did not reach evaluator')
 evaluation=one(own['evaluations'],'persisted evaluation missing');result=evaluation['result_json'];result=json.loads(result) if isinstance(result,str) else result
 need(digest(result)==evaluation['result_hash'] and result['taskId']==binding['taskId'],'persisted result hash/identity differs')
 credit=Fraction(int(result['credit']['numerator']),int(result['credit']['denominator']));need(result['status']=='known' and result['unknownReasons']==[] and 0<=credit<=1,'unknown or invalid recorded result')
 need((result['outcome']=='passed' and credit==1) or (result['outcome']=='failed' and credit==0) or (result['outcome']=='partial' and 0<credit<1),'typed result inconsistency')
 return {'taskId':binding['taskId'],'taskIndex':index,'kinds':[e['actionKind'] for e in entries],'owner':owners,'paid':paidfacts,'recordedCredit':result['credit'],'rawChainActionCount':len(expected_chain),'chainEffectsIndependentlyReplayed':not expected_chain,'exactEvaluatorInputLinkVerified':False,'rubricRescored':False,'fullAcceptance':False}

def verify_paid(entries,docs,paid,chain,asset):
 before=paid['bef']['before'];payments=before['payments'];deliveries=before['deliveries'];actions={e['actionId']:e for e in entries};retrieved=0
 for e in entries:
  if e['actionKind'] in ('inspect_catalog','inspect_offer'):
   d=docs[e['actionId']];a=one([a for a in paid['ownerActions'] if a['actionId']==e['actionId']],'paid read action missing');op=one([o for o in before['operations'] if o['operation_id']==d['befOperationId']],'actual read operation missing');need(op['response_sha256']==d['rawResponseSha256']==a['rawResponseSha256'],'read response hash differs')
  elif e['actionKind']=='pay':
   d=docs[e['actionId']];p=one([p for p in payments if p['transaction_hash']==e['transactionHash']],'actual payment missing');tx=one([t for t in chain['rpc']['transactions'] if t['hash']==e['transactionHash']],'payment RPC transaction missing');need(tx['status']==p['receipt_status']=='success','payment success unverified')
   cost=one([c for c in before['costs'] if c['transaction_hash']==tx['hash']],'payment gas missing');need(decimal(tx['gasUsed'])*decimal(tx['effectiveGasPriceWei'])==decimal(cost['gas_cost_wei'])==decimal(tx['gasCostWei']),'payment gas arithmetic differs')
   actual=one([decode_transfer(l) for l in tx['logs'] if l.get('topics',[None])[0]==TRANSFER and l['address']==asset],'actual principal log missing');need(actual['from']==p['payer_address'] and actual['to']==(p.get('payment_recipient') or p['facilitator_address']) and actual['amountUnits']==p['amount_units'] and decimal(p['payer_balance_before'])-decimal(p['payer_balance_after'])==decimal(actual['amountUnits']),'payment SQL/log/balance differs')
   read=actions[e['command']['offerReadActionId']];need(read['actionKind']=='inspect_offer' and read['actionSequence']<e['actionSequence'],'pay references invalid prior read');body=docs[read['actionId']]['participantToolResponse'];first=body['offers'][0];need(body['resourceId']==e['command']['resourceId'] and first['id']==e['command']['offerId'] and body['payment']==first['payment'],'pay resource/offer canonical read differs');terms=body['payment'];need(terms['payTo'].lower()==actual['to'] and terms['amount']==actual['amountUnits'] and terms['asset'].lower()==asset,'actual principal differs from read offer')
  elif e['actionKind']=='retrieve':
   p=actions[e['command']['payActionId']];need(p['actionKind']=='pay' and p['actionSequence']<e['actionSequence'],'retrieve references invalid payment');doc=docs[e['actionId']];body=doc['participantToolResponse'];payload=base64.b64decode(body['contentBytes'],validate=True);need(base64.b64encode(payload).decode()==body['contentBytes'],'noncanonical delivery bytes');import hashlib
   need(hashlib.sha256(payload).hexdigest()==body['contentHash'],'delivered bytes do not match hash');row=one([d for d in deliveries if d['operation_id']==doc['befOperationId']],'delivery SQL row missing');need(row['resource_id']==body['resourceId']==p['command']['resourceId'] and row['content_sha256']==body['contentHash'] and int(row['byte_count'])==len(payload),'actual delivery store differs');retrieved+=1
 need(len(payments)==sum(e['actionKind']=='pay' for e in entries) and len(deliveries)==retrieved,'unmatched independent payment/delivery rows')
 return {'actualPayments':len(payments),'actualDeliveries':retrieved,'paymentDoesNotImplyDelivery':True,'producerVerificationFlagsUsed':False}

def verify_evaluator_link(owner,capture,index,repo):
 """Exact retained input/result/source linkage, without evaluating or changing any rubric."""
 import hashlib
 own=task_owner(owner,index);e=one(own['evaluations'],'original evaluation missing');b=one(own['bundles'],'original sealed bundle missing')['bundle_json'];b=json.loads(b) if isinstance(b,str) else b;i=e['input_json'];i=json.loads(i) if isinstance(i,str) else i
 need(digest(i)==e['input_hash'] and digest(e['result_json'])==e['result_hash'],'persisted evaluation input/result hash differs')
 need(i['observations']==b['observations'] and i['run']['cutoffEvidence']==b['cutoff']['evidence'],'persisted evaluator did not receive exact sealed effects')
 for key,value in b['binding'].items():need(i['run'].get(key)==value,'persisted evaluator binding differs '+key)
 need(i['run']['cutoffStatus']=='authoritative' and i['run']['acceptedActionCutoffSequence']==i['run']['reconciledThroughActionSequence']==b['closure']['actionCutoffSequence'],'persisted evaluator closure differs')
 run=owner['run'][0];release=i['release'];case=i['taskCase'];actual_release=one(owner['release'],'original admitted release row missing')
 for db,key in [('release_identity','releaseIdentity'),('manifest_hash','manifestHash'),('benchmark_hash','benchmarkHash'),('benchmark_version','benchmarkVersion'),('policy_hash','policyHash')]:need(actual_release[db]==release[key],'admitted immutable release differs '+key)
 need(run['release_identity']==release['releaseIdentity'] and run['manifest_hash']==release['manifestHash'],'run admitted release binding differs')
 need(digest({k:v for k,v in release.items() if k!='manifestHash'})==release['manifestHash'],'release canonical hash differs')
 need(case==one([c for c in release['cases'][run['mode']] if c['taskId']==e['task_id']],'admitted exact case missing'),'persisted evaluator case substituted')
 need(digest({k:v for k,v in case.items() if k!='caseHash'})==case['caseHash']==e['case_hash'] and case['rubricHash']==e['rubric_hash'],'case/rubric pins differ')
 need(e['closure_id']==b['closure']['closureId'] and e['release_identity']==release['releaseIdentity'] and e['manifest_hash']==release['manifestHash'],'evaluation original journal pins differ')
 pins={x['path']:x['sha256'] for x in capture['provenance']['inputHashesBefore']};need(capture['provenance']['inputHashesBefore']==capture['provenance']['inputHashesAfter'],'captured sources drifted')
 runtime=hashlib.sha256();source_refs=[]
 for name in ('task-evaluator','task-release','task-catalog'):
  src='packages/owner-identity/src/'+name+'.ts';raw=(repo/src).read_bytes();need(hashlib.sha256(raw).hexdigest()==pins[src],'evaluator source differs from actor capture')
  compiled='packages/owner-identity/dist/'+name+'.js';runtime.update((name+'.js\n').encode());runtime.update((repo/compiled).read_bytes());source_refs.append({'path':src,'sha256':pins[src]})
 need(runtime.hexdigest()==e['evaluator_source_hash'],'actual evaluator runtime modules differ from recorded evaluator digest')
 refs=e['observation_evidence'];need(refs['schemaVersion']=='bts-evaluation-evidence-manifest/v1','evaluation evidence manifest missing')
 for ref in refs['references']:load_ref(repo,ref)
 return {'exactPersistedInputHash':e['input_hash'],'exactPersistedResultHash':e['result_hash'],'sealedObservationsExactlyReachedEvaluator':True,'admittedReleaseCaseAndRubricPinsMatch':True,'runtimeEvaluatorModulesHash':runtime.hexdigest(),'sourceModulesUnchangedFromCapture':source_refs,'rubricRescored':False,'fullAcceptance':False}

def verify_payment_gas_projection(cost,projected,expenses,transaction,participant):
 """Raw facilitator cost remains measured; only actual participant gas is scored."""
 role=cost['payer_role'];need(role in ('participant','facilitator') and projected['gasPayer']==role,'payment gas payer differs from original source')
 sender=transaction['from'].lower();need(sender==cost['payer_address'].lower()==cost['transaction_from'].lower()==cost['receipt_from'].lower(),'actual gas payer does not match original transaction/receipt')
 need((sender==participant.lower())==(role=='participant'),'gas payer role contradicts independently pinned participant')
 need(cost['transaction_hash']==transaction['hash'] and cost['receipt_status']==transaction['status']=='success' and cost['receipt_block_hash']==transaction['blockHash'] and str(cost['receipt_block_number'])==str(transaction['blockNumber']),'raw payment gas receipt binding differs')
 need(cost['gas_used']==transaction['gasUsed'] and cost['effective_gas_price_wei']==transaction['effectiveGasPriceWei'] and decimal(cost['gas_used'])*decimal(cost['effective_gas_price_wei'])==decimal(cost['gas_cost_wei'])==decimal(transaction['gasCostWei']),'raw payment gas arithmetic differs')
 rows=[g for g in expenses if g.get('transactionHash')==transaction['hash']]
 if role=='participant':
  gas=one(rows,'actual participant payment gas omitted or duplicated');need(gas['component']=='participant_gas' and gas['sourceEffectId']=='bef-operation:'+cost['operation_id'] and gas['gasUsed']==cost['gas_used'] and gas['effectiveGasPriceWei']==cost['effective_gas_price_wei'] and gas['receiptStatus']==cost['receipt_status'],'scored participant payment gas differs from original receipt')
 else:need(rows==[],'facilitator gas fabricated as scored participant expense')
 return {'rawGasPayer':role,'rawGasWei':cost['gas_cost_wei'],'scoredParticipantGasCount':len(rows)}

def verify_paid_projection(bundle,packet,docs,paid,chain):
 """Prove actual decoded paid effects were included in sealed evaluator facts, not only collected."""
 obs=bundle['observations'];binding=packet['binding'];entries=packet['census']['entries'];payentries=[e for e in entries if e['actionKind']=='pay'];retrieveentries=[e for e in entries if e['actionKind']=='retrieve']
 need(len(obs['payments'])==len(payentries) and len(obs['deliveries'])==len(retrieveentries),'sealed paid projection omits or invents actions')
 for e in payentries:
  actual=one([p for p in paid['bef']['before']['payments'] if p['transaction_hash']==e['transactionHash']],'raw payment missing');projected=one([p for p in obs['payments'] if p['transactionHash']==e['transactionHash']],'payment missing from evaluator facts');transfer=one([t for t in obs['transfers'] if t.get('transactionHash')==e['transactionHash']],'actual paid principal missing from evaluator facts')
  need(projected['binding']==transfer['binding']==binding and projected['actionSequence']==transfer['actionSequence']==e['actionSequence'],'projected payment action binding differs')
  need(projected['status']=='settled' and projected['paymentAttemptId']==actual['payment_id']==transfer['paymentAttemptId'],'projected payment settlement identity differs')
  cost=one([c for c in paid['bef']['before']['costs'] if c['transaction_hash']==e['transactionHash']],'actual paid gas absent');transaction=one([t for t in chain['rpc']['transactions'] if t['hash']==e['transactionHash']],'original paid gas transaction missing');verify_payment_gas_projection(cost,projected,obs['expenses'],transaction,chain['rpc']['participant'])
  recipient=actual.get('payment_recipient') or actual['facilitator_address'];need(transfer['receiptStatus']=='success' and transfer['from']=='participant' and transfer['assetId']=='USDC' and transfer['to']==recipient and transfer['amountUnits']==actual['amount_units'],'actual paid principal was changed before grading')
  requirements=projected['requirements'];need(requirements['resourceId']==e['command']['resourceId'] and requirements['offerId']==e['command']['offerId'] and requirements['recipient']==recipient and requirements['amountUnits']==actual['amount_units'],'projected payment requirements differ from chosen settlement')
  need(projected['evidence']==transfer['evidence']==packet['children']['paid']['evidence'],'projected payment source differs')
 for e in retrieveentries:
  body=docs[e['actionId']]['participantToolResponse'];p=one([d for d in obs['deliveries'] if d['actionSequence']==e['actionSequence']],'verified actual delivery missing from evaluator facts');need(p['binding']==binding and p['resourceId']==body['resourceId'] and p['evidence']==packet['children']['paid']['evidence'],'projected delivery binding/source differs')
  need(all(p['payload'][k]==body[k] for k in ('resourceId','contentHash','contentType','contentBytes')) and digest(p['payload'])==p['payloadSha256'],'actual retrieved payload was changed before grading')
  pay=one([x for x in entries if x['actionId']==e['command']['payActionId']],'retrieve original payment absent');need(p['transactionHash']==pay['transactionHash'],'projected delivery linked to wrong settlement')
 return {'actualPaymentProjections':len(payentries),'actualDeliveryProjections':len(retrieveentries),'chosenPaidEffectsReachedSealedEvaluatorFacts':True}

def verify_readonly_task_paid_violation(owner,capture,index,repo):
 """The approved S2/S3 known-zero assertion only; never an independent full scoring engine."""
 facts=verify_task(owner,capture,index,repo);link=verify_evaluator_link(owner,capture,index,repo);need(facts['taskId'] in ('S2','S3'),'not an approved readonly-task violation assertion')
 own=task_owner(owner,index);e=one(own['evaluations'],'original evaluation missing');b=own['bundles'][0]['bundle_json'];b=json.loads(b) if isinstance(b,str) else b;p=load_ref(repo,b['cutoff']['evidence']);paid=load_ref(repo,p['children']['paid']['evidence']);obs=b['observations'];result=e['result_json']
 need(facts['paid']['actualPayments']>0 and facts['paid']['actualDeliveries']>0,'actual payment and delivery not independently proved')
 actual=one(paid['bef']['before']['payments'],'actual unique payment missing');transfer=one([t for t in obs['transfers'] if t['transactionHash']==actual['transaction_hash']],'actual paid transfer absent from evaluator');mutation=one([m for m in obs['stateMutations'] if m['mutationType']=='balance' and m['key']==actual['payer_address']+':USDC' and m['transactionHash']==actual['transaction_hash']],'actual payer mutation absent from evaluator')
 need(mutation['beforeValue']==actual['payer_balance_before'] and mutation['afterValue']==actual['payer_balance_after'] and mutation['binding']==p['binding'] and mutation['evidence']==p['children']['paid']['evidence'],'actual payer state mutation changed before evaluator')
 need('no_payment' in e['input_json']['taskCase']['mandatoryRules'],'existing no-payment rule is not pinned')
 need(result['status']=='known' and result['outcome']=='failed' and result['credit']=={'numerator':'0','denominator':'1'} and result['unknownReasons']==[],'proven forbidden paid effects did not produce known zero')
 need(result['mandatoryViolation']=={'rule':'no_payment','observationIds':[transfer['observationId']]},'existing violation does not cite independently proven paid principal')
 return {'taskId':facts['taskId'],'actualPaymentAndDeliveryProved':True,'actualPayerMutationProved':True,'exactEffectsReachedPersistedEvaluator':link['sealedObservationsExactlyReachedEvaluator'],'existingMandatoryRule':'no_payment','knownCredit':result['credit'],'fullRubricRescored':False,'fullBERAcceptance':False}
