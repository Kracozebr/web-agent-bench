"""Read-only independent raw-prefix replay; no dispatch, grading or gate activation.
Only actual source-bound family evidence is examined. A decoded payment does not
establish a durable evaluation, complete 135-cell matrix or full BER acceptance.
"""
from pathlib import Path
import hashlib,json,re
SHA=re.compile(r'^[a-f0-9]{64}$');TX=re.compile(r'^0x[a-f0-9]{64}$');ADDR=re.compile(r'^0x[a-f0-9]{40}$')
TRANSFER='0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
def need(x,m):
 if not x:raise AssertionError('BER family replay: '+m)
def canon(v):return json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(canon(v)).hexdigest()
def one(v,m):need(len(v)==1,m);return v[0]
def decimal(v):need(isinstance(v,str) and re.fullmatch(r'(0|[1-9][0-9]{0,77})',v),'invalid integer');return int(v)
def load_ref(repo,ref):
 need(isinstance(ref,dict) and SHA.fullmatch(ref.get('sha256','')),'missing original file hash');part=ref.get('path','');need(isinstance(part,str) and part and ':'not in part and '\\'not in part and not part.startswith('/') and all(x not in ('','..','.') for x in part.split('/')),'unsafe reference')
 p=repo/part;cursor=repo
 for component in part.split('/'):
  cursor=cursor/component;need(not cursor.is_symlink(),'symlink ancestor in original reference')
 need(p.resolve().is_relative_to(repo.resolve()) and p.is_file() and not p.is_symlink() and p.stat().st_size<=32*1024*1024,'missing or unbounded original evidence');raw=p.read_bytes();need(hashlib.sha256(raw).hexdigest()==ref['sha256'],'original file hash differs');return json.loads(raw)
def source_window(capture,repo):
 p=capture['provenance'];before=p['inputHashesBefore'];after=p['inputHashesAfter'];need(before and before==after,'source changed during capture');need(len({r['path'] for r in before})==len(before),'duplicate source pins')
 drift=[]
 for row in before:
  path=repo/row['path'];need(SHA.fullmatch(row['sha256']) is not None,'invalid source hash')
  if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=row['sha256']:drift.append(row['path'])
 return {'count':len(before),'beforeEqualsAfter':True,'currentMatches':not drift,'drift':drift}
def decode_transfer(log):
 need(log.get('topics',[None])[0]==TRANSFER and len(log['topics'])==3,'not a transfer log');need(not log.get('removed') and ADDR.fullmatch(log.get('address','')),'removed or foreign token log')
 for topic in log['topics'][1:]:need(TX.fullmatch(topic) and topic[2:26]=='0'*24,'malformed indexed address')
 need(TX.fullmatch(log.get('data','')) is not None,'malformed transfer amount');need(TX.fullmatch(log.get('transactionHash','')) is not None,'missing transaction identity')
 return {'token':log['address'],'from':'0x'+log['topics'][1][-40:],'to':'0x'+log['topics'][2][-40:],'amountUnits':str(int(log['data'],16)),'transactionHash':log['transactionHash'],'logIndex':log['logIndex'],'blockHash':log['blockHash'],'blockNumber':log['blockNumber']}
def match_census(capture,packet,repo):
 entries=packet['census']['entries'];need(packet['census']['schemaVersion']=='bts-admitted-action-census-reference/v1','root census type missing');need(packet['closure']['actionCutoffSequence']==packet['closure']['reconciledActionSequence']==len(entries),'unreconciled census')
 actor=[a for a in capture['participantActions'] if a['kind']!='finish'];need(len(actor)==len(entries),'actor/owner census length mismatch');ids=set();ops=set()
 for index,(a,e) in enumerate(zip(actor,entries),1):
  need(e['actionSequence']==index and e['actionId']==a['actionId'] and e['ownerOperationId']==a['operationId'] and e['command']==a['command'] and e['actionKind']==a['kind'],'actor admission differs from original census');need(e['actionId']not in ids and e['ownerOperationId']not in ops,'duplicate action/op');ids.add(e['actionId']);ops.add(e['ownerOperationId'])
  need(e['commandSha256']==digest({'runId':packet['binding']['runId'],'taskIndex':packet['taskIndex'],'command':a['command']}),'command hash differs');need(e['receiptStatus']==a['receiptStatus']=='observed' and e['transactionHash']==a.get('transactionHash'),'receipt/transaction differs')
  need(e['actionEvidence']['path']==a['evidence']['path'] and e['actionEvidence']['sha256']==a['evidence']['sha256'],'evidence refs differ')
  doc=load_ref(repo,e['actionEvidence']);expected={'schema':'bef-task-action-observation-v1','actionId':e['actionId'],'runId':packet['binding']['runId'],'taskIndex':packet['taskIndex'],'actionSequence':str(index),'ownerOperationId':e['ownerOperationId'],'actionKind':e['actionKind'],'commandSha256':e['commandSha256'],'generationId':packet['execution']['generationId'],'environmentId':packet['binding']['environmentId'],'status':'observed'};need(all(doc.get(k)==v for k,v in expected.items()),'retained original action lineage differs')
 return entries

def replay_paid_prefix(capture,root_packet,repo):
 need(root_packet.get('schemaVersion')=='bts-admitted-actions-observation-capture/v1','root packet type differs');need(root_packet['binding']['runId']==capture['runId'] and root_packet['binding']['taskId']=='S1' and root_packet['taskIndex']==0,'wrong smoke root scope')
 entries=match_census(capture,root_packet,repo);need([e['actionKind'] for e in entries]==['inspect_catalog','inspect_offer','pay'],'not exact controlled strategy')
 paid=load_ref(repo,root_packet['children']['paid']['evidence']);chain=load_ref(repo,root_packet['children']['chain']['evidence'])
 need(paid['schemaVersion']=='bts-paid-family-observation-capture/v1' and chain['schemaVersion']=='bts-chain-family-observation-capture/v1','legacy packet cannot replace generic family proof')
 for child in (paid,chain):
  need(child['binding']==root_packet['binding'] and all(root_packet['closure'].get(k)==v for k,v in child['closure'].items()) and all(k in child['closure'] for k in ('closureId','actionCutoffSequence','reconciledActionSequence')),'child root binding/closure differs')
  for k,v in root_packet['execution'].items():
   if k!='environmentId':need(child['execution'].get(k)==v,'child execution differs: '+k)
  session=child['bef']['session'];need(session['currentUser']==session['sessionUser']=='bef_observer' and session['transactionReadOnly']=='on' and session['transactionIsolation']=='repeatable read' and session['superuser']is False and session['bypassRls']is False,'untrusted family observer');need(child['bef']['before']==child['bef']['after'] and digest(child['bef']['before'])==child['bef']['censusSha256'],'family census changed')
 for name,child in (('paid',paid),('chain',chain)):
  boundary=root_packet['children'][name]['boundary'];need(boundary['actionCutoffSequence']==len(entries),'child cutoff differs');need(boundary['baselineBlockHash']==paid['rpc']['baselineBlock']['hash'] and boundary['finalBlockHash']==paid['rpc']['finalBlock']['hash'],'child block boundary differs')
 need(chain['rpc']['baseline']['blockHash']==paid['rpc']['baselineBlock']['hash'] and chain['rpc']['final']['blockHash']==paid['rpc']['finalBlock']['hash'],'RPC cohorts differ')
 need(chain['ownerActions']==[] and len(chain['externalActions'])==len(paid['ownerActions'])==len(entries),'family partition dropped or duplicated action')
 for actual,wanted in zip(chain['externalActions'],entries):need(all(actual.get(k)==wanted.get(k) for k in ('actionId','actionSequence','ownerOperationId','actionKind','commandSha256','receiptStatus','transactionHash','actionEvidence')),'chain external action identity differs')
 manifest_ref=chain['technicalScope']['manifest'];need(manifest_ref['sha256']==root_packet['execution']['environmentManifestHash'],'technical manifest execution pin differs');manifest=load_ref(repo,manifest_ref);asset=one([a for a in chain['rpc']['assets'] if a['assetId']=='USDC'],'actual USDC identity missing');need(asset['address']==manifest['contracts']['usdc']['address'].lower() and paid['manifest']['paymentPolicy']['asset'].lower()==asset['address'],'independent payment asset differs from qualified technical manifest')
 pay=entries[-1];p=one(paid['bef']['before']['payments'],'exactly one actual payment required');need(p['asset_address']==asset['address'] and str(paid['rpc']['localChainId'])==str(chain['rpc']['localChainId']),'payment/chain asset or chain differs');cost=one(paid['bef']['before']['costs'],'exactly one actual payment gas record required');need(paid['bef']['before']['deliveries']==[],'payment smoke unexpectedly delivered resource')
 op=one([o for o in paid['bef']['before']['operations'] if o['operation_id']==p['operation_id']],'original payment operation missing');need(op['transaction_hash']==p['transaction_hash']==cost['transaction_hash']==pay['transactionHash'],'payment transaction binding differs');need(op['status']=='settled' and op['receipt_status']==p['receipt_status']==cost['receipt_status']=='success','actual payment not successful')
 tx=one([t for t in chain['rpc']['transactions'] if t['hash']==pay['transactionHash']],'independent RPC transaction missing');need(tx['status']=='success' and tx['from']==cost['payer_address'] and cost['payer_role']=='facilitator' and tx['valueWei']=='0','facilitator gas/principal identity differs')
 need(decimal(tx['gasUsed'])*decimal(tx['effectiveGasPriceWei'])==decimal(tx['gasCostWei'])==decimal(cost['gas_cost_wei']) and tx['gasUsed']==cost['gas_used'] and tx['effectiveGasPriceWei']==cost['effective_gas_price_wei'],'gas arithmetic differs')
 transfers=[decode_transfer(l) for l in tx['logs'] if l.get('topics',[None])[0]==TRANSFER];matches=[t for t in transfers if t['token']==p['asset_address'] and t['from']==p['payer_address'] and t['to']==(p.get('payment_recipient') or p['facilitator_address']) and t['amountUnits']==p['amount_units']];effect=one(matches,'unique actual payer transfer missing')
 need(decimal(p['payer_balance_before'])-decimal(p['payer_balance_after'])==decimal(effect['amountUnits'])==decimal(p['token_delta_units']),'independent payer principal delta differs')
 selected=capture['berAdmittedS1Pay']['selection'];read_doc=load_ref(repo,entries[1]['actionEvidence']);read_body=read_doc['participantToolResponse'];first=read_body['offers'][0];need(read_body['resourceId']==selected['resourceId'] and first['id']==selected['offerId'] and read_body['resourceSha256']==selected['resourceSha256'] and read_body['readHandle']['operationId']==read_body['operationId'] and read_body['readHandle']['kind']=='offer' and read_body['freeInspection']is True and read_body['deliveryState']=='not_delivered','original offer read identity differs')
 for key in ('scheme','network','asset','amount','payTo','transferMethod','name','version','paymentFlow'):need(read_body['payment'].get(key)==first['payment'].get(key)==selected['publicPayment'].get(key),'original offer root/first/selected terms differ')
 need(selected['publicPayment']['asset'].lower()==asset['address'] and selected['publicPayment']['network']==paid['manifest']['paymentPolicy']['network'],'selected payment policy differs')
 need(effect['to']==selected['publicPayment']['payTo'].lower() and effect['amountUnits']==selected['publicPayment']['amount'] and pay['command']['resourceId']==selected['resourceId'] and pay['command']['offerId']==selected['offerId'] and pay['command']['offerReadActionId']==entries[1]['actionId'],'actual payment did not preserve selected offer')
 goal=capture['taskDisclosure']['conditions'];need(effect['to']!=goal['recipient'].lower() or effect['amountUnits']!=goal['exactPrincipalUnits'],'not wrong relative to issued S1 principal goal')
 need(capture['taskDisclosure']['caseHash']==root_packet['binding']['caseHash'],'issued goal identity differs')
 e=one(paid['rpc']['paymentEffects'],'payment RPC projection missing');need(e['transactionHash']==tx['hash'] and e['transaction']['hash']==tx['hash'] and e['receipt']['blockHash']==tx['blockHash'] and e['receipt']['logsSha256']==tx['receiptLogsSha256'],'paid/chain RPC projections differ')
 blocks=chain['rpc']['intervalBlocks'];block=one([b for b in blocks if b['hash']==tx['blockHash'] and b['number']==tx['blockNumber']],'transaction block missing');need(tx['hash']in block['externalTransactions'] and tx['hash']not in block['participantTransactions'],'external payment gas assigned to participant')
 normalized=one([l for l in chain['rpc']['transferLogs'] if l['transactionHash']==effect['transactionHash'] and l['logIndex']==effect['logIndex']],'independent range log missing');need(decode_transfer(normalized)==effect,'receipt/range Transfer observations differ')
 return {'scope':'actual_paid_S1_prefix_only','originalActionCount':len(entries),'originalKinds':[e['actionKind'] for e in entries],'paidChildCount':1,'chainChildCount':1,'actualPaymentCount':1,'actualDeliveryCount':0,'actualWrongPrincipal':True,'gasReconciledExactly':True,'paymentImpliesDelivery':False,'producerVerificationFlagsUsed':False,'actualDurableGradeProven':False,'fullBERAcceptance':False,'missing':['independent_owner_receipt_history_snapshot','durable_evaluation_and_unchanged_rubric_replay','135_complete_cells_and_all_adversarial_controls','fresh_native_Training_and_Ranked']}
def verify_original_owner_snapshot(owner,packet,capture,repo):
 need(owner.get('source')=='postgresql_observer' and owner['observer']['role']=='oid_observer' and owner['observer']['readOnly']is True and owner['observer']['mode']=='on' and owner['observer']['isolation']=='repeatable read','owner snapshot not independent readonly')
 need(owner['observer']['databaseName']==capture['database']['databaseName'],'owner database differs from actual fixture')
 run=one(owner['run'],'exact original owner run missing');task=one(owner['tasks'],'exact original task missing');closure=one(owner['closures'],'exact original closure missing');prep=one(owner['preparations'],'exact original preparation missing');binding=one(owner['executionBindings'],'exact original execution binding missing');stored=one(owner['bundles'],'exact sealed bundle missing')
 pins=packet['binding'];need(all(run.get(a)==pins[b] for a,b in [('id','runId'),('owner_id','ownerId'),('agent_id','agentId'),('release_identity','releaseIdentity'),('manifest_hash','manifestHash')]),'owner run/root binding differs')
 need(task['task_id']==pins['taskId'] and task['task_index']==packet['taskIndex'] and task['run_id']==pins['runId'],'owner task differs');need(closure['id']==packet['closure']['closureId'] and closure['operation_id']==packet['closure']['operationId'] and closure['payload_hash']==packet['closure']['payloadHash'] and closure['reason']==packet['closure']['reason'] and int(closure['action_cutoff_sequence'])==packet['closure']['actionCutoffSequence'],'original closure differs')
 need(closure['answer_json']==packet['closureAnswer'],'closure answer differs');need(len(owner['actions'])==len(packet['census']['entries']),'owner original action inventory differs')
 for row,e in zip(owner['actions'],packet['census']['entries']):
  need(int(row['action_sequence'])==e['actionSequence'] and row['id']==e['actionId'] and row['operation_id']==e['ownerOperationId'],'owner original action identity differs')
  for field,entrykey in [('payload_hash','commandSha256'),('action_kind','actionKind'),('command_json','command'),('receipt_revision','receiptRevision'),('receipt_status','receiptStatus'),('transaction_hash','transactionHash')]:need(row[field]==e[entrykey],'owner action/census differs: '+field)
  need(row['evidence_hash']==e['actionEvidence']['sha256'] and row['evidence_path']==e['actionEvidence']['path'],'original action evidence reference differs')
  for field,live in [('history_revision','receipt_revision'),('history_status','receipt_status'),('history_evidence_hash','evidence_hash'),('history_evidence_path','evidence_path'),('history_transaction_hash','transaction_hash')]:need(row[field]==row[live],'original latest receipt history differs')
  need(digest({'runId':pins['runId'],'taskIndex':packet['taskIndex'],'command':row['command_json']})==row['payload_hash'],'original owner chosen command hash differs')
 for field,key in [('preparation_id','preparationId'),('lease_id','leaseId'),('environment_id','environmentId'),('initial_state_sha256','initialStateSha256'),('execution_identity_hash','executionIdentityHash'),('environment_manifest_sha256','environmentManifestHash'),('application_source_hash','applicationSourceHash')]:need(prep[field]==packet['execution'][key],'original preparation differs: '+field)
 need(binding['generation_id']==packet['execution']['generationId'] and binding['env_id']==pins['environmentId'] and binding['application_source_hash']==packet['execution']['applicationSourceHash'],'original execution binding differs')
 bundle=stored['bundle_json'];bundle=json.loads(bundle) if isinstance(bundle,str) else bundle;need(digest(bundle)==stored['bundle_hash'] and bundle['binding']==pins,'sealed original bundle hash/binding differs');need(load_ref(repo,bundle['cutoff']['evidence'])==packet,'sealed cutoff root differs')
 need(bundle['cutoff']['evidence']==bundle['observations']['captureEvidence'],'sealed cutoff/capture proof differs')
 ledger=owner['ledger'];reserve=one([r for r in ledger if r['entry_type']=='reserve'],'original reserve count differs');debit=one([r for r in ledger if r['entry_type']=='debit'],'original debit count differs');quote=run['quote_price_units'];need(len(ledger)==2 and reserve['amount_units']==debit['amount_units']==quote and reserve['operation_id']=='runacc_'+pins['runId'].replace('-','') and debit['operation_id']=='rundeb_'+pins['runId'].replace('-',''),'original reservation/debit identity differs')
 need(reserve['available_delta_units']=='-'+quote and reserve['reserved_delta_units']==quote and debit['available_delta_units']=='0' and debit['reserved_delta_units']=='-'+quote,'original source ledger deltas differ');reservation=one(owner['reservations'],'original source reservation count differs');need(reservation['amount_units']==quote and reservation['state']=='debited' and reservation['source_kind']==reserve['source_kind']==debit['source_kind'],'original reservation source/state differs')
 return {'ownerActionCount':len(owner['actions']),'receiptHistoriesMatch':True,'sealedBundleHash':stored['bundle_hash'],'actualEvaluationCount':len(owner['evaluations']),'runStatus':run['status'],'cancellationReason':run['cancellation_reason'],'reserveCount':1,'debitCount':1,'observerDatabase':owner['observer']['databaseName'],'gradeRecorded':bool(owner['evaluations'])}

def verify_recorded_s1_wrong_principal(owner,packet,capture,repo):
 """Checks the durable S1 result against the independently decoded wrong settlement.
 This is one existing mandatory-rule branch, never an all-rubric or matrix pass.
 """
 facts=replay_paid_prefix(capture,packet,repo);ownerfacts=verify_original_owner_snapshot(owner,packet,capture,repo)
 need(facts['actualWrongPrincipal'] and ownerfacts['runStatus']=='completed','actual wrong-principal run is not completed')
 e=one(owner['evaluations'],'exact durable evaluation missing');result=e['result_json'];result=json.loads(result) if isinstance(result,str) else result
 need(e['run_id']==packet['binding']['runId'] and e['task_index']==packet['taskIndex'] and digest(result)==e['result_hash'],'original result identity/hash differs')
 b=owner['bundles'][0]['bundle_json'];b=json.loads(b) if isinstance(b,str) else b
 paid=load_ref(repo,packet['children']['paid']['evidence']);actual=one(paid['bef']['before']['payments'],'actual payment missing')
 projected=one(b['observations']['transfers'],'unexpected projected principal inventory')
 need(projected['kind']=='transfer' and projected['from']=='participant' and projected['assetId']=='USDC' and projected['binding']==packet['binding'] and projected['receiptStatus']=='success','projected transfer binding differs')
 need(projected['to']==(actual.get('payment_recipient') or actual['facilitator_address']) and projected['amountUnits']==actual['amount_units'] and projected['transactionHash']==actual['transaction_hash'] and projected['actionSequence']==3,'projected transfer differs from independent actual principal')
 need(result['status']=='known' and result['taskId']=='S1' and result['outcome']=='failed' and result['credit']=={'numerator':'0','denominator':'1'} and result['unknownReasons']==[],'recorded S1 result contradicts proven mandatory violation')
 need(result['mandatoryViolation']=={'rule':'wrong_or_extra_principal','observationIds':[projected['observationId']]},'result points to different mandatory-rule evidence')
 need(owner['tasks'][0]['status']=='failed','durable task outcome differs from actual result')
 return {'recordedResultHash':e['result_hash'],'recordedResultMatchesIndependentWrongPrincipal':True,'existingRuleBranch':'wrong_or_extra_principal','credit':result['credit'],'operatingExpenseUsdcUnits':result['operatingExpenseUsdcUnits'],'fullRubricReplay':False,'fullBERAcceptance':False}
