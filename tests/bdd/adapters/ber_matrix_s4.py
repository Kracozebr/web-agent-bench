"""Independent independent S4 setup-effect/census partition. Requires actual original evidence."""
import copy,hashlib,re
from datetime import datetime,timezone
from tests.bdd.adapters.ber_matrix_common import need,one,digest,load_ref
ADDRESS=re.compile(r'^0x[0-9a-fA-F]{40}$')
APPROVAL='0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925'
def address(v):need(isinstance(v,str) and ADDRESS.fullmatch(v),'invalid Ethereum address');return v.lower()
def canonical_addresses(v):
 if isinstance(v,str) and ADDRESS.fullmatch(v):return v.lower()
 if isinstance(v,list):return [canonical_addresses(x) for x in v]
 if isinstance(v,dict):return {k:canonical_addresses(x) for k,x in v.items()}
 return v

def setup_partition(owner,packet,chain,repo):
 index=packet['taskIndex'];prep=copy.deepcopy(one([p for p in owner['preparations'] if p['task_index']==index],'original S4 preparation missing'));observation=one([o for o in owner['preparationObservations'] if o['task_index']==index and o['preparation_id']==prep['preparation_id']],'original S4 preparation observation missing');prep.update({k:observation[k] for k in ('fixture_evidence','baseline_evidence','baseline_state_sha256')});need(observation['generation_id']==packet['execution']['generationId'],'original setup observation generation differs');evaluation=one([e for e in owner['evaluations'] if e['task_index']==index],'no S4 grade exists; cannot claim completed setup replay');task=evaluation['input_json']['taskCase'];identity=evaluation['input_json']['release']['executionIdentity'];capture=chain['preparationFixture'];fixture=capture['fixture'];execpins=packet['execution']
 need(packet['binding']['taskId']==task['taskId']=='S4' and capture['schemaVersion']=='bts-s4-fixture-boundary-capture/v1','not actual S4 fixture capture')
 for k,v in [('preparationId',execpins['preparationId']),('environmentId',execpins['environmentId']),('generationId',execpins['generationId']),('manifestHash',execpins['environmentManifestHash']),('sourceHash',execpins['applicationSourceHash'])]:need(capture[k]==v,'setup execution binding differs '+k)
 def parsed(v):
  import json
  return json.loads(v) if isinstance(v,str) else v
 need(capture['fixtureEvidence']==parsed(prep['fixture_evidence']) and capture['baselineEvidence']==parsed(prep['baseline_evidence']),'setup refs differ from original owner preparation')
 fdoc=load_ref(repo,capture['fixtureEvidence']);bdoc=load_ref(repo,capture['baselineEvidence']);need(fdoc['kind']=='fixture' and bdoc['kind']=='baseline','original setup evidence type differs')
 created=datetime.fromisoformat(prep['created_at'].replace('Z','+00:00')).astimezone(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')
 pairs={'preparationId':'preparation_id','claimId':'claim_id','leaseId':'lease_id','environmentId':'environment_id','releaseIdentity':'release_identity','manifestHash':'manifest_hash','taskId':'task_id','caseId':'case_id','caseHash':'case_hash','initialStateSha256':'initial_state_sha256','executionIdentityHash':'execution_identity_hash','environmentManifestSha256':'environment_manifest_sha256','applicationSourceHash':'application_source_hash'}
 pins={k:prep[v] for k,v in pairs.items()};pins.update(runId=packet['binding']['runId'],taskIndex=index,createdAt=created)
 for doc in (fdoc,bdoc):need(doc['schemaVersion']=='owner-bef-task-preparation-evidence/v1' and doc['preparationId']==prep['preparation_id'] and doc['environmentId']==prep['environment_id'] and doc['publicPinsSha256']==digest(pins),'original setup public pins differ')
 original=fdoc['evidence']['s4AllowanceFixture'];need(digest(original)==fixture['proofSha256'],'actual original setup proof differs')
 need(original['stage']=='pre_task_fixture_setup' and original['outcome']=='observed' and original['operationId']==fixture['operationId'] and original['transactionHash'].lower()==fixture['transactionHash'],'original setup operation identity differs')
 before=capture['bef']['before'];need(before==capture['bef']['after'],'setup DB census changed');session=capture['bef']['session'];need(session['currentUser']==session['sessionUser']=='bef_observer' and session['transactionReadOnly']=='on' and session['transactionIsolation']=='repeatable read' and session['superuser']is False and session['bypassRls']is False,'setup observer not independent readonly')
 need(canonical_addresses(before['generation'])==canonical_addresses(chain['bef']['before']['generation']),'setup and participant generation differ')
 for k,n in [('operations',1),('selectedExecutions',1),('selectedEvents',4),('costs',1)]:need(len(before[k])==n and before['counts'][k]==str(n),'setup census does not have exact original boundary rows')
 payer=address(before['generation']['payer_address']);assets={a['assetId']:address(a['address']) for a in identity['assets'] if a.get('address')};router=address(one([c for c in identity['contracts'] if c['contractId']=='swapRouter02'],'pinned router missing')['address']);usdc=assets['USDC'];amount=int(task['objective']['initialAllowanceUnits']);need(amount>0 and address(task['objective']['spender'])==router,'setup pinned allowance target differs')
 rpc=capture['rpc'];tx=rpc['fixtureTransaction'];receipt=rpc['fixtureReceipt'];need(address(rpc['participant'])==payer and str(rpc['localChainId'])==str(identity['localChainId']),'setup RPC participant/chain differs')
 need(tx['hash'].lower()==receipt['transactionHash'].lower()==fixture['transactionHash'] and address(tx['from'])==address(receipt['from'])==payer and address(tx['to'])==address(receipt['to'])==usdc,'actual setup transaction differs')
 expected='0x095ea7b3'+router[2:].rjust(64,'0')+format(amount,'064x');need(tx['input'].lower()==expected and int(tx['value'],16)==0 and int(tx['gas'],16)==100000 and int(receipt['status'],16)==1,'actual setup is not exact successful pinned approval')
 gas=int(receipt['gasUsed'],16)*int(receipt['effectiveGasPrice'],16);need(gas==int(original['gasCostWei']),'actual setup gas arithmetic differs')
 log=one(receipt['logs'],'setup receipt must have one actual approval');need(not log.get('removed',False) and address(log['address'])==usdc and log['topics'][0].lower()==APPROVAL and len(log['topics'])==3 and address('0x'+log['topics'][1][-40:])==payer and address('0x'+log['topics'][2][-40:])==router and int(log['data'],16)==amount,'setup actual Approval log differs')
 need(log['transactionHash'].lower()==fixture['transactionHash'] and receipt['blockHash'].lower()==tx['blockHash'].lower()==fixture['blockHash'],'setup receipt block lineage differs')
 need(int(tx['blockNumber'],16)==int(fixture['blockNumber']) and int(fixture['blockNumber'])<=int(fixture['baselineNumber']),'setup was not before participant baseline')
 need(bdoc['evidence']['stateSha256']==prep['baseline_state_sha256']==task['initialState']['stateSha256'],'setup baseline state pin differs')
 need(digest(bdoc['evidence']['state']['projection'])==task['initialState']['stateSha256'],'original setup baseline projection hash differs')

 parent=rpc['parentCheckpoint'];baseline=rpc['baselineCheckpoint'];expected_state=task['initialState']
 need(parent['blockHash']==fixture['parentHash'] and int(parent['blockNumber'])+1==int(fixture['blockNumber']) and baseline['blockHash']==fixture['baselineHash'] and baseline['blockNumber']==fixture['baselineNumber'],'setup checkpoint ancestry differs')
 need(canonical_addresses(parent['balances'])==canonical_addresses(fixture['preState']['projection']['balances']) and canonical_addresses(parent['allowances'])==canonical_addresses(fixture['preState']['projection']['allowances']),'independent parent state differs from original preparation')
 need(canonical_addresses(baseline['balances'])==canonical_addresses(expected_state['balances']) and canonical_addresses(baseline['allowances'])==canonical_addresses(expected_state['allowances']),'independent baseline state differs from admitted initial state')
 balances=lambda checkpoint:{(x['account'],x['assetId']):int(x['amountUnits']) for x in checkpoint['balances']}
 pb,bb=balances(parent),balances(baseline);need(pb.keys()==bb.keys() and len(pb)==len(parent['balances']) and len(bb)==len(baseline['balances']),'setup balance inventory differs')
 for key in pb:need(bb[key]-pb[key]==(-gas if key==('participant','ETH') else 0),'setup changed principal beyond exact actual gas')
 allowances=lambda checkpoint:{(x['owner'].lower(),x['tokenAssetId'],address(x['spender'])):int(x['amountUnits']) for x in checkpoint['allowances']}
 pa,ba=allowances(parent),allowances(baseline);need(pa.keys()==ba.keys() and len(pa)==len(parent['allowances']) and len(ba)==len(baseline['allowances']),'setup allowance inventory differs')
 target=('participant','USDC',router);need(target in ba and ba[target]==amount,'setup target allowance absent')
 for key in pa:need(ba[key]==(amount if key==target else pa[key]),'setup mutated unrelated allowance')
 # This setup checkpoint producer explicitly uses participantTransactionCount='0';
 # it is not an observed nonce and is excluded from independent setup claims.
 need(rpc['fixtureBlock']['hash'].lower()==fixture['blockHash'] and rpc['fixtureBlock']['parentHash'].lower()==fixture['parentHash'] and len(rpc['fixtureBlock']['transactions'])==1 and canonical_addresses(rpc['fixtureBlock']['transactions'][0])==canonical_addresses(tx),'actual setup block contains different transaction')
 
 # Original full census stays intact. Only the separate participant view removes the proven setup.
 raw=chain['bef']['before'];need(raw==chain['bef']['after'] and digest(raw)==chain['bef']['censusSha256'],'whole chain census changed')
 for a in chain['ownerActions']+chain['externalActions']+chain.get('rejectedChainActions',[]):need(a.get('befOperationId')!=fixture['operationId'] and a.get('transactionHash')!=fixture['transactionHash'] and a.get('actionId')!=fixture['operationId'],'participant census aliases setup identity')
 for key in ('operations','selectedExecutions','selectedEvents','costs'):
  need(raw['counts'][key]==str(len(raw[key])),'whole census count differs')
  setuprows=[x for x in raw[key] if x['operationId']==fixture['operationId']];need(len(setuprows)==len(before[key]),'proven setup row omitted/duplicated in whole census')
  need(not any(x.get('transactionHash')==fixture['transactionHash'] and x['operationId']!=fixture['operationId'] for x in raw[key]),'unrelated row aliases setup transaction')
 # Exact schema mapping is verified separately against actual packet rows, never by row counts alone.
 view=verify_setup_row_partition(chain)
 return {'originalSetupRefsHashVerified':True,'actualPinnedApprovalReceiptVerified':True,'canonicalEthereumAddressComparison':True,'setupRowCountsVerified':True,'setupOperationId':fixture['operationId'],'setupTransactionHash':fixture['transactionHash'],'participantSetupIdentityDisjoint':True,'exactSetupRowMappingVerified':True,'actualSetupPrincipalAndGasBoundaryVerified':True,'participantCountsAfterSetupExclusion':view['counts'],'fullSetupPartitionVerified':True,'gradeInvented':False}

def map_setup_row(key,row):
 if key=='operations':
  fields={'operationId':'operation_id','environmentId':'env_id','generationId':'generation_id','participantId':'participant_id','idempotencyKeySha256':'idempotency_key_sha256','requestSha256':'request_sha256','actionKind':'operation_kind','status':'status','receiptStatus':'receipt_status','transactionHash':'transaction_hash','responseSha256':'response_sha256','startedAt':'started_at','completedAt':'completed_at'}
  return {k:row[v] for k,v in fields.items()}
 if key=='selectedExecutions':
  receipt=row['measurement']['receipt'];selected=row['selected_action'];return {'operationId':row['operation_id'],'environmentId':row['env_id'],'generationId':row['generation_id'],'actionKind':row['action_kind'],'selectedAction':{k:selected[k] for k in ('kind','tokenAssetId','amountUnits','gasLimit')},'prestate':row['prestate'],'transactionIntent':row['transaction_intent'],'measurement':{'measurementSha256':row['measurement']['measurementSha256'],'receipt':{'transactionHash':receipt['transactionHash'],'status':receipt['status'],'gasUsed':receipt['gasUsed'],'effectiveGasPriceWei':receipt['effectiveGasPrice'],'gasCostWei':receipt['gasCostWei']}},'transactionHash':row['transaction_hash'],'outcome':row['outcome'],'reasonCode':row['reason_code'],'completedAt':row['completed_at']}
 if key=='selectedEvents':
  result=copy.deepcopy(row)
  if row['eventKind']=='selected_action_bound':result['eventPayload']['selectedAction']={k:row['eventPayload']['selectedAction'][k] for k in ('kind','tokenAssetId','amountUnits','gasLimit')}
  return result
 need(key=='costs','unknown setup row family')
 fields={'operationId':'operation_id','environmentId':'env_id','generationId':'generation_id','transactionHash':'transaction_hash','payerAddress':'payer_address','payerRole':'payer_role','receiptStatus':'receipt_status','transactionFrom':'transaction_from','receiptFrom':'receipt_from','receiptBlockNumber':'receipt_block_number','receiptBlockHash':'receipt_block_hash','receiptBlockParentHash':'receipt_block_parent_hash','gasUsed':'gas_used','effectiveGasPriceWei':'effective_gas_price_wei','gasCostWei':'gas_cost_wei','modeledGasFeeUsdcUnits':'modeled_gas_fee_usdc_units','manifestSha256':'manifest_sha256','selectedPrincipalAsset':'selected_principal_asset','selectedPrincipalUnits':'selected_principal_units','observedPrincipalUnits':'observed_principal_units'}
 return {k:row[v] for k,v in fields.items()}

def verify_setup_row_partition(chain):
 capture=chain['preparationFixture'];fixture=capture['fixture'];whole=chain['bef']['before'];setup=capture['bef']['before'];view=copy.deepcopy(whole)
 for key in ('operations','selectedExecutions','selectedEvents','costs'):
  actual=[r for r in whole[key] if r['operationId']==fixture['operationId']];expected=[map_setup_row(key,r) for r in setup[key]]
  need(canonical_addresses(actual)==canonical_addresses(expected),'exact setup source-row mapping differs: '+key)
  view[key]=[r for r in whole[key] if r['operationId']!=fixture['operationId']]
 for key in ('externalPaymentOperations','inspectionOperations','rejectedChainOperations'):
  for row in whole.get(key,[]):
   need(row.get('operationId')!=fixture['operationId'] and row.get('transactionHash')!=fixture['transactionHash'],'setup appears in another family partition')
   if isinstance(row.get('operation'),dict):need(row['operation'].get('operationId')!=fixture['operationId'] and row['operation'].get('transactionHash')!=fixture['transactionHash'],'nested setup appears in another family partition')
 view['counts']={k:str(len(view[k])) for k in whole['counts']}
 return view
