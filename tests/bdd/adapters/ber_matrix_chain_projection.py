"""Independent chosen chain effect linkage; complete proof also requires supporting RPC reads."""
from tests.bdd.adapters.ber_chain_effects import verify_chain_action,address
from tests.bdd.adapters.ber_matrix_core import verify_task,verify_evaluator_link,load_ref,one,need
from tests.bdd.adapters.ber_matrix_chain_family import verify_chain_family_raw

def verify_sealed_transfer_sender(value,actual_from,participant):
 # Only the typed sealed observation may use this role. Raw transaction/log addresses remain strict hex.
 payer=address(participant);need(address(actual_from)==payer,'raw transfer sender differs from independently pinned participant')
 sender=payer if value=='participant' else address(value)
 need(sender==payer,'sealed transfer sender differs from independently observed payer')

def verify_approval_audit(changes,command,spender,before=None,mutations=None):
 """A successful Approval is retained as an event even if it does not mutate allowance."""
 change=one(changes,'successful Approval audit event omitted or duplicated');spender=address(spender)
 need(change['owner']=='participant' and change['tokenAssetId']==command['tokenAssetId'] and address(change['spender'])==spender and change['amountAfterUnits']==command['amountUnits'],'Approval audit target/amount differs from original selected event')
 if before is not None:
  need(int(change['amountBeforeUnits'])==int(before),'Approval audit prestate differs from independently observed allowance')
  if mutations is not None:
   delta=int(before)!=int(command['amountUnits']);need(len(mutations)==(1 if delta else 0),'allowance mutation count differs from actual changed/no-op state')
   if mutations:
    m=mutations[0];need(m['mutationType']=='allowance' and m['key']=='participant:'+command['tokenAssetId']+':'+spender and int(m['beforeValue'])==int(before) and m['afterValue']==command['amountUnits'],'allowance mutation differs from actual Approval pre/poststate')
 return {'auditEvents':1,'stateChanged':None if before is None else int(before)!=int(command['amountUnits'])}

def verify_chain_projection(owner,capture,index,repo):
 base=verify_task(owner,capture,index,repo)
 b=one([x for x in owner['bundles'] if x['task_index']==index],'original bundle missing')['bundle_json']
 p=load_ref(repo,b['cutoff']['evidence']);ch=load_ref(repo,p['children']['chain']['evidence']);entries=p['census']['entries']
 docs={e['actionId']:load_ref(repo,e['actionEvidence']) for e in entries}
 from tests.bdd.adapters.ber_matrix_s4 import setup_partition,verify_setup_row_partition
 participant_view=None
 if p["binding"]["taskId"]=="S4":setup_partition(owner,p,ch,repo);participant_view=verify_setup_row_partition(ch)
 original=verify_chain_family_raw(ch,entries,docs,participant_view)
 assets={a['assetId']:address(a['address']) for a in ch['rpc']['assets'] if a.get('address')};participant=address(ch['rpc']['participant']);obs=b['observations'];facts=[]
 chain_entries=[e for e in entries if e['family']=='chain']
 need(len(ch['rpc']['transactions'])==len({x['hash'] for x in ch['rpc']['transactions']}),'duplicate RPC transaction')
 for e in chain_entries:
  a=one([x for x in ch['ownerActions'] if x['actionId']==e['actionId']],'owner chain entry missing');tx=one([x for x in ch['rpc']['transactions'] if x['hash']==e['transactionHash']],'chain tx missing')
  f=verify_chain_action(e['command'],tx,participant,assets,ch['rpc']['routes'],a['approvalSpender']);seq=e['actionSequence'];th=tx['hash']
  def rows(key):return [x for x in obs[key] if x.get('transactionHash')==th and x['actionSequence']==seq]
  for key in ('expenses','conversions','trades','transfers','allowanceChanges','allowanceUses','stateMutations'):
   need(all(x['binding']==p['binding'] and x['source']=='persisted_observer' for x in rows(key)),'sealed effect binding/source differs')
  gas=one([x for x in rows('expenses') if x['component']=='participant_gas'],'one gas expense per original chain TX required')
  need(gas['sourceEffectId']=='bef-operation:'+a['befOperationId'] and gas['receiptStatus']==tx['status'] and gas['gasUsed']==tx['gasUsed'] and gas['effectiveGasPriceWei']==tx['effectiveGasPriceWei'],'sealed gas differs from independently decoded original receipt')
  history=one([h for h in ch['rpc']['balanceHistory'] if h['actionId']==e['actionId']],'raw balance history missing')
  deltas=f.get('participantDeltas',{'ETH':str(-int(f['gasWei'])),'WETH':'0','USDC':'0'})
  for asset,delta in deltas.items():
   raw=one([x for x in history['balances'] if x['account']=='participant' and x['assetId']==asset],'raw participant balance absent')
   need(int(raw['afterValue'])-int(raw['beforeValue'])==int(delta),'raw balance contradicts decoded principal/gas')
   matches=[x for x in rows('stateMutations') if x['mutationType']=='balance' and x['key']==participant+':'+asset]
   need(len(matches)==(1 if int(delta) else 0),'missing/extra sealed participant balance mutation')
   if matches:need(matches[0]['beforeValue']==raw['beforeValue'] and matches[0]['afterValue']==raw['afterValue'],'sealed mutation differs from independent state read')
  k=e['actionKind'];detail=f.get('detail',{})
  if f['outcome']=='reverted':
   need(not any(rows(key) for key in ('conversions','trades','transfers','allowanceChanges','allowanceUses')),'reverted transaction fabricated economic effect')
  elif k in ('wrap','unwrap'):
   cv=one(rows('conversions'),'actual conversion not projected once');amount=e['command']['amountWei'];ia,oa=('ETH','WETH') if k=='wrap' else ('WETH','ETH')
   need(cv['conversion']==k and cv['inputAssetId']==ia and cv['outputAssetId']==oa and cv['inputAmountUnits']==cv['outputAmountUnits']==amount and cv['receiptStatus']=='success','sealed conversion differs from actual Deposit/Withdrawal')
  elif k=='swap':
   tr=one(rows('trades'),'actual swap not projected once');cmd=e['command']
   need(tr['routeId']==detail['routeId'] and tr['inputAssetId']==cmd['inputAssetId'] and tr['outputAssetId']==cmd['outputAssetId'] and tr['inputAmountUnits']==detail['inputAmountUnits'] and tr['outputAmountUnits']==detail['outputAmountUnits'] and tr['receiptStatus']=='success','sealed trade differs from actual pool log')
   used=one(rows('allowanceUses'),'swap allowance usage absent');need(used['amountUnits']==detail['inputAmountUnits'] and used['tokenAssetId']==cmd['inputAssetId'] and address(used['spender'])==address(tx['to']),'allowance use differs from actual router calldata/input transfer')
  elif k=='approve':
   changes=rows('allowanceChanges');cmd=e['command'];spender=address(a['approvalSpender']);prior=one([x for x in ch['rpc']['baseline']['allowances'] if x['tokenAssetId']==cmd['tokenAssetId'] and address(x['spender'])==spender],'baseline allowance missing')['amountUnits']
   earlier=[x for x in chain_entries if x['actionSequence']<seq and (x['actionKind']=='approve' and x['command']['tokenAssetId']==cmd['tokenAssetId'] or x['actionKind']=='swap' and x['command']['inputAssetId']==cmd['tokenAssetId'])]
   verify_approval_audit(changes,cmd,spender,None if earlier else prior)
  elif k=='transfer':
   tr=one(rows('transfers'),'actual chosen transfer absent');event=detail['transfer'];verify_sealed_transfer_sender(tr['from'],event['from'],participant);need(tr['assetId']=='USDC' and address(tr['to'])==event['to'] and tr['amountUnits']==event['amountUnits'],'sealed chosen transfer differs from actual Transfer log')
  facts.append({'actionId':e['actionId'],'kind':k,'actionSequence':seq,'transactionHash':th,'outcome':f['outcome'],'gasWei':f['gasWei'],'participantDeltas':f.get('participantDeltas',{'ETH':str(-int(f['gasWei'])),'WETH':'0','USDC':'0'})})
 link=verify_evaluator_link(owner,capture,index,repo)
 return {'taskId':base['taskId'],'taskIndex':index,'actualChainActions':len(facts),'facts':facts,'originalOwnerHistoryAndCensus':True,'originalRpcReceiptLogsAndParticipantBalances':True,'sealedChosenEffectsAndGasLink':True,'evaluatorLink':link,'rawSelectedEventJsonRecomputed':False,'directPerActionAllowanceAndPoolRpc':False,'full135Acceptance':False,'nativeAgent':False}
