"""Recovery-only economic facts reconstructed from verified original EVM logs.
Pool deltas/post-price are derived; this does not prove independent absolute pool snapshots.
"""
from tests.bdd.adapters.ber_matrix_common import need,one,load_ref
from tests.bdd.adapters.ber_matrix_chain_family import verify_chain_family_raw
from tests.bdd.adapters.ber_chain_effects import verify_chain_action,address,SWAP
from tests.bdd.adapters.ber_matrix_chain_projection import verify_sealed_transfer_sender,verify_approval_audit
MAX=(1<<256)-1

def verify_derived_chain_effects(chain,entries,documents,bundle,repo):
 raw=verify_chain_family_raw(chain,entries,documents);participant=address(chain['rpc']['participant']);assets={a['assetId']:address(a['address']) for a in chain['rpc']['assets'] if a.get('address')};rpc=chain['rpc'];obs=bundle['observations'];manifest=load_ref(repo,chain['technicalScope']['manifest'])
 contracts={address(c['address']):c['codeHash'].removeprefix('0x').lower() for c in rpc['contracts']};observed={address(c['address']):c for c in rpc['identityCodeHashes']}
 for addr,pin in contracts.items():
  need(addr in observed and observed[addr]['expectedCodeHash'].removeprefix('0x').lower()==observed[addr]['observedCodeHash'].removeprefix('0x').lower()==pin,'derived history lacks pinned observed runtime code')
 blocks=rpc['intervalBlocks'];need(len(blocks)>0 and int(blocks[0]['number'])==int(rpc['baseline']['blockNumber'])+1 and blocks[0]['parentHash']==rpc['baseline']['blockHash'] and int(blocks[-1]['number'])==int(rpc['final']['blockNumber']) and blocks[-1]['hash']==rpc['final']['blockHash'],'derived history block interval incomplete');alltx=[]
 for n,b in enumerate(blocks):
  need(b['transactionCount']==len(b['participantTransactions'])+len(b['externalTransactions']) or str(b['transactionCount'])==str(len(b['participantTransactions'])+len(b['externalTransactions'])),'block transaction count differs')
  if n:need(int(b['number'])==int(blocks[n-1]['number'])+1 and b['parentHash']==blocks[n-1]['hash'],'block interval gap/reorg')
  # Baseline effects precede this closed task's action interval (e.g. exact proven S4 setup).
  alltx+=b['participantTransactions']+b['externalTransactions']
 actual={t['hash'] for t in rpc['transactions']};expected={e['transactionHash'] for e in entries if e['transactionHash'] is not None}
 need(len(alltx)==len(set(alltx)) and set(alltx)==actual==expected,'derived history contains foreign/unaccounted transaction')
 need(int(rpc['final']['participantTransactionCount'])-int(rpc['baseline']['participantTransactionCount'])==len(chain['ownerActions']),'participant nonce delta differs from original chain census')
 allowances={(x['tokenAssetId'],address(x['spender'])):int(x['amountUnits']) for x in rpc['baseline']['allowances']};facts=[]
 for a in chain['ownerActions']:
  command=a['command'];tx=one([x for x in rpc['transactions'] if x['hash']==a['transactionHash']],'actual transaction missing');f=verify_chain_action(command,tx,participant,assets,rpc['routes'],a['approvalSpender']);kind=command['kind'];seq=a['actionSequence'];rows=lambda key:[x for x in obs[key] if x.get('transactionHash')==tx['hash'] and x['actionSequence']==seq];success=f['outcome']=='success'
  gas=one([x for x in rows('expenses') if x['component']=='participant_gas'],'actual gas expense missing');need(gas['gasUsed']==tx['gasUsed'] and gas['effectiveGasPriceWei']==tx['effectiveGasPriceWei'] and gas['receiptStatus']==tx['status'],'sealed gas differs from actual receipt')
  if not success:need(not any(rows(k) for k in ('conversions','trades','transfers','allowanceChanges','allowanceUses')) and not any(m['mutationType']=='allowance' for m in rows('stateMutations')),'revert fabricated principal')
  elif kind in ('wrap','unwrap'):
   v=one(rows('conversions'),'actual conversion missing');need(v['conversion']==kind and v['inputAmountUnits']==v['outputAmountUnits']==command['amountWei'],'sealed conversion differs from actual event')
  elif kind=='transfer':
   v=one(rows('transfers'),'actual transfer missing');d=f['detail']['transfer'];verify_sealed_transfer_sender(v['from'],d['from'],participant);need(address(v['to'])==d['to'] and v['amountUnits']==d['amountUnits'] and v['assetId']=='USDC','sealed transfer differs from actual event')
  elif kind=='swap':
   v=one(rows('trades'),'actual trade missing');d=f['detail'];need(v['routeId']==d['routeId'] and v['inputAssetId']==command['inputAssetId'] and v['outputAssetId']==command['outputAssetId'] and v['inputAmountUnits']==d['inputAmountUnits'] and v['outputAmountUnits']==d['outputAmountUnits'],'sealed trade differs from actual event');use=one(rows('allowanceUses'),'actual allowance use missing');spender=address(use['spender']);key=(command['inputAssetId'],spender);need(key in allowances and allowances[key]>=int(command['amountInUnits']) and use['amountUnits']==command['amountInUnits'],'derived allowance use lacks initial anchor');allowances[key]=MAX if allowances[key]==MAX else allowances[key]-int(command['amountInUnits'])
  if success and kind=='approve':
   spender=address(a['approvalSpender']);key=(command['tokenAssetId'],spender);need(key in allowances,'derived approval lacks initial anchor');before=allowances[key];after=int(command['amountUnits']);changes=rows('allowanceChanges');mutations=[m for m in rows('stateMutations') if m['mutationType']=='allowance'];verify_approval_audit(changes,command,spender,before,mutations)
   allowances[key]=after
  facts.append({'actionId':a['actionId'],'kind':kind,'gasWei':f['gasWei'],'status':f['outcome']})
 final={(x['tokenAssetId'],address(x['spender'])):int(x['amountUnits']) for x in rpc['final']['allowances']};need(allowances==final,'derived allowance history contradicts independent final anchor')
 return {'economicEffectsVerified':True,'actions':facts,'stateHistoryMethod':'derived_from_verified_logs_and_independent_allowance_anchors','poolDeltaAndPostPriceMethod':'derived_from_verified_logs','absoluteIndependentPoolSnapshotVerified':False,'directPerActionAllowancePoolRpc':False,'full135StrongSupport':False,'fullAcceptance':False}
