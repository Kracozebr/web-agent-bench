"""Strict selected-action source partition; no scoring or acceptance claims."""
from tests.bdd.adapters.ber_matrix_common import need,one
from tests.bdd.adapters.ber_matrix_s4 import address,canonical_addresses
from tests.bdd.adapters.ber_chain_effects import verify_chain_action

def verify_chain_family_raw(chain,entries,docs,participant_view=None):
 """Actual full partition/effect join; caller also verifies original owner/closure/source and evaluator linkage."""
 selected=[e for e in entries if e['family']=='chain'];need(len(selected)==len(chain['ownerActions']),'chain family dropped or duplicated action');raw=participant_view or chain['bef']['before'];assets={a['assetId']:address(a['address']) for a in chain['rpc']['assets'] if a.get('address')};participant=address(chain['rpc']['participant']);facts=[]
 need(len(raw['operations'])==len(selected)==len(raw['selectedExecutions'])==len(raw['costs']) and len(raw['selectedEvents'])==4*len(selected),'chain operation/event/execution/cost partition differs')
 for e in selected:
  action=one([a for a in chain['ownerActions'] if a['actionId']==e['actionId']],'original chain owner action missing');opid=action['befOperationId'];tx=one([t for t in chain['rpc']['transactions'] if t['hash']==e['transactionHash']],'original chain RPC transaction missing');op=one([o for o in raw['operations'] if o['operationId']==opid],'actual selected operation missing');selected_row=one([s for s in raw['selectedExecutions'] if s['operationId']==opid],'actual selected execution missing');cost=one([s for s in raw['costs'] if s['operationId']==opid],'actual selected gas row missing')
  need(action['command']==e['command'] and action['commandSha256']==e['commandSha256'] and tx['hash']==action['transactionHash']==op['transactionHash']==selected_row['transactionHash']==cost['transactionHash'],'original chosen chain identity differs')
  need(canonical_addresses(selected_row['selectedAction'])==canonical_addresses(action['selectedAction']) and selected_row['outcome']==op['receiptStatus']==cost['receiptStatus']==tx['status'],'selected execution outcome differs')
  need(cost['payerRole']=='participant' and address(cost['payerAddress'])==address(cost['transactionFrom'])==address(cost['receiptFrom'])==participant and cost['gasUsed']==tx['gasUsed'] and cost['effectiveGasPriceWei']==tx['effectiveGasPriceWei'] and cost['gasCostWei']==tx['gasCostWei'] and cost['receiptBlockHash']==tx['blockHash'],'actual selected gas/payer/block differs')
  events=[x for x in raw['selectedEvents'] if x['operationId']==opid];need(len(events)==4 and {x['eventKind'] for x in events}=={'selected_action_bound','prestate_observed','original_tx_hash_bound','receipt_finalized'},'immutable selected event history incomplete')
  proof=verify_chain_action(e['command'],tx,participant,assets,chain['rpc']['routes'],action['approvalSpender']);history=one([h for h in chain['rpc']['balanceHistory'] if h['actionId']==e['actionId']],'independent per-action state history missing');need(history['transactionHash']==tx['hash'] and history['actionSequence']==e['actionSequence'] and history['blockHash']==tx['blockHash'] and int(history['parentBlockNumber'])+1==int(history['blockNumber']),'independent state history lineage differs')
  if proof['outcome']=='success':
   for asset,delta in proof['participantDeltas'].items():
    row=one([b for b in history['balances'] if b['account']=='participant' and b['assetId']==asset],'independent participant balance missing');need(int(row['afterValue'])-int(row['beforeValue'])==int(delta),'independent balance delta contradicts receipt effect '+asset)
  facts.append({'actionId':e['actionId'],'actionSequence':e['actionSequence'],'transactionHash':tx['hash'],**proof})
 return {'chainActionCount':len(facts),'actions':facts,'rawEventJsonHashesRecomputed':False,'sealedEffectProjectionVerified':False,'fullAcceptance':False}
