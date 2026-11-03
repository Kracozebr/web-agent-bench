"""Exact state/receipt/sealed fact joins, without deciding a task's score."""
from tests.bdd.adapters.ber_matrix_common import need,one
from tests.bdd.adapters.ber_chain_effects import verify_chain_action,address,SWAP
from tests.bdd.adapters.ber_matrix_support import uint_hex
from tests.bdd.adapters.ber_matrix_chain_projection import verify_approval_audit
MAX=(1<<256)-1
def validate_expense_components(expenses):
 need(all(x['component'] in ('participant_gas','verified_dex_fee') for x in expenses),'unknown typed expense component')

def verify_supported_chain_effects(chain,root,bundle,support):
 obs=bundle['observations'];validate_expense_components(obs['expenses']);participant=address(chain['rpc']['participant']);assets={a['assetId']:address(a['address']) for a in chain['rpc']['assets'] if a.get('address')};facts=[]
 for a in chain['ownerActions']:
  state=support['states'][a['actionId']];before,after=state['before'],state['after'];command=a['command'];kind=command['kind'];tx=one([x for x in chain['rpc']['transactions'] if x['hash']==a['transactionHash']],'actual chain tx absent');f=verify_chain_action(command,tx,participant,assets,chain['rpc']['routes'],a['approvalSpender']);success=f['outcome']=='success';gas=int(f['gasWei']);seq=a['actionSequence'];rows=lambda key:[x for x in obs[key] if x.get('transactionHash')==tx['hash'] and x['actionSequence']==seq]
  deltas=f.get('participantDeltas',{'ETH':str(-gas),'WETH':'0','USDC':'0'})
  for asset in ('ETH','WETH','USDC'):need(after['participant.'+asset]-before['participant.'+asset]==int(deltas[asset]),'support participant principal/gas differs')
  need(after['participant.nonce']==before['participant.nonce']+1,'original mined transaction nonce not counted once')
  for asset in ('WETH','USDC'):
   expected=before['allowance.'+asset]
   if success and kind=='approve' and command['tokenAssetId']==asset:expected=int(command['amountUnits'])
   if success and kind=='swap' and command['inputAssetId']==asset:
    need(expected>=int(command['amountInUnits']),'swap lacks actual input allowance');expected=MAX if expected==MAX else expected-int(command['amountInUnits'])
   need(after['allowance.'+asset]==expected,'support allowance consumption/change differs')
   mutations=[m for m in rows('stateMutations') if m['mutationType']=='allowance' and m['key']=='participant:'+asset+':'+address(a['approvalSpender'])] if a['approvalSpender'] else []
   if kind=='approve' and command['tokenAssetId']==asset:
    changes=rows('allowanceChanges');all_mutations=[m for m in rows('stateMutations') if m['mutationType']=='allowance'];verify_approval_audit(changes,command,a['approvalSpender'],before['allowance.'+asset],all_mutations)
   if mutations:
    need(len(mutations)==1 and int(mutations[0]['beforeValue'])==before['allowance.'+asset] and int(mutations[0]['afterValue'])==expected,'sealed allowance mutation differs from direct state')
  pd={'WETH':0,'USDC':0}
  if success and kind=='swap':
   detail=f['detail'];pd[command['inputAssetId']]+=int(detail['inputAmountUnits']);pd[command['outputAssetId']]-=int(detail['outputAmountUnits']);pool=state['pool'];log=one([l for l in tx['logs'] if l['topics'][0].lower()==SWAP and address(l['address'])==pool],'raw pool Swap absent');words=[int(log['data'][2+64*i:2+64*(i+1)],16) for i in range(5)];slot=after['pool.slot0'];need(uint_hex(slot[:2+64],1)==words[2] and int(slot[2+64:2+128],16)==words[4] and uint_hex(after['pool.liquidity'],1)==words[3],'direct pool price/tick/liquidity differs from original Swap log')
   need(before['pool.liquidity']==after['pool.liquidity'],'swap changed pool liquidity')
  elif success and kind=='transfer' and address(command['recipient'])==state['pool']:pd['USDC']+=int(command['amountUnits'])
  for asset in ('WETH','USDC'):need(after['pool.'+asset]-before['pool.'+asset]==pd[asset],'direct pool principal differs from original token logs')
  if not(success and kind=='swap'):need(before['pool.slot0']==after['pool.slot0'] and before['pool.liquidity']==after['pool.liquidity'],'non-swap or reverted action changed pool state')
  if state['command'].get('recipient') and address(command['recipient'])!=participant:
   for asset in ('WETH','USDC'):
    expected=int(f['detail']['outputAmountUnits']) if success and kind=='swap' and command['outputAssetId']==asset else int(command['amountUnits']) if success and kind=='transfer' and asset=='USDC' else 0
    need(after['recipient.'+asset]-before['recipient.'+asset]==expected,'direct recipient state differs from selected principal')
  if not success:need(not any(rows(k) for k in ('conversions','trades','transfers','allowanceChanges','allowanceUses')) and not any(m['mutationType']=='allowance' for m in rows('stateMutations')),'revert has fabricated economic facts')
  facts.append({'actionId':a['actionId'],'kind':kind,'outcome':f['outcome'],'gasWei':str(gas),'noopApproval':success and kind=='approve' and before['allowance.'+command['tokenAssetId']]==after['allowance.'+command['tokenAssetId']]})
 # Aggregate gas counts once, independent of whether principal came from the chain or paid family.
 original_ops={a['befOperationId'] for a in chain['ownerActions']};costs=[c for c in chain['bef']['before']['costs'] if c['operationId'] in original_ops];gasrows=[x for x in obs['expenses'] if x['component']=='participant_gas']
 need(len({x['transactionHash'] for x in gasrows})==len(gasrows),'duplicate sealed gas transaction')
 for cost in costs:
  row=one([x for x in gasrows if x.get('transactionHash')==cost['transactionHash']],'original chain gas missing from input');need(row['gasUsed']==cost['gasUsed'] and row['effectiveGasPriceWei']==cost['effectiveGasPriceWei'],'input chain gas not exactly original receipt')
 return {'actualChainActions':len(facts),'facts':facts,'directAllowancePoolRecipientStatesVerified':True,'noSecondGrader':True,'fullAcceptance':False}
