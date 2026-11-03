"""Independent exact ABI/receipt decoder for BER chain actions.

A pure decoder is not a complete owner/census/state/evaluator or environment gate.
It never dispatches actions, changes a result or implements a task rubric.
"""
import hashlib,re

# AICODE-NOTE: Keep raw receipt decoding independent of application effect/evaluator code.
# Original reference hashes and owner/census/source checks belong to the outer reader.
def need(value, message):
    if not value:
        raise AssertionError("BER chain effects: " + message)

def one(rows, message):
    need(isinstance(rows, list) and len(rows) == 1, message)
    return rows[0]

def decimal(value):
    need(isinstance(value, str) and re.fullmatch(r"(0|[1-9][0-9]{0,77})", value), "invalid integer")
    return int(value)

def address(value):
    need(isinstance(value, str) and re.fullmatch(r"0x[a-fA-F0-9]{40}", value), "invalid Ethereum address")
    return value.lower()

TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

def decode_transfer(log):
    need(len(log["topics"]) == 3 and log["topics"][0].lower() == TRANSFER, "not a Transfer event")
    need(not log.get("removed", False), "removed Transfer event")
    return {"token": address(log["address"]), "from": topic_address(log["topics"][1]),
            "to": topic_address(log["topics"][2]), "amountUnits": str(words(log["data"], 1)[0]),
            "transactionHash": log["transactionHash"], "logIndex": log["logIndex"],
            "blockHash": log["blockHash"], "blockNumber": log["blockNumber"]}

APPROVAL='0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925'
DEPOSIT='0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c'
WITHDRAWAL='0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65'
SWAP='0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67'
CHAIN_KINDS={'wrap','unwrap','approve','swap','transfer'}
def word(v):need(type(v)is int and 0<=v<2**256,'ABI uint256 bound');return format(v,'064x')
def aword(v):return address(v)[2:].rjust(64,'0')
def topic_address(v):need(isinstance(v,str) and re.fullmatch(r'0x0{24}[a-fA-F0-9]{40}',v),'ABI indexed address invalid');return address('0x'+v[-40:])
def words(data,n):need(isinstance(data,str) and re.fullmatch('0x[a-fA-F0-9]{'+str(64*n)+'}',data),'ABI event data size differs');return [int(data[2+64*i:2+64*(i+1)],16) for i in range(n)]
def signed(v):return v-2**256 if v>=2**255 else v

def expected_call(command,assets,routes,approval_spender=None):
 k=command['kind'];need(k in CHAIN_KINDS,'unsupported chain kind');gas=str(command['gasLimit'])
 if k=='approve':
  spender=address(approval_spender)
  need(any(route['tokenInAssetId']==command['tokenAssetId'] and address(route['router'])==spender for route in routes),'approval spender is outside the declared technical routes')
  return {'to':assets[command['tokenAssetId']],'input':'0x095ea7b3'+aword(spender)+word(decimal(command['amountUnits'])),'valueWei':'0','gasLimit':gas}
 if k=='transfer':return {'to':assets['USDC'],'input':'0xa9059cbb'+aword(command['recipient'])+word(decimal(command['amountUnits'])),'valueWei':'0','gasLimit':gas}
 if k=='wrap':return {'to':assets['WETH'],'input':'0xd0e30db0','valueWei':str(decimal(command['amountWei'])),'gasLimit':gas}
 if k=='unwrap':return {'to':assets['WETH'],'input':'0x2e1a7d4d'+word(decimal(command['amountWei'])),'valueWei':'0','gasLimit':gas}
 route=one([r for r in routes if r['tokenInAssetId']==command['inputAssetId'] and r['tokenOutAssetId']==command['outputAssetId'] and r['feeTier']==command.get('feeTier',500)],'unique chosen swap route missing')
 return {'to':address(route['router']),'input':'0x04e45aaf'+aword(route['tokenIn'])+aword(route['tokenOut'])+word(route['feeTier'])+aword(command['recipient'])+word(decimal(command['amountInUnits']))+word(decimal(command['amountOutMinimumUnits']))+word(0),'valueWei':'0','gasLimit':gas}

def verify_chain_action(command,tx,participant,assets,routes,approval_spender=None):
 """Input is original hash-pinned RPC tx/receipt, not a tool-response success flag."""
 participant=address(participant);assets={key:address(value) for key,value in assets.items()};call=expected_call(command,assets,routes,approval_spender)
 need(address(tx['from'])==participant and all((address(tx[k])==address(v) if k=='to' else tx[k].lower()==v.lower() if k=='input' else tx[k]==v) for k,v in call.items()),'actual transaction does not implement original chosen command')
 need(hashlib.sha256(tx['input'].encode()).hexdigest()==tx['inputSha256'],'actual calldata hash differs')
 gas=decimal(tx['gasUsed'])*decimal(tx['effectiveGasPriceWei']);need(gas==decimal(tx['gasCostWei']),'actual chain gas arithmetic differs')
 need(tx['status'] in ('success','reverted'),'actual chain status missing');logs=tx['logs']
 for log in logs:need(not log.get('removed',False) and log['transactionHash'].lower()==tx['hash'].lower() and log['blockHash'].lower()==tx['blockHash'].lower() and str(log['blockNumber'])==str(tx['blockNumber']),'receipt log belongs to different transaction/block')
 if tx['status']=='reverted':need(not logs,'reverted EVM receipt has logs');return {'outcome':'reverted','gasWei':str(gas),'principalByAsset':{},'chosenKind':command['kind']}
 k=command['kind'];deltas={'ETH':-gas,'WETH':0,'USDC':0};detail={}
 if k in ('wrap','unwrap'):
  topic=DEPOSIT if k=='wrap' else WITHDRAWAL;log=one([l for l in logs if l['topics'][0].lower()==topic and address(l['address'])==assets['WETH']],'unique actual wrapped-native event missing');need(len(log['topics'])==2 and topic_address(log['topics'][1])==participant,'wrapped-native actor differs');amount=words(log['data'],1)[0];need(amount==decimal(command['amountWei']),'wrapped-native amount differs from chosen command')
  deltas['ETH']+=-amount if k=='wrap' else amount;deltas['WETH']+=amount if k=='wrap' else -amount;detail={'conversion':k,'amountUnits':str(amount)}
 elif k=='approve':
  token=assets[command['tokenAssetId']];spender=address(approval_spender);log=one([l for l in logs if l['topics'][0].lower()==APPROVAL and address(l['address'])==token],'unique actual Approval missing');need(len(log['topics'])==3 and topic_address(log['topics'][1])==participant and topic_address(log['topics'][2])==spender and words(log['data'],1)[0]==decimal(command['amountUnits']),'actual allowance target/amount differs');detail={'allowanceAssetId':command['tokenAssetId'],'spender':spender,'amountAfterUnits':command['amountUnits']}
 elif k=='transfer':
  event=one([decode_transfer(l) for l in logs if l['topics'][0].lower()==TRANSFER and address(l['address'])==assets['USDC']],'unique actual USDC transfer missing');recipient=address(command['recipient']);need(event['from']==participant and event['to']==recipient and event['amountUnits']==command['amountUnits'],'actual transfer principal differs');deltas['USDC']-=decimal(command['amountUnits']) if recipient!=participant else 0;detail={'transfer':event}
 else:
  route=one([r for r in routes if r['tokenInAssetId']==command['inputAssetId'] and r['tokenOutAssetId']==command['outputAssetId'] and r['feeTier']==command.get('feeTier',500)],'swap route missing');pool=address(route['pool']);log=one([l for l in logs if l['topics'][0].lower()==SWAP and address(l['address'])==pool],'unique actual pool Swap missing');need(len(log['topics'])==3 and topic_address(log['topics'][1])==address(route['router']) and topic_address(log['topics'][2])==address(command['recipient']),'actual swap sender/recipient differs')
  raw=words(log['data'],5);amount0,amount1=signed(raw[0]),signed(raw[1]);input_is_zero=int(address(route['tokenIn']),16)<int(address(route['tokenOut']),16);amount_in=amount0 if input_is_zero else amount1;amount_out=-(amount1 if input_is_zero else amount0)
  need(amount_in==decimal(command['amountInUnits']) and amount_out>=decimal(command['amountOutMinimumUnits']) and amount_out>0,'actual pool input/output contradicts chosen swap')
  transfers=[decode_transfer(l) for l in logs if l['topics'][0].lower()==TRANSFER];one([t for t in transfers if t['token']==address(route['tokenIn']) and t['from']==participant and t['to']==pool and int(t['amountUnits'])==amount_in],'actual swap input transfer missing');one([t for t in transfers if t['token']==address(route['tokenOut']) and t['from']==pool and t['to']==address(command['recipient']) and int(t['amountUnits'])==amount_out],'actual swap output transfer missing')
  deltas[command['inputAssetId']]-=amount_in
  if address(command['recipient'])==participant:deltas[command['outputAssetId']]+=amount_out
  detail={'routeId':route['routeId'],'inputAmountUnits':str(amount_in),'outputAmountUnits':str(amount_out),'recipient':address(command['recipient'])}
 return {'outcome':'success','gasWei':str(gas),'participantDeltas':{k:str(v) for k,v in deltas.items()},'chosenKind':k,'detail':detail}
