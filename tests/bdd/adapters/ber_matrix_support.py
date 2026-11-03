"""Independent supporting observer replay. Reads immutable artifacts; no RPC, authority or grading."""
import sys,re
from pathlib import Path
from datetime import datetime
from tests.bdd.adapters.ber_matrix_common import need,one,digest,load_ref
from tests.bdd.adapters.ber_chain_effects import address
sys.path.insert(0,str(Path(__file__).resolve().parents[3]))
from tests.bdd.adapters.benchmark_environment_feasibility import _keccak256
HEX=re.compile(r'^0x(?:[0-9a-fA-F]{2})*$')
def ms(v):
 need(isinstance(v,str),'missing timestamp');return datetime.fromisoformat(v.replace('Z','+00:00')).timestamp()*1000

def uint_hex(v,words=None):
 need(isinstance(v,str) and re.fullmatch(r'0x[0-9a-fA-F]+',v),'invalid RPC quantity')
 if words is not None:need(len(v)==2+64*words,'invalid RPC ABI width')
 return int(v,16)
def receipt_outcome(value):
 n=uint_hex(value);need(n in (0,1),'receipt status is not exact EVM success/revert');return 'success' if n==1 else 'reverted'
def timeout(v):
 m=re.fullmatch(r'(\d+)(ms|s|min|h|d)?',v);need(m is not None,'unknown inherited statement timeout');return int(m[1])*{None:1,'ms':1,'s':1000,'min':60000,'h':3600000,'d':86400000}[m[2]]
def code_hash(v):
 need(isinstance(v,str) and HEX.fullmatch(v),'invalid raw runtime code');return _keccak256(bytes.fromhex(v[2:])).hex()
def aword(v):return address(v)[2:].rjust(64,'0')
def ref_equal(a,b):return a['path']==b['path'] and a['sha256']==b['sha256']
def _source_role(source):
 o=source['observer'];need(o['role']==o['sessionRole']=='bef_observer' and o['databaseName']=='bef' and o['readOnly'] is True and o['transactionReadOnly']=='on' and o['isolation']=='repeatable read' and o['superuser'] is False and o['bypassRls'] is False,'support BEF source role not readonly')
def snapshot_completed_at(snapshot):
 completed=ms(snapshot['observationCompletedAt']);need(all(completed>=ms(t['observed_at']) for t in snapshot['target']),'snapshot completion precedes its target SQL observation');need(all(w.get('query_start') is None or completed>=ms(w['query_start']) for w in snapshot['waiters']),'snapshot completion precedes a real waiter query');return completed

def verify_completion_witnesses(snapshots,proof,deadline=None):
 need(isinstance(snapshots,list) and len(snapshots)==4,'four actual snapshot witnesses required')
 values=[snapshot_completed_at(x) for x in snapshots]
 need(values==sorted(values) and proof['observationCompletedAt']==snapshots[1]['observationCompletedAt'],'snapshot completion witnesses missing/reversed or unbound')
 if deadline is not None:need(all(x<=deadline for x in values),'snapshot completion witness exceeds original observation deadline')
 return values

def verify_chain_support(support_ref,root_ref,owner,capture,index,repo):
 s=load_ref(repo,support_ref);need(s['schemaVersion']=='ber-chain-boundary-observer/v1' and s['status']=='captured_support_requires_independent_replay','support is absent, blocked or different schema')
 root=load_ref(repo,root_ref);chain_ref=root['children']['chain']['evidence'];chain=load_ref(repo,chain_ref);binding=root['binding'];execution=root['execution'];closure=root['closure'];target=s['target']
 need(target=={'runId':binding['runId'],'taskIndex':index,'taskId':binding['taskId']} and s['binding']==binding and s['execution']==execution and s['closure']==closure,'support root scope differs')
 need(ref_equal(s['candidateRootRef'],root_ref) and ref_equal(s['committedRootRef'],root_ref) and ref_equal(s['chainRef'],chain_ref),'support observed uncommitted/retry or different root')
 for entry in s['originalClosureIntegrity']:
  p=repo/entry['path'];need(p.is_file() and p.stat().st_size==entry['size'],'support original closure size differs');load_ref(repo,entry)
 checkpoints=s['checkpoints'];expected=['armed_before_single_finish','actual_blocked_seal','read_boundary_still_same_waiter','normal_worker_known_commit'];need([c['phase'] for c in checkpoints]==expected,'support lifecycle checkpoints incomplete')
 cp=[load_ref(repo,c['ref']) for c in checkpoints];db=capture['database']['databaseName'];pid=s['controller']['pid'];need(s['controller']['role']=='oid_owner' and s['controller']['database_name']==db and type(pid)is int and pid>0,'support controller scope differs')
 for snap in cp:
  o=snap['identity'];need(o['role']=='oid_observer' and o['database_name']==db and o['read_only']=='on' and o['isolation']=='repeatable read','support owner observer not readonly')
  t=one(snap['target'],'one support task required');need(t['run_id']==binding['runId'] and t['task_index']==index and t['task_id']==binding['taskId'] and t['env_id']==execution['environmentId'] and t['generation_id']==execution['generationId'] and t['preparation_id']==execution['preparationId'] and t['lease_id']==execution['leaseId'],'support owner target differs')
  need(len(snap['actions'])==len(root['census']['entries']),'support owner cutoff census differs')
  for a,e in zip(snap['actions'],root['census']['entries']):need(a['id']==e['actionId'] and a['operation_id']==e['ownerOperationId'] and a['command_json']==e['command'] and a['payload_hash']==e['commandSha256'] and a['receipt_status']==e['receiptStatus'] and a['transaction_hash']==e['transactionHash'] and a['evidence_path']==e['actionEvidence']['path'] and a['evidence_hash']==e['actionEvidence']['sha256'],'support original owner action differs')
 need(cp[0]['target'][0]['closure_status']=='open' and all(not x['committed'] and not x['evaluations'] for x in cp[:3]),'support did not hold before any commit/evaluation')
 blocked,still=cp[1:3];t=blocked['target'][0];completed=verify_completion_witnesses(cp,s)
 for snap in (blocked,still):
  row=snap['target'][0];need(row['run_status']=='running' and row['closure_status']=='closed' and row['closure_id']==closure['closureId'] and row['closure_operation_id']==row['journal_operation_id']==closure['operationId'] and row['closure_payload_hash']==closure['payloadHash'] and row['closure_reason']==closure['reason'] and int(row['action_cutoff_sequence'])==int(row['reconciled_action_sequence'])==int(row['journal_cutoff'])==closure['actionCutoffSequence'] and row['lease_state']=='leased' and row['lease_fenced_at'] is None,'support closed action boundary differs')
  coord=one(snap['coordinator'],'one actual coordinator lease required');need(coord['granted'] is True and str(coord['classid'])=='1330201666' and str(coord['objid'])=='1162237745' and coord['objsubid']==2,'support coordinator lock differs')
 waiters=[w for w in blocked['waiters'] if w['mode']=='RowExclusiveLock' and w['granted'] is False and pid in w['blocking_pids']];waiter=one(waiters,'one actual blocked seal required');need(blocked['coordinator'][0]['pid']==still['coordinator'][0]['pid'] and any(w['pid']==waiter['pid'] and w['granted'] is False and pid in w['blocking_pids'] and w['query_start']==waiter['query_start'] for w in still['waiters']),'support seal waiter/coordinator changed')
 settings=s['inheritedWorkerConnectionSettings'];need(settings['role']=='oid_owner' and settings['database_name']==db and settings['read_only']=='on','inherited worker settings scope differs');stmt=timeout(settings['statement_timeout']);bound=min(ms(t['closed_at'])+180000,ms(t['overall_deadline']),ms(waiter['query_start'])+stmt if stmt else float('inf'))-1000
 need(ms(s['actualReadDeadline'])==bound and ms(s['taskAdmissionDeadline'])==ms(t['deadline_at']),'support changed existing grading/statement deadline');verify_completion_witnesses(cp,s,bound)
 committed=one(cp[3]['committed'],'support did not observe original normal commit');ev=one(cp[3]['evaluations'],'support did not observe normal known evaluation');need(ref_equal(committed['bundle_json']['cutoff']['evidence'],root_ref) and digest(committed['bundle_json'])==committed['bundle_hash'] and ev['result_json']['status']=='known' and digest(ev['input_json'])==ev['input_hash'] and digest(ev['result_json'])==ev['result_hash'],'support committed evaluator input/result differs')
 original=one([e for e in owner['evaluations'] if e['task_index']==index],'original evaluation absent');need(ev['input_hash']==original['input_hash'] and ev['result_hash']==original['result_hash'] and ev['evaluator_source_hash']==original['evaluator_source_hash'],'support committed evaluation differs from owner snapshot')
 for sr in (s['befSourceRef'],s['befSourceAfterReadsRef']):
  src=load_ref(repo,sr);_source_role(src);g=one(src['generations'],'one active source generation required');need(g['generation_id']==execution['generationId'] and g['env_id']==execution['environmentId'] and g['status']=='active' and g['fenced_at'] is None and any(p['preparation_id']==execution['preparationId'] and p['status']=='ready' and p['fence_confirmed_at'] is None for p in src['preparations']),'source generation fenced/changed during reads')
 source=load_ref(repo,s['befSourceRef']);raw=source['selectedEvents'];need(digest(raw['rows'])==raw['rowsSha256'],'raw source event JSON checksum differs');events=chain['bef']['before']['selectedEvents'];need(len(raw['rows'])==len(events),'source raw event inventory differs')
 for e in events:
  row=one([r for r in raw['rows'] if r['event_id']==e['eventId']],'raw original event preimage missing');need(row['env_id']==execution['environmentId'] and row['generation_id']==execution['generationId'] and row['operation_id']==e['operationId'] and str(row['event_sequence'])==str(e['eventSequence']) and row['event_kind']==e['eventKind'] and row['transaction_hash']==e['transactionHash'] and digest(row['event_json'])==e['eventJsonSha256'],'source event preimage changed')
 rpc=s['rpc'];need(rpc['schemaVersion']=='ber-chain-per-action-readonly-rpc/v1' and rpc['requestCount']==len(rpc['requests'])<=256,'support RPC census invalid');documents={};headers={}
 for item in rpc['requests']:
  need(item['method'] in ('eth_chainId','eth_getTransactionByHash','eth_getTransactionReceipt','eth_getBlockByNumber','eth_getCode','eth_getBalance','eth_getTransactionCount','eth_call'),'non-readonly RPC in support')
  key=(item['ref']['path'],item['ref']['sha256']);need(key not in documents,'RPC raw ref repeated');doc=load_ref(repo,item['ref']);need(doc['schemaVersion']=='ber-fixed-readonly-rpc/v1' and doc['request']=={'method':item['method'],'params':item['params']} and doc['httpStatus']==200 and ms(doc['startedAt'])>=ms(t['closed_at']) and ms(doc['completedAt'])>=ms(doc['startedAt']) and ms(doc['completedAt'])<bound,'RPC outside original observation window');documents[key]=doc
  if item['method']=='eth_getBlockByNumber':headers.setdefault(digest(item['params']),[]).append(doc)
 def doc(ref):return documents[(ref['path'],ref['sha256'])]
 need(uint_hex(doc(rpc['chainIdRef'])['result'])==int(chain['rpc']['localChainId']),'support chain ID differs');need(all(ms(x['startedAt'])>=completed[1] and ms(x['completedAt'])<=completed[2] for x in documents.values()),'RPC reads do not fit actual completed SQL witness window')
 for observations in headers.values():need(len(observations)>=2 and all(d['result']==observations[0]['result'] for d in observations),'support lacks stable header re-read')
 actual=chain['ownerActions'];need(len(rpc['actions'])==len(actual) and len({a['actionId'] for a in rpc['actions']})==len(actual),'per-action support dropped/duplicated chain action');states={}
 manifest=load_ref(repo,chain['technicalScope']['manifest']);assets={a['assetId']:address(a['address']) for a in chain['rpc']['assets'] if a.get('address')};participant=address(chain['rpc']['participant']);router=address(manifest['contracts']['swapRouter02']['address'])
 pins={address(manifest['contracts']['weth']['address']):manifest['contracts']['weth']['codeHash'],address(manifest['contracts']['usdc']['address']):manifest['contracts']['usdc']['proxyCodeHash'],router:manifest['contracts']['swapRouter02']['codeHash']}
 for a in rpc['actions']:
  owner_a=one([x for x in actual if x['actionId']==a['actionId']],'foreign support action');tx=one([x for x in chain['rpc']['transactions'] if x['hash']==a['transactionHash']],'worker transaction absent');need(a['transactionHash']==owner_a['transactionHash'] and a['actionSequence']==owner_a['actionSequence'] and a['ownerOperationId']==owner_a['ownerOperationId'] and a['befOperationId']==owner_a['befOperationId'] and a['kind']==owner_a['actionKind'],'support chosen action differs')
  pool=address(manifest['contracts']['pool']['address'])
  if a['kind']=='swap':pool=address(one([r for r in chain['rpc']['routes'] if r['tokenInAssetId']==owner_a['command']['inputAssetId'] and r['tokenOutAssetId']==owner_a['command']['outputAssetId'] and r['feeTier']==owner_a['command'].get('feeTier',500)],'chosen route missing')['pool'])
  need(address(a['pool'])==pool,'support selected pool differs');poolpin=one([v for v in manifest['contracts'].values() if isinstance(v,dict) and v.get('address','').lower()==pool],'manifest pool pin absent');pins[pool]=poolpin['codeHash']
  receipt=doc(a['receiptRef']);transaction=doc(a['transactionRef']);need(receipt['request']=={'method':'eth_getTransactionReceipt','params':[a['transactionHash']]} and transaction['request']=={'method':'eth_getTransactionByHash','params':[a['transactionHash']]},'support tx query differs')
  rt,tt=receipt['result'],transaction['result'];need(rt['transactionHash']==tt['hash']==a['transactionHash'] and rt['blockHash']==tt['blockHash']==tx['blockHash'] and uint_hex(rt['blockNumber'])==uint_hex(tt['blockNumber'])==int(tx['blockNumber']) and receipt_outcome(rt['status'])==tx['status'] and uint_hex(rt['gasUsed'])==int(tx['gasUsed']) and uint_hex(rt['effectiveGasPrice'])==int(tx['effectiveGasPriceWei']) and address(tt['from'])==address(rt['from'])==participant and address(tt['to'])==address(tx['to']) and tt['input'].lower()==tx['input'].lower() and uint_hex(tt['value'])==int(tx['valueWei']) and uint_hex(tt['gas'])==int(tx['gasLimit']),'independent original tx/receipt changed')
  # Logs remain exact safe unsigned raw RPC; compare numeric hex fields to retained worker decimal fields.
  need(len(rt['logs'])==len(tx['logs']),'support receipt logs omitted')
  for rawlog,workerlog in zip(rt['logs'],tx['logs']):
   need(address(rawlog['address'])==address(workerlog['address']) and rawlog['topics']==workerlog['topics'] and rawlog['data']==workerlog['data'] and rawlog['transactionHash']==workerlog['transactionHash'] and rawlog['blockHash']==workerlog['blockHash'] and uint_hex(rawlog['blockNumber'])==int(workerlog['blockNumber']) and uint_hex(rawlog['logIndex'])==int(workerlog['logIndex']) and rawlog['removed'] is False,'independent original log changed')
  ph=doc(a['parentHeaderRef']);mh=doc(a['minedHeaderRef']);need(mh['result']['hash']==tx['blockHash'] and mh['result']['parentHash']==ph['result']['hash'] and uint_hex(ph['result']['number'])+1==uint_hex(mh['result']['number']),'per-action block ancestry differs')
  need(len(a['states'])==2,'parent/mined state pair missing');pair=[]
  for ix,state in enumerate(a['states']):
   expected_header=ph if ix==0 else mh;tag=state['blockTag'];need(state['blockHash']==expected_header['result']['hash'] and uint_hex(tag)==uint_hex(expected_header['result']['number']),'state block binding differs');values={}
   for read in state['reads']:
    label=read['label'];need(label not in values,'duplicate state label');rd=doc(read['ref']);method,params=rd['request']['method'],rd['request']['params'];need(params[-1]==tag,'state read changed block')
    if label=='participant.ETH':need(method=='eth_getBalance' and params==[participant,tag],'native state request differs');value=uint_hex(rd['result'])
    elif label=='participant.nonce':need(method=='eth_getTransactionCount' and params==[participant,tag],'nonce request differs');value=uint_hex(rd['result'])
    elif label.startswith('code.'):
     addr=address(label[5:]);need(addr in pins and method=='eth_getCode' and params==[addr,tag] and code_hash(rd['result'])==pins[addr].removeprefix('0x').lower(),'runtime code differs from pinned source');value=rd['result']
    else:
     need(method=='eth_call' and isinstance(params[0],dict) and set(params[0])=={'to','data'},'state call shape differs');section,asset=label.split('.',1)
     if label in ('pool.slot0','pool.liquidity'):
      expected_data='0x3850c7bd' if asset=='slot0' else '0x1a686502';need(address(params[0]['to'])==pool and params[0]['data']==expected_data,'pool selector differs');uint_hex(rd['result'],7 if asset=='slot0' else 1);value=rd['result']
     else:
      need(asset in ('WETH','USDC') and section in ('participant','allowance','pool','recipient'),'unrecognized state read');account=participant if section in ('participant','allowance') else pool if section=='pool' else address(owner_a['command']['recipient']);data='0xdd62ed3e'+aword(participant)+aword(router) if section=='allowance' else '0x70a08231'+aword(account);need(address(params[0]['to'])==assets[asset] and params[0]['data']==data,'balance/allowance request differs');value=uint_hex(rd['result'],1)
    values[label]=value
   required={'participant.ETH','participant.nonce','participant.WETH','participant.USDC','allowance.WETH','allowance.USDC','pool.WETH','pool.USDC','pool.slot0','pool.liquidity'}|{'code.'+x for x in pins}
   recipient=owner_a['command'].get('recipient');
   if recipient and address(recipient)!=participant:required|={'recipient.WETH','recipient.USDC'}
   need(set(values)==required,'missing/extra independent state/code target');pair.append(values)
  states[a['actionId']]={'before':pair[0],'after':pair[1],'pool':pool,'command':owner_a['command'],'transactionHash':a['transactionHash']}
 return {'directPerActionReads':True,'sourceEventPreimages':len(events),'actualActions':len(states),'states':states,'deadlineMs':bound,'fullAcceptance':False}
