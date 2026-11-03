"""Pure ABI/log/gas/state integrity controls; all vectors synthetic and never physical acceptance."""
import copy,hashlib
from pathlib import Path
import pytest
from tests.bdd.adapters.ber_chain_effects import verify_chain_action,APPROVAL,DEPOSIT,WITHDRAWAL,SWAP,TRANSFER
A={'WETH':'0x'+'1'*40,'USDC':'0x'+'2'*40};P='0x'+'5'*40;R='0x'+'6'*40;ROUTER='0x'+'3'*40;POOL='0x'+'4'*40;TX='0x'+'a'*64;BLOCK='0x'+'b'*64
ROUTES=[{'routeId':'pinned','tokenInAssetId':'WETH','tokenOutAssetId':'USDC','router':ROUTER,'pool':POOL,'tokenIn':A['WETH'],'tokenOut':A['USDC'],'feeTier':500}]
def w(v):return format(v,'064x')
def ta(v):return '0x'+v[2:].rjust(64,'0')
def log(token,topic,indexed,data):return {'address':token,'topics':[topic]+[ta(x) for x in indexed],'data':'0x'+data,'transactionHash':TX,'blockHash':BLOCK,'blockNumber':'8','logIndex':'0','removed':False}
def fixture(kind):
 tx={'hash':TX,'from':P,'to':A['WETH'],'input':'0x','valueWei':'0','gasLimit':'100000','blockHash':BLOCK,'blockNumber':'8','gasUsed':'21000','effectiveGasPriceWei':'2','gasCostWei':'42000','status':'success','logs':[]}
 if kind=='wrap':c={'kind':kind,'amountWei':'2000','gasLimit':'100000'};tx.update(input='0xd0e30db0',valueWei='2000',logs=[log(A['WETH'],DEPOSIT,[P],w(2000))])
 elif kind=='unwrap':c={'kind':kind,'amountWei':'1000','gasLimit':'100000'};tx.update(input='0x2e1a7d4d'+w(1000),logs=[log(A['WETH'],WITHDRAWAL,[P],w(1000))])
 elif kind=='approve':c={'kind':kind,'tokenAssetId':'WETH','amountUnits':'1000','gasLimit':'100000'};tx.update(input='0x095ea7b3'+ROUTER[2:].rjust(64,'0')+w(1000),logs=[log(A['WETH'],APPROVAL,[P,ROUTER],w(1000))])
 elif kind=='transfer':c={'kind':kind,'amountUnits':'1','recipient':R,'gasLimit':'100000'};tx.update(to=A['USDC'],input='0xa9059cbb'+R[2:].rjust(64,'0')+w(1),logs=[log(A['USDC'],TRANSFER,[P,R],w(1))])
 else:
  c={'kind':'swap','inputAssetId':'WETH','outputAssetId':'USDC','feeTier':500,'amountInUnits':'1000','amountOutMinimumUnits':'1','recipient':P,'gasLimit':'300000'}
  tx.update(to=ROUTER,gasLimit='300000',input='0x04e45aaf'+A['WETH'][2:].rjust(64,'0')+A['USDC'][2:].rjust(64,'0')+w(500)+P[2:].rjust(64,'0')+w(1000)+w(1)+w(0),logs=[log(POOL,SWAP,[ROUTER,P],w(1000)+w(2**256-500)+w(1)+w(1)+w(0)),log(A['WETH'],TRANSFER,[P,POOL],w(1000)),log(A['USDC'],TRANSFER,[POOL,P],w(500))])
 tx['inputSha256']=hashlib.sha256(tx['input'].encode()).hexdigest();return c,tx
@pytest.mark.parametrize('kind',['wrap','approve','swap','unwrap','transfer'])
def test_standard_abi_and_receipt_log_effects_remain_separate_from_grade_or_acceptance(kind):
 c,t=fixture(kind);f=verify_chain_action(c,t,P,A,ROUTES,ROUTER)
 assert f['outcome']=='success' and f['gasWei']=='42000'
 assert 'credit' not in f and 'fullAcceptance' not in f
@pytest.mark.parametrize('kind',['wrap','approve','swap','unwrap','transfer'])
@pytest.mark.parametrize('change',['command_amount','calldata','gas','log_amount','foreign_block'])
def test_chosen_action_cannot_borrow_conflicting_abi_log_gas_or_block_evidence(kind,change):
 c,t=fixture(kind)
 if change=='command_amount':
  key='amountWei' if kind in ('wrap','unwrap') else 'amountInUnits' if kind=='swap' else 'amountUnits';c[key]=str(int(c[key])+1)
 elif change=='calldata':t['input']='0x00000000'+t['input'][10:];t['inputSha256']=hashlib.sha256(t['input'].encode()).hexdigest()
 elif change=='gas':t['gasCostWei']='42001'
 elif change=='log_amount':t['logs'][0]['data']='0x'+w(0)*(5 if kind=='swap' else 1)
 else:t['logs'][0]['blockHash']='0x'+'f'*64
 with pytest.raises(AssertionError):verify_chain_action(c,t,P,A,ROUTES,ROUTER)
@pytest.mark.parametrize('kind',['wrap','approve','swap','unwrap','transfer'])
def test_reverted_original_transaction_proves_gas_and_no_receipt_logs_not_success(kind):
 c,t=fixture(kind);t.update(status='reverted',logs=[]);f=verify_chain_action(c,t,P,A,ROUTES,ROUTER);assert f['outcome']=='reverted' and f['gasWei']=='42000' and f['principalByAsset']=={}

# These historical files exercise actual retained wire shapes only. They do not
# qualify current source, a new sealed B campaign, or an environment scenario.
LEGACY_CHAIN_REFS=(
 ('H3','artifacts/runs/owner-identity-bef-task-coordinator/observation/1fa68047-aff6-48dd-804d-a8be72839db8/H3/4661907bd94392feb5bd06a431aa28fac62a2176dfe9cfa0f88dabd856c334a4.json','4661907bd94392feb5bd06a431aa28fac62a2176dfe9cfa0f88dabd856c334a4'),
 ('U1','artifacts/runs/owner-identity-bef-task-coordinator/observation/2e25d17a-b5cc-4ec3-b300-8db715a484b4/U1/cdf4199a9cdd20f74dd21a422b64547d53bbfa90610c5e1e3d0b069bf7e84bda.json','cdf4199a9cdd20f74dd21a422b64547d53bbfa90610c5e1e3d0b069bf7e84bda'),
)
def actual_legacy(ref):
 import json
 root=Path(__file__).resolve().parents[3];path=root/ref[1]
 if not path.is_file():pytest.skip('BLOCKED: original historical chain DTO unavailable; no synthetic replacement')
 raw=path.read_bytes();assert hashlib.sha256(raw).hexdigest()==ref[2];return json.loads(raw)
@pytest.mark.parametrize('ref',LEGACY_CHAIN_REFS,ids=['actual_H3_shape','actual_U1_shape'])
def test_original_historical_rpc_receipt_shapes_decode_without_regrading_or_current_qualification(ref):
 packet=actual_legacy(ref);assert packet['schemaVersion']=='bts-chain-task-observation-capture/v1'
 assets={a['assetId']:a['address'] for a in packet['rpc']['assets'] if a.get('address')}
 for action in packet['ownerActions']:
  tx=next(t for t in packet['rpc']['transactions'] if t['hash']==action['transactionHash'])
  fact=verify_chain_action(action['command'],tx,packet['rpc']['participant'],assets,packet['rpc']['routes'],action['approvalSpender'])
  assert fact['outcome']==tx['status'] and 'credit' not in fact
@pytest.mark.parametrize('kind',['wrap','approve','swap','unwrap','transfer'])
def test_actual_historical_command_mutation_cannot_reuse_original_transaction_and_logs(kind):
 packets=[actual_legacy(ref) for ref in LEGACY_CHAIN_REFS]
 packet,action=next((p,a) for p in packets for a in p['ownerActions'] if a['actionKind']==kind)
 command=copy.deepcopy(action['command']);key='amountWei' if kind in ('wrap','unwrap') else 'amountInUnits' if kind=='swap' else 'amountUnits';command[key]=str(int(command[key])+1)
 assets={a['assetId']:a['address'] for a in packet['rpc']['assets'] if a.get('address')};tx=next(t for t in packet['rpc']['transactions'] if t['hash']==action['transactionHash'])
 with pytest.raises(AssertionError):verify_chain_action(command,tx,packet['rpc']['participant'],assets,packet['rpc']['routes'],action['approvalSpender'])

def test_approval_cannot_authorize_a_spender_absent_from_declared_technical_routes():
 c,t=fixture('approve')
 with pytest.raises(AssertionError):verify_chain_action(c,t,P,A,[],ROUTER)
