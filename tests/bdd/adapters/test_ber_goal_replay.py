"""Retained raw/semantic diagnostics do not repin old physical source cohorts."""
import copy,json
from pathlib import Path
import pytest
from tests.bdd.adapters.ber_goal_replay import verify_semantic_capture,verify_s1_native_arithmetic
from tests.bdd.adapters.ber_matrix_common import load_ref
ROOT=Path(__file__).resolve().parents[3]
SEMANTIC={'path':'.local/ber-rubric-semantic-b57edfd2-7578-4d67-a61d-5f228dc38c99/capture.json','sha256':'daa5d4aafdc851bfa01310356626e1b84844ee2e783bf3ad7d6fb0d2dd178b1d'}

def test_actual_unchanged_canonical_suite_includes_four_distinct_numeric_reserve_cases():
 r=verify_semantic_capture(SEMANTIC,ROOT);assert r['semanticOnly'] and r['actualPassingTests']==31 and not r['isolatedLiveBelowReserveClaimed']

@pytest.fixture(scope='module')
def s1():
 folder=ROOT/'.local/ber-private-campaign/c72096d4-e5fa-484f-9b30-9b2fed4f0cd1/ranked_c';owner=load_ref(ROOT,json.loads((folder/'owner-ref.json').read_text()));bundle=owner['bundles'][0]['bundle_json'];root=load_ref(ROOT,bundle['cutoff']['evidence']);return load_ref(ROOT,root['children']['chain']['evidence']),bundle['observations']

def test_actual_s1_native_wrap_swap_and_gas_arithmetic_reaches_exact_sealed_final_state(s1):
 chain,obs=s1;r=verify_s1_native_arithmetic(chain,obs);assert int(r['initialNativeWei'])+int(r['netOriginalPrincipalAndGasWei'])==int(r['finalNativeWei'])

@pytest.mark.parametrize('fault',['final_native','initial_native','sealed_native','double_gas'])
def test_named_reserve_fact_cannot_ignore_actual_native_or_gas_mismatch(s1,fault):
 ch,obs=copy.deepcopy(s1)
 if fault in ('final_native','initial_native'):
  state=ch['rpc']['final' if fault=='final_native' else 'baseline'];row=next(b for b in state['balances'] if b['account']=='participant' and b['assetId']=='ETH');row['amountUnits']=str(int(row['amountUnits'])+1)
 elif fault=='sealed_native':
  row=next(b for b in obs['finalStates'][0]['balances'] if b['account']=='participant' and b['assetId']=='ETH');row['amountUnits']=str(int(row['amountUnits'])+1)
 else:
  c=copy.deepcopy(ch['bef']['before']['costs'][0]);c['transactionHash']='0x'+'f'*64;c['payerRole']='participant';ch['bef']['before']['costs'].append(c)
 with pytest.raises(AssertionError):verify_s1_native_arithmetic(ch,obs)


def test_all_six_historical_profile_goal_shapes_support_named_checks_without_current_cohort_claim():
 from tests.bdd.adapters.ber_goal_replay import verify_goal_controls
 reports=[]
 for mode,profile,folder in [('training','A','c72096d4-e5fa-484f-9b30-9b2fed4f0cd1/training_a'),('training','B','4e4b4249-b5ed-453a-a24f-d80d8ec3d470/training_b'),('ranked','B','4e4b4249-b5ed-453a-a24f-d80d8ec3d470/ranked_b'),('training','C','c72096d4-e5fa-484f-9b30-9b2fed4f0cd1/training_c'),('ranked','C','c72096d4-e5fa-484f-9b30-9b2fed4f0cd1/ranked_c')]:
  ref=json.loads((ROOT/'.local/ber-private-campaign'/folder/'owner-ref.json').read_text());owner=load_ref(ROOT,ref);reports.append({'ownerRef':ref,'runId':owner['run'][0]['id'],'mode':mode,'profile':profile})
 ref={'path':'.local/ber-ranked-a-r4-private-owner-snapshot-b0eb5586-f514-42b1-9ba1-d14277dfa532.json','sha256':'0fdfd91d37626c52d885460136b2a0dd701e6ba64b56a63a2c5ae8afe5f71b2c'};owner=load_ref(ROOT,ref);reports.append({'ownerRef':ref,'runId':owner['run'][0]['id'],'mode':'ranked','profile':'A'})
 facts=verify_goal_controls({'semanticRef':SEMANTIC},reports,ROOT);assert all(facts['actualGoalPredicates'].values()) and len(facts['S1NativeArithmeticAndInputLinks'])==6 and not facts['isolatedLiveBelowReserveClaimed']
 # These inputs are deliberately historical. Main full dispatcher must still rerun
 # source-bound reports; this diagnostic never creates/replaces a physical report.
