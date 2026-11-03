"""Exact derived-history negatives on original retained controlled Training B."""
import json,copy
from pathlib import Path
import pytest
from tests.bdd.adapters.ber_matrix_derived_effects import verify_derived_chain_effects
from tests.bdd.adapters.ber_matrix_common import load_ref
ROOT=Path(__file__).resolve().parents[3];OWNER=ROOT/'.local/ber-final-source-private-owner-snapshot-b02c1052-6a40-46af-a132-54b77889dab5.json'
def fixture(index=0):
 o=json.loads(OWNER.read_text());b=o['bundles'][index]['bundle_json'];p=load_ref(ROOT,b['cutoff']['evidence']);ch=load_ref(ROOT,p['children']['chain']['evidence']);docs={e['actionId']:load_ref(ROOT,e['actionEvidence']) for e in p['census']['entries']};return ch,p['census']['entries'],docs,b
@pytest.mark.parametrize('index',[0,1,2])
def test_actual_chain_derived_economics_is_separate_from_direct_state_acceptance(index):
 ch,entries,docs,b=fixture(index);f=verify_derived_chain_effects(ch,entries,docs,b,ROOT);assert f['economicEffectsVerified'] and not f['directPerActionAllowancePoolRpc'] and not f['absoluteIndependentPoolSnapshotVerified'] and not f['full135StrongSupport']
@pytest.mark.parametrize('change',['foreign_tx','gap','runtime_code','allowance_anchor','gas','trade','missing_conversion'])
def test_missing_census_or_contradictory_anchors_cannot_use_derived_history(change):
 ch,entries,docs,b=fixture()
 if change=='foreign_tx':ch['rpc']['intervalBlocks'][-1]['externalTransactions'].append('0x'+'f'*64)
 elif change=='gap':ch['rpc']['intervalBlocks'].pop(0)
 elif change=='runtime_code':ch['rpc']['identityCodeHashes'][0]['observedCodeHash']='f'*64
 elif change=='allowance_anchor':ch['rpc']['final']['allowances'][0]['amountUnits']='1'
 elif change=='gas':b['observations']['expenses'][0]['gasUsed']='1'
 elif change=='trade':b['observations']['trades'][0]['outputAmountUnits']='1'
 else:b['observations']['conversions'].pop()
 with pytest.raises(AssertionError):verify_derived_chain_effects(ch,entries,docs,b,ROOT)
