"""Synthetic dispatcher integrity controls; no physical gate is activated."""
import hashlib,json
from pathlib import Path
import pytest
from tests.bdd.adapters.ber_full_replay import verify_full_capture,SCENARIO_FACTS,source_inventory

def ref(root,name,value,raw=False):
 p=root/name;p.parent.mkdir(parents=True,exist_ok=True);b=value if raw else json.dumps(value,separators=(',',':')).encode();p.write_bytes(b);return {'path':name,'sha256':hashlib.sha256(b).hexdigest()}

@pytest.mark.parametrize('scenario',SCENARIO_FACTS)
def test_absent_actual_components_never_become_passed_by_schema_or_claimed_flags(tmp_path,scenario):
 from tests.bdd.adapters.ber_matrix_replay import READER_PATHS
 from tests.bdd.adapters.ber_full_replay import ASSEMBLY_NORMATIVE_PATHS
 refs=[ref(tmp_path,p,b'# synthetic fixture only',True) for p in set(READER_PATHS)|set(ASSEMBLY_NORMATIVE_PATHS)];inventory={r['path']:r['sha256'] for r in refs};capture=ref(tmp_path,'capture.json',{'schemaVersion':'ber-admitted-learning-full-capture/v1','sourceInputs':{'before':inventory,'after':inventory}});report=verify_full_capture(capture,scenario,repository_root=tmp_path)
 assert report['fullScenarioAcceptance']=='blocked' and report['missingBoundaries'] and not any(report['facts'].values()) and report['nativeAgentAcceptance']=='not_run'

@pytest.mark.parametrize('fault',['current_drift','before_after','producer_fact'])
def test_full_schema_cannot_waive_source_or_replace_raw_capture_with_boolean(tmp_path,fault):
 source=ref(tmp_path,'reader.py',b'# test',True);pins={source['path']:source['sha256']};v={'schemaVersion':'ber-admitted-learning-full-capture/v1','sourceInputs':{'before':pins.copy(),'after':pins.copy()}}
 if fault=='current_drift':(tmp_path/'reader.py').write_bytes(b'# changed')
 elif fault=='before_after':v['sourceInputs']['after']={}
 else:v['facts']={'all_fifteen_paths_all_nine_kinds':True}
 capture=ref(tmp_path,'capture.json',v)
 with pytest.raises((AssertionError,KeyError)):verify_full_capture(capture,'BER-SC-009',repository_root=tmp_path)

def test_dispatcher_fact_names_match_the_existing_approved_four_contracts():
 root=Path(__file__).resolve().parents[3];contracts=json.loads((root/'tests/bdd/changes/benchmark-execution-reliability/harness-contracts.json').read_text())
 # The harness uses scenarios as a list. Schema changes cannot silently add or drop a gate.
 rows=contracts['protected_scenarios']
 for sid,facts in SCENARIO_FACTS.items():
  row=rows[sid]
  assert set(row['required_observations']+row['negative_variants'])<=set(facts)
  import ast
  tree=ast.parse((root/'tests/bdd/adapters/benchmark_execution_reliability.py').read_text());method=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='_verify_'+sid.replace('-','_'));checks={n.args[0].value for n in ast.walk(method) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='check' and n.args and isinstance(n.args[0],ast.Constant)};assert checks==set(facts)
