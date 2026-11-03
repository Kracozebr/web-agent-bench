"""Synthetic causality mutations exercise the reader, never native acceptance."""
import copy,hashlib
import pytest
from tests.bdd.adapters.ber_native_replay import verify_native_action_causality

def fixture():
 run={'id':'run','intent_id':'intent','agent_id':'agent','owner_id':'owner','mode':'training'};action={'id':'action','operation_id':'original_operation','task_index':0};case={'runId':'run','intentId':'intent','agentId':'agent','ownerId':'owner','caseId':'case'}
 call={'eventId':'70000000-0000-4000-8000-000000000004','type':'mcp_tool_call_end','server':'w3bench_user','tool':'runs.task_action','callIdHash':'c'*64,'traceId':'70000000-0000-4000-8000-000000000001','outcome':'success'};terminal={'eventId':'70000000-0000-4000-8000-000000000005','type':'mcp_tool_call_end','server':'w3bench_user','tool':'runs.current_task','callIdHash':'d'*64,'traceId':'70000000-0000-4000-8000-000000000002','outcome':'success','run':{'runId':'run','status':'completed','terminal':True}}
 native={'clientVersion':'0.165.0','summary':{'exitCode':0,'interrupted':False,'terminalEvent':'turn.completed','localToolCallCount':0,'unknownMcpToolCallCount':0,'skippedOversizeLines':0,'unparsedJsonLines':0,'mcpToolCallCount':2},'implementation':'native_codex_cli','boundary':'actual_pinned_native_model_process','localToolCalls':[],'selection':{'intentId':'intent','agentId':'agent','mode':'training'},'calls':[call,terminal]}
 events=[{'source':'server','caseId':'case','stage':'sdk_validation','tool':'runs.task_action','outcome':'success','traceId':'70000000-0000-4000-8000-000000000001','callIdHash':'e'*64,'operationIdHash':hashlib.sha256(b'original_operation').hexdigest()},{'source':'server','caseId':'case','stage':'admission','outcome':'success','traceId':'70000000-0000-4000-8000-000000000001','actionId':'action','taskIndex':0}]
 diag={'source':'postgresql_observer','observer':{'role':'oid_observer','readOnly':True},'cases':[case],'events':events};outbox={'calls':native['calls'],'events':[{'eventId':call['eventId'],'source':'client','tool':call['tool'],'callIdHash':call['callIdHash'],'traceId':call['traceId'],'operationIdHash':hashlib.sha256(b'original_operation').hexdigest()}]};return native,diag,{'rows':{'run':[run],'actions':[action]}},outbox

def test_same_native_call_trace_original_operation_hash_and_actual_admission_are_required():
 n,d,p,o=fixture();r=verify_native_action_causality(n,d,p,o);assert len(r['nativeAdmissionLinks'])==1 and r['localToolCalls']==0
 assert r['nativeAdmissionLinks'][0]['nativeCallIdHash']!=r['nativeAdmissionLinks'][0]['wireCallIdHash']  # Different native-tool and JSON-RPC ID domains.

@pytest.mark.parametrize('fault',['sdk_only','no_call','foreign_trace','wrong_operation','wrong_action','foreign_case','untrusted_client','local_tool','terminal_missing','foreign_selection','duplicate_call','other_server','incomplete_census','parse_gap','nonzero_exit','null_trace_collision','invalid_trace_collision','client_operation_hash'])
def test_time_proximity_process_flags_and_client_claims_cannot_replace_causal_chain(fault):
 n,d,p,o=fixture()
 if fault=='sdk_only':d['events'].pop()
 elif fault=='no_call':n['calls'].pop(0)
 elif fault=='foreign_trace':n['calls'][0]['traceId']='another'
 elif fault=='wrong_operation':d['events'][0]['operationIdHash']='f'*64
 elif fault=='wrong_action':d['events'][1]['actionId']='another'
 elif fault=='foreign_case':d['events'][1]['caseId']='another'
 elif fault=='untrusted_client':d['events'][1]['source']='client'
 elif fault=='local_tool':n['localToolCalls']=[{'kind':'shell'}]
 elif fault=='terminal_missing':n['calls'][-1]['run']['terminal']=False
 elif fault=='foreign_selection':n['selection']['intentId']='another'
 elif fault=='duplicate_call':n['calls'].append(copy.deepcopy(n['calls'][0]))
 elif fault=='other_server':n['calls'][0]['server']='unrelated'
 elif fault=='incomplete_census':n['summary']['mcpToolCallCount']=3
 elif fault=='parse_gap':n['summary']['unparsedJsonLines']=1
 elif fault=='nonzero_exit':n['summary']['exitCode']=1
 elif fault=='client_operation_hash':o['events'][0]['operationIdHash']='f'*64
 else:
  value=None if fault=='null_trace_collision' else 'not-a-uuid';n['calls'][0]['traceId']=value
  for e in d['events']+o['events']:e['traceId']=value
 with pytest.raises(AssertionError):verify_native_action_causality(n,d,p,o)


def receipt_fixture():
 from tests.bdd.adapters.ber_matrix_common import digest
 uid=lambda n:'70000000-0000-4000-8000-'+str(n).zfill(12)
 event={'eventId':uid(4),'source':'client','stage':'handler','tool':'identity.preflight','outcome':'error'};batch={'segmentId':uid(3),'batchSequence':0,'events':[event],'completion':'complete'};batch['payloadHash']=digest(batch)
 case={'caseId':uid(1),'diagnosticSessionId':uid(5),'intentId':uid(6),'reportId':uid(2),'state':'synced','gap':0};server={**case,'ownerId':uid(7),'captureState':'complete','errorCount':1};diag={'cases':[server],'reports':[{'caseId':uid(1),'id':uid(2),'ownerId':uid(7)}],'batches':[{'caseId':uid(1),'segmentId':uid(3),'batchSequence':0,'payloadHash':batch['payloadHash'],'completion':'complete'}],'events':[{**event,'caseId':uid(1),'responsibility':'unknown'}]};out={'source':'sqlite_observer','observer':{'role':'client_sqlite_observer','readOnly':True},'case':case,'batches':[batch],'events':[event]};body={'caseId':uid(1),'segmentId':uid(3),'reportId':uid(2),'diagnosticsSynced':True,'reportCreated':True,'highestContiguousSequence':0,'highestContiguousHash':batch['payloadHash'],'completion':'complete'};http={'source':'http_transport','method':'GET','path':'/api/diagnostics/cases/'+uid(1)+'/receipt?segmentId='+uid(3),'httpStatus':200,'body':body};return {'selection':{'intentId':uid(6)}},diag,out,http

def test_native_diagnostic_receipt_replays_actual_http_ack_not_a_sql_watermark_flag():
 from tests.bdd.adapters.ber_native_replay import verify_native_receipt
 r=verify_native_receipt(*receipt_fixture());assert r['actualHttpReceiptVerified'] and r['contiguousBatches']==1

@pytest.mark.parametrize('fault',['no_http','pending','gap','bad_hash','foreign_report','missing_event','false_ack','null_ids','changed_uploaded_event'])
def test_native_receipt_requires_final_contiguous_original_bytes_report_and_http_authority(fault):
 from tests.bdd.adapters.ber_native_replay import verify_native_receipt
 n,d,o,h=receipt_fixture()
 if fault=='no_http':h['source']='sql_summary'
 elif fault=='pending':o['case']['state']='pending_auth'
 elif fault=='gap':o['batches'][0]['batchSequence']=d['batches'][0]['batchSequence']=1
 elif fault=='bad_hash':d['batches'][0]['payloadHash']='f'*64
 elif fault=='foreign_report':h['body']['reportId']='70000000-0000-4000-8000-000000000099'
 elif fault=='missing_event':o['events']=[]
 elif fault=='false_ack':h['body']['diagnosticsSynced']=False
 elif fault=='null_ids':o['case']['reportId']=h['body']['reportId']=None
 else:d['events'][0]['outcome']='success'
 with pytest.raises((AssertionError,KeyError)):verify_native_receipt(n,d,o,h)


def connection_fixture():
 g={'id':'connection','owner_id':'owner','agent_id':'agent','source':'oauth','role':'agent','resource':'http://127.0.0.1:3000/api/agent/mcp','oauth_client_id':'actual-public-client-id','access_generation':2,'created_at':'2026-11-03T00:00:00Z','expires_at':'2026-11-04T00:00:00Z','revoked_at':None};c={'source':'postgresql_observer','observer':{'role':'oid_observer','readOnly':True},'rows':[g]};p={'rows':{'run':[{'id':'run','owner_id':'owner','agent_id':'agent'}],'actions':[{'grant_id':'connection','access_generation':2,'accepted_at':'2026-11-03T00:00:01Z'}]}};d={'cases':[{'runId':'run','connectionId':'connection'}]};u={'runUrl':'http://127.0.0.1:3000/runs?agentId=agent'};return c,p,d,u

def test_native_current_oauth_authority_uses_safe_actual_grant_columns_and_admission_times():
 from tests.bdd.adapters.ber_native_replay import verify_native_connection
 r=verify_native_connection(*connection_fixture());assert r['source']=='oauth' and not r['secretColumnsRetained']

@pytest.mark.parametrize('fault',['manual','role','resource','grant','generation','expired','revoked','secret_column'])
def test_native_authority_not_inferred_from_diag_client_or_process_labels(fault):
 from tests.bdd.adapters.ber_native_replay import verify_native_connection
 c,p,d,u=connection_fixture();g=c['rows'][0]
 if fault=='manual':g['source']='manual'
 elif fault=='role':g['role']='owner'
 elif fault=='resource':g['resource']='http://127.0.0.1:3000/api/diagnostics'
 elif fault=='grant':p['rows']['actions'][0]['grant_id']='another'
 elif fault=='generation':p['rows']['actions'][0]['access_generation']=3
 elif fault=='expired':g['expires_at']='2026-11-03T00:00:00Z'
 elif fault=='revoked':g['revoked_at']='2026-11-03T00:00:00Z'
 else:g['token_hash']='must-not-be-retained'
 with pytest.raises(AssertionError):verify_native_connection(c,p,d,u)


def test_clean_complete_native_capture_has_actual_synced_receipt_without_inventing_error_report():
 from tests.bdd.adapters.ber_native_replay import verify_native_receipt
 from tests.bdd.adapters.ber_matrix_common import digest
 n,d,o,h=receipt_fixture();o['events'][0]['outcome']=d['events'][0]['outcome']='success';b=o['batches'][0];b['payloadHash']=digest({k:v for k,v in b.items() if k!='payloadHash'});d['batches'][0]['payloadHash']=h['body']['highestContiguousHash']=b['payloadHash'];d['cases'][0]['errorCount']=0;d['cases'][0]['reportId']=o['case']['reportId']=h['body']['reportId']=None;d['reports']=[];h['body']['reportCreated']=False
 r=verify_native_receipt(n,d,o,h);assert r['cleanNoErrorReport'] and r['reportId'] is None and r['actualHttpReceiptVerified']
 # A collection gap/partial state cannot borrow the clean no-report exemption.
 o['case']['gap']=1
 with pytest.raises(AssertionError):verify_native_receipt(n,d,o,h)
