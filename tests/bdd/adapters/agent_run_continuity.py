"""Independent ARC raw replay; no command dispatch or business-write client."""
from pathlib import Path
import json
import hashlib
import re
from decimal import Decimal
import xml.etree.ElementTree as ET
import pytest
from tests.bdd.adapters.ber_recovery_replay import read_reference, digest
from tests.bdd.adapters.beta_poc_recovery_verifier import _verify_provenance
ROOT=Path(__file__).resolve().parents[3]
ADAPTER_PROFILES={'agent_run_continuity'}

def need(value,reason):
    if not value: raise AssertionError(reason)

def pg_sequence(value):
    """PG bigint is a canonical decimal string; packet sequence is an integer."""
    need(isinstance(value,str) and re.fullmatch('0|[1-9][0-9]*',value) is not None,'ARC noncanonical PG sequence')
    return int(value)

def unique_actions(actions):
    need(len({x['actionId'] for x in actions})==len(actions),'ARC duplicate durable action identity')
    seen=set()
    for action in actions:
        key=(action['taskIndex'],pg_sequence(action['actionSequence']))
        need(key not in seen,'ARC duplicate per-task action sequence')
        seen.add(key)

def one(rows,label):
    need(isinstance(rows,list) and len(rows)==1,label+' must have one row');return rows[0]

def find_capture(value):
    found=[]
    def visit(v):
        if isinstance(v,dict):
            if v.get('schemaVersion')=='arc-continuity-physical-capture/v1':found.append(v);return
            for x in v.values():visit(x)
        elif isinstance(v,list):
            for x in v:visit(x)
    visit(value);return one(found,'ARC physical capture')

def physical(reference,root=ROOT):
    outer=read_reference(root,reference);database,_=_verify_provenance(outer,root);p=find_capture(outer)
    need(p['database']['databaseName']==database and p['database']['observerRole']=='oid_observer' and p['database']['readOnly'] is True,'ARC observer scope')
    final=one([s for s in p['snapshots'] if s['label']=='run_completed'],'terminal snapshot');s,c=final['snapshot'],final['completion'];run=c['run'];need(isinstance(run,dict),'completed run object')
    unique_actions(s['actions'])
    need(run['id']==p['runId'] and run['agent_id']==p['agentId'] and run['status']=='completed','ARC run/card/completion')
    need(not c['slots'] and all(x['status']=='released' for x in c['claims']),'ARC resource release')
    need(len(c['completionEvents'])==1 and len(c['terminalizationEvents'])==len(p['selectedTaskIds'])-1,'ARC once-only completion')
    ledger=c['ledger'];debits=[x for x in ledger if x['entry_type']=='debit']
    need(len(debits)==1 and debits[0]['source_kind']=='tester_bonus' and str(debits[0]['amount_units'])==p['quotePriceUnits'],'ARC one original bonus debit')
    need(not c['runRefundLedger'] and not [x for x in ledger if x['entry_type']=='refund'],'ARC no refund authority')
    need(len(s['execution'])==len(p['selectedTaskIds']) and all(x['lease_state']=='fenced' for x in s['execution']),'ARC exact generation fences')
    need(len(p['sourceProofs'])==len(p['selectedTaskIds']),'ARC all sealed task sources')
    for proof in p['sourceProofs']:
        execution=one([x for x in s['execution'] if x['task_index']==proof['task_index']],'source exact execution')
        bundle=proof['bundle_json'];fence=proof['fence_evidence'];source=one(proof['sourceFence'],'BEF fence')
        need(digest(bundle)==proof['bundle_hash'] and bundle['execution']['generationId']==execution['generation_id'],'ARC sealed generation bundle')
        need(fence['confirmed'] is True and fence['generationId']==execution['generation_id'] and fence['preparationId']==execution['preparation_id'] and fence['leaseId']==execution['lease_id'],'ARC owner generation fence')
        need(source['generation_status']==source['preparation_status']=='fenced' and source['preparation_generation_id']==execution['generation_id'],'ARC source generation fence')
        need(read_reference(root,proof['captureEvidence'])==proof['capturePacket'],'ARC hash-pinned raw capture')
    h=p['handoff'];text=h['visible'];need(h['clicked'] is True and (h['clipboard'] is None or text==h['clipboard']) and p['agentId'] in text and p['intentId'] in text,'ARC clipboard scope')
    intent=h['intentSnapshot'];need(isinstance(intent,dict),'original pending intent object')
    need(intent['id']==p['intentId'] and intent['owner_id']==p['ownerId'] and intent['agent_id']==p['agentId'] and intent['task_ids']==p['selectedTaskIds'] and intent['quote_price_units']==p['quotePriceUnits'] and intent['cash_ceiling_units']=='0' and intent['status']=='pending','ARC browser intent PG binding')
    selected=json.loads(text.split('Owner-reviewed selection (IDs are references, not credentials or permission):\n',1)[1].split('\n',1)[0])
    need(selected['agentId']==p['agentId'] and selected['intentId']==p['intentId'] and selected['mode']==intent['mode'] and selected['taskIds']==p['selectedTaskIds'] and Decimal(selected['cashCeiling'])==0 and selected['quote']['token']=='USDC' and Decimal(selected['quote']['price'])*1000000==int(p['quotePriceUnits']),'ARC reviewed prompt selection')
    durable=one(s['run'],'durable run selection')
    need(durable['id']==run['id'] and durable['intent_id']==p['intentId'] and durable['owner_id']==p['ownerId'] and durable['task_ids']==p['selectedTaskIds'],'ARC immutable run selection')
    accepted=one(s['acceptanceEvents'],'one admission event')
    need(accepted['runId']==p['runId'] and accepted['intentId']==p['intentId'] and accepted['agentId']==p['agentId'],'ARC one original admission')
    for clause in ['Do not stop after accepting the intent','run.terminal === true','runs.task_action_status','separate pay and retrieve']:
        need(clause in text,'ARC incomplete handoff')
    calls=[x for x in p['mcp'] if x['name']=='runs.current_task' and not x['isError']]
    for call in calls:
        r=call['body'];need(r['run']['runId']==p['runId'] and isinstance(r['run']['terminal'],bool),'ARC MCP scoped status')
        if r['task'] is None and not r['run']['terminal']:need(r['retryAfterMs']==1000 and r['state']!='terminal','ARC waiting is not completion')
    terminal=one([x for x in calls if x['body']['run']['terminal']],'MCP terminal read')['body'];need(terminal['run']['status']=='completed' and terminal['state']=='terminal' and terminal['retryAfterMs'] is None,'ARC authoritative terminal')
    grades=c['evaluations']
    browser=p['browserFinal'];need(browser['statusText'].strip()=='completed' and browser['feedbackHttp']['status']==200 and browser['feedbackHttp']['body']['status']=='available','ARC real browser results read')
    for grade in grades:
        rendered=one([x for x in browser['renderedTasks'] if x['taskId']==grade['task_id']],'rendered task result')
        api=one([x for x in browser['feedbackHttp']['body']['tasks'] if x['taskId']==grade['task_id']],'owner task result')
        need(api['status']==grade['result_status'] and api['outcome']==grade['outcome'] and api['credit']==grade['credit'],'ARC owner result DB binding')
        need(grade['outcome'] in rendered['text'] and 'Credit '+grade['credit']['numerator']+'/'+grade['credit']['denominator'] in rendered['text'],'ARC rendered result DB binding')
    need(len(grades)==len(p['selectedTaskIds']) and all(x['result_status']=='known' for x in grades),'ARC terminal known grades')
    if p['profile']=='paid_without_retrieve':
        need(any(x['body']['task'] is None and x['body']['run']['terminal'] is False for x in calls),'ARC observed actual nonterminal wait')
        m1=one([x for x in grades if x['task_id']=='M1'],'M1 grade');need(m1['outcome']=='failed' and m1['credit']=={'numerator':'0','denominator':'1'},'ARC M1 known zero')
        h1=one([x for x in grades if x['task_id']=='H1'],'H1 grade');need(h1['outcome']=='passed' and h1['credit']=={'numerator':'1','denominator':'1'},'ARC H1 completed')
        actions=[x for x in s['actions'] if x['taskIndex']==0];need(len(actions)==3 and sorted(x['kind'] for x in actions)==['inspect_catalog','inspect_offer','pay'],'ARC closed full admission census')
        pay=one([x for x in actions if x['kind']=='pay'],'original pay');need(pay['receiptStatus']=='observed','ARC original payment observed')
        proof=one([x for x in p['sourceProofs'] if x['task_index']==0],'M1 source proof');bundle=proof['bundle_json'];obs=bundle['observations'];payment=one(obs['payments'],'M1 settled payment');absence=payment['deliveryRequestAbsence']
        need(absence['schemaVersion']=='bts-delivery-request-absence/v1' and absence['status']=='not_admitted_at_cutoff' and absence['paymentAttemptId']==payment['paymentAttemptId'],'ARC absence/payment binding')
        need(obs['coverage']['deliveries']==obs['coverage']['payments']=='complete' and not obs['deliveries'],'ARC full source absence')
        raw=read_reference(root,absence['captureEvidence']);need(raw==proof['capturePacket'],'ARC original raw source packet binding');need(digest(bundle)==proof['bundle_hash'],'ARC sealed bundle hash')
        packet=proof['capturePacket'];census=packet['ownerActions']
        need(len(census)==3 and [x['actionSequence'] for x in census]==[1,2,3] and sorted(x['actionKind'] for x in census)==['inspect_catalog','inspect_offer','pay'],'ARC raw source census')
        need({x['actionId'] for x in census}=={x['actionId'] for x in actions} and packet['binding']['runId']==p['runId'] and packet['binding']['agentId']==p['agentId'],'ARC census durable action/run binding')
        need(packet['closure']['actionCutoffSequence']==absence['acceptedActionCutoffSequence']==3 and absence['paymentActionSequence']==pg_sequence(pay['actionSequence']),'ARC closed cutoff payment binding')
        need(absence['authority']=={key:packet[section][key] for key,section in [('closureId','closure'),('preparationId','execution'),('leaseId','execution'),('generationId','execution')]},'ARC absence exact authority')
        need(packet['bef']['after']['deliveries']==[] and p['lateRetrieve'].get('admitted') is not True,'ARC no admitted retrieval or delivery')
        successor=one([x for x in p['snapshots'] if x['label']=='m1_known_failed_h1_issued'],'M1 successor snapshot')
        need(one(successor['completion']['evaluations'],'known predecessor before successor')['outcome']=='failed','ARC M1 terminal before H1')
    else:
        need(p['profile']=='native_handoff' and h['clipboard']==text and p['selectedTaskIds']==['S1','M1','H1'],'ARC native full Training selection')
        need(all(x['outcome']=='passed' and x['credit']=={'numerator':'1','denominator':'1'} for x in grades),'ARC native full solved Training')
    return p

def verify_native_wire(p, root=ROOT):
    native=p['native'];packets=native['wireTrace']['packets']
    need([x['sequence'] for x in packets]==list(range(1,len(packets)+1)),'ARC native wire sequence')
    requests=[x['projection'] for x in packets if x['direction']=='request']
    initialize=one([x for x in requests if x.get('method')=='initialize'],'native initialize')['initialize']
    need(initialize['protocolVersion']=='2025-06-18' and initialize['clientInfo']['name']=='codex-mcp-client' and initialize['clientInfo']['version']=='0.165.0','ARC native initialize profile')
    calls=[x for x in requests if x.get('method')=='tools/call']
    pre=one([x for x in calls if x.get('toolName')=='identity.preflight'],'native preflight')
    accept=one([x for x in calls if x.get('toolName')=='runs.accept_launch_intent'],'native admission')
    need(pre['arguments']['agentId']==p['agentId'] and accept['arguments']['intentId']==p['intentId'] and calls.index(pre)<calls.index(accept),'ARC native card intent admission')
    allowed={'identity.preflight','runs.accept_launch_intent','runs.current_task','runs.task_action','runs.task_action_status','runs.finish_task'}
    for index,call in enumerate(calls):
        need(call['toolName'] in allowed,'ARC foreign native tool')
        if call['toolName'].startswith('runs.') and call['toolName']!='runs.accept_launch_intent':need(call['arguments']['runId']==p['runId'],'ARC native scoped run')
        if call['toolName']=='runs.finish_task':need(index+1<len(calls) and calls[index+1]['toolName']=='runs.current_task','ARC native finish then next task')
    need(len([x for x in calls if x['toolName']=='runs.finish_task'])==len(p['selectedTaskIds']),'ARC native all tasks finished')
    current_ids={x['id'] for x in calls if x['toolName']=='runs.current_task'}
    terminal=[]
    for packet in packets:
        if packet['direction']!='response':continue
        response=packet['projection']
        if response.get('id') not in current_ids:continue
        for payload in [response.get('result',{}),*response.get('content',[])]:
            if payload.get('run',{}).get('terminal') is True:terminal.append(payload)
    need(terminal and all(x['run']['runId']==p['runId'] and x['run']['status']=='completed' and x.get('task') is None for x in terminal),'ARC native explicit completed terminal response')
    helper_path=root/'infrastructure/owner-identity/run-codex-google-local.mjs';helper=helper_path.read_bytes();text=helper.decode()
    transformed=text.replace("const ENDPOINT = 'http://127.0.0.1:3000/api/agent/mcp';","const ENDPOINT = 'http://127.0.0.1:39001/api/agent/mcp';").replace('owner_identity','w3bench_user').replace("      'exec', '--ephemeral', '--json', '--sandbox', 'read-only', '--skip-git-repo-check',","      '--no-daemon', 'exec', '--ephemeral', '--json', '--sandbox', 'read-only', '--skip-git-repo-check',")
    expected={'baseHelperSha256':hashlib.sha256(helper).hexdigest(),'transformedHelperSha256':hashlib.sha256(transformed.encode()).hexdigest(),
      'brokerSha256':hashlib.sha256((root/'tools/run_arc_native.mjs').read_bytes()).hexdigest(),'bridgeSha256':hashlib.sha256((root/'tools/arc-native-bridge.mjs').read_bytes()).hexdigest()}
    for key,constant in [('nativeExeSha256','EXPECTED_EXE_SHA256'),('codeModeHostSha256','EXPECTED_CODE_MODE_HOST_SHA256'),('packageManifestSha256','EXPECTED_PACKAGE_MANIFEST_SHA256')]:
        expected[key]=re.search("const "+constant+" = '([A-Fa-f0-9]{64})'",text).group(1).lower()
    need(native['sourcePins']==expected,'ARC native independently pinned executable/helper/broker hashes')


def negative_reports(inputs,root):
    required={name for row in json.loads((root/'tests/bdd/changes/agent-run-continuity/harness-contracts.json').read_text())['protected_scenarios'].values() for name in row['negative_variants']}
    covered=set()
    for reference in inputs.get('negativeReports',[]):
        report=read_reference(root,reference)
        need(report.get('schemaVersion')=='arc-negative-test-report/v1' and report.get('exitCode')==0 and isinstance(report.get('command'),list) and report['command'],'ARC negative command identity')
        for source in report['sourceInputs']:read_reference(root,source,json_body=False)
        xml=ET.fromstring(read_reference(root,report['junit'],json_body=False))
        cases=list(xml.iter('testcase'));need(cases and not any(list(c.iter('failure')) or list(c.iter('error')) or list(c.iter('skipped')) for c in cases),'ARC negative executed tests failed or skipped')
        names={c.attrib.get('name') for c in cases}
        for variant,tests in report['variantTests'].items():
            need(variant in required and isinstance(tests,list) and tests and set(tests)<=names,'ARC negative variants not backed by executed JUnit cases')
            covered.add(variant)
    return covered

def history_unchanged(inputs,root):
    ref=inputs.get('historicalPreservation')
    if not ref:return False
    report=read_reference(root,ref)
    need(report.get('schemaVersion')=='arc-history-preservation/v1' and report.get('runId')=='a6e58ea5-11a2-4476-8619-3bfab98e22d3','ARC original history target')
    need(report['identity']['role']=='oid_observer' and report['identity']['readonly']=='on','ARC historical readonly observer')
    sets={'run','tasks','actions','receipts','evaluations','closures','ledger','reports','screenshots'}
    need(isinstance(report.get('before'),dict) and sets<=set(report['before']) and report['before']==report.get('after'),'ARC historical rows changed or sets missing')
    for key in sets:
        row=report['before'][key]
        need(isinstance(row.get('count'),int) and row['count']>=0 and isinstance(row.get('sha256'),str) and re.fullmatch('[a-f0-9]{64}',row['sha256']),'ARC invalid history fingerprint')
    return True


class Case:
    def __init__(self,sid):self.sid=sid
    def setup(self,context):need(context.scenario_id==self.sid,'ARC scenario mismatch')
    def execute(self,context,when_text):
        getattr(self,"_execute_"+self.sid.replace("-","_"))(context)
    def verify(self,context,then_text):
        getattr(self,"_verify_"+self.sid.replace("-","_"))(context)
    def _capture(self,context):
        path=ROOT/'tests/bdd/changes/agent-run-continuity/runtime-inputs.json'
        if not path.exists():pytest.skip('BLOCKED: ARC actual capture references not recorded')
        inputs=json.loads(path.read_text(encoding='utf-8-sig'));need(inputs.get('schemaVersion')=='arc-runtime-inputs/v1','ARC input schema')
        profile='native' if self.sid=='ARC-SC-001' else 'controlled'
        if profile not in inputs.get('captures',{}):pytest.skip('BLOCKED: ARC '+profile+' actual capture missing')
        context.state['arc_physical']=physical(inputs['captures'][profile])
        p=context.state['arc_physical']
        covered=negative_reports(inputs,ROOT)
        contract=json.loads((ROOT/'tests/bdd/changes/agent-run-continuity/harness-contracts.json').read_text())['protected_scenarios'][self.sid]
        missing=set(contract['negative_variants'])-covered
        preserved=history_unchanged(inputs,ROOT)
        if missing or not preserved:pytest.skip('BLOCKED: ARC missing actual negative controls or historical fingerprints: '+','.join(sorted(missing)))
        if self.sid=='ARC-SC-001':
            native=p.get('native',{})
            need(native.get('implementation')=='native_codex_cli' and native.get('clientVersion')=='0.165.0','ARC actual native client identity')
            need(native.get('promptSha256')==hashlib.sha256(p['handoff']['clipboard'].encode()).hexdigest(),'ARC native single prompt binding')
            trace=native.get('wireTrace',{});packets=trace.get('packets',[])
            need(trace.get('schemaVersion')=='arc-native-wire-projections/v1' and trace.get('rawPersisted') is False and packets,'ARC native wire provenance')
            need(all(x.get('rawPersisted') is False and re.fullmatch('[a-f0-9]{64}',x.get('rawSha256','')) for x in packets),'ARC native wire packet hashes')
            pins=native.get('sourcePins',{});need(set(['baseHelperSha256','transformedHelperSha256','nativeExeSha256','codeModeHostSha256','packageManifestSha256','brokerSha256','bridgeSha256'])<=set(pins) and all(re.fullmatch('[a-f0-9]{64}',v) for v in pins.values()),'ARC native helper source pins')
            need(native.get('exitCode')==0,'ARC native execution failed')
            verify_native_wire(p)
            need(native.get('status') in ['turn_completed','turn_completed_with_tool_errors'] and native.get('mcpToolCalls',0)>0 and native.get('localToolCalls')==0,'ARC native MCP execution only')
        context.state['arc_facts']={name:True for name in contract['required_observations']}



    def _execute_ARC_SC_001(self,context):
        self._capture(context)
    def _verify_ARC_SC_001(self,context):
        context.check("clipboard_selection_binding",context.state.get("arc_facts",{}).get("clipboard_selection_binding") is True)
        context.check("continuous_native_run",context.state.get("arc_facts",{}).get("continuous_native_run") is True)
        context.check("historical_run_unchanged",context.state.get("arc_facts",{}).get("historical_run_unchanged") is True)

    def _execute_ARC_SC_002(self,context):
        self._capture(context)
    def _verify_ARC_SC_002(self,context):
        context.check("raw_waiting_and_terminal_responses",context.state.get("arc_facts",{}).get("raw_waiting_and_terminal_responses") is True)
        context.check("readonly_projection",context.state.get("arc_facts",{}).get("readonly_projection") is True)
        context.check("authorization_rechecked",context.state.get("arc_facts",{}).get("authorization_rechecked") is True)

    def _execute_ARC_SC_003(self,context):
        self._capture(context)
    def _verify_ARC_SC_003(self,context):
        context.check("closed_admission_census",context.state.get("arc_facts",{}).get("closed_admission_census") is True)
        context.check("confirmed_payment_and_source_absence",context.state.get("arc_facts",{}).get("confirmed_payment_and_source_absence") is True)
        context.check("known_m1_then_h1_completion",context.state.get("arc_facts",{}).get("known_m1_then_h1_completion") is True)
        context.check("exact_fences_and_finance",context.state.get("arc_facts",{}).get("exact_fences_and_finance") is True)

def register(registry):
    for n in range(1,4):
        sid=f'ARC-SC-{n:03d}';registry.register(sid,Case(sid),adapter_profile='agent_run_continuity')
