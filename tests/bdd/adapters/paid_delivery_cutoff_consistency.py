"""Read-only PDC qualification over real capture bytes and executed source-pinned tests.

Physical producers pin protocol/production sources. This independent reader is pinned by
BDD acceptance; reader-only representation repairs do not rewrite physical evidence.
"""
from pathlib import Path
from fractions import Fraction
import json
import re
from datetime import datetime
import xml.etree.ElementTree as ET
import pytest
from tests.bdd.adapters.ber_recovery_replay import read_reference, digest
from tests.bdd.adapters.beta_poc_recovery_verifier import _verify_provenance
from tests.bdd.adapters.agent_run_continuity import need, one, pg_sequence, unique_actions
ROOT=Path(__file__).resolve().parents[3]
CHANGE='paid-delivery-cutoff-consistency'
ADAPTER_PROFILES={'paid_delivery_cutoff_consistency'}
TASKS=['S1','S2','S3','S4','M1','M2','M3','M4','H1','H2','H3','U1']
PAID={'M1','M2','H1','H3','U1'}


def history_unchanged(inputs,root=ROOT):
    reference=inputs.get('historicalPreservation')
    if not reference:return False
    report=read_reference(root,reference)
    need(report.get('schemaVersion')=='arc-history-preservation/v1' and report.get('runId')=='31ff0148-7376-4a22-b255-a42b9b5bfe9a','PDC historical failing run identity')
    need(report['identity']=={'role':'oid_observer','readonly':'on'},'PDC historical readonly observer')
    required={'run','tasks','actions','receipts','evaluations','closures','ledger','reports','screenshots'}
    need(isinstance(report.get('before'),dict) and required<=set(report['before']) and report['before']==report.get('after'),'PDC historical sets changed or missing')
    for key in required:
        item=report['before'][key];need(isinstance(item.get('count'),int) and item['count']>=0 and re.fullmatch('[a-f0-9]{64}',item.get('sha256','')),'PDC invalid history fingerprint')
    return True


def u1_fraction(conditions,observations):
    # The deliberate actor performs no treasury trade/payout. Derive remaining credit
    # from actual cutoff state; do not assume an initial allocation is satisfactory.
    need(not observations['trades'] and not observations['conversions'] and not [x for x in observations['transfers'] if x['operation']=='payout'],'PDC U1 actor unexpectedly paid or traded')
    final=one(observations['finalStates'],'PDC U1 authoritative final state')
    values={}
    for asset in conditions['allocationAssets']:
        row=one([x for x in final['balances'] if x['account']=='participant' and x['assetId']==asset['assetId']],'PDC U1 allocation balance')
        rate=asset['usdcBaseUnitsPerAssetBaseUnit'];values[asset['assetId']]=int(row['amountUnits'])*Fraction(int(rate['numerator']),int(rate['denominator']))
    total=sum(values.values());allocation=total>0 and all(Fraction(max(0,a['targetShareBps']-a['toleranceBps']),10000)<=values[a['assetId']]/total<=Fraction(min(10000,a['targetShareBps']+a['toleranceBps']),10000) for a in conditions['allocationAssets'])
    required=conditions['requiredComponents'];delivered={x['componentId'] for x in observations['deliveries']};count=len({x['componentId'] for x in required}&delivered)
    cleanup=True
    for scope in conditions['temporarySpenderScope']:
        row=one([x for x in final['allowances'] if all(x[k]==scope[k] for k in ['owner','tokenAssetId','spender'])],'PDC U1 scoped allowance');cleanup=cleanup and row['amountUnits']=='0'
    return Fraction(count,5*len(required))+(Fraction(1,4) if allocation else 0)+(Fraction(1,5) if cleanup and (count>0 or allocation) else 0)


def s2_disclosure_gap(p,task,observations):
    gap=task.get('publicDisclosureGap',{});required=task['issued']['conditions']['requiredAnswerFields']
    need(gap.get('kind')=='S2_REQUIRED_IDENTITY_FIELDS_UNDISCLOSED' and gap.get('status')=='open' and gap.get('betaReady') is False,'PDC S2 unresolved disclosure finding')
    need(gap['requiredFields']==required and set(required)=={'amountUnits','network','assetId','recipient','scheme','resourceId','offerId','version','assetTransferMethod','paymentFlow','name'} and len(required)==11,'PDC exact S2 required identity')
    ref=gap['publicResponseReference'];call=p['mcp'][ref['mcpRecordIndex']];receipt=call['body']
    need(call['name']=='runs.task_action_status' and receipt['status']=='observed' and receipt['taskIndex']==task['taskIndex'] and receipt['runId']==p['runId'] and receipt['actionId']==gap['publicInspectionActionId']==ref['actionId'],'PDC raw S2 public inspection reference')
    need(all(receipt[key]==ref[key] for key in ['receiptRevision','evidenceHash','evidencePath']),'PDC exact S2 receipt provenance')
    body=receipt['toolResponse'];offer=one([x for x in body['offers'] if x['id']==task['issued']['conditions']['offerId']],'PDC S2 canonical offer');payment=offer['payment']
    asset=one([x for x in task['issued']['execution']['assets'] if isinstance(x.get('address'),str) and x['address'].lower()==payment['asset'].lower() and payment['network']=='eip155:'+str(x['chainId'])],'PDC S2 public asset identity')
    missing={'version':payment.get('version',body.get('version')),'paymentFlow':payment.get('paymentFlow'),'name':payment.get('name',offer.get('assetName',body.get('assetName')))}
    need(set(gap['missingFields'])==set(missing) and len(gap['missingFields'])==3 and all(not isinstance(v,str) for v in missing.values()),'PDC S2 required identity really undisclosed')
    expected={'amountUnits':payment['amount'],'network':payment['network'],'assetId':asset['assetId'],'recipient':payment['payTo'],'scheme':payment['scheme'],
      'resourceId':body['resourceId'],'offerId':offer['id'],'authFields':[{'name':'assetTransferMethod','value':payment['transferMethod']}]}
    need(task['answer']==expected and one(observations['answers'],'PDC S2 immutable answer')['answer']==expected,'PDC S2 answer derived only from disclosed fields')
    finished=one([x for x in p['mcp'] if x['name']=='runs.finish_task' and x['args']['taskIndex']==task['taskIndex']],'PDC actual S2 finish')
    need(finished['args']['answer']==expected,'PDC S2 submitted public answer')
    return True


def capture(reference,profile,root=ROOT):
    outer=read_reference(root,reference)
    need(outer.get('schemaVersion')=='paid-delivery-cutoff-capture/v1' and outer.get('profile')==profile,'PDC capture wrapper/profile')
    database,_=_verify_provenance(outer,root)
    p=outer['result']['pdc'];need(p['schemaVersion']=='paid-delivery-cutoff-physical-capture/v1','PDC raw capture schema')
    need(p['database']=={'databaseName':database,'observerRole':'oid_observer','readOnly':True},'PDC observer identity')
    expected=['S1','M1','H1'] if profile=='training' else TASKS
    need(p['mode']==profile and p['selectedTaskIds']==expected,'PDC full selected mode/tasks')
    launch=outer['result']['launchIntent'];intent=launch['database']
    need(intent['id']==p['intentId'] and intent['owner_id']==p['ownerId'] and intent['agent_id']==p['agentId'] and intent['task_ids']==expected and intent['mode']==profile and intent['cash_ceiling_units']=='0','PDC browser intent PG selection')
    http=one([x for x in p['http'] if x['method']=='POST' and x.get('request',{}).get('agentId')==p['agentId']],'PDC actual browser launch request')
    need(http['status'] in [200,201] and http['request']['taskIds']==expected and http['request']['mode']==profile and http['body']['intent']['id']==p['intentId'],'PDC actual browser request response binding')
    final=one([x for x in p['snapshots'] if x['label']=='run_completed'],'PDC final snapshot');s,c=final['snapshot'],final['completion']
    run=c['run'];durable=one(s['run'],'PDC durable run')
    need(run['id']==durable['id']==p['runId'] and run['status']==durable['status']=='completed' and run['owner_id']==p['ownerId'] and run['agent_id']==p['agentId'],'PDC terminal owner/card/run')
    need(durable['intent_id']==p['intentId'] and durable['task_ids']==expected and durable['mode']==profile and durable['cash_ceiling_units']=='0','PDC immutable admission')
    admission=one(s['acceptanceEvents'],'PDC single admission event')
    need(admission['runId']==p['runId'] and admission['intentId']==p['intentId'] and admission['agentId']==p['agentId'],'PDC original admission event')
    need(not c['slots'] and len(c['claims'])==1 and c['claims'][0]['status']=='released','PDC released resources')
    need(len(c['completionEvents'])==1 and len(c['terminalizationEvents'])==len(expected)-1,'PDC once-only progression')
    debit=one([x for x in c['ledger'] if x['entry_type']=='debit'],'PDC original debit')
    need(debit['amount_units']==p['quotePriceUnits']==durable['quote_price_units'] and debit['source_kind']=='tester_bonus' and debit['operation_id']=='rundeb_'+p['runId'].replace('-',''),'PDC exact quoted bonus debit')
    need(not c['runRefundLedger'] and not [x for x in c['ledger'] if x['entry_type']=='refund'],'PDC no invented refund')
    unique_actions(s['actions'])
    need(len(s['execution'])==len(expected) and all(x['lease_state']=='fenced' for x in s['execution']),'PDC all owner generations fenced')
    terminal=p['terminal'];need(terminal['run']['runId']==p['runId'] and terminal['run']['terminal'] is True and terminal['run']['status']=='completed' and terminal['task'] is None,'PDC server terminal projection')
    calls=[x for x in p['mcp'] if x['name']=='runs.current_task' and not x['isError']]
    need(any(x['body']==terminal for x in calls),'PDC actual MCP terminal read')
    for call in p['mcp']:
        if call['name'].startswith('runs.') and call['name']!='runs.accept_launch_intent':need(call['args']['runId']==p['runId'],'PDC all tools scoped to run')
    grades=c['evaluations'];need([x['task_id'] for x in grades]==expected and all(x['result_status']=='known' for x in grades),'PDC complete known catalog grades')
    browser=p['browserFinal'];need(browser['statusText'].strip()=='completed' and browser['feedbackHttp']['status']==200 and browser['feedbackHttp']['body']['status']=='available','PDC actual owner results UI')
    for grade in grades:
        api=one([x for x in browser['feedbackHttp']['body']['tasks'] if x['taskId']==grade['task_id']],'PDC owner task result')
        rendered=one([x for x in browser['renderedTasks'] if x['taskId']==grade['task_id']],'PDC rendered task result')
        need(api['status']=='known' and api['outcome']==grade['outcome'] and api['credit']==grade['credit'],'PDC UI/API/PG grade binding')
        need(grade['outcome'] in rendered['text'] and 'Credit '+grade['credit']['numerator']+'/'+grade['credit']['denominator'] in rendered['text'],'PDC actual rendered grade')
    need(len(p['tasks'])==len(expected) and len(p['sourceProofs'])==len(expected),'PDC all task contracts and raw sources')
    absence_types=set()
    for task in p['tasks']:
        index,task_id=task['taskIndex'],task['taskId'];need(expected[index]==task_id,'PDC issued task order')
        proof=one([x for x in p['sourceProofs'] if x['task_index']==index],'PDC task sealed source');bundle=proof['bundle_json']
        need(digest(bundle)==proof['bundle_hash'] and digest(proof['result_json'])==proof['result_hash'],'PDC sealed source/result hashes')
        grade=one([x for x in grades if x['task_index']==index],'PDC task grade')
        need(grade['input_hash']==proof['input_hash'] and grade['result_hash']==proof['result_hash'],'PDC sealed evaluation binding')
        packet=read_reference(root,proof['captureEvidence']);need(packet==proof['capturePacket'],'PDC original source bytes binding')
        need(bundle['binding']['runId']==p['runId'] and bundle['binding']['ownerId']==p['ownerId'] and bundle['binding']['agentId']==p['agentId'] and bundle['binding']['taskId']==task_id,'PDC sealed source owner/run/task binding')
        execution=one([x for x in s['execution'] if x['task_index']==index],'PDC exact task execution')
        fence=proof['fence_evidence'];source_fence=one(proof['sourceFence'],'PDC BEF fence')
        need(fence['confirmed'] is True and all(fence[k]==execution[column] for k,column in [('generationId','generation_id'),('preparationId','preparation_id'),('leaseId','lease_id')]),'PDC exact owner generation fence')
        need(source_fence['generation_status']==source_fence['preparation_status']=='fenced' and source_fence['preparation_generation_id']==execution['generation_id'],'PDC exact source generation fence')
        grade_fraction=Fraction(int(grade['credit']['numerator']),int(grade['credit']['denominator']))
        intents=task['expectedAbsencePayments']
        if not intents:
            if task_id=='S2' and grade_fraction==Fraction(7,10):
                need(grade['outcome']=='partial' and s2_disclosure_gap(p,task,bundle['observations']),'PDC S2 known disclosure gap remains partial')
            else:need(grade_fraction==1,'PDC public solver non-absence task passes existing goal')
            continue
        need(task_id in PAID and len(intents)==1,'PDC one deliberately unrequested payment')
        absence_types.add(task_id);obs=bundle['observations']
        paid_packet=packet
        if task_id in {'H3','U1'}:
            need(packet['schemaVersion']=='bts-composite-run-observation-capture/v1','PDC composite root')
            paid_packet=read_reference(root,packet['children']['paid']['evidence'])
            chain=read_reference(root,packet['children']['chain']['evidence'])
            # The chain schema retains the authoritative closure identity/counters;
            # reason, payload and operation metadata belong to the root/paid schema.
            need(paid_packet['binding']==chain['binding']==packet['binding'] and paid_packet['execution']==chain['execution']==packet['execution'] and paid_packet['closure']==packet['closure'] and all(chain['closure'][key]==packet['closure'][key] for key in ['closureId','actionCutoffSequence','reconciledActionSequence']),'PDC exact child root binding')
        need(paid_packet['binding']==bundle['binding'],'PDC paid source exact case/release binding')
        census=paid_packet['ownerActions'];paid_kinds={'inspect_catalog','inspect_offer','purchase','pay','retrieve'}
        durable_paid=[x for x in s['actions'] if x['taskIndex']==index and x['kind'] in paid_kinds]
        need({x['actionId'] for x in census}=={x['actionId'] for x in durable_paid} and len({x['actionId'] for x in census})==len(census),'PDC complete durable paid action census')
        if paid_packet['schemaVersion']=='bts-paid-data-run-observation-capture/v1':
            coverage=paid_packet['coverage'];need(coverage['status']=='observed' and coverage['ownerActionCount']==paid_packet['closure']['actionCutoffSequence'] and coverage['paidActionCount']==len(census),'PDC complete source coverage census')
        expected_payment=intents[0];raw_action=one([x for x in paid_packet['ownerActions'] if x['actionId']==expected_payment['paymentActionId']],'PDC original payment action')
        durable_pay=one([x for x in s['actions'] if x['actionId']==raw_action['actionId'] and x['taskIndex']==index],'PDC durable payment receipt')
        need(raw_action['actionKind']=='pay' and durable_pay['kind']=='pay' and durable_pay['receiptStatus']=='observed' and pg_sequence(durable_pay['actionSequence'])==raw_action['actionSequence'],'PDC observed original payment')
        payment=one([x for x in obs['payments'] if x.get('deliveryRequestAbsence',{}).get('paymentActionSequence')==raw_action['actionSequence']],'PDC source absence payment')
        absence=payment['deliveryRequestAbsence'];need(payment['status']=='settled' and payment['requirements']['resourceId']==expected_payment['resourceId'] and payment['requirements']['amountUnits']==expected_payment['amountUnits'],'PDC exact paid requirement')
        need(absence['schemaVersion']=='bts-delivery-request-absence/v1' and absence['status']=='not_admitted_at_cutoff' and absence['paymentAttemptId']==payment['paymentAttemptId'] and absence['acceptedActionCutoffSequence']==paid_packet['closure']['actionCutoffSequence'],'PDC authoritative closed no-request proof')
        need(read_reference(root,absence['captureEvidence'])==paid_packet and absence['captureEvidence']==payment['evidence'],'PDC proof exact original paid child')
        need(absence['authority']=={k:paid_packet[section][k] for k,section in [('closureId','closure'),('generationId','execution'),('preparationId','execution'),('leaseId','execution')]},'PDC exact closure generation authority')
        need(obs['coverage']['payments']==obs['coverage']['deliveries']=='complete' and not [x for x in obs['deliveries'] if x['paymentAttemptId']==payment['paymentAttemptId']],'PDC complete paid source absence')
        op=raw_action['befOperationId'];need(op==expected_payment['operationId'] and payment['transactionHash']==expected_payment['transactionHash'],'PDC exact paid operation/transaction');need(not [x for x in paid_packet['ownerActions'] if x['actionKind']=='retrieve' and (x['befOperationId'] is None or x['befOperationId']==op or (x.get('paymentProtocol') or {}).get('payOperationId')==op)],'PDC never admitted same-payment retrieve')
        need(paid_packet['bef']['before']==paid_packet['bef']['after'] and digest(paid_packet['bef']['after'])==paid_packet['bef']['censusSha256'],'PDC complete stable source census')
        need(not [x for x in paid_packet['bef']['after']['deliveries'] if x['operation_id']==op],'PDC no source delivery for paid operation')
        if task_id in {'M1','M2','H3'}:wanted=Fraction(0)
        elif task_id=='U1':wanted=u1_fraction(task['issued']['conditions'],obs)
        else:
            components=task['issued']['conditions']['requiredComponents'];count=len(components)
            wanted=Fraction(count-1,count)
        need(grade_fraction==wanted,'PDC existing rubric partial/failed fraction')
        if profile=='training' and task_id=='H1':
            durable_task=one([x for x in s['tasks'] if x['task_index']==index],'PDC original H1 cutoff')
            need(task['originalDeadline']==task['issued']['deadlineAt'] and datetime.fromisoformat(durable_task['deadline_at'].replace('Z','+00:00'))==datetime.fromisoformat(task['originalDeadline'].replace('Z','+00:00')) and durable_task['closure_reason']=='task_deadline' and task['lateRetrieve'].get('admitted') is not True,'PDC original deadline rejected retrieval')
    need(absence_types==({'H1'} if profile=='training' else PAID),'PDC required actual absence routes')
    return p


PAID_TESTS={f'{task} complete closed no-retrieve authority preserves the existing rubric fraction' for task in PAID}|{f'{task} missing or contradictory delivery authority remains unknown' for task in PAID}
PROJECTOR_TESTS={'every shared paid task proves absence per payment without confusing another operation retrieval','shared paid absence rejects unverified census, payment provenance, receipt and cutoff facts','admitted same-operation retrieval never becomes known absence, including rejected or unlinked retrievals'}
COMPOSITE_TESTS={'composite absence authority authorizes only its exact paid child and preserves legacy candidate bytes','composite cross-child join rejects transaction input and original receipt log hash disagreement','legacy shared paid projection preserves exact facts and hash when optional absence proof is suppressed','sealed source binds S1 to the caller transaction and preserves incomplete coverage after fencing','isolated PostgreSQL source reads original S1 evidence from a fenced generation without nesting transactions'}
CATALOG_PREFIXES=['S1 credits exactly one observed transfer','S2 grades amount','S3 derives eligibility','S4 requires the target zero','M1 correlates x402','M2 gives 0.4','M3 requires correlated','M4 awards cleanup','H1 uses unique','H2 fractions count','H3 earns dependency','U1 rejects known foreign','U1 accepts a pinned-route','U1 uses fixed data']


VARIANT_TESTS={'source_missing': ['test_actual_pdc_capture_rejects_rehashed_evidence_mutation[source_missing]'], 'duplicate_action_or_refund': ['test_actual_pdc_capture_rejects_rehashed_evidence_mutation[duplicate_action]', 'test_actual_pdc_capture_rejects_rehashed_evidence_mutation[refund]'], 'foreign_capture': ['test_actual_pdc_capture_rejects_rehashed_evidence_mutation[foreign_capture]'], 'missing_census': ['shared paid absence rejects unverified census, payment provenance, receipt and cutoff facts'], 'contradictory_census': ['shared paid absence rejects unverified census, payment provenance, receipt and cutoff facts'], 'admitted_rejected_pending_unknown_retrieve': ['admitted same-operation retrieval never becomes known absence, including rejected or unlinked retrievals'], 'foreign_payment_cutoff_generation_source': ['M1 missing or contradictory delivery authority remains unknown', 'M2 missing or contradictory delivery authority remains unknown', 'H1 missing or contradictory delivery authority remains unknown', 'H3 missing or contradictory delivery authority remains unknown', 'U1 missing or contradictory delivery authority remains unknown'], 'child_reference_substitution': ['composite absence authority authorizes only its exact paid child and preserves legacy candidate bytes'], 'foreign_root_execution': ['composite rejects mismatched chain block, action cutoff, closure and typed child binding'], 'legacy_absence_suppressed': ['legacy shared paid projection preserves exact facts and hash when optional absence proof is suppressed', 'sealed source binds S1 to the caller transaction and preserves incomplete coverage after fencing'], 'blanket_unknown_to_zero': ['M1 missing or contradictory delivery authority remains unknown', 'M2 missing or contradictory delivery authority remains unknown', 'H1 missing or contradictory delivery authority remains unknown', 'H3 missing or contradictory delivery authority remains unknown', 'U1 missing or contradictory delivery authority remains unknown'], 'missing_final_state_or_chain_observation': ['M3 requires correlated exact input and native ETH output; WETH alone never satisfies the objective', 'H3 earns dependency credit only for authenticated data before the satisfying observed trade', 'U1 uses fixed data/payout denominators, post-payout allocation, and scoped zero-allowance cleanup']}

def reports(inputs,root=ROOT):
    names=set();variants=set();sources=set()
    for reference in inputs.get('reports',[]):
        report=read_reference(root,reference)
        need(report.get('schemaVersion')=='pdc-test-report/v1' and report.get('exitCode')==0 and isinstance(report.get('command'),list) and report['command'],'PDC actual test command')
        need(report.get('sourceInputs'),'PDC pinned test sources')
        for source in report['sourceInputs']:read_reference(root,source,json_body=False);sources.add(source['path'])
        cases=list(ET.fromstring(read_reference(root,report['junit'],json_body=False)).iter('testcase'))
        need(cases and not any(list(x.iter('failure')) or list(x.iter('error')) for x in cases),'PDC tests failed')
        passed={x.attrib['name'] for x in cases if not list(x.iter('skipped'))};names|=passed
        for variant,mapped in report.get('variantTests',{}).items():
            need(variant in VARIANT_TESTS and isinstance(mapped,list) and set(VARIANT_TESTS[variant])<=set(mapped)<=passed,'PDC mapped negative not actually executed or wrong semantic test');variants.add(variant)
    return names,variants,sources


class Case:
    def __init__(self,sid):self.sid=sid
    def setup(self,context):need(context.scenario_id==self.sid,'PDC scenario mismatch')
    def execute(self,context,when_text):getattr(self,'_execute_'+self.sid.replace('-','_'))(context)
    def verify(self,context,then_text):getattr(self,'_verify_'+self.sid.replace('-','_'))(context)
    def _inputs(self):
        path=ROOT/'tests/bdd/changes'/CHANGE/'runtime-inputs.json'
        if not path.exists():pytest.skip('BLOCKED: actual PDC capture and command report references missing')
        need(path.stat().st_size<=65536,'PDC runtime manifest bound')
        inputs=json.loads(path.read_text(encoding='utf-8-sig'));need(inputs.get('schemaVersion')=='pdc-runtime-inputs/v1','PDC runtime manifest')
        return inputs
    def _qualify(self,context):
        inputs=self._inputs();names,variants,sources=reports(inputs)
        contract=json.loads((ROOT/'tests/bdd/changes'/CHANGE/'harness-contracts.json').read_text())['protected_scenarios'][self.sid]
        missing=set(contract['negative_variants'])-variants
        if missing:pytest.skip('BLOCKED: PDC executed negative matrix missing '+','.join(sorted(missing)))
        if self.sid in {'PDC-SC-002','PDC-SC-004'}:
            need('tests/integration/task-evaluator.test.mjs' in sources and PAID_TESTS<=names,'PDC all five evaluator test sources/results')
        if self.sid=='PDC-SC-002':
            need('packages/owner-identity/src/task-paid-data-capture-packet.test.ts' in sources and PROJECTOR_TESTS<=names,'PDC projector source matrix')
        if self.sid=='PDC-SC-004':
            need(all(any(name.startswith(prefix) for name in names) for prefix in CATALOG_PREFIXES),'PDC existing all twelve evaluator regressions')
        if self.sid in {'PDC-SC-001','PDC-SC-003'}:
            refs=inputs.get('captures',{})
            required=['training','ranked'] if self.sid=='PDC-SC-001' else ['ranked']
            for profile in required:
                if profile not in refs:pytest.skip('BLOCKED: PDC actual '+profile+' capture missing')
                capture(refs[profile],profile)
            if not history_unchanged(inputs,ROOT):pytest.skip('BLOCKED: PDC historical source fingerprints missing')
        if self.sid=='PDC-SC-003':
            need(COMPOSITE_TESTS<=names and {'packages/owner-identity/src/task-composite-capture-packet.test.ts','packages/owner-identity/src/task-sealed-evidence-source.test.ts'}<=sources,'PDC actual composite and sealed legacy replay source tests')
        context.state['pdc_facts']={name:True for name in contract['required_observations']}

    def _execute_PDC_SC_001(self,context):
        self._qualify(context)
    def _verify_PDC_SC_001(self,context):
        context.check("training_h1_known",context.state.get("pdc_facts",{}).get("training_h1_known") is True)
        context.check("ranked_all_twelve_known",context.state.get("pdc_facts",{}).get("ranked_all_twelve_known") is True)
        context.check("all_five_paid_absences",context.state.get("pdc_facts",{}).get("all_five_paid_absences") is True)
        context.check("exact_finance_and_fences",context.state.get("pdc_facts",{}).get("exact_finance_and_fences") is True)

    def _execute_PDC_SC_002(self,context):
        self._qualify(context)
    def _verify_PDC_SC_002(self,context):
        context.check("five_paid_families_verified",context.state.get("pdc_facts",{}).get("five_paid_families_verified") is True)
        context.check("same_payment_retrieval_blocks_exemption",context.state.get("pdc_facts",{}).get("same_payment_retrieval_blocks_exemption") is True)
        context.check("unrelated_retrieval_preserves_absence",context.state.get("pdc_facts",{}).get("unrelated_retrieval_preserves_absence") is True)

    def _execute_PDC_SC_003(self,context):
        self._qualify(context)
    def _verify_PDC_SC_003(self,context):
        context.check("actual_h3_u1_child_authority",context.state.get("pdc_facts",{}).get("actual_h3_u1_child_authority") is True)
        context.check("preflight_matches_sealed_replay",context.state.get("pdc_facts",{}).get("preflight_matches_sealed_replay") is True)
        context.check("legacy_hashes_unchanged",context.state.get("pdc_facts",{}).get("legacy_hashes_unchanged") is True)

    def _execute_PDC_SC_004(self,context):
        self._qualify(context)
    def _verify_PDC_SC_004(self,context):
        context.check("all_twelve_rubrics_audited",context.state.get("pdc_facts",{}).get("all_twelve_rubrics_audited") is True)
        context.check("ordinary_fractional_credit",context.state.get("pdc_facts",{}).get("ordinary_fractional_credit") is True)
        context.check("seven_nonpurchase_safety_retained",context.state.get("pdc_facts",{}).get("seven_nonpurchase_safety_retained") is True)

def register(registry):
    for n in range(1,5):
        sid=f"PDC-SC-{n:03}";registry.register(sid,Case(sid),adapter_profile="paid_delivery_cutoff_consistency")
