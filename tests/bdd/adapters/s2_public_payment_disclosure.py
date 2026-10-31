"""Independent SPP reader: public provider metadata, strict tests and fresh raw qualification."""
from pathlib import Path
import json
import xml.etree.ElementTree as ET
import pytest
from tests.bdd.adapters.ber_recovery_replay import read_reference, digest
from tests.bdd.adapters.agent_run_continuity import need,one
from tests.bdd.adapters.paid_delivery_cutoff_consistency import capture as pdc_capture
ROOT=Path(__file__).resolve().parents[3]
CHANGE='s2-public-payment-disclosure'
ADAPTER_PROFILES={'s2_public_payment_disclosure'}
BASELINE={'path':'artifacts/runs/paid-delivery-cutoff-ranked/fbadf265-3c64-4840-bb96-59113039455f/capture.json','sha256':'1692f923e8bc0dd49c054d4c87317dc0e07b8d2305c51ac6e4bde385ebdff596'}
PROVIDER_TEST='public payment identity derives only from the actual provider domain policy'
PG_TEST='HTTP inspection, /pay idempotency, cross-route conflict, and deferred delivery use durable PostgreSQL state'
STRICT_TEST='public identity rejects partial extra substituted and mixed root offer metadata'
LEGACY_TEST='complete public identity validates without changing the exact legacy accepted terms'


def unit_reports(inputs,root=ROOT):
    names=set();sources=set()
    for reference in inputs.get('testReports',[]):
        report=read_reference(root,reference)
        need(report.get('schemaVersion')=='spp-test-report/v1' and report.get('exitCode')==0 and report.get('command'),'SPP actual executed command')
        need(report.get('sourceInputs'),'SPP actual test source pins')
        for source in report['sourceInputs']:read_reference(root,source,json_body=False);sources.add(source['path'])
        cases=list(ET.fromstring(read_reference(root,report['junit'],json_body=False)).iter('testcase'))
        need(cases and not any(list(x.iter('failure')) or list(x.iter('error')) for x in cases),'SPP failed tests')
        names|={x.attrib['name'] for x in cases if not list(x.iter('skipped'))}
    return names,sources


def public_s2(p,manifest):
    task=one([x for x in p['tasks'] if x['taskId']=='S2'],'SPP actual S2 task')
    need(not task.get('publicDisclosureGap'),'SPP disclosure defect remains open')
    calls=[x for x in p['mcp'] if x['name']=='runs.task_action_status' and not x['isError'] and x['body'].get('taskIndex')==task['taskIndex'] and x['body'].get('status')=='observed']
    receipt=one(calls,'SPP actual public offer receipt')['body'];body=receipt['toolResponse']
    conditions=task['issued']['conditions'];offer=one([x for x in body['offers'] if x['id']==conditions['offerId']],'SPP selected canonical offer');payment=offer['payment']
    identity={'version':manifest['x402']['eip712Domain']['version'],'name':manifest['x402']['eip712Domain']['name'],'paymentFlow':'authorization'}
    for terms in [body['payment'],*(x['payment'] for x in body['offers'])]:need({key:terms.get(key) for key in identity}==identity,'SPP actual public provider identity')
    asset=one([x for x in task['issued']['execution']['assets'] if isinstance(x.get('address'),str) and x['address'].lower()==payment['asset'].lower() and payment['network']=='eip155:'+str(x['chainId'])],'SPP public token mapping')
    expected={'amountUnits':payment['amount'],'network':payment['network'],'assetId':asset['assetId'],'recipient':payment['payTo'],'scheme':payment['scheme'],
      'resourceId':body['resourceId'],'offerId':offer['id'],'version':identity['version']}
    answer=task['answer'];need({k:v for k,v in answer.items() if k!='authFields'}==expected,'SPP public-derived S2 answer')
    auth=answer['authFields'];need(len(auth)==4 and {x['name']:x['value'] for x in auth}=={**identity,'assetTransferMethod':payment['transferMethod']},'SPP complete public auth identity')
    finish=one([x for x in p['mcp'] if x['name']=='runs.finish_task' and x['args']['taskIndex']==task['taskIndex']],'SPP actual answer submission')
    need(finish['args']['answer']==answer,'SPP actual MCP answer matches public response')
    proof=one([x for x in p['sourceProofs'] if x['task_index']==task['taskIndex']],'SPP sealed S2 source')
    need(one(proof['bundle_json']['observations']['answers'],'SPP immutable sealed answer')['answer']==answer,'SPP public answer retained at cutoff')
    result=proof['result_json'];need(result['status']=='known' and result['outcome']=='passed' and result['credit']=={'numerator':'1','denominator':'1'},'SPP unchanged evaluator full credit')
    return proof


def actual(inputs,root=ROOT):
    reference=inputs['rankedCapture'];p=pdc_capture(reference,'ranked',root);outer=read_reference(root,reference)
    release=outer['result']['release'];baseline=read_reference(root,BASELINE);old=baseline['result']['release']
    need(release['releaseIdentity']!=old['releaseIdentity'] and release['manifestHash']!=old['manifestHash'],'SPP fresh release identity required')
    candidate=read_reference(root,{'path':release['candidatePath'],'sha256':release['candidateSha256']})
    validation=read_reference(root,{'path':release['validationPath'],'sha256':release['validationSha256']})
    source=candidate['manifest'];bound=validation['validation']['release']['manifest'];binding=validation['manifestBinding']
    need(source['manifestHash']==binding['originalManifestHash'] and bound['manifestHash']==release['manifestHash']==binding['boundManifestHash'],'SPP candidate and bound release hash identities')
    need(digest({k:v for k,v in source.items() if k!='manifestHash'})==source['manifestHash'] and digest({k:v for k,v in bound.items() if k!='manifestHash'})==bound['manifestHash'],'SPP independently recomputed manifest hashes')
    expected={**source,'manifestHash':bound['manifestHash'],'difficultyReviewEvidence':binding['difficultyReviewEvidence']}
    need(bound==expected,'SPP only verified difficulty-review binding may alter candidate manifest')
    read_reference(root,binding['difficultyReviewEvidence'])
    need(validation['validation']['status']=='validated' and validation['status']=='validated_candidate','SPP new release validation')
    manifest=read_reference(root,{'path':'infrastructure/benchmark-environment/manifest.json','sha256':release['environmentManifestSha256']})
    proof=public_s2(p,manifest);old_proof=one([x for x in baseline['result']['pdc']['sourceProofs'] if x['task_index']==1],'SPP original S2 source')
    need(proof['bundle_json']['execution']['applicationSourceHash']!=old_proof['bundle_json']['execution']['applicationSourceHash'],'SPP actual fresh provider source')
    before=read_reference(root,{'path':old['candidatePath'],'sha256':old['candidateSha256']})['manifest']['cases']['ranked'][1]
    after=candidate['manifest']['cases']['ranked'][1]
    need(all(before[key]==after[key] for key in ['rubricHash','taskWeight','taskDeadlineSeconds']) and before['objective']['requiredAnswerFields']==after['objective']['requiredAnswerFields'],'SPP grading goal and deadline unchanged')
    return p


class Case:
    def __init__(self,sid):self.sid=sid
    def setup(self,context):need(context.scenario_id==self.sid,'SPP scenario identity')
    def execute(self,context,when_text):getattr(self,'_execute_'+self.sid.replace('-','_'))(context)
    def verify(self,context,then_text):getattr(self,'_verify_'+self.sid.replace('-','_'))(context)
    def _inputs(self):
        path=ROOT/'tests/bdd/changes'/CHANGE/'runtime-inputs.json'
        if not path.exists():pytest.skip('BLOCKED: SPP actual qualified source and executed reports missing')
        need(path.stat().st_size<=65536,'SPP input bound')
        value=json.loads(path.read_text(encoding='utf-8-sig'));need(value.get('schemaVersion')=='spp-runtime-inputs/v1','SPP runtime schema');return value
    def _qualify(self,context):
        inputs=self._inputs();names,sources=unit_reports(inputs)
        if self.sid=='SPP-SC-001':
            need({PROVIDER_TEST,PG_TEST}<=names and {'packages/benchmark-environment/src/payment-identity.test.ts','packages/benchmark-environment/src/pay-retrieve.test.ts'}<=sources,'SPP actual provider and PG public route tests')
        elif self.sid=='SPP-SC-002':
            owner_tests={'payment reference accepts exact legacy or complete public identity and projects only six consent terms','payment reference rejects partial malformed unknown or conflicting public identity','payment reference verifies the original raw response hash before interpreting added public metadata'}
            consumer_tests={'public quote validator preserves legacy bytes and validates only the complete pinned identity group','public inspection validates catalog and offer identity before unchanged economic projection','M1 packet retains complete public identity and rejects foreign or partial metadata without changing legacy bytes','S3 catalog and offer accept complete public identity while rejecting partial and foreign version','paid sealed replay binds owner command, durable receipt history, actual response and BEF request hash'}
            needed_sources={'packages/benchmark-environment/src/probe/task-split-resource-capture.test.ts','packages/owner-identity/src/task-payment-references.test.ts','packages/owner-identity/src/task-public-payment-quote.test.ts','packages/owner-identity/src/task-m1-capture-packet.test.ts','packages/owner-identity/src/task-s3-capture-packet.test.ts','packages/owner-identity/src/task-sealed-evidence-source.test.ts'}
            if not consumer_tests<=names:pytest.skip('BLOCKED: SPP post-provider consumer compatibility regression report missing')
            need({STRICT_TEST,LEGACY_TEST}|owner_tests|consumer_tests<=names and needed_sources<=sources,'SPP exact provider, observer, replay and owner new/legacy boundary tests')
        else:
            mutations={f'test_actual_s2_public_capture_rejects_rehashed_mutation[{name}]' for name in ['undisclosed_identity','foreign_public_response','historical_pin_rewrite']}
            if 'rankedCapture' not in inputs:pytest.skip('BLOCKED: SPP fresh actual Ranked capture missing')
            if not mutations<=names or 'tests/bdd/adapters/test_s2_public_payment_disclosure.py' not in sources:pytest.skip('BLOCKED: SPP actual adversarial capture controls missing')
            actual(inputs)
        context.state['spp_verified']=True
    def _execute_SPP_SC_001(self,context):self._qualify(context)
    def _verify_SPP_SC_001(self,context):
        context.check('provider_protocol_metadata_match',context.state.get('spp_verified') is True)
        context.check('all_public_payments_complete',context.state.get('spp_verified') is True)
        context.check('economic_terms_unchanged',context.state.get('spp_verified') is True)
    def _execute_SPP_SC_002(self,context):self._qualify(context)
    def _verify_SPP_SC_002(self,context):
        context.check('new_identity_strictly_validated',context.state.get('spp_verified') is True)
        context.check('legacy_projection_bytes_unchanged',context.state.get('spp_verified') is True)
    def _execute_SPP_SC_003(self,context):self._qualify(context)
    def _verify_SPP_SC_003(self,context):
        context.check('fresh_release_qualified',context.state.get('spp_verified') is True)
        context.check('public_derived_s2_answer',context.state.get('spp_verified') is True)
        context.check('known_s2_full_credit',context.state.get('spp_verified') is True)
        context.check('full_run_finance_and_fences',context.state.get('spp_verified') is True)


def register(registry):
    for n in range(1,4):
        sid=f'SPP-SC-{n:03}';registry.register(sid,Case(sid),adapter_profile='s2_public_payment_disclosure')
