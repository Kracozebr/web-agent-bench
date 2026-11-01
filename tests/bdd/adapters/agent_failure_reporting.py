"""Independent AFR evidence reader. Never dispatches tools or modifies business state."""
from pathlib import Path
import hashlib
import json
import re
from datetime import datetime
import xml.etree.ElementTree as ET
import pytest
from tests.bdd.adapters.ber_recovery_replay import read_reference
from tests.bdd.adapters.beta_poc_recovery_verifier import _verify_provenance

ROOT = Path(__file__).resolve().parents[3]
ADAPTER_PROFILES = {'agent_failure_reporting'}
TOOLS = {'identity.preflight', 'runs.accept_launch_intent', 'runs.current_task', 'runs.task_action',
         'runs.task_action_status', 'runs.finish_task', 'support.report', 'support.report_receipt'}
REASONS = {'coordinator_evaluation_unknown', 'coordinator_preparation_failed',
           'coordinator_interrupted_preparation', 'coordinator_executor_session_lost', 'coordinator_platform_failure'}
PG_TEST = 'supplementary local DB-authenticated MCP report and screenshot smoke'
POLICY_TEST = 'only authoritative terminal platform categories create a deterministic safe private report'
CONFIG_TEST = 'profile patch adds only report and receipt, preserves unrelated data and is idempotent'
CONFIG_WRITE_TEST = 'apply requires exact review hash, keeps private exact backup and leaves config unchanged on stale hash'
PG_VARIANTS = {'uncertain_unchanged_retry','foreign_run_task_action','report_or_receipt_denied','forged_principal','foreign_link','expired_grant','revoked_grant'}
POLICY_VARIANTS = {'ordinary_failed_partial','nonterminal_null','unconfirmed_transport','hidden_payload_excluded'}

def need(value, reason):
    if not value:
        raise AssertionError(reason)

def one(rows, reason):
    need(isinstance(rows, list) and len(rows) == 1, reason)
    return rows[0]

def facts(packet):
    p = packet.get('projection', {})
    return [p.get('result', {})] + p.get('content', [])

def date(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))

def verify_intent_binding(proof):
    run, intent = proof['run'], proof['handoff']['intentSnapshot']
    need(run.get('intent_id') == proof['intentId'] == intent.get('id'), 'AFR immutable PG run/intent binding')
    need(run['id'] == proof['runId'] and run['agent_id'] == proof['agentId'] == intent.get('agent_id') and run['owner_id'] == intent.get('owner_id'), 'AFR immutable intent private owner/agent scope')

def physical(reference, root=ROOT):
    outer = read_reference(root, reference)
    need(outer.get('schemaVersion') == 'agent-failure-reporting-capture/v1', 'AFR wrapper schema')
    database, _ = _verify_provenance(outer, root)
    p = outer.get('result', {}).get('afr', {})
    need(p.get('schemaVersion') == 'agent-failure-reporting-physical-capture/v1' and p.get('status') == 'verified', 'AFR actual verified capture')
    need(p.get('nativeExecutionMode') == 'same_production_handoff', 'AFR report-only continuation does not prove automatic trigger')
    need(p['database']['role'] == 'oid_observer' and p['database']['read_only'] == 'on' and p['database']['database_name'] == database, 'AFR independent read-only observer')
    run, report, native = p['run'], p['report'], p['native']
    verify_intent_binding(p)
    terminal = p['terminalBeforeReport']['run']
    reason = terminal.get('cancellationReason') if terminal.get('cancellationReason') in REASONS else terminal.get('terminalReason')
    need(terminal['runId'] == p['runId'] == run['id'] and terminal['terminal'] is True and run['status'] == terminal['status'], 'AFR actual terminal run')
    need(reason in REASONS and reason in (run.get('cancellation_reason'), run.get('terminal_reason')), 'AFR explicit platform category')
    operation = 'afr_' + p['runId'].replace('-', '')
    expected_body = f"Server-confirmed platform failure; runStatus={run['status']}; reason={reason}."
    need(report['operation_id'] == operation and report['title'] == 'Platform run failure' and report['body'] == expected_body, 'AFR safe deterministic report content')
    need(report['owner_id'] == run['owner_id'] and report['agent_id'] == report['reporter_id'] == p['agentId'] == run['agent_id'] and report['reporter_kind'] == report['source'] == 'agent' and report['run_id'] == p['runId'], 'AFR report private identity and links')
    need(p['receipt']['report']['id'] == report['id'] and p['receipt']['report']['status'] == report['status'], 'AFR actual report receipt')
    audit = one(p['reportAudit'], 'AFR exactly one creation audit')
    need(audit['report_id'] == report['id'] and audit['event_type'] == 'created' and audit['revision'] == 1, 'AFR durable creation audit')
    need(p['domainBefore'] == p['domainAfter'] and len(p['domainBefore']) == 7, 'AFR no benchmark/financial mutation')
    need({x['domain'] for x in p['domainBefore']} == {'run','tasks','actions','closures','grades','events','ledger'} and all(re.fullmatch('[a-f0-9]{32}', x['digest']) for x in p['domainBefore']), 'AFR complete unchanged domain census')
    ui = p['adminUI']
    need(ui['clicked'] is True and ui['httpStatus'] == 200 and ui['reportId'] == report['id'] and ui['title'] == report['title'] and ui['body'] == expected_body and ui['links']['runId'] == p['runId'], 'AFR actual administrator UI/API/PG correlation')
    handoff = p['handoff']; text = handoff['clipboard']
    need(handoff['clicked'] is True and handoff['visible'] == text and 'Automatic private support reporting:' in text and 'support.report_receipt' in text, 'AFR actual production clipboard instruction')
    need(native['promptSha256'] == p['nativePromptSha256'] == hashlib.sha256(text.encode()).hexdigest(), 'AFR one original native handoff')
    need(native['implementation'] == 'native_codex_cli' and native['clientVersion'] == '0.165.0' and native['exitCode'] == 0 and native['localToolCalls'] == 0 and native['mcpToolCalls'] > 0 and not native.get('nativeObservationErrors'), 'AFR actual native participant with no local tools')
    need(set(native['enabledTools']) == TOOLS and len(native['enabledTools']) == 8, 'AFR exact eight-tool profile')
    need(native['status'] in ('turn_completed','turn_completed_with_tool_errors'), 'AFR native turn terminal')
    packets = native['wireTrace']['packets']
    need(packets and all(x['rawPersisted'] is False and re.fullmatch('[a-f0-9]{64}', x['rawSha256']) for x in packets), 'AFR native bounded protocol projections')
    requests = [x for x in packets if x['direction'] == 'request' and x.get('projection', {}).get('method') == 'tools/call']
    accepts = [x for x in requests if x['projection'].get('toolName') == 'runs.accept_launch_intent']
    accept = one(accepts, 'AFR one native admission')
    need(accept['projection']['arguments']['intentId'] == p['intentId'], 'AFR exact original intent')
    report_calls = [x for x in requests if x['projection'].get('toolName') == 'support.report']
    need(1 <= len(report_calls) <= 2 and all(x['projection']['arguments'].get('operationId') == operation and x['projection']['arguments'].get('runId') == p['runId'] for x in report_calls), 'AFR native same-operation report retry')
    terminal_packets = [x for x in packets if x['direction'] == 'response' and any(v.get('run', {}).get('terminal') is True and v['run'].get('runId') == p['runId'] for v in facts(x))]
    need(terminal_packets and min(x['sequence'] for x in terminal_packets) < report_calls[0]['sequence'] and accept['sequence'] < report_calls[0]['sequence'], 'AFR native reports only after terminal failure')
    receipt_calls = [x for x in requests if x['projection'].get('toolName') == 'support.report_receipt']
    need(receipt_calls and any(x['projection']['arguments'].get('reportId') == report['id'] for x in receipt_calls), 'AFR native receipt call')
    def report_responses(call):
        return [x for x in packets if x['direction'] == 'response' and x['sequence'] > call['sequence'] and x['projection'].get('id') == call['projection'].get('id') and any(v.get('report', {}).get('id') == report['id'] for v in facts(x))]
    need(any(any(v.get('replayed') is False for v in facts(response)) for response in report_responses(report_calls[0])), 'AFR native created report response')
    need(any(report_responses(call) for call in receipt_calls), 'AFR native confirmed receipt response')
    need(not [x for x in requests if x['sequence'] > report_calls[0]['sequence'] and x['projection'].get('toolName') in {'runs.accept_launch_intent','runs.task_action','runs.finish_task'}], 'AFR reporting never restarts benchmark effects')
    retry = one([x for x in p['mcp'] if x['name'] == 'support.report'], 'AFR independently exercised unchanged retry')
    need(retry['body']['replayed'] is True and retry['body']['report']['id'] == report['id'], 'AFR durable report deduplication')
    if p.get('failureBoundary') == 'successor_preparation_unavailable':
        verify_preparation_failure(p)
        return p
    fault = p['fault']; need(fault['interventions'], 'AFR actual observer failure injection')
    for intervention in fault['interventions']:
        need(intervention['runId'] == p['runId'] and intervention['taskId'] == 'H1' and intervention['mode'] == 'missing' and intervention['deliveredReceipt'] is None and int(intervention['originalReceipt']['status'], 16) == 1, 'AFR successful chain receipt withheld only from observer')
    h1 = one([x for x in p['failureTasks'] if x['task_id'] == 'H1'], 'AFR H1 failure task')
    need(not h1['evaluation_present'] and date(run['finished_at']) >= date(h1['evaluation_retry_deadline']) and (date(h1['evaluation_retry_deadline']) - date(h1['closed_at'])).total_seconds() == 180, 'AFR original 180-second unknown grace without invented grade')
    return p

def verify_preparation_failure(p):
    """Additional physical boundary; never reinterpret a missing chain receipt as this fault."""
    run, fault, row = p['run'], p['fault'], p['successorFailure']
    need(run['status'] == 'cancelled' and run['cancellation_reason'] == 'coordinator_preparation_failed', 'AFR bounded preparation terminal reason')
    need(fault.get('kind') == 'successor_preparation_unavailable' and fault.get('interventions'), 'AFR actual preparation health fault')
    need(row['run_id'] == p['runId'] and row['status'] == run['status'] and row['cancellation_reason'] == run['cancellation_reason'], 'AFR preparation PG binding')
    need(row['predecessor_task_id'] == 'S1' and row['predecessor_status'] in {'completed','failed'} and row['predecessor_known'] is True and row['predecessor_fenced'] is True, 'AFR known fenced predecessor')
    need(row['successor_task_id'] == 'M1' and row['successor_started_at'] is None and row['successor_preparations'] == 0, 'AFR unavailable successor never started')
    seconds = row['successor_preparation_timeout_seconds']
    need(isinstance(seconds, int) and 1 <= seconds <= 3600, 'AFR pinned preparation timeout')
    need(date(row['finished_at']) == date(run['finished_at']) and (date(row['finished_at']) - date(row['predecessor_finished_at'])).total_seconds() >= seconds, 'AFR terminalization after pinned window')
    for intervention in fault['interventions']:
        need(intervention['runId'] == p['runId'] and intervention['taskId'] == 'M1' and intervention['mode'] == 'unavailable' and intervention['responseStatus'] == 503, 'AFR exact successor health fault')
        need(date(row['predecessor_finished_at']) <= date(intervention['requestedAt']) <= date(run['finished_at']), 'AFR preparation fault timing')

def negative_reports(inputs, root=ROOT):
    covered = set()
    for reference in inputs.get('negativeReports', []):
        report = read_reference(root, reference)
        need(report.get('schemaVersion') == 'afr-test-report/v1' and report.get('exitCode') == 0 and report.get('command'), 'AFR source-bound test report')
        for path, expected in report.get('sourceInputs', {}).items():
            target = (root / path).resolve(); need(target.is_relative_to(root.resolve()) and target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == expected, 'AFR test source drift')
        need(report.get('sourceInputs'), 'AFR report source inventory')
        junit_ref = report['junit']; read_reference(root, junit_ref, json_body=False)
        tree = ET.parse(root / junit_ref['path']); passed = {x.attrib.get('name') for x in tree.iter('testcase') if not any(x.find(n) is not None for n in ('failure','error','skipped'))}
        for variant, names in report.get('variantTests', {}).items():
            need(isinstance(names, list) and names and set(names) <= passed, 'AFR negative variant must name successful testcases')
            if variant in PG_VARIANTS:
                need(names == [PG_TEST] and 'packages/owner-identity/src/report-mcp-auth.pg.test.ts' in report['sourceInputs'], 'AFR canonical actual PG auth control')
                need('OID_AGENT_FAILURE_REPORTING_PG_TEST=1' in ' '.join(report['command']), 'AFR expanded terminal/expired PG controls not enabled')
                pg = read_reference(root, report['pgCapture'])
                need(pg.get('schemaVersion') == 'bpc-local-authenticated-mcp-report-smoke/v1' and pg.get('status') == 'completed', 'AFR actual authenticated MCP PG capture')
                checks = pg.get('agentFailureReporting', {})
                need(all(checks.get(key) is True for key in ('terminalLinksAvailable','exactRetryDeduplicated','foreignTerminalLinkDenied','expiredReportAndReceiptDenied')), 'AFR terminal/expired/foreign PG outcomes missing')
            elif variant in POLICY_VARIANTS:
                need(names == [POLICY_TEST] and 'packages/owner-acceptance/src/agent-failure-reporting-cases.test.mjs' in report['sourceInputs'] and 'packages/owner-acceptance/src/agent-failure-reporting-cases.mjs' in report['sourceInputs'], 'AFR canonical policy/privacy control')
            elif variant in {'already_patched','concurrent_config_edit'}:
                expected = CONFIG_TEST if variant == 'already_patched' else CONFIG_WRITE_TEST
                need(names == [expected] and 'tools/enable-agent-failure-reporting.test.mjs' in report['sourceInputs'] and 'tools/enable-agent-failure-reporting.mjs' in report['sourceInputs'], 'AFR canonical isolated config control')
            else:
                raise AssertionError('AFR unknown negative-control variant')
            covered.add(variant)
    return covered

class Case:
    def __init__(self, sid): self.sid = sid
    def setup(self, context): need(context.scenario_id == self.sid, 'AFR scenario mismatch')
    def execute(self, context, when_text): getattr(self, '_execute_' + self.sid.replace('-', '_'))(context)
    def verify(self, context, then_text): getattr(self, '_verify_' + self.sid.replace('-', '_'))(context)
    def _capture(self, context):
        path = ROOT / 'tests/bdd/changes/agent-failure-reporting/runtime-inputs.json'
        if not path.exists(): pytest.skip('BLOCKED: AFR actual native automatic-report capture missing')
        inputs = json.loads(path.read_text(encoding='utf-8-sig'))
        need(inputs.get('schemaVersion') == 'afr-runtime-inputs/v1', 'AFR runtime input schema')
        if 'reporting' not in inputs.get('captures', {}): pytest.skip('BLOCKED: AFR actual reporting capture reference missing')
        context.state['afr'] = physical(inputs['captures']['reporting'])
        contract = json.loads((ROOT / 'tests/bdd/changes/agent-failure-reporting/harness-contracts.json').read_text())['protected_scenarios'][self.sid]
        missing = set(contract['negative_variants']) - negative_reports(inputs)
        if missing: pytest.skip('BLOCKED: AFR missing source-bound negative controls: ' + ','.join(sorted(missing)))
        context.state['afr_observations'] = contract['required_observations']
    def _execute_AFR_SC_001(self, context): self._capture(context)
    def _verify_AFR_SC_001(self, context):
        context.check('same_handoff_terminal_report', bool(context.state.get('afr')))
        context.check('one_private_report_and_receipt', bool(context.state.get('afr')))
        context.check('admin_ui_pg_binding', bool(context.state.get('afr')))
        context.check('benchmark_finance_unchanged', bool(context.state.get('afr')))
    def _execute_AFR_SC_002(self, context): self._capture(context)
    def _verify_AFR_SC_002(self, context):
        context.check('ordinary_outcomes_do_not_trigger', bool(context.state.get('afr')))
        context.check('report_failure_preserves_run', bool(context.state.get('afr')))
        context.check('safe_report_content', bool(context.state.get('afr')))
    def _execute_AFR_SC_003(self, context): self._capture(context)
    def _verify_AFR_SC_003(self, context):
        context.check('eight_tool_scope', bool(context.state.get('afr')))
        context.check('terminal_reporting_available', bool(context.state.get('afr')))
        context.check('revoked_expired_foreign_denied', bool(context.state.get('afr')))
        context.check('private_config_backup', bool(context.state.get('afr')))

def register(registry):
    for n in range(1, 4):
        sid = f'AFR-SC-{n:03d}'; registry.register(sid, Case(sid), adapter_profile='agent_failure_reporting')
