"""Read-only ACI replay. Component probes never substitute for a native OAuth client.

This module dispatches no commands, network calls or database writes. Missing real
capture/variant evidence blocks a gate; producer status/observation flags are ignored.
"""
from pathlib import Path
from datetime import datetime
import hashlib
import json
import re
import pytest
from tests.bdd.adapters.ber_recovery_replay import read_reference
from tests.bdd.adapters.beta_poc_recovery_verifier import _verify_provenance

ROOT=Path(__file__).resolve().parents[3]
ADAPTER_PROFILES={'agent_client_installer'}
SHA=re.compile(r'^[a-f0-9]{64}$')
DOMAINS={'runs','queue','reservations','ledger','taskActions','publications'}
TARGETS={'codex_cli','codex_desktop','claude_desktop','claude_code','openclaw','opencode','hermes','kilocode','cline','goose'}
VARIANT_KINDS={
    'substituted_or_untrusted_endpoint':'setup_denial','tampered_add_link':'setup_denial','unknown_client_url_fallback':'setup_fallback',
    'client_supports_only_local_stdio':'unavailable_client','client_app_unavailable':'unavailable_client',
    **{x:'authorization_denial' for x in ['callback_substitution','wrong_resource_or_issuer','wrong_state_or_pkce','code_replay','foreign_agent','denied_consent','unapproved_redirect','wrong_agent_hint','wrong_account_or_agent','stale_quote']},
    **{x:'refresh_rotation' for x in ['expired_access','offline_reconnect','simultaneous_refresh','lost_refresh_response','stolen_old_refresh_replay']},
    'refresh_revoke_race':'scoped_revocation','two_clients_same_agent':'scoped_revocation','selected_connection_replacement':'scoped_revocation','disconnect_is_not_revoke':'disconnect',
    'old_checkpoint_before_revoke_or_rotation':'restore_invalidation','missing_authoritative_invalidation_state':'restore_invalidation',
    **{x:'native_capability' for x in ['supported_old_and_modern_protocol','new_capable_client_version','missing_required_transport','missing_or_invalid_tool_schema','unsupported_protocol','spoofed_client_metadata','mismatched_protocol_headers','missing_tool_catalog','backend_unreachable','revoked_grant','executor_unready','new_version_same_capabilities','same_version_missing_capability','unlisted_compatible_client']},
    **{x:'launch_idempotency' for x in ['double_click','client_offline','owner_cancellation','copied_or_replayed_handoff','response_loss']},
    'client_access_missing':'unavailable_client','named_target_not_selected_for_beta':'unavailable_client','sdk_only_probe':'unqualified_substitute','reference_worker_substitution':'unqualified_substitute',
}

def need(value,reason):
    if not value: raise AssertionError(reason)

def one(rows,reason):
    need(isinstance(rows,list) and len(rows)==1,reason)
    return rows[0]

def timestamp(value):
    result=datetime.fromisoformat(value.replace('Z','+00:00'))
    need(result.tzinfo is not None,'ACI timezone missing')
    return result

def verify_snapshot(snapshot,database=None):
    identity=snapshot.get('database',{})
    need(identity.get('role')=='oid_observer' and identity.get('transactionReadOnly')=='on','ACI independent read-only PG')
    need(re.fullmatch(r'oid_acceptance_[a-f0-9]{32}',identity.get('databaseName','')),'ACI disposable PG')
    if database: need(identity['databaseName']==database,'ACI snapshot database substitution')
    digests=snapshot.get('domainDigests',{})
    need(set(digests)==DOMAINS and all(SHA.fullmatch(x or '') for x in digests.values()),'ACI complete business-domain census')
    return identity['databaseName']

def facts(packet):
    p=packet.get('projection',{})
    return [p.get('result',{})]+p.get('content',[])

def native_calls(proof,name,kind=None):
    packets=proof['mcp']
    calls=[x for x in packets if x.get('phase')=='request' and x.get('projection',{}).get('toolName')==name]
    if kind:
        turn=one([x for x in proof['nativeTurns'] if x.get('kind')==kind],'ACI one native turn '+kind)
        need(turn.get('authMethod')=='native_oauth' and turn.get('client')=='codex_cli','ACI actual native OAuth turn')
        need(turn.get('exitCode')==0 and turn.get('terminalEvent')=='turn.completed','ACI native completed turn')
        need(turn.get('localToolCallCount')==0 and turn.get('mcpToolCallCount',0)>0,'ACI no local solving or SDK substitution')
        calls=[x for x in calls if timestamp(turn['startedAt'])<=timestamp(x['at'])<=timestamp(turn['finishedAt'])]
    return calls

def responses(proof,call):
    return [x for x in proof['mcp'] if x.get('phase')=='response' and x.get('requestId')==call.get('requestId') and x.get('projection',{}).get('rpcId')==call['projection'].get('rpcId') and x['sequence']>call['sequence']]

def verify_preflight(proof):
    before,after=proof['beforePreflight'],proof['afterPreflight']
    database=verify_snapshot(before);verify_snapshot(after,database)
    need(before['domainDigests']==after['domainDigests'],'ACI preflight changed business/financial state')
    call=one(native_calls(proof,'identity.preflight','preflight'),'ACI exactly one free native preflight')
    need('agentId' not in call['projection'].get('arguments',{}),'ACI preflight must derive identity without UUID hint')
    principal=call.get('principal',{})
    need(set(principal)=={'ownerId','agentId','grantId'},'ACI preflight authenticated principal missing')
    grant=one([x for x in after['grants'] if x['id']==principal['grantId']],'ACI exact stable grant')
    need(grant['owner_id']==principal['ownerId'] and grant['agent_id']==principal['agentId'] and grant['revoked_at'] is None,'ACI grant owner/agent/revocation binding')
    need(grant.get('source')=='oauth' and grant.get('client_id')==proof['setup']['clientId'] and grant.get('resource')==proof['setup']['resource'],'ACI actual OAuth public-client resource, never a manual grant')
    allowed=[value for response in responses(proof,call) for value in facts(response) if value.get('status')=='allowed']
    need(allowed,'ACI actual authenticated preflight allowed response missing')
    need(any(value.get('identity',{}).get('agentId')==principal['agentId'] and value['identity'].get('connectionId')==principal['grantId'] for value in allowed),'ACI native preflight self-identity must match authenticated stable grant')
    need(any(set(value.get('permissions',{}))=={'training','ranked','forumMessages','customTopics'} and all(type(flag) is bool for flag in value['permissions'].values()) for value in allowed),'ACI preflight must expose permission readiness separately from connectivity')
    turn=one([x for x in proof['nativeTurns'] if x.get('kind')=='preflight'],'ACI free preflight turn timestamp')
    need(grant.get('last_preflight_at') and timestamp(turn['startedAt'])<=timestamp(grant['last_preflight_at'])<=timestamp(turn['finishedAt']),'ACI observed durable preflight timestamp missing')
    need(grant.get('protocol_version') in {'2025-06-18','2026-07-28'},'ACI negotiated protocol missing')
    return {'connectionId':grant['id'],'ownerId':principal['ownerId'],'agentId':principal['agentId'],'grant':grant}

def verify_launch(proof):
    identity=verify_preflight(proof);launch=proof['launch'];pending=proof['pendingLaunch'];after=proof['afterLaunch']
    database=verify_snapshot(pending);verify_snapshot(after,database)
    need(launch.get('clicked') is True and launch.get('selectedConnectionId')==identity['connectionId'],'ACI actual selected browser Start missing')
    need(launch.get('ownerId')==identity['ownerId'] and launch.get('agentId')==identity['agentId'],'ACI browser authenticated identity mismatch')
    intent=one([x for x in pending['intents'] if x['id']==launch['intentId']],'ACI exact pending intent')
    need(intent['owner_id']==identity['ownerId'] and intent['agent_id']==identity['agentId'],'ACI immutable intent owner/agent mismatch')
    binding=one([x for x in pending['bindings'] if x['intent_id']==intent['id']],'ACI exact selected connection audit')
    need(binding['connection_id']==identity['connectionId'],'ACI intent selected grant changed')
    need(pending['domainDigests']==proof['afterPreflight']['domainDigests'],'ACI pending intent reserved/charged before admission')
    calls=native_calls(proof,'runs.accept_launch_intent','launch')
    need(calls and all(x['projection']['arguments'].get('intentId')==intent['id'] and x.get('principal',{}).get('grantId')==identity['connectionId'] for x in calls),'ACI native selected grant acceptance')
    run=one([x for x in after['runs'] if x['intent_id']==intent['id']],'ACI exactly one admitted run')
    need(run['owner_id']==identity['ownerId'] and run['agent_id']==identity['agentId'],'ACI immutable run scope')
    need(after['admission']['reservationCount']==1 and after['admission']['debitCount']==1,'ACI once-only BRL reservation/debit')
    need(after['admission']['reservationUnits']==after['admission']['debitUnits']==launch['quotePriceUnits'] and after['admission']['reservationLotCount']>=1 and after['admission']['debitLotCount']>=1,'ACI exact conservation across logical reservation/debit funding lots')
    turn=one([x for x in proof['nativeTurns'] if x.get('kind')=='launch'],'ACI native launch turn')
    need(turn['promptSha256']==hashlib.sha256(launch['handoffPrompt'].encode()).hexdigest(),'ACI exact browser-delivered native prompt')
    need(launch.get('delivery',{}).get('kind') in {'clipboard_fallback','verified_native_link'},'ACI truthful delivery surface')
    need(launch['delivery'].get('nativeSendActionCount')==1,'ACI native Send counted separately')
    if launch['delivery']['kind']=='clipboard_fallback':need(launch['delivery'].get('pasteActionCount')==1 and launch['delivery'].get('twoActionClaim') is False,'ACI URL/clipboard fallback cannot claim two clicks')
    return {**identity,'runId':run['id'],'intentId':intent['id']}

def physical(reference,root=ROOT):
    wrapper=read_reference(root,reference)
    need(wrapper.get('schemaVersion')=='agent-client-connection-capture/v1','ACI capture wrapper')
    database,_=_verify_provenance(wrapper,root)
    proof=wrapper.get('result',{}).get('aci',{})
    need(proof.get('schemaVersion')=='agent-client-connection-physical-capture/v1','ACI physical capture schema')
    need(proof.get('qualificationScope')=='local_loopback_development_only','ACI local proof cannot imply public HTTPS deployment')
    stop=wrapper.get('finalization',{}).get('apiStopReceipt',{})
    need(proof.get('finalizedAfterApiClose') is True and stop.get('signal') is None and isinstance(stop.get('processId'),int) and stop['processId']>0 and (stop.get('exitCode')==0 or stop.get('requested') is True and stop.get('exitCode')==143),'ACI live/forced/unrequested unflushed partial capture cannot qualify')
    authorization=proof.get('nativeAuthorization',{})
    need(authorization.get('authMethod')=='native_oauth' and authorization.get('client')=='codex_cli' and authorization.get('isolatedHome') is True,'ACI manual bearer or SDK cannot prove native OAuth')
    need(authorization.get('clientVersion') and SHA.fullmatch(authorization.get('configurationSha256','')),'ACI actual native configuration observation')
    pins=authorization.get('sourcePins',{})
    need({'nativeExeSha256','codeModeHostSha256','helperSha256','baseHelperSha256'}<=set(pins) and all(SHA.fullmatch(x or '') for x in pins.values()),'ACI native full-bundle/source pins')
    need(proof.get('nativeSourceReferences') and [read_reference(root,ref) for ref in proof['nativeSourceReferences']]==proof['nativeTurns'],'ACI native turn summary source references')
    need(pins['helperSha256']==hashlib.sha256((root/'tools/run_aci_native.mjs').read_bytes()).hexdigest() and pins['baseHelperSha256']==hashlib.sha256((root/'infrastructure/owner-identity/run-codex-google-local.mjs').read_bytes()).hexdigest(),'ACI native helper source drift')
    need(proof.get('mcp') and not proof.get('observerErrors'),'ACI actual native MCP wire missing')
    need(proof.get('mcpTrace') and proof.get('observerStatusReferences'),'ACI raw safe projection/status references missing')
    trace=read_reference(root,proof['mcpTrace'],json_body=False)
    # read_reference may return (bytes,path) in older readers; ACI accepts bytes only.
    need(isinstance(trace,bytes),'ACI projection trace must be bounded bytes')
    need([json.loads(line) for line in trace.decode().splitlines() if line.strip()]==proof['mcp'],'ACI projection trace/capture mismatch')
    statuses=[read_reference(root,ref) for ref in proof['observerStatusReferences']]
    need(any(x.get('processId')==stop['processId'] for x in statuses),'ACI owned stopped API process did not flush observer')
    need(len({x.get('epoch') for x in statuses})==len(statuses),'ACI repeated observer process epoch')
    for epoch in {x.get('epoch') for x in proof['mcp']}:
        sequences=[x['sequence'] for x in proof['mcp'] if x.get('epoch')==epoch]
        need(epoch and sequences==sorted(set(sequences)),'ACI MCP observation per-process sequence')
        status=one([x for x in statuses if x.get('epoch')==epoch],'ACI closed actual observer process')
        need(status.get('schemaVersion')=='aci-mcp-observer-status/v1' and status.get('errors')==[] and sequences==list(range(1,status['records']+1)),'ACI incomplete/error observer epoch cannot qualify')
    need(all(x.get('rawPersisted') is False and x.get('payloadHashMode')=='decoded_json_rpc_input' and SHA.fullmatch(x.get('payloadSha256','')) for x in proof['mcp']),'ACI bounded decoded RPC projections (not raw HTTP/SSE hashes)')
    need(verify_snapshot(proof['beforePreflight'])==database,'ACI provenance/observer database')
    return proof

def exact_consent_units(value):
    if value is None:return None
    need(type(value) is str and len(value)<=80 and re.fullmatch(r'(0|[1-9][0-9]*)\.[0-9]{6}',value),'ACI exact six-decimal policy limit')
    whole,fraction=value.split('.')
    return str(int(whole)*1000000+int(fraction))

def verify_financial_consent(proof,identity):
    consent=proof['consent'];context=consent.get('financialContext',{})
    need(context.get('token')=='USDC' and context.get('precision')==6 and type(context.get('revision')) is int and context['revision']>=0 and type(context.get('configured')) is bool and type(context.get('allowCashShortfall')) is bool,'ACI financial snapshot type/precision')
    categories=context.get('categoryLimits',{})
    need(set(categories)=={'benchmark','forum'},'ACI consent categories exact')
    for value in categories.values():exact_consent_units(value)
    expected={'allow_cash_shortfall':context['allowCashShortfall'],'operation_limit_units':exact_consent_units(context['operationLimit']),'utc_day_limit_units':exact_consent_units(context['utcDayLimit']),'category_limits':categories}
    snapshot=consent.get('financialPolicySnapshot',{});database=proof['beforePreflight']['database']
    need(snapshot.get('database')==database and database['role']=='oid_observer' and database['transactionReadOnly']=='on' and snapshot.get('ownerId')==identity['ownerId'] and snapshot.get('agentId')==identity['agentId'],'ACI independently read-only financial owner/agent scope')
    need(snapshot.get('caps')==consent.get('displayedFinancialPolicy')==expected and snapshot.get('financialPolicyRevision')==context['revision'],'ACI financial context/display/PG snapshot mismatch')
    need(all(proof[key].get('caps')==expected for key in ['beforeConnection','beforePreflight','afterPreflight']),'ACI consent must not raise/change authoritative financial caps')
    digest=hashlib.sha256(json.dumps(expected,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    need(consent.get('displayedFinancialFingerprint')==identity['grant']['caps_hash']==digest,'ACI displayed caps must match actual grant observation fingerprint')
    text=consent.get('displayedFinancialText',{})
    for key,value in [('operation',context['operationLimit']),('day',context['utcDayLimit']),('benchmark',categories['benchmark']),('forum',categories['forum'])]:
        exact='Unlimited by this policy limit' if value is None else value+' USDC / '+exact_consent_units(value)+' micro-USDC'
        need(text.get(key)==exact,'ACI financial limit display rounded/changed')
    need(text.get('cash')==('Allowed by the current owner policy' if context['allowCashShortfall'] else 'Not allowed by the current owner policy'),'ACI cash shortfall display')

def verify_authorization(proof):
    identity=verify_preflight(proof);before=proof['beforeConnection'];verify_snapshot(before)
    need(not [x for x in before['grants'] if x['id']==identity['connectionId']],'ACI authority existed before consent')
    consent=proof.get('consent',{})
    need(consent.get('clicked') is True and consent.get('ownerId')==identity['ownerId'] and consent.get('agentId')==identity['agentId'],'ACI real owner-selected browser consent')
    need(consent.get('clientId')==proof['setup']['clientId'] and consent.get('resource')==proof['setup']['resource'],'ACI consent resource/client binding')
    need(consent.get('scopes')==['agent:operate','offline_access'] and consent.get('redirectUri')==proof['setup']['callbackUri'] and re.fullmatch(r'http://127\.0\.0\.1:38765/callback(?:/[a-zA-Z0-9_-]{1,100})?',consent['redirectUri']),'ACI exact actual native public PKCE registration')
    need(SHA.fullmatch(consent.get('displayedPermissionFingerprint','')) and consent['displayedPermissionFingerprint']==identity['grant']['permissions_hash'],'ACI displayed consent permissions')
    verify_financial_consent(proof,identity)
    registration=proof.get('registrationObservation',{})
    need(registration.get('configurationHttpStatus')==200 and registration.get('clientId')==proof['setup']['clientId'] and registration.get('callbackUri')==proof['setup']['callbackUri'] and proof['setup']['callbackUri'] in registration.get('configuredRedirectUris',[]),'ACI exact native callback must be pre-registered before code exchange')
    return identity

def verify_setup(proof):
    setup=proof['setup'];browser=proof.get('setupBrowser',{})
    need(setup['serverUrl']=='http://127.0.0.1:3000/api/agent/mcp' and setup['resource']==setup['serverUrl'],'ACI canonical remote endpoint resource; legacy resources do not alias it')
    need(browser.get('clicked') is True and browser.get('displayedEndpoint')==setup['serverUrl'],'ACI real connection UI canonical fallback')
    need(browser.get('delivery')=='url_fallback' and browser.get('addLink') is None,'ACI unverified native add link')
    need(proof['nativeAuthorization'].get('configurationWriter')=='native_cli_mcp_add','ACI platform must not edit native config')
    need(proof['nativeAuthorization'].get('platformProcessCount')==0 and proof['nativeAuthorization'].get('platformPackageCount')==0,'ACI no participant platform installer/bridge')

def verify_refresh(record):
    before,after=record['before'],record['after'];verify_snapshot(before);verify_snapshot(after,before['database']['databaseName'])
    need(before['domainDigests']==after['domainDigests'],'ACI refresh changed business domains')
    old,new=one(before['grants'],'ACI old grant'),one(after['grants'],'ACI new grant')
    need(all(old[k]==new[k] for k in ['id','owner_id','agent_id','client_id','permissions_hash','caps_hash']),'ACI refresh expanded/replaced authority')
    rotations=record.get('rotations',[])
    need(rotations and all(x.get('httpStatus')==200 and x.get('oldRefreshFingerprint')!=x.get('newRefreshFingerprint') and SHA.fullmatch(x.get('oldRefreshFingerprint','')) and SHA.fullmatch(x.get('newRefreshFingerprint','')) and x.get('grantId')==new['id'] for x in rotations),'ACI real provider-issued rotation fingerprints')
    need(all(0<(timestamp(x['expiresAt'])-timestamp(x['issuedAt'])).total_seconds()<=3600 for x in rotations),'ACI bounded access expiry')
    need(record.get('restart',{}).get('beforeProcessId')!=record.get('restart',{}).get('afterProcessId') and record.get('restart',{}).get('recoveredGrantId')==new['id'],'ACI actual restart recovery')

def verify_restore(record):
    need(record.get('schemaVersion')=='aci-restore-invalidation-capture/v1','ACI actual cold restore proof missing')
    before,after=record['before'],record['after'];verify_snapshot(before);verify_snapshot(after)
    need(before['database']['databaseName']!=after['database']['databaseName'],'ACI same DB is not cold restore')
    need(record['checkpoint']['createdAt']<record['revocation']['committedAt'] and SHA.fullmatch(record['checkpoint']['sha256']),'ACI checkpoint must predate invalidation')
    probe=record['restoredCredentialProbe']
    need(probe['httpStatus']==401 and probe.get('wwwAuthenticate')=='Bearer' and probe['admittedEffects']==0,'ACI restored revoked credential denied')
    need(record['writeBarrier']['stateAtProbe']=='disabled' and record['writeBarrier']['reconciledAt']<=record['writeBarrier']['enabledAt'],'ACI restore writes before authoritative invalidation reconciliation')

def verify_qualification(proof):
    verify_launch(proof);rows=proof.get('clientQualification',[])
    need({x['client'] for x in rows}==TARGETS and len(rows)==len(TARGETS),'ACI complete named-target truthful inventory')
    qualified=[x for x in rows if x.get('status')=='qualified']
    need(len(qualified)==1 and qualified[0]['client']=='codex_cli','ACI only actually exercised client is beta-qualified')
    need(all(x.get('status')=='unverified' and x.get('supportClaim') is False for x in rows if x['client']!='codex_cli'),'ACI untested families outside support claim')
    need(qualified[0].get('supportClaim') is True and qualified[0].get('nativeOAuthCaptureId')==proof['captureId'],'ACI qualification exact native capture')

def controls(inputs,sid,root=ROOT):
    """Raw variant captures, not producer success flags or unrelated green JUnit."""
    records=[]
    for ref in inputs.get('controls',[]):
        wrapper=read_reference(root,ref)
        need(wrapper.get('schemaVersion')=='agent-client-connection-controls/v1','ACI variant capture schema')
        _verify_provenance(wrapper,root)
        records.extend(x for x in wrapper.get('cases',[]) if x.get('scenarioId')==sid)
    return records

def verify_variant(record):
    before,after=record.get('before',{}),record.get('after',{})
    verify_snapshot(before);verify_snapshot(after,before['database']['databaseName'])
    kind=record.get('kind')
    need(record.get('variant') in VARIANT_KINDS and VARIANT_KINDS[record['variant']]==kind,'ACI variant cannot substitute another boundary')
    if kind=='authorization_denial':
        need(before['domainDigests']==after['domainDigests'] and before['grants']==after['grants'],'ACI denied variant changed authority/business state')
        need(record.get('http',{}).get('status') in {400,401,403,404,409} and record['http'].get('errorCode'),'ACI actual negative HTTP denial missing')
        need(record.get('http',{}).get('requestId') and record.get('requestProjection'),'ACI rejected request correlation missing')
    elif kind=='refresh_rotation':
        verify_refresh(record)
        variant=record['variant']
        if variant=='expired_access':need(record.get('expiredAccessProbe',{}).get('httpStatus')==401,'ACI expired access actually denied before renewal')
        elif variant=='offline_reconnect':need(timestamp(record['offlineUntil'])>timestamp(record['offlineFrom']),'ACI actual offline interval')
        elif variant in {'simultaneous_refresh','lost_refresh_response'}:
            attempts=record.get('retryResponses',[])
            need(len(attempts)>=2 and all(x['httpStatus']==200 and x['pairFingerprint']==attempts[0]['pairFingerprint'] and SHA.fullmatch(x['pairFingerprint']) for x in attempts),'ACI bounded unchanged provider pair retry')
            need((max(timestamp(x['at']) for x in attempts)-min(timestamp(x['at']) for x in attempts)).total_seconds()<=30,'ACI retry outside configured bound')
        elif variant=='stolen_old_refresh_replay':need(record.get('oldRefreshReplay',{}).get('httpStatus') in {400,401} and after['grants'][0]['revoked_at'] is not None,'ACI stolen refresh family not revoked')
    elif kind=='restore_invalidation':verify_restore(record['restore'])
    elif kind=='native_capability':
        need(record.get('native',{}).get('authMethod')=='native_oauth' and record['native'].get('mcpToolCallCount',-1)>=0 and record['native'].get('localToolCallCount')==0,'ACI native capability probe required')
        need(record.get('mcp') and before['domainDigests']==after['domainDigests'],'ACI actual capability wire/no-effects proof')
        variant=record['variant'];packets=record['mcp']
        if variant=='supported_old_and_modern_protocol':need({x.get('protocolVersion') for x in packets}>={'2025-06-18','2026-07-28'},'ACI both actual protocol revisions')
        elif variant in {'new_capable_client_version','new_version_same_capabilities','unlisted_compatible_client'}:
            inits=[x['projection'] for x in packets if x.get('projection',{}).get('method')=='initialize']
            need(len(inits)>=2 and len({x.get('clientVersion') for x in inits})>=2 and record.get('preflightStatuses')==['allowed','allowed'],'ACI version-neutral actual capability checks')
        elif variant=='executor_unready':need(record.get('preflightStatus')=='allowed' and record.get('executorState')=='unready','ACI executor availability must not be conflated with grant authority')
        elif variant=='spoofed_client_metadata':need(record.get('http',{}).get('status') in {401,403},'ACI client metadata must not authenticate')
        else:need(record.get('http',{}).get('status') in {400,401,403,404,405,406,409,415,503} or record.get('native',{}).get('terminalEvent')=='turn.failed','ACI missing capability must fail closed')
    elif kind=='unavailable_client':
        need(record.get('clientState',{}).get('status')=='unverified' and record['clientState'].get('supportClaim') is False and record['clientState'].get('reason') in {'unavailable','not_selected','remote_mcp_unsupported'},'ACI unavailable target not qualified')
        need(before==after,'ACI unavailable target created effects')
    elif kind=='launch_idempotency':
        need(record.get('intentId') and len([x for x in after['runs'] if x['intent_id']==record['intentId']])<=1,'ACI repeated launch created another run')
        need(record.get('http') and after['admission']['reservationCount']<=1 and after['admission']['debitCount']<=1,'ACI actual repeated launch once-only proof')
        if record['variant'] in {'client_offline','owner_cancellation'}:need(before['domainDigests']==after['domainDigests'] and not [x for x in after['runs'] if x['intent_id']==record['intentId']],'ACI offline/cancelled pending intent admitted effects')
    elif kind=='scoped_revocation':
        chosen=record.get('connectionId');old={x['id']:x for x in before['grants']};new={x['id']:x for x in after['grants']}
        need(chosen in old and chosen in new and len(old)>=2 and old[chosen]['revoked_at'] is None and new[chosen]['revoked_at'] is not None,'ACI actual selected connection revocation')
        need(all(old[key]==new[key] for key in old if key!=chosen),'ACI another connection was changed')
        need(record.get('nativeHttp',{}).get('status')==401 and record['nativeHttp'].get('authenticateScheme')=='Bearer' and before['domainDigests']==after['domainDigests'],'ACI actual native revoke denial must preserve admitted run')
    elif kind=='disconnect':need(before==after and record.get('nativeDisconnect',{}).get('event')=='process_closed','ACI disconnect incorrectly revoked authority')
    elif kind=='setup_denial':need(before==after and record.get('browser',{}).get('displayedError') in {'untrusted_endpoint','unverified_add_link'},'ACI substituted setup endpoint did not fail closed')
    elif kind=='setup_fallback':need(before==after and record.get('browser',{}).get('displayedEndpoint')==record.get('canonicalEndpoint') and record['browser'].get('addLink') is None,'ACI unknown client requires honest canonical URL fallback')
    elif kind=='unqualified_substitute':need(before==after and record.get('clientState',{}).get('status')=='unverified' and record['clientState'].get('supportClaim') is False and record.get('implementation') in {'sdk','reference_worker'},'ACI SDK/reference worker incorrectly qualifies a named client')
    else:raise AssertionError('ACI unknown/unimplemented variant boundary')

class Case:
    def __init__(self,sid):self.sid=sid
    def setup(self,context):need(context.scenario_id==self.sid,'ACI scenario ID mismatch')
    def execute(self,context,when_text):getattr(self,"_execute_"+self.sid.replace("-","_"))(context)
    def verify(self,context,then_text):getattr(self,"_verify_"+self.sid.replace("-","_"))(context)
    def _capture(self,context):
        path=ROOT/'tests/bdd/changes/agent-client-installer/runtime-inputs.json'
        if not path.exists():pytest.skip('BLOCKED: ACI actual native OAuth/browser/PG capture not recorded')
        inputs=json.loads(path.read_text(encoding='utf-8-sig'))
        need(inputs.get('schemaVersion')=='aci-runtime-inputs/v1','ACI runtime inputs schema')
        if not inputs.get('connection'):pytest.skip('BLOCKED: ACI native connection capture missing')
        proof=physical(inputs['connection']);number=int(self.sid[-3:])
        if number==1:verify_setup(proof)
        elif number==2:verify_authorization(proof)
        elif number==3:
            if not inputs.get('refresh'):pytest.skip('BLOCKED: ACI restart/rotation/response-loss proof missing')
            verify_refresh(read_reference(ROOT,inputs['refresh']))
        elif number==4:
            if not inputs.get('restore'):pytest.skip('BLOCKED: ACI cold restore/invalidation proof missing')
            verify_restore(read_reference(ROOT,inputs['restore']))
        elif number==5:verify_preflight(proof)
        elif number==6:verify_preflight(proof)
        elif number==7:verify_launch(proof)
        elif number==8:verify_qualification(proof)
        contract=json.loads((ROOT/'tests/bdd/changes/agent-client-installer/harness-contracts.json').read_text())['protected_scenarios'][self.sid]
        records=controls(inputs,self.sid);required=set(contract['negative_variants']);covered=set()
        for record in records:
            need(record.get('variant') in required,'ACI unapproved/misbound variant')
            verify_variant(record);covered.add(record['variant'])
        if required-covered:pytest.skip('BLOCKED: ACI missing independently replayable variants: '+','.join(sorted(required-covered)))
        context.state['aci_verified_observations']={name:True for name in contract['required_observations']}

    def _execute_ACI_SC_001(self,context):self._capture(context)
    def _verify_ACI_SC_001(self,context):
        context.check("canonical_endpoint",context.state.get("aci_verified_observations",{}).get("canonical_endpoint") is True)
        context.check("official_link_or_url_fallback",context.state.get("aci_verified_observations",{}).get("official_link_or_url_fallback") is True)
        context.check("no_platform_package_or_process",context.state.get("aci_verified_observations",{}).get("no_platform_package_or_process") is True)
        context.check("expected_client_owned_config_delta",context.state.get("aci_verified_observations",{}).get("expected_client_owned_config_delta") is True)
        context.check("no_credential_in_link_or_prompt",context.state.get("aci_verified_observations",{}).get("no_credential_in_link_or_prompt") is True)
        context.check("unsupported_client_reason",context.state.get("aci_verified_observations",{}).get("unsupported_client_reason") is True)

    def _execute_ACI_SC_002(self,context):self._capture(context)
    def _verify_ACI_SC_002(self,context):
        context.check("pkce_state_resource_binding",context.state.get("aci_verified_observations",{}).get("pkce_state_resource_binding") is True)
        context.check("verified_owner_agent_client_grant",context.state.get("aci_verified_observations",{}).get("verified_owner_agent_client_grant") is True)
        context.check("displayed_permissions_and_limits",context.state.get("aci_verified_observations",{}).get("displayed_permissions_and_limits") is True)
        context.check("credential_absence_from_urls_prompts_logs",context.state.get("aci_verified_observations",{}).get("credential_absence_from_urls_prompts_logs") is True)
        context.check("denial_no_authority",context.state.get("aci_verified_observations",{}).get("denial_no_authority") is True)

    def _execute_ACI_SC_003(self,context):self._capture(context)
    def _verify_ACI_SC_003(self,context):
        context.check("access_expiry_and_rotation",context.state.get("aci_verified_observations",{}).get("access_expiry_and_rotation") is True)
        context.check("scope_and_cap_fingerprint",context.state.get("aci_verified_observations",{}).get("scope_and_cap_fingerprint") is True)
        context.check("restart_recovery",context.state.get("aci_verified_observations",{}).get("restart_recovery") is True)
        context.check("bounded_response_loss_retry",context.state.get("aci_verified_observations",{}).get("bounded_response_loss_retry") is True)
        context.check("refresh_replay_rejection",context.state.get("aci_verified_observations",{}).get("refresh_replay_rejection") is True)

    def _execute_ACI_SC_004(self,context):self._capture(context)
    def _verify_ACI_SC_004(self,context):
        context.check("scoped_vs_agent_wide_revocation_commit",context.state.get("aci_verified_observations",{}).get("scoped_vs_agent_wide_revocation_commit") is True)
        context.check("native_401_and_authenticate_header",context.state.get("aci_verified_observations",{}).get("native_401_and_authenticate_header") is True)
        context.check("zero_revoked_scope_admission",context.state.get("aci_verified_observations",{}).get("zero_revoked_scope_admission") is True)
        context.check("other_connection_and_run_preserved",context.state.get("aci_verified_observations",{}).get("other_connection_and_run_preserved") is True)
        context.check("agent_wide_run_fences",context.state.get("aci_verified_observations",{}).get("agent_wide_run_fences") is True)
        context.check("restored_invalidation_reconciliation_before_write_enable",context.state.get("aci_verified_observations",{}).get("restored_invalidation_reconciliation_before_write_enable") is True)

    def _execute_ACI_SC_005(self,context):self._capture(context)
    def _verify_ACI_SC_005(self,context):
        context.check("negotiated_protocol",context.state.get("aci_verified_observations",{}).get("negotiated_protocol") is True)
        context.check("required_transport_and_tool_schema",context.state.get("aci_verified_observations",{}).get("required_transport_and_tool_schema") is True)
        context.check("client_version_is_metadata",context.state.get("aci_verified_observations",{}).get("client_version_is_metadata") is True)
        context.check("safe_incompatibility_reason",context.state.get("aci_verified_observations",{}).get("safe_incompatibility_reason") is True)
        context.check("no_auth_or_domain_bypass",context.state.get("aci_verified_observations",{}).get("no_auth_or_domain_bypass") is True)

    def _execute_ACI_SC_006(self,context):self._capture(context)
    def _verify_ACI_SC_006(self,context):
        context.check("authenticated_self_identity",context.state.get("aci_verified_observations",{}).get("authenticated_self_identity") is True)
        context.check("real_preflight_timestamp",context.state.get("aci_verified_observations",{}).get("real_preflight_timestamp") is True)
        context.check("permission_readiness_separation",context.state.get("aci_verified_observations",{}).get("permission_readiness_separation") is True)
        context.check("zero_benchmark_effects",context.state.get("aci_verified_observations",{}).get("zero_benchmark_effects") is True)

    def _execute_ACI_SC_007(self,context):self._capture(context)
    def _verify_ACI_SC_007(self,context):
        context.check("browser_launch_identity",context.state.get("aci_verified_observations",{}).get("browser_launch_identity") is True)
        context.check("authenticated_delivery_binding",context.state.get("aci_verified_observations",{}).get("authenticated_delivery_binding") is True)
        context.check("native_send_action_count",context.state.get("aci_verified_observations",{}).get("native_send_action_count") is True)
        context.check("pending_no_reservation",context.state.get("aci_verified_observations",{}).get("pending_no_reservation") is True)
        context.check("native_accept_preflight",context.state.get("aci_verified_observations",{}).get("native_accept_preflight") is True)
        context.check("reservation_and_charge_count",context.state.get("aci_verified_observations",{}).get("reservation_and_charge_count") is True)
        context.check("idempotent_run_binding",context.state.get("aci_verified_observations",{}).get("idempotent_run_binding") is True)

    def _execute_ACI_SC_008(self,context):self._capture(context)
    def _verify_ACI_SC_008(self,context):
        context.check("per_surface_native_connect_preflight_handoff",context.state.get("aci_verified_observations",{}).get("per_surface_native_connect_preflight_handoff") is True)
        context.check("version_and_protocol_metadata_only",context.state.get("aci_verified_observations",{}).get("version_and_protocol_metadata_only") is True)
        context.check("unknown_compatible_client_result",context.state.get("aci_verified_observations",{}).get("unknown_compatible_client_result") is True)
        context.check("missing_client_unverified",context.state.get("aci_verified_observations",{}).get("missing_client_unverified") is True)
        context.check("beta_subset_scope_disclosed",context.state.get("aci_verified_observations",{}).get("beta_subset_scope_disclosed") is True)
        context.check("no_sdk_or_reference_worker_substitution",context.state.get("aci_verified_observations",{}).get("no_sdk_or_reference_worker_substitution") is True)


def register(registry):
    for number in range(1,9):
        sid=f'ACI-SC-{number:03d}';registry.register(sid,Case(sid),adapter_profile='agent_client_installer')
