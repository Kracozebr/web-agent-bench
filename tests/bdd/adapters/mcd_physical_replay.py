"""Read-only MCD replay. No network, database connection or application classifiers.

Every assertion derives from hash-bound observer rows, transport responses, native
events or browser captures. Producer observation flags are deliberately unused.
"""
from datetime import datetime
import hashlib
import json
import re
from pathlib import PurePosixPath
from tests.bdd.adapters.ber_recovery_replay import read_reference

SHA = re.compile(r"^[a-f0-9]{64}$")
BUSINESS = {"runs", "tasks", "actions", "receipts", "evaluations", "ledger", "bonuses"}


def need(value, message):
    if not value: raise AssertionError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(value): return hashlib.sha256(canonical(value)).hexdigest()


def rows(document, table):
    need(document.get("source") == "postgresql_observer", "MCD rows require independent PostgreSQL observer")
    result = document.get(table)
    need(isinstance(result, list), "MCD missing observer table " + table)
    return result


def stable_business(before, after):
    need(before.get("source") == after.get("source") == "postgresql_observer", "MCD business observer missing")
    a, b = before.get("domainHashes", {}), after.get("domainHashes", {})
    need(set(a) == set(b) == BUSINESS and all(SHA.fullmatch(v) for v in a.values()), "MCD business inventory incomplete")
    need(a == b, "MCD diagnostic operation changed business history")


def one(values, message):
    need(len(values) == 1, message)
    return values[0]


def load_variants(capture, root, required):
    declared = capture.get("variants")
    need(isinstance(declared, list), "MCD variant boundaries missing")
    names = [item.get("name") for item in declared]
    need(len(set(names)) == len(names) and set(names) == set(required), "MCD exact approved variants missing or duplicated")
    result = {}
    for item in declared:
        data = {key: read_reference(root, item[key + "Ref"]) for key in
                ("request", "response", "beforeBusiness", "afterBusiness", "beforeDiagnostic", "afterDiagnostic")}
        stable_business(data["beforeBusiness"], data["afterBusiness"])
        for phase in ("beforeDiagnostic", "afterDiagnostic"):
            for table in ("cases", "events", "reports", "batches", "audits"):
                rows(data[phase], table)
        result[item["name"]] = data
    return result


def _time(event):
    try:
        start = datetime.fromisoformat(event["startedAt"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(event["completedAt"].replace("Z", "+00:00"))
        duration = event["durationMs"]
        need(start.tzinfo and end.tzinfo and end >= start, "MCD invalid source-local time")
        need(type(duration) is int and 0 <= duration <= 86_400_000, "MCD invalid source-local duration")
    except (KeyError, ValueError, TypeError) as error:
        raise AssertionError("MCD source-local timing missing") from error


def replay_001(raw, variants, root):
    stages = {"malformed_json_rpc":"ingress", "sdk_rejected_fields":"sdk_validation", "expired_or_revoked_auth":"authentication",
              "handler_failure":"handler", "dispatch_failure":"dispatch", "duplicate_operation":"admission"}
    for name, stage in stages.items():
        v = variants[name]; response = v["response"]
        need(response.get("httpStatus", 0) >= 400 or response.get("rpcErrorCode") is not None or response.get("toolError") is True, "MCD failure response missing")
        event = one([e for e in rows(v["afterDiagnostic"], "events") if e.get("traceId") == response.get("traceId") and e.get("outcome")=="error" and e.get("eventId") not in {e.get("eventId") for e in rows(v["beforeDiagnostic"], "events")}], "MCD exact fresh correlated failure event missing")
        need(event.get("source") == "server" and event.get("stage") == stage and event.get("errorCode") == response.get("errorCode") and event.get("outcome") == "error", "MCD stage/error mismatch")
        _time(event)
        if v["request"].get("binding"):
            case = one([c for c in rows(v["afterDiagnostic"], "cases") if c.get("caseId") == event.get("caseId")], "MCD validated case missing")
            need(all(case.get(k) == value for k, value in v["request"]["binding"].items()), "MCD unvalidated diagnostic link")
        else: need(event.get("caseId") is None, "MCD anonymous event fabricated a case binding")
    protocol = raw["protocol"]
    before, after = (read_reference(root, protocol[key]) for key in ("beforeRestartRef", "afterRestartRef"))
    for table in ("cases", "events", "reports", "batches"):
        need(rows(before, table) == rows(after, table), "MCD restart lost persisted " + table)
    need(rows(before,"events"),"MCD restart control retained no failure events")
    return {name:True for name in ("stage_and_error_identity","source_local_timings","validated_links","survives_restart")}


def _canonical_identity(document):
    cases = rows(document,"cases"); keys = set()
    for case in cases:
        key = (case["ownerId"], case.get("intentId") or case["diagnosticSessionId"], case["kind"])
        need(key not in keys, "MCD duplicate canonical case"); keys.add(key)
    reports = rows(document,"reports"); report_keys = set()
    for report in reports:
        key = (report["ownerId"], report["caseId"], report["kind"])
        need(key not in report_keys, "MCD duplicate canonical report"); report_keys.add(key)
        one([c for c in cases if c["caseId"] == report["caseId"] and c["ownerId"] == report["ownerId"]], "MCD report not linked to owned case")
    batches = rows(document,"batches"); batch_keys=set()
    for batch in batches:
        key=(batch["caseId"],batch["segmentId"],batch["batchSequence"])
        need(key not in batch_keys and SHA.fullmatch(batch["payloadHash"]), "MCD batch identity collision"); batch_keys.add(key)


def _watermark(document, receipt):
    need(receipt.get("diagnosticsSynced") is True, "MCD final delivery has no synchronized receipt")
    batches = sorted([b for b in rows(document,"batches") if b["caseId"] == receipt["caseId"] and b["segmentId"] == receipt["segmentId"]], key=lambda b:b["batchSequence"])
    highest=-1; payload_hash=None
    for batch in batches:
        if batch["batchSequence"] != highest+1: break
        highest=batch["batchSequence"]; payload_hash=batch["payloadHash"]
    need(receipt.get("highestContiguousSequence")==highest and receipt.get("highestContiguousHash")==payload_hash, "MCD receipt watermark differs from durable batches")
    report=one([r for r in rows(document,"reports") if r["caseId"]==receipt["caseId"]], "MCD receipt report absent")
    need(receipt.get("reportId")==report["id"] and receipt.get("reportCreated") is True, "MCD report-created receipt mismatch")
    if receipt.get("diagnosticsSynced"):
        need(batches and len(batches)==highest+1 and receipt.get("completion") in ("complete","partial") and batches[-1].get("completion")==receipt.get("completion"), "MCD synchronized receipt hides a segment gap or missing final declaration")
        if receipt["completion"]=="partial":
            case=one([c for c in rows(document,"cases") if c["caseId"]==receipt["caseId"]],"MCD partial receipt case absent")
            need(case.get("captureState") in ("partial","partial_quota"),"MCD known partial synchronized receipt claimed complete capture")


def replay_002(raw, variants, root):
    native=raw["native"]
    need(native.get("implementation")=="native_codex_cli" and native.get("clientVersion") in ("0.165.0","0.166.0"), "MCD qualified native CLI missing")
    calls=native.get("calls",[])
    need(calls and all(c.get("server")=="w3bench_user" and c.get("type") in ("mcp_tool_call","mcp_tool_call_end") for c in calls), "MCD native tool events missing")
    need(native.get("localToolCalls")==[], "MCD native boundary used local solution tools")
    need(any(c.get("outcome")=="error" for c in calls), "MCD native error not observed")
    oauth=raw["oauth"]
    grant=oauth["grant"]
    need(grant.get("clientId")=="w3bench-diagnostics-helper-v1" and grant.get("scope")=="diagnostics:write offline_access" and grant.get("resource", "").endswith("/api/diagnostics"), "MCD helper grant audience/scope mismatch")
    need(oauth.get("authorizationRequest",{}).get("codeChallengeMethod")=="S256" and oauth.get("consent",{}).get("action")=="click" and oauth["consent"].get("approved") is True, "MCD separate PKCE browser consent absent")
    for name in ("missing_consent_wrong_scope_audience","helper_denied_task_admin_diagnostic_read","revoked_auth"):
        v=variants[name]
        responses=v["response"].get("attempts",[v["response"]])
        need(responses and all(r.get("httpStatus") in (401,403,404) for r in responses), "MCD helper capability boundary not denied")
        need(rows(v["beforeDiagnostic"],"reports")==rows(v["afterDiagnostic"],"reports"), "MCD denied helper created a report")
        need(v["response"].get("outboxState")=="pending_auth", "MCD denied helper lost pending authorization state")
    denied_helper_capabilities(variants["missing_consent_wrong_scope_audience"],root,grant)
    carrier=raw["carrier"]
    valid_ids={c["caseId"] for c in rows(variants["client_only_validation"]["afterDiagnostic"],"cases")}
    need(carrier.get("nativeCaseId") in valid_ids and carrier.get("helperCaseId")==carrier.get("nativeCaseId"), "MCD native/helper canonical carrier mismatch")
    need(carrier.get("serverTraceId") and carrier["serverTraceId"] in {c.get("traceId") for c in calls}, "MCD native server trace carrier missing")
    foreign=variants["foreign_case_header_or_hidden_trace_carrier"]["response"]
    need(foreign.get("httpStatus") in (403,404) and foreign.get("captureState") in ("partial","unavailable"), "MCD forged carrier was trusted or missing carrier hidden")
    for name,v in variants.items():
        _canonical_identity(v["afterDiagnostic"])
        if name not in {"missing_consent_wrong_scope_audience","helper_denied_task_admin_diagnostic_read","revoked_auth","foreign_case_header_or_hidden_trace_carrier","same_key_different_payload","failed_report_retry_no_recursion"}:
            _watermark(v["afterDiagnostic"],v["response"]["receipt"])
    crash=variants["crash_with_active_known_run"]
    crash_native=read_reference(root,crash["response"]["nativeRef"]) if "nativeRef" in crash["response"] else native
    crash_outbox=read_reference(root,crash["response"]["clientOutboxRef"]) if "clientOutboxRef" in crash["response"] else raw["clientOutbox"]
    active_crash_observation(crash_native,crash_outbox,crash)
    conflict=variants["same_key_different_payload"]
    need(conflict["response"].get("httpStatus")==409 and rows(conflict["beforeDiagnostic"],"batches")==rows(conflict["afterDiagnostic"],"batches"), "MCD payload conflict changed saved batch")
    retry=variants["failed_report_retry_no_recursion"]
    need(len(rows(retry["afterDiagnostic"],"reports"))<=len(rows(retry["beforeDiagnostic"],"reports"))+1, "MCD report failure recursively generated reports")
    native_delivery_boundaries(variants, root)
    delivery=raw["delivery"]
    need(delivery.get("mechanism")=="deterministic_helper" and delivery.get("trigger") in ("native_exit","native_error","resume"), "MCD report depends on model discretion")
    browser=delivery["adminBrowser"]
    from urllib.parse import urlsplit
    need(browser.get("action")=="click" and urlsplit(browser.get("url","")).path=="/admin/diagnostics" and browser.get("caseId")==carrier["nativeCaseId"] and browser.get("reportId"), "MCD admin browser report not demonstrated")
    one([r for r in rows(variants["client_only_validation"]["afterDiagnostic"],"reports") if r["caseId"]==browser["caseId"] and r["id"]==browser["reportId"]],"MCD browser report differs from canonical PostgreSQL report")
    return {name:True for name in ("native_call_events","helper_oauth_scope_and_revocation","native_case_trace_carrier","canonical_case_identity","automatic_report_and_watermark_receipt","admin_report_visible","deduplicated_delivery","blocked_delivery_zero_report_writes")}


def _observed_time(value):
    try:
        result=datetime.fromisoformat(value.replace("Z","+00:00"))
        need(result.tzinfo is not None,"MCD observer timestamp has no timezone")
        return result
    except (AttributeError,TypeError,ValueError) as error:
        raise AssertionError("MCD observer timestamp missing") from error


def denied_helper_capabilities(variant,root,grant):
    """Distinct real requests, not three identical denial labels."""
    proof=read_reference(root,variant["response"]["evidenceRef"])
    oauth_source=(root/"packages/owner-identity/src/mcp-diagnostics-oauth.ts").read_text(encoding="utf-8-sig")
    route_source=(root/"packages/owner-identity/src/mcp-diagnostics-routes.ts").read_text(encoding="utf-8-sig")
    oauth_code=one(re.findall(r"new HttpError\(400,'([^']+)','Diagnostic OAuth request is invalid'",oauth_source),"MCD authorization source guard missing")
    missing_code=one(re.findall(r"new HttpError\(401, '([^']+)', 'A diagnostic helper authorization is required'",route_source),"MCD missing-consent source guard missing")
    resource=grant["resource"]
    for name in ("missing_consent","wrong_scope","wrong_audience"):
        control=proof[name];request=read_reference(root,control["requestRef"]);response=read_reference(root,control["responseRef"])
        need(request.get("source")=="http_transport" and request.get("origin")==resource.removesuffix("/api/diagnostics"),"MCD capability request source/origin missing")
        if name=="missing_consent":
            need(request.get("method")=="POST" and request.get("path")=="/api/diagnostics/cases" and request.get("headers")=={"content-type":"application/json"},"MCD missing consent request included authorization or wrong boundary")
            need(response.get("httpStatus")==401 and response.get("errorCode")==missing_code,"MCD missing consent actual response mismatch")
        else:
            q=request.get("query",{})
            expected={"client_id":"w3bench-diagnostics-helper-v1","redirect_uri":"http://127.0.0.1:38766/diagnostics/callback","response_type":"code","code_challenge_method":"S256","code_challenge":"A"*43,"state":"mcd_diagnostic_negative_probe_20261102","scope":grant["scope"],"resource":resource}
            expected["scope" if name=="wrong_scope" else "resource"]="diagnostics:read" if name=="wrong_scope" else resource.removesuffix("/api/diagnostics")+"/api/agent/mcp"
            need(request.get("method")=="GET" and request.get("path")=="/api/diagnostics/oauth/authorize" and q==expected,"MCD capability probe did not change exactly scope or audience")
            need(response.get("httpStatus")==400 and response.get("errorCode")==oauth_code,"MCD actual authorization scope/audience rejection missing")


def _retained_rows(before, after, table, keys):
    original={tuple(row.get(k) for k in keys):row for row in rows(before,table)}
    current={tuple(row.get(k) for k in keys):row for row in rows(after,table)}
    need(len(original)==len(rows(before,table)) and len(current)==len(rows(after,table)),"MCD duplicate retained row identity")
    need(all(current.get(key)==row for key,row in original.items()),"MCD late delivery mutated or lost original "+table)


def native_delivery_boundaries(variants,root):
    """Recompute mandatory SC002 fault/recovery facts, never variant-name flags."""
    refusal=variants["refused_endpoint_and_recovery"]["response"]
    need(any(a.get("socketRefusal")=={"transport":"tcp","endpoint":"loopback_reserved_then_closed","errorCode":"CONNECTION_REFUSED","credentialBytesSent":0} for a in refusal.get("attempts",[])),"MCD actual refused endpoint missing")
    lost=variants["lost_report_response"]
    attempts=lost["response"].get("attempts",[])
    dropped=[a for a in attempts if a.get("controlledResponseLoss") is True]
    need(len(dropped)==1 and dropped[0].get("httpStatus")==200 and dropped[0].get("receipt",{}).get("reportCreated") is True,"MCD actual successful report response was not lost")
    receipt=lost["response"]["receipt"]
    need(any(a.get("httpStatus")==200 and not a.get("controlledResponseLoss") and a.get("receipt",{}).get("highestContiguousHash")==receipt["highestContiguousHash"] for a in attempts),"MCD lost report reply was not retried with original hash")
    need(dropped[0]["receipt"].get("reportId")==receipt["reportId"],"MCD report response loss created another report")
    admission=variants["lost_admission_response"]["response"]
    transport=read_reference(root,admission["transportRef"])
    need(transport.get("boundary")=="actual_origin_preserving_loopback_proxy" and transport.get("observationOverflowCount")==0,"MCD admission transport incomplete")
    observations=transport.get("observations",[])
    drop=one([o for o in observations if o.get("kind")=="admission_response_dropped"],"MCD verified admission reply was not dropped once")
    replay=one([o for o in observations if o.get("kind")=="admission_retry_response" and o.get("replayed") is True],"MCD identical admission was not replayed")
    for key in ("runId","taskIndex","operationIdHash","actionId"):
        need(drop.get(key) is not None and drop[key]==replay.get(key),"MCD admission retry changed operation or action")
    need(SHA.fullmatch(drop["operationIdHash"]) and drop.get("httpStatus")==replay.get("httpStatus")==200,"MCD admission replay response missing")
    need(_observed_time(replay["enteredAt"])>=_observed_time(drop["droppedAt"]),"MCD admission retry predates response loss")
    native=read_reference(root,admission["nativeRef"])
    need(native.get("localToolCalls")==[] and any(c.get("tool")=="runs.task_action" and c.get("outcome")=="success" for c in native.get("calls",[])),"MCD admission replay not observed by native client")
    retry=variants["failed_report_retry_no_recursion"]
    response=retry["response"]; attempts=response.get("attempts",[])
    need(len(attempts)>=2,"MCD report failure retry missing")
    first=attempts[0]
    if not (first.get("httpStatus")==429 and first.get("errorCode")=="REPORT_RATE_LIMITED"):
        need(first.get("httpStatus")==200 and first.get("receipt",{}).get("reportCreated") is False and first["receipt"].get("diagnosticsSynced") is False,"MCD first report delivery did not fail")
        rate=read_reference(root,response["rateFailureRef"])
        need(rate.get("source")=="postgresql_observer" and rate.get("observer",{}).get("readOnly") is True,"MCD report rate cause lacks independent observation")
        policy=(root/"packages/owner-identity/src/report-service.ts").read_text(encoding="utf-8-sig")
        limits={key:int(one(re.findall(r"const "+name+r"\s*=\s*(\d+)",policy),"MCD pinned report rate policy absent")) for key,name in (("minute","REPORTS_PER_MINUTE_PER_PRINCIPAL"),("hour","REPORTS_PER_HOUR_PER_OWNER"))}
        need(rate.get("limits")==limits,"MCD report rate cause changed pinned limits")
        need(any(r.get("scope") in ("principal_minute","owner_hour") and int(r.get("windowStart",-1))==int(r.get("observedSeconds",-2))//(60 if r["scope"]=="principal_minute" else 3600)*(60 if r["scope"]=="principal_minute" else 3600) and int(r.get("requestCount",-1))>=rate.get("limits",{}).get("minute" if r["scope"]=="principal_minute" else "hour",float("inf")) for r in rate.get("rows",[])),"MCD report rate limit was not exhausted")
    need(response.get("actualWaitMs",-1)>=max(1000,first.get("retryAfterMs",0)),"MCD report retry did not respect observed wait")
    _watermark(retry["afterDiagnostic"],response["receipt"])
    need(response.get("identicalPayloadHash")==response["receipt"]["highestContiguousHash"],"MCD report retry replaced original batch")
    need(any(a.get("httpStatus")==200 and a.get("receipt",{}).get("reportCreated") is True for a in attempts[1:]),"MCD report retry has no successful HTTP receipt")
    owner_helper_race(variants["owner_import_races_helper"],root)
    late_native_binding(variants["late_run_binding_and_batches"],root)
    native_restart_restore(variants["restart_and_restore"],root)


def owner_helper_race(variant,root):
    proof=read_reference(root,variant["response"]["evidenceRef"])
    attempts=proof.get("attempts",[])
    need(len(attempts)==2 and {a.get("actor") for a in attempts}=={"owner","helper"},"MCD owner/helper race lacks both actors")
    first,second=attempts
    need(max(_observed_time(a["startedAt"]) for a in attempts)<min(_observed_time(a["completedAt"]) for a in attempts),"MCD owner/helper requests did not overlap")
    for key in ("caseId","segmentId","batchSequence","payloadHash"):
        need(first["request"].get(key) is not None and first["request"][key]==second["request"].get(key),"MCD owner/helper race changed original batch identity")
    for a in attempts:
        need(a["response"].get("httpStatus")==200,"MCD owner/helper race request failed")
        _watermark(variant["afterDiagnostic"],a["response"]["receipt"])
        need(a["response"]["receipt"]["caseId"]==a["request"]["caseId"] and a["response"]["receipt"]["highestContiguousHash"]==a["request"]["payloadHash"],"MCD race response not bound to original batch")
    need(first["response"]["receipt"]["reportId"]==second["response"]["receipt"]["reportId"],"MCD owner/helper race created two reports")


def late_native_binding(variant,root):
    proof=read_reference(root,variant["response"]["evidenceRef"])
    before,after,append_before,append_after=[read_reference(root,proof[k]) for k in ("beforeBindingRef","afterBindingRef","beforeAppendRef","afterAppendRef")]
    case_id=variant["response"]["receipt"]["caseId"]
    old=one([c for c in rows(before,"cases") if c["caseId"]==case_id],"MCD pre-run case absent")
    bound=one([c for c in rows(after,"cases") if c["caseId"]==case_id],"MCD bound case absent")
    need(old.get("intentId") and old.get("runId") is None and bound.get("intentId")==old["intentId"] and bound.get("runId"),"MCD late intent/run join was not observed")
    for table,keys in (("reports",("id",)),("batches",("caseId","segmentId","batchSequence")),("events",("eventId",)),("audits",("reportId","revision","eventType"))):
        _retained_rows(before,after,table,keys);_retained_rows(append_before,append_after,table,keys)
    need(rows(before,"reports") and rows(after,"reports")==rows(before,"reports") and rows(append_before,"reports")==rows(append_after,"reports"),"MCD late binding/appends duplicated or rewrote report")
    need(len(rows(append_after,"batches"))>len(rows(append_before,"batches")) and len(rows(append_after,"events"))>len(rows(append_before,"events")),"MCD late evidence did not append new keys")
    _watermark(append_after,variant["response"]["receipt"])


def native_restart_restore(variant,root):
    proof=read_reference(root,variant["response"]["evidenceRef"])
    locals_=[read_reference(root,proof[k]) for k in ("beforeOutboxRef","afterOutboxRef","restoredOutboxRef")]
    original=locals_[0]
    for document in locals_:
        need(document.get("source")=="sqlite_observer" and document.get("observer",{}).get("readOnly") is True,"MCD restart/restore lacks independent SQLite rows")
        need(all(document.get("case",{}).get(k)==original.get("case",{}).get(k) and document["case"][k] for k in ("localCaseId","caseId","diagnosticSessionId","reportId")),"MCD restart/restore changed canonical outbox identity")
        need(document.get("batches")==original.get("batches") and original.get("batches"),"MCD restart/restore lost or re-keyed original batches")
    server=[read_reference(root,proof[k]) for k in ("beforeDiagnosticRef","afterDiagnosticRef","restoredDiagnosticRef")]
    for document in server[1:]:
        for table in ("cases","events","reports","batches","audits"):
            need(rows(document,table)==rows(server[0],table),"MCD restart/restore lost diagnostic "+table)
    _watermark(server[-1],variant["response"]["receipt"])



def active_crash_observation(native,client_outbox,variant):
    """Cross-check the client's safe durable observation; never grant it score authority."""
    observation=client_outbox.get("runObservation",{})
    need(client_outbox.get("source")=="sqlite_observer" and client_outbox.get("observer",{}).get("readOnly") is True,"MCD active crash lacks independent client SQLite observation")
    need(observation.get("status") in ("queued","preparing","running","cancellation_requested","unknown") and observation.get("terminal") is not True and (observation.get("status")!="unknown" or observation.get("terminal") is False),"MCD active crash last observation was not nonterminal")
    call=one([c for c in native.get("calls",[]) if c.get("callIdHash")==observation.get("sourceCallIdHash") and c.get("tool")==observation.get("sourceTool") and c.get("outcome")=="success"],"MCD active crash observation has no matching actual native run read")
    need(call.get("tool") in ("runs.accept_launch_intent","runs.current_task"),"MCD crash observation source is not a run read")
    observed=observation.get("observedAt","")
    need(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z",observed),"MCD crash observation time missing")
    pair={"clientRunStatus":observation["status"],"clientRunObservedAt":observed}
    need(native.get("lastRunObservation")==pair,"MCD native and durable last observations differ")
    cases=rows(variant["afterDiagnostic"],"cases")
    case=one([c for c in cases if c.get("intentId")==native.get("selection",{}).get("intentId") and c.get("runId")==observation.get("runId")],"MCD crash run observation not bound to canonical intent/run")
    errors=[e for e in rows(variant["afterDiagnostic"],"events") if e.get("caseId")==case["caseId"] and e.get("source")=="client" and e.get("stage")=="client_runtime" and e.get("outcome")=="error" and all(e.get(k)==v for k,v in pair.items())]
    need(errors,"MCD active crash lost last client status/time from durable report")
    for event in errors:
        _time(event)
        need(event["completedAt"]>=observed,"MCD crash runtime event predates its alleged last observation")
        need(event.get("responsibility")=="unknown","MCD client observation fabricated verified crash responsibility")
    return pair


def classify(facts):
    """Independent normative evidence matrix; deliberately not the app classifier."""
    if not facts.get("independentlyVerified") or not facts.get("evidenceIds") or facts.get("ambiguousTransport"): return "unknown"
    choices=[]
    if all(facts.get(k) is True for k in ("serverValidationRejected","compatibilityVerified","schemaCompatible","violationMatchesPins")): choices.append("client_contract")
    if facts.get("compatibilityVerified") and facts.get("issuedOperationUnrepresentable"): choices.append("platform_contract")
    if facts.get("clientExceptionReproduced") and facts.get("matchingValidServerResponse") and not facts.get("serverFailure"): choices.append("client_runtime")
    if facts.get("serverFailure") and facts.get("dependencyCauseExcluded"): choices.append("platform_runtime")
    if facts.get("dependencyFailure") and facts.get("competingCausesExcluded"): choices.append("external_dependency")
    if facts.get("policyMatched"): choices.append("expected_policy_denial")
    return choices[0] if len(choices)==1 and not facts.get("conflicting") else "unknown"


def _accepts(schema, value):
    """Bounded JSON Schema subset used by synthetic contract boundary probes.

    Fail on unsupported validation keywords rather than silently accepting an
    operation whose complete issued contract this reader cannot interpret.
    """
    allowed={"type","properties","required","additionalProperties","enum","const","format","pattern","minLength","maxLength","minimum","maximum","items","minItems","maxItems","anyOf","oneOf","description","title","$schema","default"}
    need(isinstance(schema,dict) and set(schema)<=allowed,"MCD issued schema requires unsupported replay keyword")
    if "anyOf" in schema and not any(_accepts(s,value) for s in schema["anyOf"]): return False
    if "oneOf" in schema and sum(_accepts(s,value) for s in schema["oneOf"])!=1: return False
    kind=schema.get("type")
    if isinstance(kind,list): return any(_accepts({**schema,"type":k},value) for k in kind)
    actual={"object":isinstance(value,dict),"array":isinstance(value,list),"string":isinstance(value,str),"integer":type(value) is int,"number":type(value) in (int,float),"boolean":type(value) is bool,"null":value is None}
    if kind is not None:
        need(kind in actual,"MCD unsupported issued schema type")
        if not actual[kind]: return False
    if "enum" in schema and value not in schema["enum"] or "const" in schema and value!=schema["const"]: return False
    if isinstance(value,dict):
        if any(k not in value for k in schema.get("required",[])): return False
        properties=schema.get("properties",{})
        if schema.get("additionalProperties") is False and set(value)-set(properties): return False
        for k,v in value.items():
            sub=properties.get(k,schema.get("additionalProperties"))
            if isinstance(sub,dict) and not _accepts(sub,v): return False
    if isinstance(value,str):
        if not schema.get("minLength",0)<=len(value)<=schema.get("maxLength",2**31): return False
        if "pattern" in schema and not re.search(schema["pattern"],value): return False
        if "format" in schema:
            need(schema["format"] in ("uuid","date-time"),"MCD unsupported issued schema format")
            if schema["format"]=="uuid" and not re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}",value): return False
            if schema["format"]=="date-time":
                try: datetime.fromisoformat(value.replace("Z","+00:00"))
                except ValueError: return False
    if type(value) in (int,float) and not schema.get("minimum",float("-inf"))<=value<=schema.get("maximum",float("inf")): return False
    if isinstance(value,list):
        if not schema.get("minItems",0)<=len(value)<=schema.get("maxItems",2**31): return False
        if "items" in schema and not all(_accepts(schema["items"],item) for item in value): return False
    return True


def _source_envelope_schema(source):
    """Independently parse only the pinned strict finite Zod vocabulary in use.

    No application imports/classifier calls. Unsupported source changes require
    reader review instead of trusting a producer-exported schema or byte count.
    """
    def enum(name):
        match=re.search(r"(?:export )?const "+name+r"\s*=\s*(\[[^\n]+?\])\s+as const",source)
        need(match,"MCD pinned registry missing: "+name)
        return json.loads(match.group(1).replace("'",'"'))
    body=source.split("diagnosticEnvelopeSchema=z.object({",1)
    need(len(body)==2 and "}).strict().superRefine" in body[1],"MCD envelope strict schema source shape changed")
    body=body[1].split("}).strict().superRefine",1)[0]
    fields=list(re.finditer(r"(?:^|,)\s*(\w+):",body))
    need(fields,"MCD finite schema fields missing")
    props={}
    for index,match in enumerate(fields):
        name=match.group(1);expression=body[match.end():fields[index+1].start() if index+1<len(fields) else len(body)].strip()
        if expression.startswith("z.array(z.enum("):
            registry=re.search(r"z\.enum\((\w+)\)",expression);maximum=re.search(r"\.max\((\d+)\)",expression)
            need(registry and maximum,"MCD finite array source bound missing")
            spec={"type":"array","items":{"type":"string","enum":enum(registry.group(1))},"maxItems":int(maximum.group(1))}
        elif expression.startswith("z.enum("):
            argument=expression[len("z.enum("):].split(")",1)[0]
            values=json.loads(argument.replace("'",'"')) if argument.startswith("[") else enum(argument)
            spec={"type":"string","enum":values}
        elif expression.startswith("hash."):
            need("const hash=z.string().regex(/^[a-f0-9]{64}$/)" in source,"MCD pinned hash bound changed")
            spec={"type":"string","pattern":"^[a-f0-9]{64}$"}
        elif expression.startswith("z.string().uuid()"):
            spec={"type":"string","format":"uuid"}
        elif expression.startswith("z.string().datetime().length(24)"):
            spec={"type":"string","format":"date-time","minLength":24,"maxLength":24}
        elif expression.startswith("z.number().int()"):
            minimum=re.search(r"\.min\(([-\d_]+)\)",expression);maximum=re.search(r"\.max\(([-\d_]+)\)",expression)
            need(minimum and maximum,"MCD numeric finite bound missing")
            spec={"type":"integer","minimum":int(minimum.group(1).replace("_","")),"maximum":int(maximum.group(1).replace("_",""))}
        else: raise AssertionError("MCD unsupported pinned envelope expression: "+name)
        need(name not in props,"MCD duplicate source field");props[name]=spec
    return {"type":"object","properties":props,"additionalProperties":False}


def maximum_schema_value(schema):
    if "enum" in schema:
        need(schema["enum"] and all(isinstance(x,str) and x.isascii() for x in schema["enum"]),"MCD unbounded/non-ASCII enum")
        return max(schema["enum"],key=lambda x:len(canonical(x)))
    kind=schema.get("type")
    if kind=="object":
        need(schema.get("additionalProperties") is False,"MCD envelope allows unbounded fields")
        return {k:maximum_schema_value(v) for k,v in schema["properties"].items()}
    if kind=="array":
        need(type(schema.get("maxItems")) is int and 0<=schema["maxItems"]<=4096,"MCD unbounded array")
        return [maximum_schema_value(schema["items"]) for _ in range(schema["maxItems"])]
    if kind=="integer":
        need(type(schema.get("minimum")) is int and type(schema.get("maximum")) is int,"MCD unbounded number")
        return max((schema["minimum"],schema["maximum"]),key=lambda x:len(canonical(x)))
    if kind=="string":
        if schema.get("format")=="uuid": return "11111111-1111-4111-8111-111111111111"
        if schema.get("format")=="date-time" and schema.get("maxLength")==24: return "2026-11-02T00:00:00.000Z"
        if schema.get("pattern")=="^[a-f0-9]{64}$": return "a"*64
    raise AssertionError("MCD source bound cannot be independently maximized")


def maximum_envelope_value(schema,source):
    maximum=maximum_schema_value(schema)
    observation={"clientRunStatus","clientRunObservedAt"}
    if observation & set(schema["properties"]):
        need(observation <= set(schema["properties"]),"MCD paired run observation schema incomplete")
        guard="if(hasClientRunObservation&&(value.clientRunStatus===undefined||value.clientRunObservedAt===undefined||value.source!=='client'||value.stage!=='client_runtime'||value.outcome!=='error'))"
        need("const hasClientRunObservation=value.clientRunStatus!==undefined||value.clientRunObservedAt!==undefined;" in source and guard in source,"MCD run observation conditional bound requires source review")
        with_observation={**maximum,"source":"client","stage":"client_runtime","outcome":"error"}
        without_observation={k:v for k,v in maximum.items() if k not in observation}
        maximum=max((with_observation,without_observation),key=lambda value:len(canonical(value)))
    return maximum


def envelope_bound(proof,root):
    need(proof["schemaSourceRef"].get("path")=="packages/owner-identity/src/mcp-diagnostics-contract.ts","MCD envelope source is not the actual pinned contract")
    source=read_reference(root,proof["schemaSourceRef"],json_body=False).decode("utf-8-sig")
    need(source_numeric_limits(source,"DIAGNOSTIC_LIMITS")["envelopeBytes"]==2048,"MCD configured envelope ceiling changed")
    schema=read_reference(root,proof["schemaRef"])
    independent=_source_envelope_schema(source)
    need(set(schema.get("properties",{}))==set(independent["properties"]) and schema.get("additionalProperties") is False,"MCD exported schema differs from pinned fields")
    for name,spec in independent["properties"].items():
        exported=schema["properties"][name]
        need(all(exported.get(k)==v for k,v in spec.items() if k!="items"),"MCD exported schema bound differs: "+name)
        if "items" in spec: need(exported.get("items")==spec["items"],"MCD exported array enum differs")
    maximum=maximum_envelope_value(independent,source);bound=len(canonical(maximum))
    witness=read_reference(root,proof["maximumEnvelopeRef"])
    response=read_reference(root,proof["maximumResponseRef"])
    need(_accepts(schema,witness) and set(witness)==set(maximum) and len(canonical(witness))==bound,"MCD reachable maximal envelope witness differs from schema-derived bound")
    if "clientRunStatus" in maximum:
        need(all(witness.get(k)==v for k,v in {"source":"client","stage":"client_runtime","outcome":"error"}.items()),"MCD maximal witness violates pinned client observation conditional")
    need(response.get("httpStatus") in (200,201,202,204),"MCD maximal representable envelope was not accepted at actual boundary")
    need(bound<2048,"MCD envelope ceiling no longer dominated; restore exact accepted-limit probe")
    return bound


def source_numeric_limits(source,name):
    match=re.search(r"(?:export )?const "+name+r"\s*=\s*Object\.freeze\(\{([^}]+)\}\)",source)
    need(match,"MCD pinned finite limits object missing")
    result={}
    for entry in match.group(1).split(","):
        key,expression=entry.strip().split(":",1);parts=expression.replace("_","").split("*")
        need(all(p.strip().isdigit() for p in parts),"MCD unsupported finite limit expression")
        value=1
        for part in parts:value*=int(part.strip())
        result[key]=value
    return result


def reference_causal_facts(control,observations,root):
    """Derive controlled-reference causes from HTTP/SDK/server observations.

    The reference fixture is qualified only for its own SDK/profile; this never
    establishes a cause for an unrelated native Codex event or client log.
    """
    observation=one(observations,"MCD causal control requires one correlated reference observation")
    profile=observation.get("profile",{})
    need(profile=={"implementation":"mcd_controlled_reference_sdk","clientPackage":"@modelcontextprotocol/client","version":"2.4.0","nativeClient":False},"MCD unqualified causal reference profile")
    source=observation.get("verifierSource",{})
    need(source.get("path")=="packages/owner-acceptance/src/mcp-diagnostics-classification.mjs","MCD causal reference source missing")
    read_reference(root,source,json_body=False)
    wire=observation.get("wire",[])
    need(all(any(row.get("method")==method for row in wire) for method in ("initialize","tools/list","tools/call")),"MCD actual reference SDK HTTP sequence missing")
    call=one([row for row in wire if row.get("method")=="tools/call"],"MCD causal call identity ambiguous")
    need(SHA.fullmatch(call.get("callIdHash","")),"MCD causal request hash missing")
    server=observation.get("serverObservations",[])
    need(all(row.get("callIdHash")==call["callIdHash"] for row in server),"MCD server/client causal call mismatch")
    dependencies=observation.get("dependencyObservations",[]);result=observation.get("clientResult") or {};exception=observation.get("clientException") or {}
    failed=call.get("httpStatus",0)>=400 or call.get("rpcErrorCode") is not None or call.get("toolError") is True
    facts={"independentlyVerified":True}
    if control["name"] in ("positive_client_contract","positive_platform_contract"):
        schema=read_reference(root,control["issuedSchemaRef"]);contract=read_reference(root,control["issuedContractRef"])
        need(failed and not server and not dependencies,"MCD schema rejection did not precede actual handler entry")
        if _accepts(schema,contract["requiredOperation"]):
            need(not _accepts(schema,control["clientArguments"]),"MCD client operation did not violate issued schema")
            facts.update(serverValidationRejected=True,compatibilityVerified=True,schemaCompatible=True,violationMatchesPins=True)
        else:facts.update(compatibilityVerified=True,issuedOperationUnrepresentable=True)
        return facts
    phases={row.get("phase") for row in server}
    if result.get("status")=="ok" and not failed and exception.get("name")=="TypeError" and phases=={"handler_entered"} and not dependencies:
        facts.update(clientExceptionReproduced=True,matchingValidServerResponse=True)
    elif failed and phases=={"handler_entered","handler_throw"} and not dependencies and all(row.get("mode")=="platform_runtime" for row in server):
        facts.update(serverFailure=True,dependencyCauseExcluded=True)
    elif failed and phases=={"handler_entered"} and dependencies==[{"method":"GET","path":"/synthetic-dependency","httpStatus":503}] and all(row.get("mode")=="external_dependency" for row in server):
        facts.update(dependencyFailure=True,competingCausesExcluded=True)
    elif failed and phases=={"handler_entered","policy_deny"} and not dependencies and any(row.get("ruleId")=="synthetic_reference_policy" for row in server):
        facts.update(policyMatched=True)
    else:
        need(not failed and result.get("status")=="ok" and not exception and not dependencies,"MCD missing/conflicting causal control is not independently understood")
        facts={"independentlyVerified":False}
    return facts


def allocation_observation(reference,root,envelope_max,local=False):
    """SQL aggregate rows selected from allocations, never quota usage counters."""
    document=read_reference(root,reference)
    need(document.get("source")==("sqlite_observer" if local else "postgresql_observer") and document.get("queryKind")=="diagnostic_allocation_aggregates","MCD independent allocation query missing")
    observer=document.get("observer",{})
    need(observer.get("readOnly") is True and observer.get("role")==("client_sqlite_observer" if local else "oid_observer"),"MCD allocation observer authority missing")
    groups=document.get("groups",[])
    need(groups and len({g["kind"] for g in groups})==len(groups),"MCD allocation SQL groups missing/duplicate")
    reserved=document.get("reservedGroups")
    need(isinstance(reserved,list) and len({g["kind"] for g in reserved})==len(reserved),"MCD in-flight allocation inventory missing")
    result={"rows":0,"bytes":0,"cases":0}
    for group in groups+reserved:
        kind=group.get("kind");count=group.get("count");size=group.get("sumBytes");maximum=group.get("maxBytes")
        need(kind in ("event","batch","segment","case") and type(count) is int and count>=0 and type(size) is int and size>=0 and type(maximum) is int and maximum>=0 and SHA.fullmatch(group.get("rowsSha256","")),"MCD malformed allocation aggregate row")
        if kind=="event": need(maximum<=envelope_max and size<=count*envelope_max,"MCD observed envelope exceeded independently derived schema bound")
        elif not local:
            weight={"batch":512,"segment":256,"case":512}[kind]
            need(size==count*weight and maximum==(weight if count else 0),"MCD allocation charge differs from pinned server rule")
        if kind=="case": result["cases"]+=count
        elif not local or kind=="event": result["rows"]+=count
        result["bytes"]+=size
    return result,document


def successful_tools_response(response):
    wire=response.get("wire",{})
    return response.get("httpStatus")==200 and response.get("resultKind")=="tools" and type(response.get("toolCount")) is int and response["toolCount"]>0 and wire.get("framing") in ("json","sse") and wire.get("rootKeys")==["jsonrpc","id","result"] and wire.get("hasMcpResponse") is True and wire.get("resultIsError") is False and "rpcErrorCode" in wire and wire["rpcErrorCode"] is None


def capacity_probe(p,root,envelope_max,limits,allocation_source):
    name=p["limit"];limit=limits[name];local=name.startswith("local")
    before,document=allocation_observation(p["observationRef"],root,envelope_max,local)
    after,after_document=allocation_observation(p["afterObservationRef"],root,envelope_max,local)
    response=read_reference(root,p["blockingResponseRef"])
    need(before==after and document["groups"]==after_document["groups"] and document["reservedGroups"]==after_document["reservedGroups"],"MCD rejected quota probe changed retained allocations")
    if name in ("anonymousRows","anonymousBytes"):
        need(successful_tools_response(response) and response.get("captureState")=="unavailable","MCD anonymous telemetry exhaustion changed the valid business response or hid dropped coverage")
    else: need(response.get("httpStatus") in (400,413,429) or local and response.get("errorCode")=="DIAGNOSTICS_QUOTA_EXCEEDED","MCD actual over-limit/earlier-blocker rejection missing")
    field="bytes" if name.endswith("Bytes") else "rows" if name.endswith("Rows") else "cases"
    need(before[field]<=limit,"MCD observed retained allocation exceeds configured ceiling")
    if p.get("mode")=="exact_over":
        accepted=read_reference(root,p["acceptedResponseRef"])
        need(accepted.get("httpStatus") in (200,201,202,204) or local and accepted.get("outcome")=="accepted","MCD exact quota acceptance missing")
        if name=="anonymousRows":need(successful_tools_response(accepted),"MCD anonymous limit was filled with failing business requests")
        need(before[field]==limit,"MCD exact-limit observation derived from rows does not reach configured ceiling")
        return
    need(p.get("mode")=="dominated" and field=="bytes","MCD quota requires actual exact/over witness or independently proven byte dominance")
    if local:
        sqlite=document.get("sqlite",{});page=sqlite.get("pageSize",0);max_pages=sqlite.get("maxPageCount",0);pages=sqlite.get("pageCount",0)
        reserve=max(32768,min(1024*1024,limit//8))
        need(type(page) is int and page>=512 and page&(page-1)==0 and type(max_pages) is int and max_pages==(limit-reserve)//(2*page+8),"MCD SQLite physical reserve differs from pinned guard")
        need(sqlite.get("journalMode")=="delete" and max_pages-4<=pages<=max_pages and before["bytes"]<=pages*page,"MCD actual SQLite blocker/page occupancy missing")
        files=document.get("files",[])
        need(files and all(type(f.get("bytes")) is int and f["bytes"]>=0 for f in files) and sum(f["bytes"] for f in files)<=limit,"MCD observed SQLite files exceed total physical ceiling")
        need(max_pages*page<limit and "(diskBytes-reserve)/(2*pageSize+8)" in allocation_source["local"],"MCD local bytes are not dominated by pinned physical page guard")
        return
    prefix=name.removesuffix("Bytes")
    row_limit=limits[prefix+"Rows"];case_limit=0 if prefix=="anonymous" else limits[prefix+"Cases"]
    need(before["rows"]<=row_limit and before["cases"]<=case_limit,"MCD observed committed plus reserved allocation exceeds the earlier ceiling")
    # Every server allocation is either a finite envelope row, 512-byte batch,
    # 256-byte segment, or a separately bounded 512-byte case registration.
    maximum=row_limit*max(envelope_max,512,256)+case_limit*512
    need(maximum<limit,"MCD claimed byte dominance is false")
    need(before["rows"]==row_limit or before["cases"]==case_limit and case_limit>0,"MCD claimed earlier row/case blocker was not observed")
    need("fresh.length+1+(segment?0:1)" in allocation_source["server"] and "+512+(segment?0:256)" in allocation_source["server"],"MCD pinned server allocation accounting changed")


def replay_003(raw, variants, root):
    controls=raw["classification"].get("controls",[])
    by_name={c["name"]:c for c in controls}
    positives={"positive_"+c:c for c in ("client_contract","platform_contract","client_runtime","platform_runtime","external_dependency","expected_policy_denial")}
    need(len(controls)==len(by_name) and set(by_name)==set(positives)|{"contradictory_or_missing_evidence"}, "MCD classification matrix incomplete")
    for name,control in by_name.items():
        facts=control["facts"]; projection=control["projection"]
        evidence=control.get("evidenceReferences",[])
        need(evidence, "MCD classification independent raw evidence absent")
        evidence_ids={ref["sha256"] for ref in evidence}
        observations=[]
        for ref in evidence:
            observation=read_reference(root,ref)
            need(observation.get("observer",{}).get("readOnly") is True and observation["observer"].get("role") in ("oid_observer","qualified_client_reproducer"),"MCD causal evidence lacks independent observer provenance")
            observations.append(observation)
        need(set(facts.get("evidenceIds",[]))<=evidence_ids, "MCD causal evidence reference not retained")
        derived=reference_causal_facts(control,observations,root)
        need({k:v for k,v in facts.items() if k!="evidenceIds"}==derived,"MCD producer causal flags differ from independently replayed HTTP/SDK observations")
        expected=classify(facts)
        need(expected==positives.get(name,"unknown") and projection.get("responsibility")==expected, "MCD incorrect causal responsibility projection")
        need(set(projection.get("evidenceIds",[]))==set(facts.get("evidenceIds",[])), "MCD projection lost causal evidence")
        if name in ("positive_client_contract","positive_platform_contract"):
            schema=read_reference(root,control["issuedSchemaRef"]); contract=read_reference(root,control["issuedContractRef"])
            need(schema.get("type")=="object" and isinstance(schema.get("properties"),dict) and contract.get("tool"), "MCD issued schema/contract not retained")
            need(facts.get("compatibilityVerified") is True, "MCD unverified contract compatibility")
            representable=_accepts(schema,contract["requiredOperation"])
            if name=="positive_client_contract":
                need(representable and not _accepts(schema,control["clientArguments"]) and facts.get("schemaCompatible") is True,"MCD client violation not reproduced against compatible issued schema")
            else: need(not representable and facts.get("issuedOperationUnrepresentable") is True,"MCD platform contract mismatch not reproduced against issued operation")
    mutated=raw["classification"].get("allUnknownMutation",[])
    need(len(mutated)==len(positives) and all(p.get("responsibility")=="unknown" for p in mutated), "MCD all-unknown control projection absent")
    need(any(classify(by_name[p["name"]]["facts"])!=p["responsibility"] for p in mutated), "MCD reader accepted all-unknown positive mutation")
    return {name:True for name in ("schema_contract_compatibility","positive_matrix_categories","classification_evidence","reject_all_unknown_projection","unknown_preserved","business_hashes_unchanged")}


def replay_004(raw, variants, root):
    browser=raw["browser"]
    for name in ("owner","admin"):
        view=browser[name]
        need(view.get("action")=="click" and view.get("httpStatus")==200 and view.get("caseIds"), "MCD real private browser view missing")
        cases=rows(read_reference(root,view["databaseRef"]),"cases")
        wanted=[c["caseId"] for c in cases if name=="admin" or c["ownerId"]==view.get("ownerId")]
        need(set(view["caseIds"])==set(wanted) and all(case_id in view.get("domText","") for case_id in wanted), "MCD browser view differs from owned database cases")
        need("Client-observed evidence" in view["domText"] and "Unknown responsibility" in view["domText"], "MCD browser hides source trust or unknown attribution")
    for name in ("foreign_owner","anonymous","task_agent_read","forged_run_action_reference"):
        v=variants[name]
        need(v["response"].get("httpStatus") in (401,403,404) and not v["response"].get("caseIds"), "MCD private access boundary disclosed rows")
        need(v["beforeDiagnostic"]==v["afterDiagnostic"], "MCD unauthorized/read operation changed diagnostics")
    forged=variants["client_claim_of_server_authority"]
    need(forged["response"].get("httpStatus") in (400,403,404) or all(e.get("responsibility")=="unknown" and e.get("source")=="client" for e in rows(forged["afterDiagnostic"],"events")), "MCD imported authority claim trusted")
    for name in ("ordinary_failed_grade_only","error_free_capture"):
        v=variants[name]
        need(rows(v["beforeDiagnostic"],"reports")==rows(v["afterDiagnostic"],"reports"), "MCD grade or zero errors triggered a report")
    for name in ("ordinary_failed_grade_only","completed_run_with_client_errors"):
        response=variants[name]["response"];observation=read_reference(root,response["runObservationRef"])
        need(observation.get("source")=="postgresql_observer" and observation.get("observer",{}).get("role")=="oid_observer" and observation["observer"].get("readOnly") is True and observation.get("runId")==response.get("runId"),"MCD actual reference run observer binding missing")
        run=one(observation.get("rows",[]),"MCD terminal reference run row missing")
        need(run.get("status")=="completed" and (name!="ordinary_failed_grade_only" or run.get("task_status")=="failed"),"MCD completed/grade-only reference boundary not observed")
    complete=variants["completed_run_with_client_errors"]
    need(len(rows(complete["afterDiagnostic"],"reports"))==len(rows(complete["beforeDiagnostic"],"reports"))+1, "MCD completed-run error report missing")
    return {name:True for name in ("own_rows_visible","admin_authorized","foreign_denied","source_trust_visible","diagnostic_trigger_distinct")}


def bundle_size_boundary(probe,content):
    """The oversized UI guard rejects before HTTP; never invent a status code."""
    p=probe
    if p["bytes"]==8*1024*1024:
        need(p.get("httpStatus") in (200,201,202,204) and p.get("browser",{}).get("action")=="file_select_and_click" and p["browser"].get("fileBytes")==p["bytes"],"MCD exact bundle did not cross actual file selection and import")
        need(isinstance(json.loads(content),dict),"MCD exact bundle was not a JSON export")
    else:
        browser=p.get("browser",{})
        need("httpStatus" not in p and p.get("boundary")=="owner_browser_file_size_guard" and browser.get("action")=="file_select" and browser.get("fileBytes")==p["bytes"] and browser.get("validationText")=="Diagnostic export exceeds 8 MiB." and browser.get("importDisabled") is True and browser.get("uploadRequests")==[],"MCD oversized browser export was uploaded or rejection was fabricated as HTTP")


def concurrent_reservation_boundary(concurrent,race,root,envelope_max=2048):
    need(concurrent.get("actors")==["helper","owner_import","replica"] and concurrent.get("source")=="postgresql_observer","MCD reservation actors/source missing")
    attempts=concurrent.get("attempts",[])
    need(len(attempts)==3 and {a.get("actor") for a in attempts}=={"helper","owner_import","replica"} and sum(a.get("httpStatus")==200 for a in attempts)==1 and sum(a.get("httpStatus")==429 and a.get("errorCode")=="DIAGNOSTICS_QUOTA_EXCEEDED" for a in attempts)==2 and concurrent.get("waitingLockConnections",0)>=3,"MCD actual helper/import/replica race did not overlap")
    lock_observation=read_reference(root,concurrent["lockObservationRef"])
    need(lock_observation.get("source")=="postgresql_observer" and lock_observation.get("observer",{}).get("role")=="oid_observer" and lock_observation["observer"].get("readOnly") is True and lock_observation.get("queryKind")=="ungranted_locks_same_disposable_database_owner_role" and one(lock_observation.get("rows",[]),"MCD concurrent lock observation absent").get("n")==concurrent["waitingLockConnections"],"MCD real concurrent lock evidence missing")
    replica=concurrent.get("replica",{})
    need(replica.get("boundary")=="actual_same_build_disposable_database_replica" and replica.get("primaryPort")==8784 and replica.get("replicaPort")==8785 and replica.get("serverBuildSha256")==replica.get("serverBuildRef",{}).get("sha256"),"MCD replica build/process identity missing")
    need(replica["serverBuildRef"].get("path")=="packages/owner-identity/dist/server.js" and lock_observation["observer"].get("databaseName")==replica.get("databaseName"),"MCD replica build/database binding differs")
    read_reference(root,replica["serverBuildRef"],json_body=False)
    for attempt in attempts:
        if attempt["actor"]=="owner_import":
            need(attempt.get("browser",{}).get("action")=="click" and attempt["browser"].get("requestPath")=="/api/owner/diagnostics/import","MCD owner race bypassed actual browser import")
        else: need(attempt.get("transport",{}).get("remotePort")== (8785 if attempt["actor"]=="replica" else 8784),"MCD race did not cross distinct actual API listeners")
    before_events={e["eventId"] for e in rows(race["beforeDiagnostic"],"events")}
    after_events=rows(race["afterDiagnostic"],"events")
    before_hashes={e["eventId"]:digest(e) for e in rows(race["beforeDiagnostic"],"events")}
    after_hashes={e["eventId"]:digest(e) for e in after_events if e["eventId"] in before_events}
    need(before_hashes and before_hashes==after_hashes and concurrent.get("retainedBeforeHashes")==before_hashes and concurrent.get("retainedAfterHashes")==after_hashes,"MCD concurrent reservation changed/evicted old evidence")
    fresh=[e["eventId"] for e in after_events if e["eventId"] not in before_events]
    need(len(fresh)==1 and fresh==concurrent.get("newEventIds") and len(concurrent.get("newBatches",[]))==1 and rows(race["beforeDiagnostic"],"reports")==rows(race["afterDiagnostic"],"reports"),"MCD race duplicated events/reports or lost retained rows")
    before_batches={(b["caseId"],b["segmentId"],b["batchSequence"]) for b in rows(race["beforeDiagnostic"],"batches")}
    fresh_batches=[b for b in rows(race["afterDiagnostic"],"batches") if (b["caseId"],b["segmentId"],b["batchSequence"]) not in before_batches]
    need(fresh_batches==concurrent["newBatches"] and len(fresh_batches)==1 and fresh_batches[0].get("payloadHash")==concurrent.get("payloadHash"),"MCD replica race batch allocation does not match independent rows")
    need(len({a.get("request",{}).get("segmentId") for a in attempts})==3 and len({a.get("request",{}).get("eventId") for a in attempts})==3 and len({a.get("request",{}).get("payloadHash") for a in attempts})==3,"MCD quota race only replayed one idempotency key")
    winner=one([a for a in attempts if a["httpStatus"]==200],"MCD quota race accepted more than one reservation")
    receipt=winner.get("receipt",{});request=winner.get("request",{})
    need(receipt.get("caseId")==concurrent.get("caseId") and receipt.get("segmentId")==request.get("segmentId")==concurrent.get("segmentId") and receipt.get("highestContiguousHash")==request.get("payloadHash")==concurrent.get("payloadHash") and fresh==[request.get("eventId")],"MCD race receipt/row did not match winning distinct reservation")
    owner_before,before_doc=allocation_observation(concurrent["ownerReservationBeforeRef"],root,envelope_max)
    owner_after,after_doc=allocation_observation(concurrent["ownerReservationAfterRef"],root,envelope_max)
    need(owner_before["rows"]==16381 and owner_after["rows"]==16384 and before_doc.get("scope")==after_doc.get("scope")=={"ownerId":concurrent.get("ownerId")},"MCD quota race did not cross the actual last owner rows")
    case=one([c for c in rows(race["afterDiagnostic"],"cases") if c.get("caseId")==concurrent.get("caseId")],"MCD quota race case absent")
    need(case.get("ownerId")==concurrent.get("ownerId"),"MCD quota race owner scope unbound")



def windows_host_capacity(reference,quota,root):
    evidence=read_reference(root,reference)
    need(evidence.get("schemaVersion")=="mcd-local-capacity-host-evidence/v1","MCD Windows capacity evidence missing")
    job=read_reference(root,evidence["jobRef"]);result=read_reference(root,evidence["resultRef"])
    need(job.get("schemaVersion")=="mcd-local-capacity-host-job/v1" and result.get("schemaVersion")=="mcd-local-capacity-host-result/v1" and result.get("jobSha256")==evidence["jobRef"]["sha256"] and all(result.get(k)==job.get(k) for k in ("captureId","jobId")),"MCD host capacity result crossed jobs or original bytes")
    need(result.get("probeId")==job["captureId"]+"-host-"+job["jobId"] and result.get("host",{}).get("platform")=="win32" and re.match(r"^v24\.",result["host"].get("nodeVersion","")),"MCD physical client boundary was not Windows Node24")
    sources=job.get("sourceInputs",{})
    required={"tools/mcd-local-capacity-host.mjs","tools/mcd-local-capacity-restore.mjs","tools/mcp-diagnostics-client.mjs"}
    need(required<=set(sources) and result.get("sourceInputs")=={"before":sources,"after":sources},"MCD host probe source inventory drifted or omitted actual helper")
    for path,expected in sources.items():
        file=(root/path).resolve()
        need(file.is_relative_to(root.resolve()) and file.is_file() and SHA.fullmatch(expected) and hashlib.sha256(file.read_bytes()).hexdigest()==expected,"MCD host current source/hash differs")
    local=result.get("local",{})
    need(local.get("capacityProbes")==[p for p in quota.get("capacityProbes",[]) if p.get("limit") in ("localBytes","localRows","localCases")],"MCD assembled local quotas differ from actual Windows result")
    observations=evidence.get("serverObservations",[])
    need(len(observations)==2,"MCD host expiry lacks both actual server observations")
    request_ids=set()
    for sequence,pair in enumerate(observations):
        request=read_reference(root,pair["requestRef"]);response=read_reference(root,pair["responseRef"])
        request_id=request.get("requestId","")
        need(re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}",request_id) and request_id not in request_ids and request.get("schemaVersion")=="mcd-local-server-counts/v1" and all(request.get(k)==job.get(k) for k in ("captureId","jobId")) and request.get("kind")=="read_server_rows" and request.get("sequence")==sequence and response.get("requestId")==request_id,"MCD host server count request was reused, reordered or unbound")
        request_ids.add(request_id)
        need(response.get("schemaVersion")=="mcd-local-server-counts/v1" and all(response.get(k)==job.get(k) for k in ("captureId","jobId")) and response.get("sequence")==sequence and response.get("source")=="postgresql_observer" and response.get("observer",{}).get("role")=="oid_observer" and response["observer"].get("readOnly") is True and response["observer"].get("databaseName")=="oid_acceptance_"+job["captureId"].replace("-",""),"MCD host count response lacks independent bound observer")
        counts=one(response.get("rows",[]),"MCD host counts row absent")
        need(set(counts)=={"cases","events","reports"} and all(type(n) is int and n>=0 for n in counts.values()),"MCD host server counts malformed")
        need(local.get("localRetention",{}).get("serverRowsBefore" if sequence==0 else "serverRowsAfter")==response["rows"],"MCD host expiry server counts were substituted")
    need(local["localRetention"]["serverRowsBefore"]==local["localRetention"]["serverRowsAfter"],"MCD local host capacity/expiry changed server evidence")


def anonymous_bucket_boundary(value,root,database_name):
    before=read_reference(root,value["beforeRef"]);after=read_reference(root,value["afterRef"])
    def counts(document):
        need(document.get("source")=="postgresql_observer" and document.get("observer",{}).get("role")=="oid_observer" and document["observer"].get("readOnly") is True and document["observer"].get("databaseName")==database_name,"MCD anonymous buckets lack bound independent observer")
        rows=document.get("rows",[])
        need(len(rows)==128 and {r.get("bucket") for r in rows}==set(range(128)),"MCD anonymous bucket registry changed")
        result={}
        for row in rows:
            need(type(row.get("bucket")) is int and re.fullmatch(r"\d+",str(row.get("dropped_count",""))),"MCD malformed fixed bucket loss count")
            count=int(row["dropped_count"]);need(0<=count<=9223372036854775807,"MCD loss counter outside pinned bigint ceiling");result[row["bucket"]]=count
        return result
    a,b=counts(before),counts(after)
    need(value.get("before")==value.get("after")==128 and value.get("newAllocationRows")==[] and set(a)==set(b) and all(b[k]>=a[k] for k in a) and sum(b.values())>sum(a.values()),"MCD anonymous overflow allocated rows, evicted loss evidence or did not record dropped detail")


def replay_005(raw, variants, root):
    quota=raw["quotas"]
    maximum=envelope_bound(quota["envelopeBound"],root)
    canaries=quota.get("syntheticCanaries",[])
    need(canaries and all(isinstance(c,str) and len(c)>=16 for c in canaries), "MCD privacy canary controls absent")
    surfaces=quota.get("retainedSurfaces",[])
    need(surfaces, "MCD retained surface inventory absent")
    for reference in surfaces:
        document=read_reference(root,reference)
        serialized=canonical(document).decode()
        need(all(c not in serialized for c in canaries), "MCD synthetic sensitive canary leaked")
    probes=quota.get("sizeProbes",[])
    expected={(kind,size) for kind,limit in (("envelope",2048),("bundle",8*1024*1024)) for size in (limit,limit+1)}
    need({(p["kind"],p["bytes"]) for p in probes}==expected,"MCD exact size controls absent")
    for p in probes:
        reference=p["inputRef"]; content=read_reference(root,reference,json_body=False)
        actual=len(content.encode("utf-8")) if isinstance(content,str) else len(content)
        need(actual==p["bytes"],"MCD size probe bytes disagree")
        if p["kind"]=="envelope":
            need(p["httpStatus"] in (400,413,429),"MCD schema-dominated 2048/2049 envelope was accepted")
            try: envelope=json.loads(content)
            except (ValueError,TypeError): envelope=None
            schema=read_reference(root,quota["envelopeBound"]["schemaRef"])
            need(envelope is not None and not _accepts(schema,envelope),"MCD oversized envelope did not exercise strict schema rejection")
        else:
            bundle_size_boundary(p,content)
    limits={"ownerBytes":32*1024*1024,"ownerRows":16384,"ownerCases":128,"deploymentBytes":256*1024*1024,"deploymentRows":131072,"deploymentCases":4096,"anonymousBytes":4*1024*1024,"anonymousRows":2048,"localBytes":64*1024*1024,"localRows":32768,"localCases":128}
    capacity=quota.get("capacityProbes",[])
    need({p["limit"] for p in capacity}==set(limits),"MCD owner/deployment/anonymous/local quota controls missing")
    windows_host_capacity(quota["hostCapacityEvidenceRef"],quota,root)
    sources=quota["allocationSources"]
    need(sources["server"]["path"]=="packages/owner-identity/src/mcp-diagnostics-service.ts" and sources["local"]["path"]=="tools/mcp-diagnostics-client.mjs","MCD actual allocation sources missing")
    allocation_source={key:read_reference(root,ref,json_body=False).decode("utf-8-sig") for key,ref in sources.items()}
    contract_source=read_reference(root,quota["envelopeBound"]["schemaSourceRef"],json_body=False).decode("utf-8-sig")
    configured=source_numeric_limits(contract_source,"DIAGNOSTIC_LIMITS")
    local_configured=source_numeric_limits(allocation_source["local"],"LOCAL_DIAGNOSTIC_LIMITS")
    for name,value in limits.items():
        key={"localBytes":"spoolBytes","localRows":"spoolRows","localCases":"spoolCases"}.get(name,name)
        need((local_configured if name.startswith("local") else configured).get(key)==value,"MCD configured quota ceiling changed: "+name)
    need(configured.get("controlBytes")==8*1024*1024,"MCD control reserve ceiling changed")
    for p in capacity:
        capacity_probe(p,root,maximum,limits,allocation_source)
    counters=quota["canonicalCaseCounts"]
    need(counters.get("accepted")==4096 and counters.get("attempted")==4097 and counters.get("durable")==4096,"MCD canonical event bound not enforced")
    anonymous=quota["anonymousBuckets"]
    anonymous_bucket_boundary(anonymous,root,variants["anonymous_overflow_fixed_buckets"]["afterDiagnostic"].get("observer",{}).get("databaseName"))
    for name in ("truncated_input","parser_or_storage_failure","reachable_exact_over_or_proven_dominated_quotas"):
        v=variants[name]
        need(any(c.get("captureState") in ("partial","partial_quota","unavailable") for c in rows(v["afterDiagnostic"],"cases")),"MCD missing explicit incomplete coverage")
    concurrent=quota["concurrentReservations"]
    need(concurrent.get("actors")==["helper","owner_import","replica"] and concurrent.get("source")=="postgresql_observer" and concurrent.get("retainedBeforeHashes")==concurrent.get("retainedAfterHashes"),"MCD concurrent reservation evicted evidence or missing actors")
    concurrent_reservation_boundary(concurrent,variants["concurrent_helper_import_replica_reservations"],root,maximum)
    return {name:True for name in ("canaries_absent","exact_finite_bounds","independently_proven_dominance","shared_quota_reservations","anonymous_fixed_buckets","gap_markers","no_duplicate_effect")}


def expired_owner_exports(restore,root):
    controls=restore.get("ownerIntakeControls",[])
    need(len(controls)==2 and {c.get("kind") for c in controls}=={"original_owned_export_after_purge","fresh_owned_export"},"MCD both legitimate expired owner exports were not tested")
    before=read_reference(root,restore["beforeDatabaseRef"]);full=read_reference(root,restore["fullSourceRef"])["before"]
    purge=read_reference(root,restore["purgeObservationRef"])
    database=before.get("observer",{}).get("databaseName")
    need(purge.get("source")=="postgresql_observer" and purge.get("observer",{}).get("role")=="oid_observer" and purge["observer"].get("readOnly") is True and purge["observer"].get("databaseName")==database,"MCD actual post-purge observer binding missing")
    counts=one(purge.get("counts",[]),"MCD purge detail count observation absent")
    need(counts.get("cases")==counts.get("events")==0,"MCD expired export controls ran before actual detail purge")
    receipt=one(purge.get("retention",[]),"MCD committed purge receipt absent")
    need(receipt.get("caseCount")==full["tableFingerprints"]["oid_mcp_diagnostic_case"]["rowCount"]>0 and receipt.get("eventCount")==full["tableFingerprints"]["oid_mcp_diagnostic_event"]["rowCount"]>0,"MCD purge receipt does not reconcile original diagnostic data")
    original=one([c for c in controls if c["kind"]=="original_owned_export_after_purge"],"MCD original export control missing")
    request=read_reference(root,original["requestRef"]);case=read_reference(root,original["originalCaseRef"])
    need(case.get("source")=="postgresql_observer" and case.get("observer",{}).get("role")=="oid_observer" and case["observer"].get("readOnly") is True and case["observer"].get("databaseName")==database,"MCD original owner export was not bound before purge")
    source_case=one([c for c in rows(before,"cases") if c.get("caseId")==case.get("caseId")],"MCD original case absent from pre-purge source")
    need(all(source_case.get(k)==case.get(k) for k in ("caseId","diagnosticSessionId","ownerId","agentId","connectionId")),"MCD owner expiry control substituted original identifiers")
    need(request.get("caseId")==case["caseId"] and request.get("diagnosticSessionId")==case["diagnosticSessionId"] and request.get("binding")=={"agentId":case["agentId"],"connectionId":case["connectionId"]},"MCD expired original export was invalid before expiry")
    batch=request.get("batch",{});payload={k:v for k,v in batch.items() if k!="payloadHash"}
    need(batch.get("payloadHash")==digest(payload),"MCD original expired export payload hash changed")
    one([b for b in rows(before,"batches") if b.get("caseId")==case["caseId"] and b.get("segmentId")==batch.get("segmentId") and b.get("batchSequence")==batch.get("batchSequence") and b.get("payloadHash")==batch.get("payloadHash")],"MCD expired export did not replay the actual original saved batch")
    need(read_reference(root,original["preExpiryResponseRef"]).get("httpStatus")==200,"MCD original export had no actual successful pre-expiry replay")
    for control in controls:
        response=read_reference(root,control["responseRef"])
        need(response.get("httpStatus")==410 and response.get("errorCode")=="REPORT_RETENTION_EXPIRED","MCD valid post-purge owner export did not terminate with intake expiry")
    fresh=read_reference(root,one([c for c in controls if c["kind"]=="fresh_owned_export"],"MCD fresh owner export missing")["requestRef"])
    need("caseId" not in fresh and fresh.get("diagnosticSessionId")!=request["diagnosticSessionId"] and fresh.get("binding")==request["binding"],"MCD fresh owner control reused a stale case or invalid binding")


def replay_006(raw, variants, root):
    restore=raw["restore"]
    before,after=(read_reference(root,restore[key]) for key in ("beforeDatabaseRef","afterDatabaseRef"))
    for table in ("cases","events","reports","batches","audits"):
        need(rows(before,table) and rows(before,table)==rows(after,table),"MCD restored diagnostic identity/history differs: "+table)
    manifest=read_reference(root,restore["serverManifestRef"])
    received=restore.get("receivedFiles",[])
    need(received and manifest.get("diagnostics",{}).get("files")==received,"MCD server received manifest inventory differs")
    inventory=read_reference(root,restore["checkpointInventoryRef"])
    official_ref=manifest["officialManifestRef"];official=read_reference(root,official_ref)
    need(official.get("schemaVersion")=="beta-official-evidence-source/v1" and official_ref.get("sha256")==inventory.get("checkpointSource",{}).get("officialEvidenceSource",{}).get("manifestSha256") and official.get("sourceBuildSha256")==inventory.get("sourceBuildSha256"),"MCD received evidence is not bound to actual checkpoint official manifest")
    for reference in received:
        content=read_reference(root,reference,json_body=False)
        one([row for row in official.get("files",[]) if row.get("path")=="evidence/official/"+reference["path"] and row.get("sha256")==reference["sha256"] and row.get("bytes")==len(content)],"MCD received server artifact absent from actual restored official manifest")
    restore_full_database(restore,root,inventory)
    image=read_reference(root,restore["imageRestoreProofRef"])
    need(image.get("source")=="postgresql_observer_and_filesystem_hash" and type(image.get("bytes")) is int and 0<image["bytes"]<=5*1024*1024 and SHA.fullmatch(image.get("sha256","")),"MCD actual image restore proof missing")
    for key in ("sourceFileRef","restoredFileRef"):
        content=read_reference(root,image[key],json_body=False)
        need(len(content)==image["bytes"] and image[key]["sha256"]==image["sha256"],"MCD actual screenshot bytes changed across restore")
    one([row for row in official["files"] if row.get("path")=="evidence/official/"+image["sourceFileRef"]["path"] and row.get("sha256")==image["sha256"] and row.get("bytes")==image["bytes"]],"MCD screenshot copy absent from actual checkpoint official manifest")
    fixture=read_reference(root,restore["sourceFixtureRef"])
    need(fixture.get("image",{}).get("uploadId")==image.get("uploadId") and fixture["image"].get("reportId")==image.get("reportId") and fixture["image"].get("sha256")==image["sha256"] and all(type(fixture.get("sourceCounts",{}).get(k)) is int and fixture["sourceCounts"][k]>0 for k in ("bonuses","evaluations","reports","screenshots")),"MCD actual UI source lacks a declared backup data family")
    pending=restore.get("clientPendingReferences",[])
    need(pending and not set(r["path"] for r in pending)&set(r["path"] for r in received),"MCD server backup falsely includes remote pending files")
    fence=restore_readonly_fence(restore["readOnlyFenceRef"],root)
    need(after.get("observer",{}).get("databaseName")==fence["observer"]["databaseName"] and after["observer"].get("role")=="oid_observer" and after["observer"].get("readOnly") is True,"MCD restored snapshot did not come from the fenced restore database")
    authority=read_reference(root,restore["rawAuthorityBeforeRef"])
    need(authority.get("source")=="postgresql_observer" and authority.get("observer",{}).get("role")=="oid_observer" and authority["observer"].get("readOnly") is True,"MCD source raw authority observer missing")
    need(authority.get("accessGrants") and authority.get("executionLeases") and authority["accessGrants"]==fence["rawAccessGrants"] and authority["executionLeases"]==fence["rawExecutionLeases"],"MCD restore changed or omitted raw native grant or execution lease history")
    need(restore.get("serverWriteMode")=="disabled" and restore.get("restoredAccessGrants")==fence["effectiveAccessGrants"] and restore.get("restoredExecutionLeases")==fence["effectiveExecutionLeases"],"MCD cold restore restored write/execution authority")
    need(restore.get("revocationsBefore") and restore["revocationsBefore"]==restore.get("revocationsAfter"),"MCD restore lost revocation journal")
    need(any(c.get("captureState") in ("partial","partial_quota","unavailable") for c in rows(after,"cases")),"MCD restore invented complete coverage")
    local=restore["localRetention"]
    need(local.get("source")=="sqlite_observer" and local.get("elapsedDays",0)>=30 and local.get("beforePendingBytes",0)>0 and local.get("afterResumePendingBytes")==0,"MCD local 30-day expiry not observed on resume")
    need(local.get("serverRowsBefore")==local.get("serverRowsAfter") and restore.get("serverIntakeClosedStatus")==410,"MCD local/server retention boundaries mixed")
    expired_owner_exports(restore,root)
    intake=restore.get("serverIntakeOutboxObservation",{})
    need(intake.get("source")=="sqlite_observer" and intake.get("observer",{}).get("readOnly") is True and intake.get("state")=="retention_expired","MCD closed server intake did not durably stop helper retries")
    identity=read_reference(root,intake["identityRef"])
    need(identity.get("source")=="sqlite_observer" and identity.get("observer",{}).get("readOnly") is True,"MCD intake helper state lacks independent SQLite observation")
    case=one([c for c in identity.get("cases",[]) if c.get("local_id")==intake.get("localCaseId")],"MCD intake helper case missing")
    need(case.get("state")=="retention_expired" and any(r.get("httpStatus")==410 and r.get("path","").startswith("/api/diagnostics/") for r in intake.get("httpResponses",[])),"MCD helper retention expiry was inferred from owner HTTP410")
    restore_tamper_rejection(variants["missing_or_tampered_received_evidence"]["response"],root)
    need(variants["revoked_helper"]["response"].get("httpStatus") in (401,403),"MCD revoked helper authorization was accepted")
    need(restore.get("stoppedHelper",{}).get("state")=="not_running" and restore["stoppedHelper"].get("remotePurgeClaimed") is False,"MCD offline helper falsely claimed remote deletion")
    return {name:True for name in ("server_received_inventory_and_hashes","remote_pending_excluded","partial_retained","write_disabled","revocation_retained","separate_retention_boundaries","case_batch_report_identity_retained")}


def restore_full_database(restore,root,inventory):
    original=read_reference(root,restore["fullSourceRef"]);restored=read_reference(root,restore["fullRestoredDatabaseRef"])
    need(original.get("source")==restored.get("source")=="postgresql_observer","MCD full database observer references missing")
    before,after,target=original["before"],original["after"],restored["snapshot"]
    need(restored.get("observer",{}).get("databaseName")==target.get("observerIdentity",{}).get("databaseName")==target.get("sourceDatabase") and re.fullmatch(r"oid_restore_[a-f0-9]{32}",target.get("sourceDatabase","")),"MCD full restore fingerprint database identity mismatch")
    for snapshot in (before,after,target):
        identity=snapshot.get("observerIdentity",{})
        need(snapshot.get("schemaVersion")=="beta-combined-source-observation/v1" and identity.get("databaseRole")=="oid_observer" and identity.get("transactionReadOnly")=="on","MCD full database snapshot is not independent read-only observation")
        tables=snapshot.get("tableFingerprints",{})
        need(tables and all(type(v.get("rowCount")) is int and v["rowCount"]>=0 and SHA.fullmatch(v.get("sha256","")) for v in tables.values()),"MCD full table fingerprints incomplete")
        need(snapshot.get("databaseTotalsSha256")==digest({"tableFingerprints":tables,"sequenceSha256":snapshot["sequenceSha256"]}),"MCD full database total does not match its actual table fingerprints")
    need(before["tableFingerprints"]==after["tableFingerprints"] and before["sequenceSha256"]==after["sequenceSha256"],"MCD source changed across actual checkpoint")
    names=["oid_diagnostic_oauth_request","oid_diagnostic_oauth_grant","oid_diagnostic_oauth_token"]
    empty={"rowCount":0,"sha256":hashlib.sha256(b"").hexdigest()}
    need(all(name in before["tableFingerprints"] for name in names),"MCD helper authority schemas missing from full source")
    expected={**before["tableFingerprints"],**{name:empty for name in names}}
    need(target["tableFingerprints"]==expected and target["sequenceSha256"]==before["sequenceSha256"],"MCD restore changed data beyond exact three helper authority exclusions")
    policy=inventory.get("restoreDataPolicy",{})
    need(policy.get("schemaVersion")=="beta-diagnostic-helper-authority-exclusion/v1" and policy.get("excludedTableData")==names and policy.get("sourceTableFingerprints")=={name:before["tableFingerprints"][name] for name in names} and policy.get("restoredTableFingerprints")=={name:empty for name in names} and policy.get("sourceDatabaseTotalsSha256")==before["databaseTotalsSha256"] and policy.get("restorableDatabaseTotalsSha256")==target["databaseTotalsSha256"],"MCD actual checkpoint authority exclusion declaration differs from independently derived rows")


def restore_readonly_fence(reference,root):
    proof=read_reference(root,reference);identity=proof.get("observer",{});database=identity.get("databaseName","")
    need(proof.get("source")=="postgresql_observer" and identity.get("role")=="oid_observer" and identity.get("readOnly") is True and re.fullmatch(r"oid_restore_[a-f0-9]{32}",database),"MCD independent restore fence observer missing")
    need(any(row.get("databaseName")==database and "default_transaction_read_only=on" in row.get("setconfig",[]) for row in proof.get("databaseSettings",[])),"MCD restored database persistent read-only setting absent")
    probe=proof.get("ownerWriteProbe",{})
    need(probe.get("role")=="oid_owner" and probe.get("databaseName")==database and probe.get("defaultTransactionReadOnly")==probe.get("transactionReadOnly")=="on" and probe.get("sqlState")=="25006","MCD actual owner new-connection write was not fenced")
    tables=proof.get("helperAuthorityTables",[])
    expected={"oid_diagnostic_oauth_request","oid_diagnostic_oauth_grant","oid_diagnostic_oauth_token"}
    need(len(tables)==3 and {row.get("name") for row in tables}==expected and all(type(row.get("count")) is int and row["count"]==0 for row in tables),"MCD restore included helper credential authority")
    need(isinstance(proof.get("rawAccessGrants"),list) and isinstance(proof.get("rawExecutionLeases"),list),"MCD raw historical authority inventory missing")
    need(proof.get("effectiveAccessGrants")==proof.get("effectiveExecutionLeases")==[],"MCD restored effective authority is not empty")
    api=proof.get("apiProbe",{})
    need(proof.get("servedApi") is False and api.get("outcome")=="connection_refused" and api.get("errorCode")=="ECONNREFUSED" and api.get("url")=="http://127.0.0.1:8784/healthz","MCD cold restore has no actual closed configured API observation")
    return proof


def cipher_identity(reference,root):
    """Stream a finite sealed bundle hash; never decrypt or retain blob bytes."""
    text=reference.get("path");expected=reference.get("sha256")
    need(isinstance(text,str) and SHA.fullmatch(expected or "") and not PurePosixPath(text).is_absolute() and ":" not in text and "\\" not in text and all(part not in ("",".","..") for part in text.split("/")),"MCD unsafe cipher reference")
    base=root.resolve(strict=True);file=base
    for part in text.split("/"):
        file=file/part;need(not file.is_symlink(),"MCD cipher reference is a symlink")
    file=file.resolve(strict=True);need(file.is_relative_to(base) and file.is_file(),"MCD cipher reference escapes root")
    before=file.stat();limit=2*1024**3+32*1024**2
    need(0<before.st_size<=limit,"MCD sealed bundle exceeds bounded payload/manifest size")
    actual=hashlib.sha256();count=0
    with file.open("rb") as stream:
        while chunk:=stream.read(1024*1024):
            count+=len(chunk);need(count<=limit,"MCD cipher file grew beyond bound");actual.update(chunk)
    after=file.stat();need((before.st_size,before.st_mtime_ns,before.st_ino)==(after.st_size,after.st_mtime_ns,after.st_ino) and count==after.st_size,"MCD sealed bundle changed during hashing")
    need(actual.hexdigest()==expected,"MCD cipher reference hash mismatch")
    return {"sha256":actual.hexdigest(),"bytes":count}


def restore_tamper_rejection(response,root):
    need(response.get("boundary")=="unified_backup_restore_verifier" and response.get("outcome")=="rejected" and response.get("errorCode") in ("beta_backup_file_integrity","beta_backup_bundle_ciphertext_integrity") and "httpStatus" not in response,"MCD actual operator verifier did not reject tampered ciphertext")
    inventory=read_reference(root,response["checkpointInventoryRef"])
    need(inventory.get("schemaVersion")=="beta-backup-inventory/v2","MCD tamper probe inventory is not actual sealed checkpoint format")
    sealed=one([row for row in inventory.get("files",[]) if row.get("kind")=="sealed_bundle" and row.get("path")=="checkpoint.bundle.enc"],"MCD sealed checkpoint inventory missing")
    need(response["beforeBundleRef"]["path"]!=response["afterTamperRef"]["path"],"MCD tamper probe overwrote original checkpoint")
    before=cipher_identity(response["beforeBundleRef"],root);after=cipher_identity(response["afterTamperRef"],root)
    need(before=={"bytes":sealed.get("bytes"),"sha256":sealed.get("sha256")} and after["bytes"]==before["bytes"] and after["sha256"]!=before["sha256"],"MCD actual cipher mutation is not bound to unchanged original inventory")


REPLAY={"MCD-SC-001":replay_001,"MCD-SC-002":replay_002,"MCD-SC-003":replay_003,"MCD-SC-004":replay_004,"MCD-SC-005":replay_005,"MCD-SC-006":replay_006}
