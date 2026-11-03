"""Reader-integrity controls; synthetic documents cannot qualify physical gates."""
import hashlib
import json
import pytest
from pathlib import Path
from tests.bdd.adapters.mcp_call_diagnostics import load_physical, physical
from tests.bdd.adapters.mcd_physical_replay import classify, stable_business, envelope_bound, _source_envelope_schema, maximum_schema_value, maximum_envelope_value, _watermark, active_crash_observation, bundle_size_boundary, concurrent_reservation_boundary, windows_host_capacity, anonymous_bucket_boundary, expired_owner_exports, capacity_probe, reference_causal_facts, restore_readonly_fence, restore_tamper_rejection, restore_full_database, digest, owner_helper_race, late_native_binding, native_restart_restore, native_delivery_boundaries, denied_helper_capabilities


def reference(root, name, value):
    file = root / name
    file.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value) + "\n").encode()
    file.write_bytes(raw)
    return {"path": name, "sha256": hashlib.sha256(raw).hexdigest()}


def test_aggregate_count_or_producer_success_flags_cannot_qualify_diagnostic_boundary(tmp_path):
    ref = reference(tmp_path, "fake.json", {"schemaVersion": "mcd-physical-capture/v1", "scenarioId": "MCD-SC-001", "status": "passed", "mcpErrors": 27, "observations": {"all": True}})
    with pytest.raises(AssertionError, match="observer"):
        physical(ref, "MCD-SC-001", tmp_path)


def test_diagnostic_raw_reference_and_current_source_hashes_are_required(tmp_path):
    source = tmp_path / "source.ts"; source.write_text("synthetic source-bound reader control")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    capture = {"schemaVersion": "mcd-physical-capture/v1", "scenarioId": "MCD-SC-001", "observer": {"role": "oid_observer", "readOnly": True, "databaseName":"synthetic_mcd"}, "sourceInputs": {"before":{"source.ts": source_hash},"after":{"source.ts": source_hash}}, "raw": {}}
    with pytest.raises(AssertionError, match="raw boundary"):
        load_physical(reference(tmp_path, "missing-raw.json", capture), "MCD-SC-001", tmp_path)
    capture["raw"] = {"rows": reference(tmp_path, "rows.json", {"synthetic": True})}
    ref = reference(tmp_path, "capture.json", capture)
    with pytest.raises(AssertionError, match="variant boundaries"): physical(ref, "MCD-SC-001", tmp_path)
    source.write_text("changed source")
    with pytest.raises(AssertionError, match="source drift"): load_physical(ref, "MCD-SC-001", tmp_path)


def test_foreign_scenario_or_tampered_file_does_not_pass_replay(tmp_path):
    ref = reference(tmp_path, "capture.json", {"schemaVersion": "mcd-physical-capture/v1", "scenarioId": "MCD-SC-002"})
    with pytest.raises(AssertionError, match="scenario binding"): load_physical(ref, "MCD-SC-001", tmp_path)
    (tmp_path / "capture.json").write_text("changed")
    with pytest.raises(AssertionError, match="hash mismatch"): load_physical(ref, "MCD-SC-002", tmp_path)


def protocol_control(root, mutation=None):
    """Synthetic reader control only; never published into runtime-inputs."""
    source=root/"source.ts"; source.write_text("synthetic reader source")
    source_hash=hashlib.sha256(source.read_bytes()).hexdigest()
    business={"source":"postgresql_observer","domainHashes":{k:"a"*64 for k in ("runs","tasks","actions","receipts","evaluations","ledger","bonuses")}}
    before={"source":"postgresql_observer",**{k:[] for k in ("cases","events","reports","batches","audits")}}
    variants=[]; all_events=[]
    for index,(name,stage) in enumerate({"malformed_json_rpc":"ingress","sdk_rejected_fields":"sdk_validation","expired_or_revoked_auth":"authentication","handler_failure":"handler","dispatch_failure":"dispatch","duplicate_operation":"admission"}.items()):
        trace=f"11111111-1111-4111-8111-{index:012d}"
        event={"eventId":trace,"traceId":trace,"caseId":None,"source":"server","stage":stage,"outcome":"error","errorCode":"INVALID_ARGUMENTS","startedAt":"2026-11-02T00:00:00.000Z","completedAt":"2026-11-02T00:00:00.001Z","durationMs":1}
        response={"httpStatus":400,"traceId":trace,"errorCode":"INVALID_ARGUMENTS"}
        after={**before,"events":[event]}
        documents={"request":{"method":"POST","path":"/mcp/user"},"response":response,"beforeBusiness":business,"afterBusiness":json.loads(json.dumps(business)),"beforeDiagnostic":before,"afterDiagnostic":after}
        if mutation and index==0: mutation(documents)
        variants.append({"name":name,**{key+"Ref":reference(root,f"{name}-{key}.json",v) for key,v in documents.items()}})
        all_events.append(event)
    restart={**before,"events":all_events}
    protocol={"beforeRestartRef":reference(root,"before-restart.json",restart),"afterRestartRef":reference(root,"after-restart.json",restart)}
    capture={"schemaVersion":"mcd-physical-capture/v1","scenarioId":"MCD-SC-001","observer":{"role":"oid_observer","readOnly":True,"databaseName":"synthetic_mcd"},"sourceInputs":{"before":{"source.ts":source_hash},"after":{"source.ts":source_hash}},"variants":variants,"raw":{"protocol":reference(root,"protocol.json",protocol)}}
    return reference(root,"capture.json",capture)


def test_protocol_reader_recomputes_trace_stage_timing_and_no_business_effect(tmp_path):
    assert all(physical(protocol_control(tmp_path),"MCD-SC-001",tmp_path).values())
    mutations=[
        lambda d:d["afterDiagnostic"]["events"][0].update(stage="handler"),
        lambda d:d["response"].update(traceId="not-observed"),
        lambda d:d["afterDiagnostic"]["events"][0].update(durationMs=-1),
        lambda d:d["afterBusiness"]["domainHashes"].update(ledger="b"*64),
        lambda d:d["afterDiagnostic"]["events"][0].update(caseId="foreign-case"),
    ]
    for index,mutation in enumerate(mutations):
        directory=tmp_path/str(index); directory.mkdir()
        with pytest.raises(AssertionError): physical(protocol_control(directory,mutation),"MCD-SC-001",directory)


def test_independent_classification_rejects_unknown_positive_conflicting_or_client_only_evidence():
    evidence={"independentlyVerified":True,"evidenceIds":["a"*64]}
    controls={"client_contract":{"serverValidationRejected":True,"compatibilityVerified":True,"schemaCompatible":True,"violationMatchesPins":True},"platform_contract":{"compatibilityVerified":True,"issuedOperationUnrepresentable":True},"client_runtime":{"clientExceptionReproduced":True,"matchingValidServerResponse":True},"platform_runtime":{"serverFailure":True,"dependencyCauseExcluded":True},"external_dependency":{"dependencyFailure":True,"competingCausesExcluded":True},"expected_policy_denial":{"policyMatched":True}}
    for category,facts in controls.items():
        assert classify({**evidence,**facts})==category
        assert classify({**evidence,**facts,"independentlyVerified":False})=="unknown"
        assert classify({**evidence,**facts,"conflicting":True})=="unknown"
        assert classify({**evidence,**facts,"ambiguousTransport":True})=="unknown"
    assert classify({**evidence,**controls["client_contract"],**controls["platform_runtime"]})=="unknown"


def envelope_control(root):
    """Source-bound synthetic reader control, never actual acceptance capture."""
    contract_path="packages/owner-identity/src/mcp-diagnostics-contract.ts"
    source=(Path(__file__).resolve().parents[3]/contract_path).read_text(encoding="utf-8-sig")
    file=root/contract_path;file.parent.mkdir(parents=True,exist_ok=True);file.write_text(source,encoding="utf-8")
    source_ref={"path":contract_path,"sha256":hashlib.sha256(file.read_bytes()).hexdigest()}
    schema=_source_envelope_schema(source);maximum=maximum_envelope_value(schema,source)
    proof={"schemaSourceRef":source_ref,"schemaRef":reference(root,"schema.json",schema),"maximumEnvelopeRef":reference(root,"maximum.json",maximum),"maximumResponseRef":reference(root,"response.json",{"httpStatus":200})}
    return proof,schema,maximum


def test_schema_dominance_is_recomputed_from_current_source_not_claimed_counter(tmp_path):
    proof,schema,maximum=envelope_control(tmp_path)
    bound=envelope_bound(proof,tmp_path)
    assert bound==len(json.dumps(maximum,sort_keys=True,ensure_ascii=False,separators=(",",":")).encode())<2048
    # Changing the exported enum without the pinned source cannot raise the bound.
    changed=json.loads(json.dumps(schema));changed["properties"]["errorCode"]["enum"].append("X"*3000)
    with pytest.raises(AssertionError,match="bound differs"):
        envelope_bound({**proof,"schemaRef":reference(tmp_path,"forged-schema.json",changed)},tmp_path)
    with pytest.raises(AssertionError,match="maximal envelope"):
        envelope_bound({**proof,"maximumEnvelopeRef":reference(tmp_path,"short.json",{k:v for k,v in maximum.items() if k!="errorCode"})},tmp_path)
    with pytest.raises(AssertionError,match="not accepted"):
        envelope_bound({**proof,"maximumResponseRef":reference(tmp_path,"denied.json",{"httpStatus":400})},tmp_path)
    changed_source=(tmp_path/proof["schemaSourceRef"]["path"]).read_text().replace("envelopeBytes:2048","envelopeBytes:4096")
    (tmp_path/proof["schemaSourceRef"]["path"]).write_text(changed_source)
    weakened_ref={"path":proof["schemaSourceRef"]["path"],"sha256":hashlib.sha256((tmp_path/proof["schemaSourceRef"]["path"]).read_bytes()).hexdigest()}
    with pytest.raises(AssertionError,match="ceiling changed"): envelope_bound({**proof,"schemaSourceRef":weakened_ref},tmp_path)


def test_dominated_byte_quota_requires_actual_earlier_blocker_and_reserved_row_hashes(tmp_path):
    proof,_,_=envelope_control(tmp_path);maximum=envelope_bound(proof,tmp_path)
    observation={"source":"postgresql_observer","queryKind":"diagnostic_allocation_aggregates","observer":{"role":"oid_observer","readOnly":True},"groups":[{"kind":"event","count":16384,"sumBytes":16384*maximum,"maxBytes":maximum,"rowsSha256":"a"*64},{"kind":"case","count":4,"sumBytes":2048,"maxBytes":512,"rowsSha256":"b"*64}],"reservedGroups":[]}
    probe={"limit":"ownerBytes","mode":"dominated","observationRef":reference(tmp_path,"before.json",observation),"afterObservationRef":reference(tmp_path,"after.json",observation),"blockingResponseRef":reference(tmp_path,"rejected.json",{"httpStatus":429})}
    limits={"ownerBytes":32*1024*1024,"ownerRows":16384,"ownerCases":128}
    sources={"server":"fresh.length+1+(segment?0:1) +512+(segment?0:256)"}
    capacity_probe(probe,tmp_path,maximum,limits,sources)
    for mutation in (lambda o:o["groups"][0].update(count=16383,sumBytes=16383*maximum),lambda o:o["reservedGroups"].append({"kind":"event","count":1,"sumBytes":maximum,"maxBytes":maximum,"rowsSha256":"c"*64})):
        changed=json.loads(json.dumps(observation));mutation(changed)
        with pytest.raises(AssertionError): capacity_probe({**probe,"observationRef":reference(tmp_path,"changed-before.json",changed),"afterObservationRef":reference(tmp_path,"changed-after.json",changed)},tmp_path,maximum,limits,sources)
    changed=json.loads(json.dumps(observation));changed["groups"][0]["rowsSha256"]="c"*64
    with pytest.raises(AssertionError,match="changed retained"):
        capacity_probe({**probe,"afterObservationRef":reference(tmp_path,"changed-after.json",changed)},tmp_path,maximum,limits,sources)
    with pytest.raises(AssertionError): capacity_probe(probe,tmp_path,maximum,{**limits,"ownerBytes":1024},sources)


def test_reference_attribution_replays_http_server_and_client_evidence_without_claiming_native_qualification(tmp_path):
    path='packages/owner-acceptance/src/mcp-diagnostics-classification.mjs'
    file=tmp_path/path;file.parent.mkdir(parents=True);file.write_bytes((Path(__file__).resolve().parents[3]/path).read_bytes())
    source={'path':path,'sha256':hashlib.sha256(file.read_bytes()).hexdigest()}
    profile={'implementation':'mcd_controlled_reference_sdk','clientPackage':'@modelcontextprotocol/client','version':'2.4.0','nativeClient':False}
    observation={'profile':profile,'verifierSource':source,'wire':[{'method':method,'callIdHash':'a'*64,'httpStatus':200} for method in ('initialize','tools/list','tools/call')],'clientResult':{'status':'ok','isError':False},'clientException':{'name':'TypeError'},'dependencyObservations':[],'serverObservations':[{'phase':'handler_entered','mode':'client_runtime','callIdHash':'a'*64}]}
    control={'name':'positive_client_runtime'}
    assert reference_causal_facts(control,[observation],tmp_path)=={'independentlyVerified':True,'clientExceptionReproduced':True,'matchingValidServerResponse':True}
    changed=json.loads(json.dumps(observation));changed['clientException']=None
    assert reference_causal_facts(control,[changed],tmp_path)=={'independentlyVerified':False}
    changed=json.loads(json.dumps(observation));changed['serverObservations'][0]['callIdHash']='b'*64
    with pytest.raises(AssertionError,match='call mismatch'):reference_causal_facts(control,[changed],tmp_path)
    changed=json.loads(json.dumps(observation));changed['profile']['nativeClient']=True
    with pytest.raises(AssertionError,match='unqualified'):reference_causal_facts(control,[changed],tmp_path)


def test_restored_effective_authority_requires_real_setting_owner_write_rejection_and_excluded_credentials(tmp_path):
    database='oid_restore_'+'a'*32
    proof={'source':'postgresql_observer','observer':{'role':'oid_observer','readOnly':True,'databaseName':database},'databaseSettings':[{'databaseName':database,'setconfig':['default_transaction_read_only=on']}],'ownerWriteProbe':{'role':'oid_owner','databaseName':database,'defaultTransactionReadOnly':'on','transactionReadOnly':'on','sqlState':'25006'},'helperAuthorityTables':[{'name':name,'count':0} for name in ('oid_diagnostic_oauth_request','oid_diagnostic_oauth_grant','oid_diagnostic_oauth_token')],'rawAccessGrants':[{'id':'reference-native-history'}],'rawExecutionLeases':[{'id':'reference-lease-history'}],'effectiveAccessGrants':[],'effectiveExecutionLeases':[],'servedApi':False,'apiProbe':{'url':'http://127.0.0.1:8784/healthz','outcome':'connection_refused','errorCode':'ECONNREFUSED'}}
    assert restore_readonly_fence(reference(tmp_path,'fence.json',proof),tmp_path)==proof
    for mutation in [lambda p:p['databaseSettings'][0].update(setconfig=[]),lambda p:p['ownerWriteProbe'].update(sqlState='00000'),lambda p:p['helperAuthorityTables'][0].update(count=1),lambda p:p.update(effectiveAccessGrants=[{'id':'restored-authority'}]),lambda p:p.update(apiProbe={}),lambda p:p['ownerWriteProbe'].update(databaseName='other')]:
        changed=json.loads(json.dumps(proof));mutation(changed)
        with pytest.raises(AssertionError):restore_readonly_fence(reference(tmp_path,'bad-fence.json',changed),tmp_path)


def test_operator_tamper_rejection_uses_actual_cipher_hashes_not_an_invented_http_status(tmp_path):
    def binary(name,content):
        file=tmp_path/name;file.write_bytes(content);return {'path':name,'sha256':hashlib.sha256(content).hexdigest()}
    original=binary('original.enc',b'synthetic encrypted control bytes');tampered=binary('tampered.enc',b'Synthetic encrypted control bytes')
    inventory={'schemaVersion':'beta-backup-inventory/v2','files':[{'path':'checkpoint.bundle.enc','kind':'sealed_bundle','bytes':(tmp_path/'original.enc').stat().st_size,'sha256':original['sha256']}]}
    response={'boundary':'unified_backup_restore_verifier','outcome':'rejected','errorCode':'beta_backup_file_integrity','checkpointInventoryRef':reference(tmp_path,'inventory.json',inventory),'beforeBundleRef':original,'afterTamperRef':tampered}
    restore_tamper_rejection(response,tmp_path)
    for change in ({'httpStatus':422},{'errorCode':'unverified_failure'},{'afterTamperRef':original}):
        with pytest.raises(AssertionError):restore_tamper_rejection({**response,**change},tmp_path)
    (tmp_path/'original.enc').write_bytes(b'changed original')
    with pytest.raises(AssertionError):restore_tamper_rejection(response,tmp_path)


def test_full_restore_preserves_every_table_except_exact_three_helper_authority_data_tables(tmp_path):
    names=['oid_diagnostic_oauth_request','oid_diagnostic_oauth_grant','oid_diagnostic_oauth_token']
    tables={name:{'rowCount':2,'sha256':'a'*64} for name in names};tables['oid_ledger_entry']={'rowCount':3,'sha256':'b'*64}
    sequence='c'*64;empty={'rowCount':0,'sha256':hashlib.sha256(b'').hexdigest()}
    def snapshot(rows,database):return {'schemaVersion':'beta-combined-source-observation/v1','sourceDatabase':database,'observerIdentity':{'databaseRole':'oid_observer','databaseName':database,'transactionReadOnly':'on'},'tableFingerprints':rows,'sequenceSha256':sequence,'databaseTotalsSha256':digest({'tableFingerprints':rows,'sequenceSha256':sequence})}
    before=snapshot(tables,'oid_acceptance_'+'a'*32);expected={**tables,**{name:empty for name in names}};target=snapshot(expected,'oid_restore_'+'b'*32)
    source={'source':'postgresql_observer','before':before,'after':before};restored={'source':'postgresql_observer','observer':{'databaseName':target['sourceDatabase']},'snapshot':target}
    inventory={'restoreDataPolicy':{'schemaVersion':'beta-diagnostic-helper-authority-exclusion/v1','excludedTableData':names,'sourceTableFingerprints':{name:tables[name] for name in names},'restoredTableFingerprints':{name:empty for name in names},'sourceDatabaseTotalsSha256':before['databaseTotalsSha256'],'restorableDatabaseTotalsSha256':target['databaseTotalsSha256']}}
    restore={'fullSourceRef':reference(tmp_path,'full-source.json',source),'fullRestoredDatabaseRef':reference(tmp_path,'full-restored.json',restored)}
    restore_full_database(restore,tmp_path,inventory)
    changed=json.loads(json.dumps(restored));changed['snapshot']['tableFingerprints']['oid_ledger_entry']['sha256']='d'*64;changed['snapshot']['databaseTotalsSha256']=digest({'tableFingerprints':changed['snapshot']['tableFingerprints'],'sequenceSha256':sequence})
    with pytest.raises(AssertionError,match='beyond exact three'):restore_full_database({**restore,'fullRestoredDatabaseRef':reference(tmp_path,'bad-restored.json',changed)},tmp_path,inventory)
    policy=json.loads(json.dumps(inventory));policy['restoreDataPolicy']['excludedTableData'].append('oid_ledger_entry')
    with pytest.raises(AssertionError,match='exclusion declaration'):restore_full_database(restore,tmp_path,policy)


def test_final_partial_watermark_ack_does_not_claim_complete_capture():
    receipt={"caseId":"case","segmentId":"segment","highestContiguousSequence":0,"highestContiguousHash":"a"*64,"reportId":"report","reportCreated":True,"diagnosticsSynced":True,"completion":"partial"}
    doc={"source":"postgresql_observer","cases":[{"caseId":"case","captureState":"partial"}],"reports":[{"caseId":"case","id":"report"}],"batches":[{"caseId":"case","segmentId":"segment","batchSequence":0,"payloadHash":"a"*64,"completion":"partial"}]}
    _watermark(doc,receipt)
    for change in ({"completion":"open"},{"highestContiguousSequence":1},{"reportCreated":False},{"diagnosticsSynced":False}):
        with pytest.raises(AssertionError): _watermark(doc,{**receipt,**change})
    doc["cases"][0]["captureState"]="complete"
    with pytest.raises(AssertionError): _watermark(doc,receipt)


def test_snapshot_maximum_is_conditional_on_pinned_source_guard():
    source=Path("packages/owner-identity/src/mcp-diagnostics-contract.ts").read_text(encoding="utf-8-sig")
    schema=_source_envelope_schema(source)
    maximum=maximum_envelope_value(schema,source)
    assert maximum["source"]=="client" and maximum["stage"]=="client_runtime" and maximum["outcome"]=="error"
    assert len(json.dumps(maximum,sort_keys=True,separators=(",",":")).encode())<2048
    with pytest.raises(AssertionError): maximum_envelope_value(schema,source.replace("value.source!=='client'","value.source!=='server'"))


def test_active_crash_preserves_correlated_last_observation_without_grade_authority():
    pair={"clientRunStatus":"running","clientRunObservedAt":"2026-11-02T00:00:00.000Z"}
    native={"selection":{"intentId":"intent"},"lastRunObservation":pair,"calls":[{"tool":"runs.current_task","callIdHash":"a"*64,"outcome":"success"}]}
    local={"source":"sqlite_observer","observer":{"readOnly":True},"runObservation":{"runId":"run","status":"running","observedAt":pair["clientRunObservedAt"],"sourceCallIdHash":"a"*64,"sourceTool":"runs.current_task","terminal":False}}
    variant={"afterDiagnostic":{"source":"postgresql_observer","cases":[{"caseId":"case","intentId":"intent","runId":"run"}],"events":[{"caseId":"case","source":"client","stage":"client_runtime","outcome":"error","responsibility":"unknown","startedAt":"2026-11-02T00:00:01.000Z","completedAt":"2026-11-02T00:00:01.000Z","durationMs":0,**pair}]}}
    assert active_crash_observation(native,local,variant)==pair
    for change in ({"sourceCallIdHash":"b"*64},{"status":"completed"},{"observedAt":"2026-11-02T00:00:02.000Z"},{"runId":"other-run"},{"terminal":True}):
        with pytest.raises(AssertionError): active_crash_observation(native,{**local,"runObservation":{**local["runObservation"],**change}},variant)
    unknown_native=json.loads(json.dumps(native));unknown_local=json.loads(json.dumps(local));unknown_variant=json.loads(json.dumps(variant))
    unknown_native["lastRunObservation"]["clientRunStatus"]="unknown";unknown_local["runObservation"]["status"]="unknown";unknown_variant["afterDiagnostic"]["events"][0]["clientRunStatus"]="unknown"
    assert active_crash_observation(unknown_native,unknown_local,unknown_variant)["clientRunStatus"]=="unknown"
    del unknown_local["runObservation"]["terminal"]
    with pytest.raises(AssertionError): active_crash_observation(unknown_native,unknown_local,unknown_variant)
    variant["afterDiagnostic"]["events"][0]["responsibility"]="platform_runtime"
    with pytest.raises(AssertionError): active_crash_observation(native,local,variant)


def test_browser_bundle_overflow_rejects_before_http_and_cannot_be_forged_as_413():
    exact={"bytes":8*1024*1024,"httpStatus":200,"browser":{"action":"file_select_and_click","fileBytes":8*1024*1024}}
    bundle_size_boundary(exact,b'{"schemaVersion":"synthetic-reader-control"}')
    over={"bytes":8*1024*1024+1,"boundary":"owner_browser_file_size_guard","browser":{"action":"file_select","fileBytes":8*1024*1024+1,"validationText":"Diagnostic export exceeds 8 MiB.","importDisabled":True,"uploadRequests":[]}}
    bundle_size_boundary(over,b'not-read-by-size-guard')
    for change in ({"httpStatus":413},{"boundary":"fake-http-guard"},{"browser":{**over["browser"],"uploadRequests":[{"method":"POST"}]}},{"browser":{**over["browser"],"importDisabled":False}},{"browser":{**over["browser"],"fileBytes":1}}):
        with pytest.raises(AssertionError): bundle_size_boundary({**over,**change},b'not-read-by-size-guard')
    with pytest.raises(AssertionError): bundle_size_boundary({**exact,"httpStatus":413},b'{}')


def test_replica_race_requires_real_distinct_listeners_lock_overlap_and_immutable_rows(tmp_path):
    build=reference(tmp_path,"packages/owner-identity/dist/server.js",{"synthetic":"reader mutation control only"})
    lock=reference(tmp_path,"locks.json",{"source":"postgresql_observer","observer":{"role":"oid_observer","readOnly":True,"databaseName":"oid_acceptance_control"},"queryKind":"ungranted_locks_same_disposable_database_owner_role","rows":[{"n":3}]})
    old={"eventId":"old","caseId":"case"};new={"eventId":"new","caseId":"case"};batch={"caseId":"case","segmentId":"segment","batchSequence":0,"payloadHash":"a"*64}
    before={"source":"postgresql_observer","events":[old],"batches":[],"reports":[{"id":"report"}],"cases":[{"caseId":"case","ownerId":"owner"}]};after={**before,"events":[old,new],"batches":[batch]};race={"beforeDiagnostic":before,"afterDiagnostic":after}
    receipt={"caseId":"case","segmentId":"segment","highestContiguousHash":"a"*64}
    attempts=[{"actor":"helper","httpStatus":200,"transport":{"remotePort":8784},"receipt":receipt,"request":{"segmentId":"segment","payloadHash":"a"*64,"eventId":"new"}},{"actor":"replica","httpStatus":429,"errorCode":"DIAGNOSTICS_QUOTA_EXCEEDED","transport":{"remotePort":8785},"request":{"segmentId":"second","payloadHash":"b"*64,"eventId":"second"}},{"actor":"owner_import","httpStatus":429,"errorCode":"DIAGNOSTICS_QUOTA_EXCEEDED","browser":{"action":"click","requestPath":"/api/owner/diagnostics/import"},"request":{"segmentId":"third","payloadHash":"c"*64,"eventId":"third"}}]
    def allocation(count): return {"source":"postgresql_observer","observer":{"role":"oid_observer","readOnly":True},"queryKind":"diagnostic_allocation_aggregates","scope":{"ownerId":"owner"},"reservedGroups":[],"groups":[{"kind":"batch","count":count,"sumBytes":count*512,"maxBytes":512,"rowsSha256":"a"*64}]}
    before_ref=reference(tmp_path,"owner-before.json",allocation(16381));after_ref=reference(tmp_path,"owner-after.json",allocation(16384))
    control={"actors":["helper","owner_import","replica"],"source":"postgresql_observer","ownerId":"owner","waitingLockConnections":3,"lockObservationRef":lock,"ownerReservationBeforeRef":before_ref,"ownerReservationAfterRef":after_ref,"replica":{"boundary":"actual_same_build_disposable_database_replica","databaseName":"oid_acceptance_control","primaryPort":8784,"replicaPort":8785,"serverBuildSha256":build["sha256"],"serverBuildRef":build},"retainedBeforeHashes":{"old":digest(old)},"retainedAfterHashes":{"old":digest(old)},"caseId":"case","segmentId":"segment","payloadHash":"a"*64,"newEventIds":["new"],"newBatches":[batch],"attempts":attempts}
    concurrent_reservation_boundary(control,race,tmp_path)
    for change in ({"waitingLockConnections":2},{"attempts":attempts[:2]},{"retainedAfterHashes":{}},{"newBatches":[]},{"newEventIds":[]},{"ownerReservationAfterRef":reference(tmp_path,"owner-too-many.json",allocation(16385))}):
        with pytest.raises(AssertionError): concurrent_reservation_boundary({**control,**change},race,tmp_path)
    changed=json.loads(json.dumps(control));changed["attempts"][1]["transport"]["remotePort"]=8784
    with pytest.raises(AssertionError): concurrent_reservation_boundary(changed,race,tmp_path)
    changed=json.loads(json.dumps(control));changed["attempts"][1]["httpStatus"]=200
    with pytest.raises(AssertionError): concurrent_reservation_boundary(changed,race,tmp_path)
    changed=json.loads(json.dumps(control));changed["attempts"][1]["request"]=changed["attempts"][0]["request"]
    with pytest.raises(AssertionError): concurrent_reservation_boundary(changed,race,tmp_path)
    changed_race=json.loads(json.dumps(race));changed_race["afterDiagnostic"]["events"][0]["tampered"]=True
    with pytest.raises(AssertionError): concurrent_reservation_boundary(control,changed_race,tmp_path)


def test_windows_host_capacity_requires_bound_original_jobs_and_fresh_capture_database_observations(tmp_path):
    capture="11111111-1111-4111-8111-111111111111";job_id="22222222-2222-4222-8222-222222222222"
    sources={}
    for name in ("tools/mcd-local-capacity-host.mjs","tools/mcd-local-capacity-restore.mjs","tools/mcp-diagnostics-client.mjs"):
        file=tmp_path/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_text("synthetic reader control, not executable acceptance")
        sources[name]=hashlib.sha256(file.read_bytes()).hexdigest()
    job={"schemaVersion":"mcd-local-capacity-host-job/v1","captureId":capture,"jobId":job_id,"sourceInputs":sources};job_ref=reference(tmp_path,"job.json",job)
    counts=[{"cases":3,"events":4,"reports":2}];local={"capacityProbes":[{"limit":name} for name in ("localBytes","localRows","localCases")],"localRetention":{"serverRowsBefore":counts,"serverRowsAfter":counts}}
    result={"schemaVersion":"mcd-local-capacity-host-result/v1","captureId":capture,"jobId":job_id,"jobSha256":job_ref["sha256"],"probeId":capture+"-host-"+job_id,"host":{"platform":"win32","nodeVersion":"v24.14.1"},"sourceInputs":{"before":sources,"after":sources},"local":local}
    pairs=[]
    for sequence,request_id in enumerate(("33333333-3333-4333-8333-333333333333","44444444-4444-4444-8444-444444444444")):
        request={"schemaVersion":"mcd-local-server-counts/v1","captureId":capture,"jobId":job_id,"requestId":request_id,"sequence":sequence,"kind":"read_server_rows"}
        response={k:v for k,v in request.items() if k!="kind"};response.update(source="postgresql_observer",observer={"role":"oid_observer","readOnly":True,"databaseName":"oid_acceptance_"+capture.replace("-","")},rows=counts)
        pairs.append({"requestRef":reference(tmp_path,f"request{sequence}.json",request),"responseRef":reference(tmp_path,f"response{sequence}.json",response)})
    evidence={"schemaVersion":"mcd-local-capacity-host-evidence/v1","jobRef":job_ref,"resultRef":reference(tmp_path,"result.json",result),"serverObservations":pairs};quota={"capacityProbes":local["capacityProbes"]}
    windows_host_capacity(reference(tmp_path,"evidence.json",evidence),quota,tmp_path)
    changed=json.loads(json.dumps(result));changed["host"]["platform"]="linux"
    with pytest.raises(AssertionError):windows_host_capacity(reference(tmp_path,"wrong-host-evidence.json",{**evidence,"resultRef":reference(tmp_path,"wrong-host.json",changed)}),quota,tmp_path)
    response=json.loads((tmp_path/"response1.json").read_text());response["observer"]["databaseName"]="owner_identity"
    wrong_pair={**pairs[1],"responseRef":reference(tmp_path,"foreign-response.json",response)}
    with pytest.raises(AssertionError):windows_host_capacity(reference(tmp_path,"foreign-evidence.json",{**evidence,"serverObservations":[pairs[0],wrong_pair]}),quota,tmp_path)
    with pytest.raises(AssertionError):windows_host_capacity(reference(tmp_path,"reused-evidence.json",{**evidence,"serverObservations":[pairs[0],pairs[0]]}),quota,tmp_path)


def test_anonymous_detail_exhaustion_keeps_a_verified_successful_mcp_response(tmp_path):
    observed={"source":"postgresql_observer","observer":{"role":"oid_observer","readOnly":True},"queryKind":"diagnostic_allocation_aggregates","reservedGroups":[],"groups":[{"kind":"event","count":2048,"sumBytes":204800,"maxBytes":100,"rowsSha256":"a"*64}]}
    observation=reference(tmp_path,"anon-observation.json",observed)
    response={"httpStatus":200,"captureState":"unavailable","resultKind":"tools","toolCount":8,"wire":{"framing":"sse","rootKeys":["jsonrpc","id","result"],"hasMcpResponse":True,"resultIsError":False,"rpcErrorCode":None}}
    probe={"limit":"anonymousRows","mode":"exact_over","observationRef":observation,"afterObservationRef":observation,"blockingResponseRef":reference(tmp_path,"anon-block.json",response),"acceptedResponseRef":reference(tmp_path,"anon-accepted.json",response)}
    capacity_probe(probe,tmp_path,1168,{"anonymousRows":2048},{})
    for change in ({"httpStatus":500,"errorCode":"INTERNAL_ERROR"},{"httpStatus":429},{"captureState":"recorded"},{"toolCount":0},{"wire":{**response["wire"],"resultIsError":True}},{"wire":{**response["wire"],"rpcErrorCode":-32602}}):
        with pytest.raises(AssertionError):capacity_probe({**probe,"blockingResponseRef":reference(tmp_path,"bad-anon-block.json",{**response,**change})},tmp_path,1168,{"anonymousRows":2048},{})


def test_anonymous_overflow_requires_actual_fixed_buckets_and_increasing_loss_count(tmp_path):
    database="oid_acceptance_control";before={"source":"postgresql_observer","observer":{"role":"oid_observer","readOnly":True,"databaseName":database},"rows":[{"bucket":i,"dropped_count":"0"} for i in range(128)]};after=json.loads(json.dumps(before));after["rows"][1]["dropped_count"]="3"
    b=reference(tmp_path,"bucket-before.json",before);a=reference(tmp_path,"bucket-after.json",after);value={"before":128,"after":128,"newAllocationRows":[],"beforeRef":b,"afterRef":a}
    anonymous_bucket_boundary(value,tmp_path,database)
    for changed in (before,{**after,"rows":after["rows"]+[{"bucket":128,"dropped_count":"1"}]},{**after,"observer":{**after["observer"],"databaseName":"foreign"}}):
        with pytest.raises(AssertionError):anonymous_bucket_boundary({**value,"afterRef":reference(tmp_path,"bad-buckets.json",changed)},tmp_path,database)


def test_expired_original_owner_export_is_valid_before_purge_and_terminal_after_actual_purge(tmp_path):
    database="oid_acceptance_control";observer={"role":"oid_observer","readOnly":True,"databaseName":database};case={"caseId":"case","diagnosticSessionId":"session","ownerId":"owner","agentId":"agent","connectionId":"connection"}
    batch={"segmentId":"segment","batchSequence":0,"events":[],"completion":"complete"};batch["payloadHash"]=digest(batch)
    body={"diagnosticSessionId":"session","caseId":"case","binding":{"agentId":"agent","connectionId":"connection"},"batch":batch}
    original_case=reference(tmp_path,"original-case.json",{"source":"postgresql_observer","observer":observer,**case});before=reference(tmp_path,"original-db.json",{"source":"postgresql_observer","observer":observer,"cases":[case],"batches":[{"caseId":"case",**{k:batch[k] for k in ("segmentId","batchSequence","payloadHash")}}]})
    full=reference(tmp_path,"full-source.json",{"before":{"tableFingerprints":{"oid_mcp_diagnostic_case":{"rowCount":4096},"oid_mcp_diagnostic_event":{"rowCount":130018}}}})
    purge={"source":"postgresql_observer","observer":observer,"counts":[{"cases":0,"events":0}],"retention":[{"caseCount":4096,"eventCount":130018}]};purge_ref=reference(tmp_path,"purged.json",purge)
    response=reference(tmp_path,"expired.json",{"httpStatus":410,"errorCode":"REPORT_RETENTION_EXPIRED"})
    controls=[{"kind":"original_owned_export_after_purge","requestRef":reference(tmp_path,"original-request.json",body),"responseRef":response,"originalCaseRef":original_case,"preExpiryResponseRef":reference(tmp_path,"before-expiry.json",{"httpStatus":200})},{"kind":"fresh_owned_export","requestRef":reference(tmp_path,"fresh-request.json",{**{k:v for k,v in body.items() if k!="caseId"},"diagnosticSessionId":"fresh"}),"responseRef":response}]
    restore={"ownerIntakeControls":controls,"beforeDatabaseRef":before,"fullSourceRef":full,"purgeObservationRef":purge_ref};expired_owner_exports(restore,tmp_path)
    for change in ({"purgeObservationRef":reference(tmp_path,"not-yet-purged.json",{**purge,"counts":[{"cases":1,"events":1}]})},{"ownerIntakeControls":[{**controls[0],"requestRef":reference(tmp_path,"invalid-original.json",{**body,"diagnosticSessionId":"wrong"})},controls[1]]},{"ownerIntakeControls":[{**controls[0],"responseRef":reference(tmp_path,"missing.json",{"httpStatus":404})},controls[1]]}):
        with pytest.raises(AssertionError):expired_owner_exports({**restore,**change},tmp_path)


def native_delivery_control(root):
    """Synthetic reader mutation inputs ONLY, never a physical SC002 capture."""
    import copy
    receipt={"caseId":"case","segmentId":"segment","highestContiguousSequence":0,"highestContiguousHash":"a"*64,"reportId":"report","reportCreated":True,"diagnosticsSynced":True,"completion":"complete"}
    diagnostic={"source":"postgresql_observer","cases":[{"caseId":"case","intentId":"intent","runId":None,"ownerId":"owner"}],"reports":[{"caseId":"case","id":"report"}],"batches":[{"caseId":"case","segmentId":"segment","batchSequence":0,"payloadHash":"a"*64,"completion":"complete"}],"events":[{"eventId":"first","source":"client"}],"audits":[{"reportId":"report","revision":1,"eventType":"submitted"}]}
    def ref(name,value):return reference(root,name+'.json',value)
    request={"caseId":"case","segmentId":"segment","batchSequence":0,"payloadHash":"a"*64}
    race={"attempts":[{"actor":actor,"startedAt":"2026-11-02T00:00:00.000Z","completedAt":"2026-11-02T00:00:00.100Z","request":dict(request),"response":{"httpStatus":200,"receipt":copy.deepcopy(receipt)}} for actor in ("owner","helper")]}
    bound=copy.deepcopy(diagnostic);bound["cases"][0]["runId"]="run"
    appended=copy.deepcopy(bound);appended["events"].append({"eventId":"second","source":"client"});appended["batches"].append({"caseId":"case","segmentId":"segment","batchSequence":1,"payloadHash":"b"*64,"completion":"complete"})
    late={"beforeBindingRef":ref("pre-binding",diagnostic),"afterBindingRef":ref("bound",bound),"beforeAppendRef":ref("pre-append",bound),"afterAppendRef":ref("appended",appended)}
    local={"source":"sqlite_observer","observer":{"readOnly":True},"case":{"localCaseId":"local","caseId":"case","diagnosticSessionId":"session","reportId":"report"},"batches":[{"segmentId":"segment","batchSequence":0,"payloadHash":"a"*64}]}
    restart={**{k:ref(k,local) for k in ("beforeOutboxRef","afterOutboxRef","restoredOutboxRef")},**{k:ref(k,diagnostic) for k in ("beforeDiagnosticRef","afterDiagnosticRef","restoredDiagnosticRef")}}
    drop={"kind":"admission_response_dropped","runId":"run","taskIndex":0,"operationIdHash":"c"*64,"actionId":"action","httpStatus":200,"droppedAt":"2026-11-02T00:00:00.000Z"}
    replay={**drop,"kind":"admission_retry_response","replayed":True,"enteredAt":"2026-11-02T00:00:00.001Z"}
    transport={"boundary":"actual_origin_preserving_loopback_proxy","observationOverflowCount":0,"observations":[drop,replay]}
    native={"localToolCalls":[],"calls":[{"tool":"runs.task_action","outcome":"success"}]}
    base={"beforeDiagnostic":copy.deepcopy(diagnostic),"afterDiagnostic":copy.deepcopy(diagnostic),"response":{"receipt":copy.deepcopy(receipt)}}
    variants={k:copy.deepcopy(base) for k in ("refused_endpoint_and_recovery","lost_report_response","lost_admission_response","failed_report_retry_no_recursion","owner_import_races_helper","late_run_binding_and_batches","restart_and_restore")}
    variants["refused_endpoint_and_recovery"]["response"]["attempts"]=[{"socketRefusal":{"transport":"tcp","endpoint":"loopback_reserved_then_closed","errorCode":"CONNECTION_REFUSED","credentialBytesSent":0}}]
    variants["lost_report_response"]["response"]["attempts"]=[{"httpStatus":200,"controlledResponseLoss":True,"receipt":copy.deepcopy(receipt)},{"httpStatus":200,"receipt":copy.deepcopy(receipt)}]
    variants["lost_admission_response"]["response"].update(transportRef=ref("transport",transport),nativeRef=ref("native",native))
    variants["failed_report_retry_no_recursion"]["response"].update(attempts=[{"httpStatus":429,"errorCode":"REPORT_RATE_LIMITED","retryAfterMs":1000},{"httpStatus":200,"receipt":copy.deepcopy(receipt)}],actualWaitMs=1001,identicalPayloadHash="a"*64)
    variants["owner_import_races_helper"]["response"]["evidenceRef"]=ref("race",race)
    variants["late_run_binding_and_batches"]["response"].update(evidenceRef=ref("late",late),receipt={**receipt,"highestContiguousSequence":1,"highestContiguousHash":"b"*64})
    variants["restart_and_restore"]["response"]["evidenceRef"]=ref("restart",restart)
    return variants,{"race":race,"late":late,"restart":restart,"transport":transport,"diagnostic":diagnostic,"local":local}


def test_native_reader_requires_real_fault_then_same_identity_recovery_and_sync(tmp_path):
    import copy
    variants,proof=native_delivery_control(tmp_path);native_delivery_boundaries(variants,tmp_path)
    mutations=[lambda v:v["refused_endpoint_and_recovery"]["response"].update(attempts=[]),lambda v:v["lost_report_response"]["response"]["attempts"][0].update(controlledResponseLoss=False),lambda v:v["lost_report_response"]["response"]["attempts"][1]["receipt"].update(highestContiguousHash="d"*64),lambda v:v["failed_report_retry_no_recursion"]["response"].update(actualWaitMs=0),lambda v:v["failed_report_retry_no_recursion"]["response"].update(identicalPayloadHash="d"*64),lambda v:v["failed_report_retry_no_recursion"]["response"]["receipt"].update(diagnosticsSynced=False)]
    for mutate in mutations:
        changed=copy.deepcopy(variants);mutate(changed)
        with pytest.raises(AssertionError):native_delivery_boundaries(changed,tmp_path)
    for key,value in (("actionId","other-action"),("operationIdHash","d"*64),("replayed",False)):
        changed=copy.deepcopy(proof["transport"]);changed["observations"][1][key]=value
        variants["lost_admission_response"]["response"]["transportRef"]=reference(tmp_path,"changed-transport.json",changed)
        with pytest.raises(AssertionError):native_delivery_boundaries(variants,tmp_path)


def test_native_owner_helper_race_must_overlap_and_share_original_keys_and_report(tmp_path):
    import copy
    variants,proof=native_delivery_control(tmp_path);variant=variants["owner_import_races_helper"]
    owner_helper_race(variant,tmp_path)
    for mutation in (lambda p:p["attempts"][1].update(actor="owner"),lambda p:p["attempts"][1].update(startedAt="2026-11-02T00:00:01.000Z"),lambda p:p["attempts"][1]["request"].update(payloadHash="c"*64),lambda p:p["attempts"][1]["response"]["receipt"].update(reportId="second-report")):
        changed=copy.deepcopy(proof["race"]);mutation(changed)
        variant["response"]["evidenceRef"]=reference(tmp_path,"changed-race.json",changed)
        with pytest.raises(AssertionError):owner_helper_race(variant,tmp_path)


def test_native_report_pending_response_requires_actual_pinned_rate_cause(tmp_path):
    variants,_=native_delivery_control(tmp_path)
    policy=Path("packages/owner-identity/src/report-service.ts").read_text(encoding="utf-8-sig")
    policy_file=tmp_path/"packages/owner-identity/src/report-service.ts";policy_file.parent.mkdir(parents=True);policy_file.write_text(policy)
    import re
    limits={key:int(re.search(r"const "+name+r"\s*=\s*(\d+)",policy).group(1)) for key,name in (("minute","REPORTS_PER_MINUTE_PER_PRINCIPAL"),("hour","REPORTS_PER_HOUR_PER_OWNER"))}
    response=variants["failed_report_retry_no_recursion"]["response"]
    response["attempts"][0]={"httpStatus":200,"receipt":{"reportCreated":False,"diagnosticsSynced":False}}
    rate={"source":"postgresql_observer","observer":{"readOnly":True},"rows":[{"scope":"principal_minute","windowStart":120,"observedSeconds":121,"requestCount":limits["minute"]}],"limits":limits}
    response["rateFailureRef"]=reference(tmp_path,"rate.json",rate);native_delivery_boundaries(variants,tmp_path)
    for change in ({"rows":[{**rate["rows"][0],"requestCount":0}]},{"limits":{**limits,"minute":0}},{"rows":[{**rate["rows"][0],"windowStart":60}]}):
        response["rateFailureRef"]=reference(tmp_path,"wrong-rate.json",{**rate,**change})
        with pytest.raises(AssertionError):native_delivery_boundaries(variants,tmp_path)


def test_native_late_binding_and_append_cannot_be_proved_by_unchanged_names(tmp_path):
    import copy
    variants,proof=native_delivery_control(tmp_path);variant=variants["late_run_binding_and_batches"]
    late_native_binding(variant,tmp_path)
    for field,document in (("afterBindingRef",proof["diagnostic"]),("afterAppendRef",proof["diagnostic"]),("beforeBindingRef",{**proof["diagnostic"],"reports":[]})):
        changed=copy.deepcopy(proof["late"]);changed[field]=reference(tmp_path,"wrong-late-rows.json",document)
        variant["response"]["evidenceRef"]=reference(tmp_path,"changed-late.json",changed)
        with pytest.raises(AssertionError):late_native_binding(variant,tmp_path)


def test_native_restart_and_restore_preserve_readonly_actual_outbox_and_server_rows(tmp_path):
    import copy
    variants,proof=native_delivery_control(tmp_path);variant=variants["restart_and_restore"]
    native_restart_restore(variant,tmp_path)
    for key,document in (("restoredOutboxRef",{**proof["local"],"batches":[]}),("afterOutboxRef",{**proof["local"],"case":{**proof["local"]["case"],"reportId":"new"}}),("restoredDiagnosticRef",{**proof["diagnostic"],"reports":[]})):
        changed=copy.deepcopy(proof["restart"]);changed[key]=reference(tmp_path,"wrong-restore-rows.json",document)
        variant["response"]["evidenceRef"]=reference(tmp_path,"changed-restart.json",changed)
        with pytest.raises(AssertionError):native_restart_restore(variant,tmp_path)


def test_native_missing_consent_scope_and_audience_require_three_distinct_real_requests(tmp_path):
    import copy
    for file in ("mcp-diagnostics-oauth.ts","mcp-diagnostics-routes.ts"):
        target=tmp_path/"packages/owner-identity/src"/file;target.parent.mkdir(parents=True,exist_ok=True);target.write_text((Path("packages/owner-identity/src")/file).read_text(encoding="utf-8-sig"))
    grant={"scope":"diagnostics:write offline_access","resource":"http://127.0.0.1:3000/api/diagnostics"}
    origin="http://127.0.0.1:3000"
    query={"client_id":"w3bench-diagnostics-helper-v1","redirect_uri":"http://127.0.0.1:38766/diagnostics/callback","response_type":"code","code_challenge_method":"S256","code_challenge":"A"*43,"state":"mcd_diagnostic_negative_probe_20261102",**grant}
    proof={}
    for name in ("missing_consent","wrong_scope","wrong_audience"):
        request={"source":"http_transport","origin":origin,"method":"POST","path":"/api/diagnostics/cases","headers":{"content-type":"application/json"}} if name=="missing_consent" else {"source":"http_transport","origin":origin,"method":"GET","path":"/api/diagnostics/oauth/authorize","query":{**query,**({"scope":"diagnostics:read"} if name=="wrong_scope" else {"resource":origin+"/api/agent/mcp"})}}
        response={"httpStatus":401,"errorCode":"DIAGNOSTICS_UNAUTHORIZED"} if name=="missing_consent" else {"httpStatus":400,"errorCode":"INVALID_DIAGNOSTIC_AUTHORIZATION"}
        proof[name]={"requestRef":reference(tmp_path,name+"-request.json",request),"responseRef":reference(tmp_path,name+"-response.json",response)}
    variant={"response":{"evidenceRef":reference(tmp_path,"capabilities.json",proof)}};denied_helper_capabilities(variant,tmp_path,grant)
    for name in ("wrong_scope","wrong_audience"):
        changed=copy.deepcopy(proof);changed[name]=changed["missing_consent"]
        variant["response"]["evidenceRef"]=reference(tmp_path,"wrong-capabilities.json",changed)
        with pytest.raises(AssertionError):denied_helper_capabilities(variant,tmp_path,grant)
