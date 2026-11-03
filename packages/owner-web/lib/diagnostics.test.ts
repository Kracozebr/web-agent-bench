import assert from "node:assert/strict";
import test from "node:test";
import { diagnosticCoverageText, diagnosticResponsibilityText, diagnosticSummary, diagnosticTrustText, isDiagnosticCallback, parseDiagnosticBundle } from "./diagnostics";

test("missing diagnostic coverage never becomes an error-free successful run", () => {
  for (const captureState of ["open", "partial", "partial_quota", "unavailable"] as const) {
    assert.match(diagnosticSummary({ captureState, eventCount: 0, errorCount: 0 }), /coverage is incomplete/);
    assert.doesNotMatch(diagnosticCoverageText(captureState), /capture complete/);
  }
  assert.match(diagnosticSummary({ captureState: "complete", eventCount: 10, errorCount: 2 }), /2 errors \/ 10 events in the declared capture/);
  for (const counts of [{ eventCount: 1, errorCount: 2 }, { eventCount: -1, errorCount: 0 }, { eventCount: NaN, errorCount: 0 }]) {
    assert.equal(diagnosticSummary({ captureState: "complete", ...counts }), "Diagnostic counts are unavailable.");
  }
});

test("fallback import keeps original identities and rejects raw logs or sensitive arbitrary values before upload", () => {
  const id="11111111-1111-4111-8111-111111111111";
  const batch={segmentId:id,batchSequence:0,payloadHash:"a".repeat(64),completion:"partial",events:[{
    eventId:id,source:"client",stage:"client_validation",tool:"identity.preflight",outcome:"error",errorCode:"INPUT_VALIDATION_ERROR",
    startedAt:"2026-11-02T00:00:00.000Z",completedAt:"2026-11-02T00:00:00.001Z",durationMs:1,
  }]};
  const bundle={schemaVersion:"w3bench-diagnostic-bundle/v1",diagnosticSessionId:id,caseId:id,segments:[{segmentId:id,batches:[batch]}]};
  assert.deepEqual(parseDiagnosticBundle(JSON.stringify(bundle)),bundle);
  for (const bad of [
    {...bundle,rawLogs:"synthetic-sensitive-message"},
    {...bundle,caseId:undefined},
    {...bundle,segments:[{segmentId:id,batches:[batch,batch]}]},
    {...bundle,segments:[{segmentId:id,batches:[{...batch,events:[{...batch.events[0],message:"synthetic-sensitive-message"}]}]}]},
    {...bundle,segments:[{segmentId:id,batches:[{...batch,events:[{...batch.events[0],errorCode:"synthetic-sensitive-message"}]}]}]},
    {...bundle,segments:[{segmentId:id,batches:[{...batch,events:[{...batch.events[0],fieldPaths:["synthetic-sensitive-message"]}]}]}]},
  ]) assert.throws(()=>parseDiagnosticBundle(JSON.stringify(bad)));
  assert.throws(()=>parseDiagnosticBundle(" ".repeat(8*1024*1024+1)));
});

test("diagnostic presentation separates observed source from proven responsibility", () => {
  assert.equal(diagnosticResponsibilityText("unknown"), "Unknown responsibility");
  assert.match(diagnosticTrustText("client_observed_unverified"), /not independently confirmed/);
  assert.match(diagnosticTrustText("server_observed"), /alone does not establish responsibility/);
  assert.equal(diagnosticResponsibilityText("platform_contract"), "Platform contract mismatch");
});

test("diagnostic consent only follows the exact registered callback with one result and state", () => {
  assert.equal(isDiagnosticCallback("http://127.0.0.1:38766/diagnostics/callback?code=synthetic-code&state=synthetic-state"), true);
  assert.equal(isDiagnosticCallback("http://127.0.0.1:38766/diagnostics/callback?error=access_denied&state=synthetic-state"), true);
  for (const url of [
    "https://example.org/diagnostics/callback?code=x&state=s",
    "http://127.0.0.1:38765/diagnostics/callback?code=x&state=s",
    "http://127.0.0.1:38766/callback?code=x&state=s",
    "http://127.0.0.1:38766/diagnostics/callback?code=x",
    "http://127.0.0.1:38766/diagnostics/callback?code=x&state=",
    "http://127.0.0.1:38766/diagnostics/callback?code=x&state=s&state=t",
    "http://127.0.0.1:38766/diagnostics/callback?code=x&code=y&state=s",
    "http://127.0.0.1:38766/diagnostics/callback?code=x&error=oops&state=s",
    "http://127.0.0.1:38766/diagnostics/callback?code=x&state=s&redirect=https://example.org",
    "http://127.0.0.1:38766/diagnostics/callback?code=x&state=s#fragment",
    "http://user@127.0.0.1:38766/diagnostics/callback?code=x&state=s",
  ]) assert.equal(isDiagnosticCallback(url), false);
});


test("crash snapshot imports only a paired unverified client runtime observation", () => {
  const id="11111111-1111-4111-8111-111111111111";
  const event={eventId:id,source:"client",stage:"client_runtime",tool:"unknown",outcome:"error",errorCode:"CLIENT_RUNTIME_ERROR",startedAt:"2026-11-02T00:00:00.000Z",completedAt:"2026-11-02T00:00:01.000Z",durationMs:1000,clientRunStatus:"running",clientRunObservedAt:"2026-11-02T00:00:00.000Z"};
  const bundle=(value:Record<string,unknown>)=>JSON.stringify({schemaVersion:"w3bench-diagnostic-bundle/v1",diagnosticSessionId:id,caseId:id,segments:[{segmentId:id,batches:[{segmentId:id,batchSequence:0,payloadHash:"a".repeat(64),completion:"partial",events:[value]}]}]});
  assert.doesNotThrow(()=>parseDiagnosticBundle(bundle(event)));
  for (const value of [{...event,clientRunStatus:undefined},{...event,clientRunObservedAt:undefined},{...event,source:"server"},{...event,stage:"handler"},{...event,outcome:"success"},{...event,clientRunStatus:"probably_done"},{...event,clientRunId:id}]) assert.throws(()=>parseDiagnosticBundle(bundle(value)));
});
