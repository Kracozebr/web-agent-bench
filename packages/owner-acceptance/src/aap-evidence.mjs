import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile, rename } from "node:fs/promises";
import { resolve } from "node:path";
import { REPOSITORY_ROOT, EVIDENCE_ROOT, assertSecretFree, sha256 } from "./evidence.mjs";

export async function saveAapEvidence({ browserData, databaseData, provenance, credentialData }) {
  const contractBytes = await readFile(resolve(REPOSITORY_ROOT, "tests/bdd/changes/agent-access-and-permissions/harness-contracts.json"));
  const contract = JSON.parse(contractBytes);
  const results = [];
  for (const [scenarioId, row] of Object.entries(contract.protected_scenarios)) {
    if (!/^AAP-SC-(?:00[1-9]|01[0-6])$/.test(scenarioId)) throw new Error("Invalid AAP scenario identity");
    const runId = randomUUID();
    const root = resolve(EVIDENCE_ROOT, scenarioId);
    const directory = resolve(root, "runs", runId);
    await mkdir(directory, { recursive: true });
    const hasCardObservation = ["AAP-SC-001", "AAP-SC-006", "AAP-SC-014"].includes(scenarioId);
    const hasCredentialObservation = Boolean(credentialData) && ["AAP-SC-004", "AAP-SC-005", "AAP-SC-007", "AAP-SC-009", "AAP-SC-010", "AAP-SC-011", "AAP-SC-014"].includes(scenarioId);
    const observedBrowser = hasCardObservation ? { ...browserData, ...(hasCredentialObservation ? { credentials: credentialData.browserData } : {}) }
      : hasCredentialObservation ? credentialData.browserData : { noScenarioSpecificMutationAttempted: true };
    const observedDatabase = hasCardObservation ? { ...databaseData, ...(hasCredentialObservation ? { credentials: credentialData.databaseData } : {}) }
      : hasCredentialObservation ? credentialData.databaseData : { observer: databaseData.observer };
    const artifacts = [];
    for (const [name, payload, boundary] of [
      ["browser.json", observedBrowser, "Actual private-card/credential controls and labelled direct HTTP verifier probes; no MCP or paid-domain pass claimed"],
      ["database.json", observedDatabase, "Independent oid_observer SELECT-only PostgreSQL reads"],
      ["provenance.json", { ...provenance, contractSha256: sha256(contractBytes) }, "Source hashes, container runtime and unchanged approved AAP contract"],
    ]) {
      assertSecretFree(payload, `${scenarioId}/${name}`);
      const bytes = Buffer.from(JSON.stringify(payload, null, 2) + "\n");
      await writeFile(resolve(directory, name), bytes, { flag: "wx" });
      artifacts.push({ path: name, sha256: sha256(bytes), boundary, contentType: "application/json" });
    }
    const credentialPassed = scenarioId === "AAP-SC-004" && credentialData?.sc004Ready === true && provenance.sourceStableDuringRun === true;
    const status = credentialPassed ? "passed" : "blocked";
    const blockedReasonCode = !provenance.sourceStableDuringRun ? "source_inputs_changed_during_run"
      : scenarioId === "AAP-SC-016" ? "actual_client_matrix_unavailable" : "downstream_domain_unavailable";
    const notRun = () => ({ status: "not_run", reasonCode: blockedReasonCode });
    const observation = () => credentialPassed ? { status: "observed", evidence: ["browser.json", "database.json"] } : notRun();
    const manifest = { schemaVersion: "agent-access-acceptance/v1", specProfile: "active-delta", scenarioId, runId,
      status, ...(credentialPassed ? {} : { blockedReasonCode }),
      observationStatus: credentialPassed ? "complete" : "not_run", negativeVariantStatus: credentialPassed ? "complete" : "not_run",
      statusDetail: credentialPassed ? "Actual browser manual issuance, header verifier and owner/resource isolation with independent persisted evidence."
        : hasCardObservation || hasCredentialObservation ? "Card/credential observations are partial for this full scenario; actual OAuth, domain, lifecycle or client effects remain unavailable." : "This scenario's actual credential, domain or client boundary has not been implemented/executed.",
      observations: Object.fromEntries(row.required_observations.map((name) => [name, observation()])),
      negativeVariants: Object.fromEntries(row.negative_variants.map((name) => [name, observation()])), artifacts };
    assertSecretFree(manifest);
    await writeFile(resolve(directory, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n", { flag: "wx" });
    let runs = [];
    try { runs = JSON.parse(await readFile(resolve(root, "manifest.json"), "utf8")).runs ?? []; } catch { /* First capture. */ }
    const index = { schemaVersion: "agent-access-evidence-index/v1", scenarioId, latestRunId: runId,
      status, ...(credentialPassed ? {} : { blockedReasonCode }), runs: [...new Set([...runs, runId])] };
    const temporary = resolve(root, `.manifest-${randomUUID()}.tmp`);
    await writeFile(temporary, JSON.stringify(index, null, 2) + "\n", { flag: "wx" });
    await rename(temporary, resolve(root, "manifest.json"));
    results.push({ scenarioId, runId, status });
  }
  return results;
}
