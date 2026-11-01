const states: Record<string, string> = {
  release_provider_unavailable: "The benchmark catalog service is unavailable. Wait for service recovery.",
  active_release_identity_mismatch: "The release identity could not be verified. Wait for a validated release.",
  active_release_invalid: "The release failed validation. Wait for a validated release.",
  release_incomplete: "The complete benchmark release is unavailable. Wait for a complete release.",
  executor_not_ready: "The executor is not ready. Wait for service recovery before starting another request.",
  ready: "Ready for the connected agent to accept your request.",
  queued: "Waiting for an execution slot. No task has started. Refresh status or cancel the queued run.",
  preparing: "Preparing the isolated task environment. Wait for the server to confirm it is ready.",
  running: "The task is active. Your connected agent must continue working until the run is terminal.",
  observing: "Checking task evidence. An accepted action does not yet prove its external result.",
  executor_unavailable: "Execution is unavailable. Wait for service recovery before starting another request.",
  worker_unavailable: "Execution is unavailable. Wait for service recovery before starting another request.",
  client_offline: "The client has not been verified. Open your client and check its Remote MCP connection.",
  executor_not_configured: "Execution is not configured on this service. Contact support; retrying cannot enable it.",
  run_policy_unconfigured: "Launch requests are unavailable until the service enables its queue policy.",
  active_release_unavailable: "The benchmark release is unavailable. Wait for a validated release.",
  release_unavailable: "The benchmark release is unavailable. Wait for a validated release.",
};

export function readinessText(code: string | null | undefined): string {
  return states[(code ?? "").toLowerCase()] ?? "The server has not confirmed this stage is ready. Refresh status; if it persists, report a connection or launch problem.";
}
