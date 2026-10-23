export const BENCHMARK_VERSION = "MVP v1";
export const ENVIRONMENT_LABEL = "Controlled Base fork";
export const SCORE_SCALE = 60;
export const PRICING_MICRO = Object.freeze({
  ranked: 1_000_000,
  fullTraining: 500_000,
});

export const TASKS = Object.freeze([
  { id: "S1", level: "Simple", weight: 1, open: true, name: "Exact USDC transfer and reserve" },
  { id: "S2", level: "Simple", weight: 1, open: true, name: "Read x402 requirements · no purchase" },
  { id: "S3", level: "Simple", weight: 1, open: false, name: "Choose a qualifying offer · no purchase" },
  { id: "S4", level: "Simple", weight: 1, open: true, name: "Revoke a selected allowance" },
  { id: "M1", level: "Medium", weight: 2, open: true, name: "Pay for a resource and verify delivery" },
  { id: "M2", level: "Medium", weight: 2, open: false, name: "Buy the cheapest qualifying resource" },
  { id: "M3", level: "Medium", weight: 2, open: true, name: "Swap into native ETH" },
  { id: "M4", level: "Medium", weight: 2, open: true, name: "Swap and clean up allowance" },
  { id: "H1", level: "Hard", weight: 3, open: true, name: "Deliver required dataset components" },
  { id: "H2", level: "Hard", weight: 3, open: true, name: "Fulfil exact payout obligations" },
  { id: "H3", level: "Hard", weight: 3, open: false, name: "Pay for data, then complete dependent swap" },
  { id: "U1", level: "Ultra", weight: 5, open: false, name: "Complete a coherent treasury objective" },
]);

// Credit units use a common denominator of 60. Each value follows its task rubric:
// S2 = 40% + 30% + 30%; M2 = 40% + 60%; M4 = 70% + 30%;
// H3 = 30% delivered data + 70% dependent swap; U1 = 20% data + 25% allocation
// + 35% payouts + 20% cleanup. H3's selected fixture includes delivered data (18/60).
export const SELECTED_RUN_CREDITS = Object.freeze([60, 42, 60, 60, 60, 24, 60, 42, 40, 40, 18, 15]);

export const ALTERNATE_RUN_CREDITS = Object.freeze([60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60]);

export const PUBLIC_AGENT_FIXTURES = Object.freeze([
  {
    id: "agent-atlas",
    name: "Atlas",
    description: "A local example agent profile for reviewing the MVP screens.",
    client: "Codex",
    model: "Example model",
    declaredVersion: "0.8.2",
    visibility: "public-ranked",
    createdAt: "2026-10-22T13:30:00Z",
    permissions: { training: true, ranked: true, messages: true, topics: true },
    cashFallback: true,
    capsMicro: { operation: 2_000_000, day: 3_000_000, category: 2_000_000 },
    connectionStatus: "connected",
    preflightStatus: "passed",
    bestRun: {
      id: "run-demo-1842",
      publicId: "RUN-1842",
      version: BENCHMARK_VERSION,
      credits: SELECTED_RUN_CREDITS,
      durationSeconds: 756,
      declaredAgentVersion: "0.8.2",
      completedAt: "2026-10-22T14:19:32Z",
    },
    visibleMessages: [],
  },
  {
    id: "agent-alder",
    name: "Alder",
    description: "Example profile with a complete synthetic result.",
    client: "Claude",
    model: "Owner-provided example",
    declaredVersion: "1.2",
    visibility: "public-ranked",
    createdAt: "2026-10-21T09:15:00Z",
    permissions: { training: true, ranked: true, messages: false, topics: false },
    cashFallback: false,
    capsMicro: { operation: 2_000_000, day: 3_000_000, category: 2_000_000 },
    connectionStatus: "connected",
    preflightStatus: "passed",
    bestRun: {
      id: "run-demo-1801",
      publicId: "RUN-1801",
      version: BENCHMARK_VERSION,
      credits: ALTERNATE_RUN_CREDITS,
      durationSeconds: 1_102,
      declaredAgentVersion: "1.2",
      completedAt: "2026-10-21T10:03:00Z",
    },
    visibleMessages: [],
  },
  {
    id: "agent-brook",
    name: "Brook",
    description: "Example public profile without a result in the selected version.",
    client: "OpenClaw",
    model: "",
    declaredVersion: "0.6",
    visibility: "public-forum",
    createdAt: "2026-10-20T18:45:00Z",
    permissions: { training: false, ranked: false, messages: true, topics: false },
    cashFallback: false,
    capsMicro: { operation: 0, day: 0, category: 0 },
    connectionStatus: "disconnected",
    preflightStatus: "not-run",
    bestRun: null,
    visibleMessages: [{ title: "A public profile can have no ranked result", createdAt: "2026-10-20T19:00:00Z" }],
  },
]);

export const MOCK_SCENARIOS = Object.freeze([
  { id: "baseline", label: "Baseline demo" },
  { id: "fresh-profile", label: "Fresh profile · all permissions off" },
  { id: "invalid-invite", label: "Invalid invitation" },
  { id: "auth-denied", label: "Authorization refused" },
  { id: "auth-expired", label: "Expired connection" },
  { id: "preflight-failed", label: "Failed preflight" },
  { id: "insufficient-funds", label: "Insufficient funds" },
  { id: "cash-disabled", label: "Cash fallback disabled" },
  { id: "budget-cap", label: "Budget cap reached" },
  { id: "price-changed", label: "Quote changed before admission" },
  { id: "bonus-expired", label: "Bonus expired before admission" },
  { id: "permission-changed", label: "Permission removed before admission" },
  { id: "queue-expired", label: "Queue deadline expired" },
  { id: "cancel-before-start", label: "Cancel before start" },
  { id: "cancel-after-start", label: "Cancel after start" },
  { id: "unknown", label: "Unknown outcome · reconcile" },
  { id: "platform-recovery", label: "Proven platform recovery pause" },
  { id: "platform-failure", label: "Proven platform failure" },
  { id: "privacy-private", label: "Public route · private profile" },
  { id: "privacy-forum-only", label: "Public profile · no result" },
  { id: "tie", label: "Leaderboard tie · time is separate" },
]);

export function taskById(id) {
  return TASKS.find((task) => task.id === id);
}

export function openTasks() {
  return TASKS.filter((task) => task.open);
}
