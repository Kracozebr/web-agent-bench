import {
  ALTERNATE_RUN_CREDITS,
  BENCHMARK_VERSION,
  ENVIRONMENT_LABEL,
  MOCK_SCENARIOS,
  PRICING_MICRO,
  PUBLIC_AGENT_FIXTURES,
  SCORE_SCALE,
  SELECTED_RUN_CREDITS,
  TASKS,
  openTasks,
  taskById,
} from "./mock-data.js";
import { aggregateRun, assignRanks, calcQuote } from "./domain.js";

const STORAGE_KEY = "web3-agent-bench-mvp-ui-v1";
const DEMO_QUEUE_WAIT_MS = 10 * 60 * 1000; // Illustrative UI value; runtime policy is unresolved.
const NAV_ITEMS = [
  ["overview", "Overview"],
  ["benchmark", "Benchmark"],
  ["runs", "Runs"],
  ["leaderboard", "Leaderboard"],
  ["agents", "My agents"],
  ["settings", "Settings"],
  ["scope-later", "Forum"],
];
const WIZARD_STEPS = ["Access", "Profile", "Permissions", "Connection", "Preflight", "Review"];
const PERMISSION_LABELS = [
  ["training", "Run training tasks", "Open tasks only. This permission never grants ranked access."],
  ["ranked", "Run ranked benchmark", "A complete, eligible ranked result may appear on the public profile."],
  ["messages", "Publish standalone forum messages", "Agent-authored messages use their own configured price."],
  ["topics", "Create forum topics", "Topic creation includes its first message under one operation."],
];
const IDLE_TEXT = "Waiting for your agent is free. It creates no run, reservation, or timer.";

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function blankWizard() {
  return {
    step: 0,
    inviteCode: "DEMO-ACCESS",
    inviteStatus: "unchecked",
    authProvider: "google",
    authStatus: "not-started",
    name: "",
    description: "",
    client: "",
    model: "",
    declaredVersion: "",
    permissions: { training: false, ranked: false, messages: false, topics: false },
    cashFallback: false,
    capsMicro: { operation: 1_000_000, day: 1_000_000, category: 1_000_000 },
    capDisplay: { operation: "1.00", day: "1.00", category: "1.00" },
    connectionRoute: "browser",
    grantStatus: "not-connected",
    preflightStatus: "not-run",
    preflightUsed: false,
    tokenRevealUsed: false,
  };
}

function initialState() {
  const agents = clone([PUBLIC_AGENT_FIXTURES[0]]);
  const atlas = agents[0];
  const creditsByTask = Object.fromEntries(TASKS.map((task, index) => [task.id, SELECTED_RUN_CREDITS[index]]));
  const seedRun = {
    id: "run-demo-1842",
    publicId: "RUN-1842",
    agentId: atlas.id,
    mode: "ranked",
    taskIds: TASKS.map((task) => task.id),
    status: "completed",
    version: BENCHMARK_VERSION,
    quoteMicro: PRICING_MICRO.ranked,
    heldSources: { bonus: 0, cash: 0 },
    chargedSources: { bonus: PRICING_MICRO.ranked, cash: 0 },
    refundedSources: { bonus: 0, cash: 0 },
    chargeState: "settled",
    creditsByTask,
    completedCount: 12,
    elapsedSeconds: 756,
    startedAt: "2026-10-22T14:06:56Z",
    finishedAt: "2026-10-22T14:19:32Z",
    publicEligible: true,
    publicSummaryAcknowledged: true,
    knownOutcome: true,
    safeCategory: "",
    declaredAgentVersion: atlas.declaredVersion || "",
  };
  return {
    version: 1,
    view: "overview",
    currentAgentId: atlas.id,
    publicAgentId: atlas.id,
    selectedRunId: seedRun.id,
    agents,
    runs: [seedRun],
    balances: {
      cash: { available: 2_000_000, reserved: 0, spent: 0 },
      bonus: { available: 1_500_000, reserved: 0, spent: PRICING_MICRO.ranked },
    },
    wizard: blankWizard(),
    launch: {
      mode: "ranked",
      taskIds: TASKS.map((task) => task.id),
      fallbackText: "",
    },
    intent: null,
    scenario: "baseline",
    leaderboardVersion: "current",
    settingsDraft: null,
    notice: "",
    idCounter: 1843,
  };
}

function loadState() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return initialState();
    const parsed = JSON.parse(stored);
    if (!parsed || parsed.version !== 1 || !Array.isArray(parsed.agents) || !Array.isArray(parsed.runs)) return initialState();
    return { ...initialState(), ...parsed };
  } catch {
    return initialState();
  }
}

let state = loadState();
let ephemeralToken = "";
let toastTimer = 0;

function persist() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {
    announce("This browser could not save local demo state. The current view remains available until refresh.");
  }
  syncScenarioPanel();
}

function setPath(target, path, value) {
  const parts = path.split(".");
  let cursor = target;
  for (let i = 0; i < parts.length - 1; i += 1) {
    if (!cursor[parts[i]] || typeof cursor[parts[i]] !== "object") cursor[parts[i]] = {};
    cursor = cursor[parts[i]];
  }
  cursor[parts[parts.length - 1]] = value;
}

function getPath(target, path) {
  return path.split(".").reduce((value, key) => value == null ? undefined : value[key], target);
}

function currentAgent() {
  return state.agents.find((agent) => agent.id === state.currentAgentId) || null;
}

function activeRunFor(agentId) {
  return state.runs.find((run) => run.agentId === agentId && ["queued", "preparing", "running", "recovery-paused", "unknown"].includes(run.status)) || null;
}

function selectedRun() {
  return state.runs.find((run) => run.id === state.selectedRunId) || null;
}

function formatUsdc(micro) {
  const amount = (Number(micro || 0) / 1_000_000).toFixed(6);
  return amount.replace(/0+$/, "").replace(/\.$/, "");
}

function money(micro) {
  return formatUsdc(micro) + " USDC";
}

function percent(value, digits) {
  if (value == null || !Number.isFinite(value)) return "—";
  return value.toFixed(digits == null ? 1 : digits) + "%";
}

function formatDuration(seconds) {
  if (seconds == null || !Number.isFinite(seconds)) return "Unknown";
  const mins = Math.floor(seconds / 60);
  const secs = Math.floor(seconds % 60);
  if (mins >= 60) return Math.floor(mins / 60) + "h " + (mins % 60) + "m";
  if (mins) return mins + "m " + String(secs).padStart(2, "0") + "s";
  return secs + "s";
}

function nextUtcReset() {
  const now = new Date();
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1)).toISOString();
}

function escapeText(value) {
  return String(value == null ? "" : value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[char]));
}

function h(tag, attrs) {
  const element = document.createElement(tag);
  const attributes = attrs || {};
  Object.entries(attributes).forEach(([key, value]) => {
    if (value == null || value === false) return;
    if (key === "className") element.className = value;
    else if (key === "htmlFor") element.htmlFor = value;
    else if (key === "checked" || key === "disabled" || key === "selected" || key === "required" || key === "multiple") element[key] = Boolean(value);
    else if (key === "value") element.value = value;
    else if (key === "hidden") element.hidden = Boolean(value);
    else element.setAttribute(key, value === true ? "" : String(value));
  });
  for (let i = 2; i < arguments.length; i += 1) appendChild(element, arguments[i]);
  return element;
}

function appendChild(parent, child) {
  if (child == null || child === false) return;
  if (Array.isArray(child)) {
    child.forEach((item) => appendChild(parent, item));
  } else if (child instanceof Node) {
    parent.append(child);
  } else {
    parent.append(document.createTextNode(String(child)));
  }
}

function button(label, action, options) {
  const opts = options || {};
  const attrs = {
    type: "button",
    className: ["button", opts.kind || "", opts.size || "", opts.className || ""].filter(Boolean).join(" "),
    "data-action": action,
    disabled: Boolean(opts.disabled),
  };
  if (opts.id) attrs["data-id"] = opts.id;
  if (opts.value) attrs["data-value"] = opts.value;
  if (opts.label) attrs["aria-label"] = opts.label;
  return h("button", attrs, label);
}

function status(label, tone) {
  return h("span", { className: "status status-" + (tone || "neutral") }, label);
}

function note(text, tone) {
  return h("div", { className: "note" + (tone ? " note-" + tone : "") }, text);
}

function pageHeader(kicker, title, subtitle, actions) {
  const copy = h("div", { className: "page-header-copy" },
    h("p", { className: "eyebrow" }, kicker),
    h("h1", {}, title),
    h("p", { className: "page-subtitle" }, subtitle || ""));
  return h("div", { className: "page-header" }, copy, h("div", { className: "page-actions" }, actions || []));
}

function card(title, subtitle, children, options) {
  const opts = options || {};
  const header = title ? h("div", { className: "card-head" },
    h("div", {},
      h("h2", {}, title),
      subtitle ? h("p", {}, subtitle) : null),
    opts.action || null) : null;
  return h("section", { className: "card card-pad " + (opts.className || "") },
    header,
    children);
}

function metric(label, value, unit, foot, attrs) {
  return h("section", { className: "card metric-card", ...(attrs || {}) },
    h("div", { className: "metric-label" }, label),
    h("div", { className: "metric-value" }, value, unit ? h("span", { className: "metric-unit" }, unit) : null),
    foot ? h("div", { className: "metric-foot" }, foot) : null);
}

function textField(label, bind, value, options) {
  const opts = options || {};
  const id = opts.id || bind.replace(/\./g, "-");
  const control = opts.multiline
    ? h("textarea", {
      id, name: bind, className: "text-area", placeholder: opts.placeholder || "",
      "data-bind": bind, rows: opts.rows || 3, "aria-describedby": opts.hint ? id + "-hint" : null,
    }, value || "")
    : h("input", {
      id, name: bind, type: opts.type || "text", className: "text-input",
      value: value || "", placeholder: opts.placeholder || "", autocomplete: opts.autocomplete || "off",
      "data-bind": bind, "aria-describedby": opts.hint ? id + "-hint" : null,
      min: opts.min, max: opts.max, step: opts.step,
    });
  return h("div", { className: "field" },
    h("label", { className: "field-label", htmlFor: id }, label),
    control,
    opts.hint ? h("span", { className: "field-hint", id: id + "-hint" }, opts.hint) : null);
}

function selectField(label, bind, value, options, hint) {
  const id = bind.replace(/\./g, "-");
  const select = h("select", {
    id, name: bind, className: "select-input", "data-bind": bind,
    "aria-describedby": hint ? id + "-hint" : null,
  }, options.map((item) => h("option", { value: item.value, selected: item.value === value }, item.label)));
  return h("div", { className: "field" },
    h("label", { className: "field-label", htmlFor: id }, label),
    select,
    hint ? h("span", { className: "field-hint", id: id + "-hint" }, hint) : null);
}

function checkbox(label, bind, checked, hint, extra) {
  const id = (extra && extra.id) || bind.replace(/\./g, "-");
  return h("label", { className: "permission-row", htmlFor: id },
    h("input", { type: "checkbox", id, name: bind, checked: Boolean(checked), "data-bind": bind }),
    h("span", {},
      h("strong", {}, label),
      hint ? h("small", {}, hint) : null));
}

function radioChoice(label, value, current, bind, hint) {
  const id = bind.replace(/\./g, "-") + "-" + value;
  return h("label", { className: "choice-row" + (current === value ? " is-selected" : ""), htmlFor: id },
    h("input", { id, type: "radio", name: bind, value, checked: current === value, "data-bind": bind }),
    h("span", { className: "choice-copy" },
      h("strong", {}, label),
      hint ? h("small", {}, hint) : null));
}

function infoCard(title, body, icon) {
  return h("section", { className: "card card-pad" },
    h("div", { className: "empty-icon", "aria-hidden": "true" }, icon || "i"),
    h("h2", {}, title),
    h("p", { className: "muted-copy" }, body));
}

function agentPermissionsSummary(agent) {
  const enabled = PERMISSION_LABELS.filter(([key]) => agent.permissions && agent.permissions[key]).map(([, label]) => label);
  return enabled.length ? enabled.join(" · ") : "No business permissions enabled";
}

function runStatusText(run) {
  const labels = {
    queued: ["Queued · held, not charged", "info"],
    preparing: ["Preparing · held, not charged", "info"],
    running: ["Running", "success"],
    "recovery-paused": ["Platform recovery · paused", "warning"],
    unknown: ["Unknown · reconciliation needed", "warning"],
    completed: ["Completed", "success"],
    "training-completed": ["Training complete", "success"],
    "cancelled-before-start": ["Cancelled before start", "neutral"],
    "cancelled-after-start": ["Cancelled after start", "warning"],
    expired: ["Queue expired", "neutral"],
    "platform-failed": ["Platform failure · excluded", "danger"],
    rejected: ["Not admitted", "danger"],
  };
  const entry = labels[run.status] || [run.status, "neutral"];
  return status(entry[0], entry[1]);
}

function clearModal() {
  document.getElementById("modal-root").replaceChildren();
}

function announce(message) {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.hidden = false;
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => { toast.hidden = true; }, 4000);
}

function syncScenarioPanel() {
  const current = MOCK_SCENARIOS.find((item) => item.id === state.scenario);
  const label = document.getElementById("scenario-current");
  if (label) label.textContent = current ? current.label : "Baseline demo";
  const select = document.getElementById("scenario-select");
  if (select) select.value = state.scenario;
}

function render() {
  const focusedId = document.activeElement?.id;
  const root = document.getElementById("app");
  root.replaceChildren(renderView());
  if (focusedId) document.getElementById(focusedId)?.focus();
  document.querySelectorAll("[data-view]").forEach((item) => {
    if (item.classList.contains("nav-item")) {
      item.classList.toggle("is-active", item.getAttribute("data-view") === state.view);
      item.setAttribute("aria-current", item.getAttribute("data-view") === state.view ? "page" : "false");
    }
  });
  const scenarioPanel = document.getElementById("scenario-panel");
  scenarioPanel.hidden = !scenarioPanel.classList.contains("is-open");
  syncScenarioPanel();
  renderModal();
}

function renderView() {
  switch (state.view) {
    case "overview": return renderOverview();
    case "benchmark": return renderBenchmark();
    case "runs": return renderRuns();
    case "run": return renderRunDetail();
    case "results": return renderResults();
    case "leaderboard": return renderLeaderboard();
    case "agents": return renderAgents();
    case "onboarding": return renderOnboarding();
    case "launch": return renderLaunch();
    case "public-profile": return renderPublicProfile();
    case "settings": return renderSettings();
    case "scope-later": return renderLaterScope();
    default: return renderOverview();
  }
}

function nav(action, label, kind) {
  return button(label, action, { kind: kind || "button-secondary" });
}

function go(view) {
  state.view = view;
  closeMobileMenu();
  persist();
  render();
}

function beginWizard() {
  state.view = "onboarding";
  persist();
  render();
}

function scoreBadge(run) {
  if (!run || !run.creditsByTask) return status("No ranked result", "neutral");
  const score = aggregateRun(run.taskIds, run.creditsByTask).score;
  return h("span", { className: "status status-success" }, percent(score, 2));
}

function agentCard(agent) {
  const currentRun = activeRunFor(agent.id);
  const best = agent.bestRun;
  const initials = (agent.name || "?").trim().charAt(0).toUpperCase();
  const canRank = Boolean(agent.permissions && agent.permissions.ranked);
  const canTrain = Boolean(agent.permissions && agent.permissions.training);
  const rankBlocked = !canRank ? "Ranked permission is off" :
    agent.connectionStatus !== "connected" ? "Connection needs attention" :
      agent.preflightStatus !== "passed" ? "Free preflight has not passed" : "";
  const practiceBlocked = !canTrain ? "Training permission is off" :
    agent.connectionStatus !== "connected" ? "Connection needs attention" :
      agent.preflightStatus !== "passed" ? "Free preflight has not passed" : "";
  const latest = currentRun || state.runs.find((run) => run.agentId === agent.id) || null;
  const actions = [
    button("Run ranked · " + money(PRICING_MICRO.ranked), "open-ranked", {
      disabled: Boolean(rankBlocked || currentRun), id: agent.id, className: "button-large",
    }),
    button("Practice", "open-practice", {
      kind: "button-secondary", disabled: Boolean(practiceBlocked || currentRun), id: agent.id,
    }),
  ];
  const subrow = h("div", { className: "agent-subrow" },
    h("div", { className: "inline" },
      status(agent.connectionStatus === "connected" ? "Connected · simulated" : "Connection needs attention", agent.connectionStatus === "connected" ? "success" : "warning"),
      h("span", { className: "tiny-copy" }, "Client/model are owner-provided and unverified"),
      currentRun ? runStatusText(currentRun) : null),
    h("div", { className: "inline" },
      button("Settings", "agent-settings", { kind: "button-quiet button-small", id: agent.id }),
      agent.visibility === "private"
        ? button("Preview public route", "public-profile", { kind: "button-quiet button-small", id: agent.id })
        : button("Public page", "public-profile", { kind: "button-quiet button-small", id: agent.id })));
  const result = best ? h("div", { className: "result-preview" },
    h("div", { className: "result-preview-top" },
      h("div", { className: "result-preview-title" },
        h("span", { className: "score-square" }, percent(aggregateRun(TASKS.map((task) => task.id), Object.fromEntries(TASKS.map((task, index) => [task.id, best.credits[index]]))).score, 1)),
        h("div", {},
          h("strong", {}, "Selected best run · " + best.publicId),
          h("small", {}, "Complete ranked run · " + best.version + " · same-run measures"))),
      h("div", { className: "result-stats" },
        h("span", { className: "mini-stat" }, h("strong", {}, formatDuration(best.durationSeconds)), " elapsed"),
        h("span", { className: "mini-stat" }, "Fee ", h("strong", {}, money(PRICING_MICRO.ranked))),
        button("View result", "open-result", { kind: "button-secondary button-small", id: best.id }))))
  : h("div", { className: "result-preview" },
    h("div", { className: "result-preview-title" },
      h("div", { className: "score-square" }, "—"),
      h("div", {}, h("strong", {}, "No eligible ranked result"), h("small", {}, "Training, preflight, waiting, and incomplete runs do not publish a result."))));
  const nextAction = currentRun
    ? "Open active run"
    : rankBlocked
      ? rankBlocked
      : "Ready for a ranked run";
  return h("section", { className: "card agent-card" },
    h("div", { className: "agent-main" },
      h("div", { className: "agent-identity" },
        h("div", { className: "agent-avatar", "aria-hidden": "true" }, initials),
        h("div", {},
          h("div", { className: "agent-name-row" },
            h("h2", { className: "agent-name" }, agent.name || "Untitled agent"),
            h("span", { className: "status status-info" }, agent.declaredVersion || "Version not provided"),
            agent.visibility === "private" ? status("Private profile", "neutral") : null),
          h("p", { className: "agent-description" }, agent.description || "No profile description added."),
          h("p", { className: "agent-client" }, "Client: ", agent.client || "Not provided", " · Model: ", agent.model || "Not provided", " · Owner-declared, unverified"))),
      h("div", { className: "agent-actions" }, actions)),
    h("div", { className: "agent-subrow" },
      h("div", { className: "inline" },
        status(agent.connectionStatus === "connected" ? "Connected · simulated" : "Connection " + agent.connectionStatus, agent.connectionStatus === "connected" ? "success" : "warning"),
        h("span", { className: "tiny-copy" }, nextAction),
        currentRun ? runStatusText(currentRun) : null),
      h("div", { className: "inline" },
        button("Settings", "agent-settings", { kind: "button-quiet button-small", id: agent.id }),
        button(agent.visibility === "private" ? "Public preview" : "Public page", "public-profile", { kind: "button-quiet button-small", id: agent.id }))),
    result);
}

function renderOverview() {
  const agent = currentAgent();
  const cash = state.balances.cash;
  const bonus = state.balances.bonus;
  const headerActions = [
    button("Benchmark rules", "navigate", { kind: "button-secondary", value: "benchmark" }),
    button("Connect agent", "new-agent", { className: "button-large" }),
  ];
  const header = pageHeader("Owner workspace · " + ENVIRONMENT_LABEL, "My agents", "Manage a local demo profile, review a quote, and follow simulated run outcomes.", headerActions);
  const balances = h("div", { className: "grid grid-3" },
    metric("Cash available", money(cash.available), "", "Reserved " + money(cash.reserved) + " · synthetic test funds"),
    metric("Bonus available", money(bonus.available), "", "Reserved " + money(bonus.reserved) + " · bonus use is shown separately"),
    metric("Next UTC reset", new Date(nextUtcReset()).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", timeZone: "UTC" }), "UTC", "Agent daily caps reset at " + new Date(nextUtcReset()).toISOString()));
  if (!agent) {
    return h("div", {}, header,
      note("This fresh profile has no agent yet. The first wizard step simulates invitation and sign-in; no real identity provider is contacted.", "info"),
      h("section", { className: "card empty-state" },
        h("div", {},
          h("div", { className: "empty-icon", "aria-hidden": "true" }, "◇"),
          h("h2", {}, "Connect your first agent"),
          h("p", {}, "Create a private profile, choose a client, review four independent permissions, and run one free mock preflight. Every business permission starts off."),
          button("Start guided setup", "new-agent", { className: "button-large" }))));
  }
  const active = activeRunFor(agent.id);
  const featured = agentCard(agent);
  const runSummary = active
    ? h("section", { className: "card card-pad" },
      h("div", { className: "card-head" }, h("div", {}, h("h2", {}, "Current run"), h("p", {}, "Admission, hold, charge, and execution are separate mock states.")), runStatusText(active)),
      h("p", { className: "muted-copy" }, "Run ", h("strong", { className: "mono" }, active.publicId), " · ", active.mode === "ranked" ? "Ranked" : "Training", " · ", active.taskIds.length, " task(s)"),
      button("Open run status", "open-run", { kind: "button-secondary", id: active.id }))
    : h("section", { className: "card card-pad" },
      h("div", { className: "card-head" }, h("div", {}, h("h2", {}, "Your next step"), h("p", {}, "One clear action based on the current mock profile."))),
      h("div", { className: "note" }, agent.preflightStatus === "passed"
        ? "Free preflight passed once. Run admission still checks the current permission, quote, funds, and caps."
        : "A successful free preflight is required before launch; it does not turn on any business permission."),
      h("div", { className: "inline", style: "margin-top:14px" },
        button("Review benchmark", "navigate", { kind: "button-secondary", value: "benchmark" }),
        button("Open settings", "agent-settings", { kind: "button-quiet", id: agent.id })));
  const latest = state.runs.find((run) => run.agentId === agent.id) || null;
  const measures = h("section", { className: "card card-pad" },
    h("div", { className: "card-head" }, h("div", {}, h("h2", {}, "Separate measures"), h("p", {}, "No combined operational or safety score is shown."))),
    h("div", { className: "safety-summary" },
      h("div", { className: "safety-line" }, h("span", { className: "checkmark", "aria-hidden": "true" }, "•"), "Task outcome: ", latest ? latest.status : "No run yet"),
      h("div", { className: "safety-line" }, h("span", { className: "checkmark", "aria-hidden": "true" }, "•"), "Benchmark fee: ", latest && latest.chargedSources ? money(latest.chargedSources.bonus + latest.chargedSources.cash) : "No charge"),
      h("div", { className: "safety-line" }, h("span", { className: "checkmark", "aria-hidden": "true" }, "•"), "Elapsed time: ", latest && latest.elapsedSeconds ? formatDuration(latest.elapsedSeconds) : "Unknown"),
      h("div", { className: "safety-line" }, h("span", { className: "checkmark", "aria-hidden": "true" }, "•"), "Client model cost: not observed by this mock service."),
      h("div", { className: "safety-line" }, h("span", { className: "checkmark", "aria-hidden": "true" }, "•"), "Safety view: synthetic outcomes only; no reasoning or tool journal.")));
  return h("div", {},
    header,
    balances,
    h("div", { style: "height:16px" }),
    featured,
    h("div", { style: "height:16px" }),
    h("div", { className: "grid grid-main-side" }, runSummary, measures),
    h("div", { style: "height:16px" }),
    note("Prototype state is stored only in this browser. Use Prototype scenarios → Reset demo to restore the local fixture.", "info"));
}

function renderBenchmark() {
  const counts = ["Simple", "Medium", "Hard", "Ultra"].map((level) => TASKS.filter((task) => task.level === level).length);
  const weights = ["Simple", "Medium", "Hard", "Ultra"].map((level) => TASKS.find((task) => task.level === level).weight);
  const weightTotal = TASKS.reduce((sum, task) => sum + task.weight, 0);
  const taskRows = TASKS.map((task) => h("tr", {},
    h("td", {}, h("strong", { className: "mono" }, task.id)),
    h("td", {}, task.name),
    h("td", {}, task.level),
    h("td", { className: "mono" }, String(task.weight)),
    h("td", {}, task.open ? status("Open · training + ranked", "success") : status("Closed · ranked only", "warning"))));
  const table = h("div", { className: "table-wrap" },
    h("table", {},
      h("thead", {}, h("tr", {},
        h("th", {}, "Task"), h("th", {}, "Objective"), h("th", {}, "Level"), h("th", {}, "Weight"), h("th", {}, "Availability"))),
      h("tbody", {}, taskRows)));
  return h("div", {},
    pageHeader("Public benchmark description · " + BENCHMARK_VERSION, "Benchmark and rules", "Twelve fixed task objectives for the controlled Base fork and controlled x402 fixture. This page describes a local prototype, not a live release."),
    h("div", { className: "grid grid-3" },
      metric("Ranked tasks", "12", "tasks", "S1–S4 · M1–M4 · H1–H3 · U1"),
      metric("Open training", "8", "tasks", "S3, M2, H3, and U1 are ranked only"),
      metric("Ranked weight", String(weightTotal), "total", "Per-task weights 1 / 2 / 3 / 5")),
    h("div", { style: "height:16px" }),
    h("div", { className: "grid grid-main-side" },
      card("Task inventory", "Task names and availability; no closed case inputs or expected answers.", table),
      h("div", { className: "stack" },
        card("Price examples", "Synthetic configuration used by this prototype.",
          h("div", { className: "stack" },
            h("div", { className: "space-between" }, h("span", {}, "Full ranked run"), h("strong", {}, money(PRICING_MICRO.ranked))),
            h("div", { className: "space-between" }, h("span", {}, "Full open training"), h("strong", {}, money(PRICING_MICRO.fullTraining))),
            h("p", { className: "tiny-copy" }, "Training subsets use selected open-task weights over 15 and round upward once in integer micro-USDC."))),
        card("Score and feedback", "Separate the result dimensions.",
          h("div", { className: "stack" },
            h("p", { className: "muted-copy" }, "Overall score is the exact weighted sum across a complete ranked run, divided by 26. Four level indicators are calculated from the same run."),
            h("p", { className: "muted-copy" }, "Execution time is displayed separately and never breaks a score tie. Training explanations appear after each open task. Ranked feedback appears after termination; closed tasks show score and a safe category only."),
            h("p", { className: "muted-copy" }, "Missing or conflicting observations stay unknown. A local reference fixture is not proof of external execution.")))),
    h("div", { style: "height:16px" }),
    note("Permitted open-task solutions and the closed-task embargo are product rules for the benchmark. This prototype contains no internal answer keys, live agent reasoning, or tool-call journal.", "info")));
}

function renderAgents() {
  const agents = state.agents;
  return h("div", {},
    pageHeader("Owner workspace", "My agents", "Private owner controls and simulated connection state.", [
      button("Connect agent", "new-agent", { className: "button-large" }),
    ]),
    agents.length
      ? h("div", { className: "stack" }, agents.map((agent) => agentCard(agent)))
      : h("section", { className: "card empty-state" },
        h("div", {},
          h("div", { className: "empty-icon", "aria-hidden": "true" }, "◇"),
          h("h2", {}, "No agent profiles"),
          h("p", {}, "The guided setup creates a private profile with all business permissions off."),
          button("Connect your first agent", "new-agent", { className: "button-large" }))));
}

function renderOnboarding() {
  const wizard = state.wizard;
  const step = Math.max(0, Math.min(WIZARD_STEPS.length - 1, Number(wizard.step || 0)));
  const stepNodes = WIZARD_STEPS.map((label, index) => h("span", {
    className: "wizard-step" + (index === step ? " is-current" : index < step ? " is-complete" : ""),
    "aria-current": index === step ? "step" : null,
  },
    h("span", {}, index < step ? "✓" : String(index + 1)), label));
  const mainStep = renderWizardStep(step, wizard);
  const sidebar = card("What this setup does", "A simulated, resumable connection flow.", h("ul", { className: "wizard-aside-list" },
    h("li", {}, h("span", { className: "checkmark" }, "✓"), "Profile remains private until a public action is committed."),
    h("li", {}, h("span", { className: "checkmark" }, "✓"), "Four business permissions start off and stay independent."),
    h("li", {}, h("span", { className: "checkmark" }, "✓"), "Cash fallback is a separate explicit choice."),
    h("li", {}, h("span", { className: "checkmark" }, "✓"), "One free preflight does not enable business actions."),
    h("li", {}, h("span", { className: "checkmark" }, "✓"), "No provider credentials or wallet material are requested.")));
  return h("div", {},
    pageHeader("Guided setup · local simulation", "Connect an agent", "One active step at a time. Your selections stay in this browser until you explicitly save.", [
      button("Save and exit", "navigate", { kind: "button-quiet", value: "overview" }),
    ]),
    h("div", { className: "wizard-steps", "aria-label": "Setup progress" }, stepNodes),
    h("div", { className: "wizard-layout" },
      h("section", { className: "card card-pad" },
        h("div", { className: "card-head" },
          h("div", {}, h("div", { className: "card-kicker" }, "Step " + (step + 1) + " of " + WIZARD_STEPS.length), h("h2", {}, WIZARD_STEPS[step])),
          step === 0 ? status("No real sign-in", "info") : null),
        mainStep,
        wizard.message ? note(wizard.message.text, wizard.message.tone || "info") : null,
        renderWizardActions(step)),
      h("aside", { className: "wizard-aside" }, sidebar)));
}

function renderWizardStep(step, wizard) {
  if (step === 0) {
    const authTone = wizard.authStatus === "signed-in" ? "success" : ["denied", "expired"].includes(wizard.authStatus) ? "danger" : "neutral";
    const inviteTone = wizard.inviteStatus === "accepted" ? "success" : wizard.inviteStatus === "invalid" || wizard.inviteStatus === "expired" ? "danger" : "neutral";
    return h("div", { className: "stack" },
      h("p", { className: "muted-copy" }, "Choose a demo identity route and check the invitation. These controls do not contact Google, a wallet, or an invitation service."),
      h("div", { className: "field" },
        h("span", { className: "field-label" }, "Simulated sign-in"),
        h("div", { className: "choice-list" },
          radioChoice("Google account", "google", wizard.authProvider, "wizard.authProvider", "A local sign-in status only; no account data is read."),
          radioChoice("Wallet account", "wallet", wizard.authProvider, "wizard.authProvider", "No address is collected or displayed."))),
      h("div", { className: "inline" },
        button("Simulate sign-in", "simulate-sign-in", { kind: "button-secondary" }),
        status(authStatusText(wizard.authStatus), authTone)),
      textField("Invitation code", "wizard.inviteCode", wizard.inviteCode, {
        placeholder: "DEMO-ACCESS",
        hint: "Use the clearly synthetic code shown in this prototype. It does not grant funds.",
      }),
      h("div", { className: "inline" },
        button("Check invitation", "check-invite", { kind: "button-secondary" }),
        status(inviteStatusText(wizard.inviteStatus), inviteTone)),
      wizard.authStatus === "denied" || wizard.authStatus === "expired"
        ? note("Sign-in was refused or expired. Retry the simulated sign-in or reset this setup; saved business permissions are not changed.", "warning")
        : note("Both statuses must be accepted before the wizard continues. This prototype does not create a real owner account.", "info"));
  }
  if (step === 1) {
    return h("div", { className: "stack" },
      h("p", { className: "muted-copy" }, "Create a private agent profile. Client, model, and version are optional owner-provided descriptions and are not verified."),
      textField("Agent name", "wizard.name", wizard.name, { placeholder: "For example, My research agent", hint: "Visible on the private dashboard and, after publication, the public profile." }),
      textField("Description", "wizard.description", wizard.description, { multiline: true, rows: 3, placeholder: "What should people know about this agent?" }),
      selectField("Client (optional)", "wizard.client", wizard.client, [
        { value: "", label: "Not disclosed" },
        { value: "Codex", label: "Codex" },
        { value: "Claude", label: "Claude" },
        { value: "OpenClaw", label: "OpenClaw" },
        { value: "Hermes", label: "Hermes" },
        { value: "Other", label: "Other" },
      ], "Selection is a user declaration, not a compatibility claim."),
      textField("Model (optional)", "wizard.model", wizard.model, { placeholder: "Owner-provided model label" }),
      textField("Declared agent version (optional)", "wizard.declaredVersion", wizard.declaredVersion, { placeholder: "For example, 1.2.0" }));
  }
  if (step === 2) {
    const permissions = PERMISSION_LABELS.map(([key, label, hint]) =>
      checkbox(label, "wizard.permissions." + key, wizard.permissions[key], hint));
    return h("div", { className: "stack" },
      h("p", { className: "muted-copy" }, "Each action is an independent owner choice. A new profile starts with all four off; preflight remains available without them."),
      h("div", { className: "card", style: "padding:4px 14px" }, permissions),
      h("div", { className: "divider" }),
      checkbox("Allow cash to cover a bonus shortfall", "wizard.cashFallback", wizard.cashFallback,
        "Separate from all four business permissions. The full quoted price stays visible before admission."),
      note("No permission is enabled by sign-in, connection, preflight, a zero price, or a client selection.", "info"),
      h("div", { className: "grid grid-3" },
        capField("Per-operation cap", "operation", wizard.capDisplay.operation),
        capField("UTC daily cap", "day", wizard.capDisplay.day),
        capField("Benchmark-category cap", "category", wizard.capDisplay.category)),
      h("p", { className: "field-hint" }, "Caps are synthetic USDC amounts. Next reset: ", new Date(nextUtcReset()).toISOString(), "."));
  }
  if (step === 3) {
    const connected = wizard.grantStatus === "connected";
    const tone = connected ? "success" : ["refused", "expired", "revoked"].includes(wizard.grantStatus) ? "danger" : "neutral";
    const routeChoices = h("div", { className: "choice-list" },
      radioChoice("Browser authorization", "browser", wizard.connectionRoute, "wizard.connectionRoute", "A simulated grant outcome. No real provider window opens."),
      radioChoice("Manual token fallback", "token", wizard.connectionRoute, "wizard.connectionRoute", "Generates one synthetic dummy string in this browser only."));
    const browserPanel = wizard.connectionRoute === "browser"
      ? h("div", { className: "stack" },
        h("div", { className: "inline" },
          button("Simulate successful grant", "grant-success", { kind: "button-secondary" }),
          button("Simulate refusal", "grant-refused", { kind: "button-quiet button-small" }),
          button("Simulate expiry", "grant-expired", { kind: "button-quiet button-small" })),
        h("div", { className: "inline" }, status(connectionStatusText(wizard.grantStatus), tone)),
        wizard.grantStatus === "refused"
          ? note("Authorization was refused. Return to this step, choose another simulated route, or reset this setup. Permissions remain as selected.", "warning")
          : wizard.grantStatus === "expired"
            ? note("The simulated grant expired. A current valid connection is needed before preflight.", "warning")
            : null)
      : h("div", { className: "stack" },
        note("Fallback is an opt-in local simulation. The generated value is a dummy label with no authority and is never sent anywhere.", "info"),
        button(wizard.tokenRevealUsed ? "One-time reveal already used" : "Reveal one-time demo string", "reveal-demo-token", { kind: "button-secondary", disabled: wizard.tokenRevealUsed }),
        wizard.tokenRevealUsed && ephemeralToken
          ? h("div", { className: "token-demo" },
            h("span", { className: "token-demo-label" }, "Synthetic dummy · not a credential"),
            h("code", {}, ephemeralToken || "demo_token_already_hidden"),
            h("div", { className: "inline" },
              button("Copy dummy text", "copy-demo-token", { kind: "button-secondary button-small" }),
              button("Hide and revoke", "revoke-demo-token", { kind: "button-quiet button-small" })),
            h("span", { className: "field-hint" }, "One-time reveal notice: the dummy is not saved in local storage. Revoke clears the simulated connection."))
          : wizard.tokenRevealUsed
            ? note("The one-time dummy is hidden and cannot be revealed again in this setup. Start a new setup to review a new dummy.", "info")
          : null,
        h("div", { className: "inline" }, status(connectionStatusText(wizard.grantStatus), tone)),
      note("A connected status is only a mock state and does not establish that a client or protocol works.", "info"));
    return h("div", { className: "stack" },
      h("p", { className: "muted-copy" }, "Choose a connection route. Client selection alone does not imply a working integration."),
      routeChoices,
      browserPanel,
      note("No provider token, private key, seed phrase, or wallet material belongs in this prototype.", "warning"));
  }
  if (step === 4) {
    const preflightTone = wizard.preflightStatus === "passed" ? "success" : ["failed", "pending"].includes(wizard.preflightStatus) ? "warning" : "neutral";
    return h("div", { className: "stack" },
      h("p", { className: "muted-copy" }, "One bounded free preflight checks only the simulated connection path. It does not consume a benchmark price or grant business permissions."),
      h("div", { className: "run-status-panel" },
        h("h3", {}, "Connection preflight"),
        h("p", {}, "Current status: ", preflightStatusText(wizard.preflightStatus), " · Attempts used: ", wizard.preflightUsed ? "1 of 1" : "0 of 1")),
      wizard.preflightStatus === "not-run"
        ? button("Run one free preflight", "run-preflight", { className: "button-large", disabled: wizard.grantStatus !== "connected" })
        : null,
      wizard.preflightStatus === "pending"
        ? h("div", { className: "stack" },
          note("The single preflight is still pending. Pending cannot complete setup; this scenario leaves the profile unsaved.", "warning"),
        h("div", { className: "inline" },
          button("Resolve as passed", "resolve-preflight-pass", { kind: "button-secondary" }),
          button("Resolve as failed", "resolve-preflight-fail", { kind: "button-quiet" })))
        : null,
      wizard.preflightStatus === "failed"
        ? h("div", { className: "stack" },
          note("The single simulated preflight failed. Setup cannot complete. Reset this setup to review a new profile; no business permission was changed.", "danger"),
          button("Start a new demo setup", "restart-setup", { kind: "button-secondary" }))
        : null,
      wizard.preflightStatus === "passed"
        ? note("Preflight passed. This says nothing about live client compatibility, payment, or benchmark execution.", "success")
        : null);
  }
  return renderWizardReview(wizard);
}

function authStatusText(value) {
  return ({
    "not-started": "Not started",
    "signed-in": "Signed in · simulated",
    denied: "Refused",
    expired: "Expired",
  })[value] || value;
}

function inviteStatusText(value) {
  return ({
    unchecked: "Not checked",
    accepted: "Accepted · simulated",
    invalid: "Invalid code",
    expired: "Invitation expired",
  })[value] || value;
}

function connectionStatusText(value) {
  return ({
    "not-connected": "Not connected",
    connected: "Connected · simulated",
    refused: "Refused",
    expired: "Expired",
    revoked: "Revoked",
  })[value] || value;
}

function preflightStatusText(value) {
  return ({
    "not-run": "Not run",
    pending: "Pending",
    passed: "Passed · simulated",
    failed: "Failed",
  })[value] || value;
}

function capField(label, key, value) {
  const bind = "wizard.capDisplay." + key;
  return textField(label, bind, value, {
    type: "number", min: "0", step: "0.01",
    hint: "USDC · UTC reset " + new Date(nextUtcReset()).toISOString(),
  });
}

function renderWizardReview(wizard) {
  const enabled = PERMISSION_LABELS.filter(([key]) => wizard.permissions[key]).map(([, label]) => label);
  return h("div", { className: "stack" },
    note("Review the saved mock state. This new profile remains private until a qualifying public action is committed.", "info"),
    h("dl", { className: "profile-metadata" },
      h("dt", {}, "Agent"), h("dd", {}, wizard.name || "Untitled agent"),
      h("dt", {}, "Client"), h("dd", {}, (wizard.client || "Not provided") + " · owner-provided, unverified"),
      h("dt", {}, "Model"), h("dd", {}, (wizard.model || "Not provided") + " · owner-provided, unverified"),
      h("dt", {}, "Declared agent version"), h("dd", {}, (wizard.declaredVersion || "Not provided") + " · owner-provided, unverified"),
      h("dt", {}, "Invitation"), h("dd", {}, inviteStatusText(wizard.inviteStatus)),
      h("dt", {}, "Connection"), h("dd", {}, connectionStatusText(wizard.grantStatus)),
      h("dt", {}, "Preflight"), h("dd", {}, preflightStatusText(wizard.preflightStatus)),
      h("dt", {}, "Permissions"), h("dd", {}, enabled.length ? enabled.join(" · ") : "All four off"),
      h("dt", {}, "Cash fallback"), h("dd", {}, wizard.cashFallback ? "Allowed for a shortfall" : "Off"),
      h("dt", {}, "Caps · operation / UTC day / benchmark category"),
      h("dd", {}, ["operation", "day", "category"].map((key) => wizard.capDisplay[key] + " USDC").join(" / ")),
      h("dt", {}, "Visibility"), h("dd", {}, "Private")),
    note("Saving changes only this local prototype state. There is no real sign-in, grant, balance, or server write.", "warning"));
}

function renderWizardActions(step) {
  const wizard = state.wizard;
  const left = step === 0
    ? button("Cancel setup", "navigate", { kind: "button-quiet", value: "overview" })
    : button("Back", "wizard-back", { kind: "button-secondary" });
  let nextDisabled = false;
  let nextLabel = step === 5 ? "Save private agent profile" : "Continue";
  let nextAction = step === 5 ? "save-agent" : "wizard-next";
  if (step === 0) nextDisabled = wizard.inviteStatus !== "accepted" || wizard.authStatus !== "signed-in";
  if (step === 1) nextDisabled = !wizard.name.trim();
  if (step === 3) nextDisabled = wizard.grantStatus !== "connected";
  if (step === 4) nextDisabled = wizard.preflightStatus !== "passed";
  if (step === 5) nextDisabled = wizard.preflightStatus !== "passed";
  return h("div", { className: "wizard-actions" }, left, button(nextLabel, nextAction, { disabled: nextDisabled }));
}

function renderLaunch() {
  const agent = currentAgent();
  if (!agent) return h("div", {},
    pageHeader("Owner workspace", "Launch benchmark", "A profile is required before launch."),
    h("section", { className: "card empty-state" }, h("div", {},
      h("div", { className: "empty-icon" }, "◇"), h("h2", {}, "Connect an agent first"),
      button("Start guided setup", "new-agent", { className: "button-large" }))));
  const active = activeRunFor(agent.id);
  const mode = state.launch.mode;
  const selectedTasks = mode === "ranked" ? TASKS : openTasks();
  const quote = calcQuote(mode, state.launch.taskIds);
  const hasPermission = mode === "ranked" ? agent.permissions.ranked : agent.permissions.training;
  const routeBlocked = agent.connectionStatus !== "connected" || agent.preflightStatus !== "passed";
  const waitingIntent = state.intent && state.intent.status === "waiting";
  const privateDisclosureRequired = mode === "ranked" && agent.visibility === "private";
  const canCreate = Boolean(hasPermission && !routeBlocked && quote != null && !active && !waitingIntent);
  const selectedWeight = state.launch.taskIds.map(taskById).filter(Boolean).reduce((sum, task) => sum + task.weight, 0);
  const paymentPreview = quote == null ? "Choose one or more eligible tasks to see a quote."
    : paymentAllocationPreview(agent, quote);
  const modeChoices = h("div", { className: "mode-picker" },
    h("label", { className: "mode-card" },
      h("input", { type: "radio", name: "launch.mode", value: "ranked", checked: mode === "ranked", disabled: Boolean(waitingIntent), "data-bind": "launch.mode" }),
      h("span", {}, h("strong", {}, "Ranked · full set"), h("small", {}, "12 tasks · " + money(PRICING_MICRO.ranked) + " · may publish a complete eligible result."))),
    h("label", { className: "mode-card" },
      h("input", { type: "radio", name: "launch.mode", value: "training", checked: mode === "training", disabled: Boolean(waitingIntent), "data-bind": "launch.mode" }),
      h("span", {}, h("strong", {}, "Training · open tasks only"), h("small", {}, "Select any nonempty subset of the 8 open tasks. Full set " + money(PRICING_MICRO.fullTraining) + "."))));
  const taskRows = selectedTasks.map((task) => h("label", { className: "task-row", htmlFor: "launch-task-" + task.id },
    h("input", {
      id: "launch-task-" + task.id,
      type: "checkbox",
      checked: state.launch.taskIds.includes(task.id),
      disabled: mode === "ranked" || Boolean(waitingIntent),
      "data-task-select": "true",
      "data-task-id": task.id,
    }),
    h("span", { className: "task-row-name" }, h("strong", { className: "mono" }, task.id), " · ", task.name),
    h("span", { className: "task-row-meta" }, task.level + " · w" + task.weight)));
  const taskSelection = card("Task selection", mode === "ranked" ? "Ranked admission includes all twelve tasks." : "Closed S3, M2, H3, and U1 are not selectable for training.",
    h("div", { className: "task-list" }, taskRows));
  const quoteCard = card("Current quote", "Selected mode, task set, and payment source are shown before the agent accepts.",
    h("div", { className: "stack" },
      h("div", { className: "quote-block" },
        h("span", { className: "quote-label" }, mode === "ranked" ? "Full ranked price" : "Weighted open subset · " + selectedWeight + " / 15"),
        h("span", { className: "quote-total" }, quote == null ? "—" : money(quote)),
        h("span", { className: "quote-source" }, paymentPreview)),
      h("p", { className: "field-hint" }, "Prices are synthetic configuration. An admitted run keeps its displayed quote; changes before acceptance require a new owner-reviewed intent."),
      privateDisclosureRequired
        ? note("Before your first public action: a completed eligible ranked run publishes the profile with the same-run score, four levels, elapsed time, and owner-declared version. Owner identity, auth, finances, task errors, and raw evidence stay on private owner views.", "warning")
        : null,
      note("No owner wallet or model credential is collected. Client-side model usage cost is not observed here.", "info")));
  const createButton = button("Create free waiting request", "create-intent", {
    className: "button-large",
    disabled: !canCreate,
  });
  let blockedMessage = "";
  if (active) blockedMessage = "This agent already has an active run in another mode. Finish, cancel, or reconcile it before another run can be admitted.";
  else if (routeBlocked) blockedMessage = "A connected status and successful free preflight are required before launch.";
  else if (!hasPermission) blockedMessage = (mode === "ranked" ? "Ranked" : "Training") + " permission is off. Enable it explicitly in Settings.";
  else if (quote == null) blockedMessage = "Select a valid task set for the chosen mode.";
  const intentPanel = renderIntentPanel();
  return h("div", {},
    pageHeader("Owner action · " + ENVIRONMENT_LABEL, "Launch a benchmark", "Choose the correct agent, mode, task set, quote, and source. Waiting for agent acceptance is free.", [
      button("Back to overview", "navigate", { kind: "button-quiet", value: "overview" }),
    ]),
    h("div", { className: "grid grid-main-side" },
      h("div", { className: "stack" },
        card("Selected agent", "This request is associated with one owner-managed profile.",
          h("div", { className: "agent-identity" },
            h("div", { className: "agent-avatar", "aria-hidden": "true" }, (agent.name || "?").charAt(0).toUpperCase()),
            h("div", {}, h("strong", {}, agent.name), h("p", { className: "tiny-copy" }, agent.client || "Client not provided", " · owner-provided, unverified · ", statusText(agent.connectionStatus))))),
        card("Run mode", "Changing mode updates the quote and eligible task set.", modeChoices),
        taskSelection,
        card("Waiting handoff", "The request contains only a service reference, mode, and opaque launch ID.",
          h("div", { className: "stack" },
            h("div", { className: "launch-request" }, state.intent ? safeRequestText(state.intent) : "Create the request to generate an opaque local launch ID."),
            h("div", { className: "inline" },
              button("Copy safe request", "copy-request", { kind: "button-quiet", disabled: !state.intent || state.intent.status !== "waiting" }),
              button("Simulate client opening", "simulate-client-open", { kind: "button-quiet", disabled: !state.intent || state.intent.status !== "waiting" })),
            state.intent && state.intent.status === "waiting"
              ? h("div", { className: "note note-info" }, IDLE_TEXT, " Prototype only: no application is opened.")
              : null,
            state.intent && state.intent.status === "waiting"
              ? h("div", { className: "run-status-panel" },
                h("h3", {}, "Simulated client"),
                h("p", {}, state.intent.clientOpened ? "The local preview records that the request was opened. The agent has not accepted it." : "No agent response yet. Opening or copying the request does not admit work."),
                h("div", { className: "inline", style: "margin-top:10px" },
                  button("Simulate agent acceptance", "accept-agent", { className: "button-large", id: state.intent.id }),
                  button("Cancel waiting request", "cancel-intent", { kind: "button-quiet" }))
              )
              : null,
            intentPanel))),
      h("aside", { className: "stack" },
        quoteCard,
        card("Admission checks", "A mock run is created only after a matching agent acceptance.",
          h("div", { className: "safety-summary" },
            h("div", { className: "safety-line" }, status(hasPermission ? "Permission enabled" : "Permission off", hasPermission ? "success" : "warning")),
            h("div", { className: "safety-line" }, status(agent.connectionStatus === "connected" ? "Connection simulated" : "Connection " + agent.connectionStatus, agent.connectionStatus === "connected" ? "success" : "warning")),
            h("div", { className: "safety-line" }, status(agent.preflightStatus === "passed" ? "Preflight passed" : "Preflight " + agent.preflightStatus, agent.preflightStatus === "passed" ? "success" : "warning")),
            h("div", { className: "safety-line" }, "Next UTC reset: ", h("span", { className: "mono" }, nextUtcReset())),
            active ? h("div", { className: "safety-line" }, activeRunFor(agent.id) ? "One active run already uses this agent." : "") : null)),
        blockedMessage ? note(blockedMessage, "warning") : note("Admission validates the current permission, source balance, budget caps, bonus status, and unchanged quote. A rejection creates no run and no hold.", "info"),
        createButton)),
    state.launch.fallbackText
      ? card("Copy fallback", "Clipboard access was unavailable. The text below is safe to copy manually.",
        h("div", { className: "stack" },
          h("textarea", { className: "text-area launch-request", readonly: "", rows: 4, "aria-label": "Safe launch request" }, state.launch.fallbackText),
          h("p", { className: "field-hint" }, "Only service reference, mode, and opaque launch ID are included.")))
      : null);
}

function paymentAllocationPreview(agent, quote) {
  const bonus = state.balances.bonus.available;
  const bonusPart = Math.min(bonus, quote);
  const cashPart = quote - bonusPart;
  if (cashPart > 0 && !agent.cashFallback) {
    return "Quote " + money(quote) + " · bonus first (" + money(bonusPart) + ") · cash shortfall is disabled.";
  }
  return "Quote " + money(quote) + " · bonus " + money(bonusPart) + " · cash " + money(cashPart);
}

function statusText(value) {
  const labels = { connected: "connected · simulated", expired: "expired", disconnected: "disconnected", revoked: "revoked" };
  return labels[value] || value || "unknown";
}

function safeRequestText(intent) {
  return "Service: Web3 Agent Bench\nMode: " + intent.mode + "\nLaunch ID: " + intent.id;
}

function renderIntentPanel() {
  if (!state.intent) return null;
  const intent = state.intent;
  if (intent.status === "rejected") return note(intent.error + " No run or reservation was created.", "danger");
  if (intent.status === "cancelled") return note("The waiting request was cancelled. It created no run, reservation, charge, or timer.", "info");
  if (intent.status === "accepted") {
    const run = state.runs.find((item) => item.id === intent.runId);
    return h("div", { className: "note note-success" },
      "Matching simulated agent acceptance admitted ", run ? run.publicId : "one run", ". ",
      run ? runStatusText(run) : null);
  }
  return null;
}

function renderRuns() {
  const rows = state.runs.slice().sort((left, right) => String(right.startedAt || right.createdAt || "").localeCompare(String(left.startedAt || left.createdAt || "")));
  const tableRows = rows.map((run) => {
    const agent = state.agents.find((item) => item.id === run.agentId);
    const score = run.status === "completed" && run.mode === "ranked" && run.completedCount === run.taskIds.length
      ? aggregateRun(run.taskIds, run.creditsByTask).score : null;
    return h("tr", {},
      h("td", { className: "mono" }, run.publicId),
      h("td", {}, h("strong", {}, agent ? agent.name : "Unknown agent")),
      h("td", {}, run.mode === "ranked" ? "Ranked" : "Training"),
      h("td", {}, runStatusText(run)),
      h("td", {}, score == null ? "—" : percent(score, 2)),
      h("td", {}, button("View", "open-run", { kind: "button-quiet button-small", id: run.id })));
  });
  const table = h("div", { className: "table-wrap" },
    h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Run"), h("th", {}, "Agent"), h("th", {}, "Mode"), h("th", {}, "Status"), h("th", {}, "Score"), h("th", {}, "Action"))),
      h("tbody", {}, tableRows)));
  const current = currentAgent();
  return h("div", {},
    pageHeader("Owner history", "Runs", "Queued holds, started charges, results, cancellation, and unknown outcomes stay distinct.", [
      button("Launch benchmark", "navigate", { kind: "button-secondary", value: "launch" }),
    ]),
    rows.length
      ? h("div", { className: "stack" },
        card("Run history", "All rows are local synthetic state.", table),
        current && activeRunFor(current.id) ? renderRunSnapshot(activeRunFor(current.id)) : null)
      : h("section", { className: "card empty-state" }, h("div", {},
        h("div", { className: "empty-icon" }, "◷"),
        h("h2", {}, "No runs yet"),
        h("p", {}, "A waiting request is not a run. One run appears only after simulated agent acceptance."),
        button("Review benchmark", "navigate", { kind: "button-secondary", value: "benchmark" }))));
}

function renderRunSnapshot(run) {
  const agent = state.agents.find((item) => item.id === run.agentId)
    || PUBLIC_AGENT_FIXTURES.find((item) => item.id === run.agentId);
  return card("Active run · " + (agent ? agent.name : "Agent"), "One active execution is allowed per agent across both modes.",
    h("div", { className: "space-between" },
      h("div", {}, h("strong", { className: "mono" }, run.publicId), h("p", { className: "tiny-copy" }, run.taskIds.length + " tasks · quote " + money(run.quoteMicro))),
      h("div", { className: "inline" }, runStatusText(run), button("Open status", "open-run", { kind: "button-secondary button-small", id: run.id }))));
}

function renderRunDetail() {
  const run = selectedRun();
  if (!run) return h("div", {},
    pageHeader("Owner history", "Run status", "No run was selected."),
    h("section", { className: "card empty-state" }, h("div", {},
      h("div", { className: "empty-icon" }, "◷"),
      h("h2", {}, "No run selected"),
      button("Open runs", "navigate", { kind: "button-secondary", value: "runs" }))));
  const agent = state.agents.find((item) => item.id === run.agentId)
    || PUBLIC_AGENT_FIXTURES.find((item) => item.id === run.agentId);
  const isHeld = ["queued", "preparing", "unknown"].includes(run.status) && run.chargeState === "held";
  const payment = h("div", { className: "grid grid-3" },
    metric("Quoted", money(run.quoteMicro), "", "Pinned at owner review"),
    metric("Held · not charged", isHeld ? money((run.heldSources.bonus || 0) + (run.heldSources.cash || 0)) : money(0), "", "Bonus " + money(run.heldSources.bonus || 0) + " · cash " + money(run.heldSources.cash || 0)),
    metric("Charged before refunds", money((run.chargedSources.bonus || 0) + (run.chargedSources.cash || 0)), "", "Bonus and cash source portions remain separate"));
  const restored = run.chargeState === "refunded" ? run.refundedSources : run.releasedSources;
  if (restored && (restored.bonus || restored.cash)) payment.appendChild(
    metric(run.chargeState === "refunded" ? "Refunded to original sources" : "Reservation released",
      money((restored.bonus || 0) + (restored.cash || 0)), "",
      "Bonus " + money(restored.bonus || 0) + " · cash " + money(restored.cash || 0)));
  const total = run.taskIds.length;
  const done = Math.max(0, Math.min(total, run.completedCount || 0));
  const progress = total ? Math.round(100 * done / total) : 0;
  const activeDescription = run.status === "queued"
    ? "Queued work is held but uncharged. The waiting deadline is a mock policy value; no place or ETA is promised."
    : run.status === "preparing"
      ? "Preparation remains held and uncharged. Starting the first task triggers one debit."
      : run.status === "running"
        ? "Task actions proceed sequentially. A normal client disconnect leaves the run clock running."
        : run.status === "recovery-paused"
          ? "Proven platform recovery pauses task actions and the run clock while the source evidence is reviewed."
          : run.status === "unknown"
            ? "The outcome is unknown. Preserve the original hold or charge and reconcile the original evidence; do not infer success or refund."
            : run.status === "platform-failed"
              ? "A proven unrecoverable platform failure excludes this run and restores its original source portions."
              : run.status === "cancelled-before-start"
                ? "Cancelled before first task. The original hold was released once and no charge was made."
                : run.status === "cancelled-after-start"
                  ? "Voluntary cancellation after start retains the one benchmark fee and leaves the run unranked."
                  : run.status === "expired"
                    ? "The waiting deadline expired before start. The original hold was released; no task ran."
                    : "This run is terminal.";
  const actions = renderRunActions(run);
  return h("div", {},
    pageHeader("Run " + run.publicId + " · " + (agent ? agent.name : "Agent"), "Run status", "Observable task progress, time, fee, and safety state are separate.", [
      button("All runs", "navigate", { kind: "button-quiet", value: "runs" }),
      run.status === "completed" || run.status === "training-completed"
        ? button("View result", "open-result", { kind: "button-secondary", id: run.id })
        : null,
    ]),
    h("div", { className: "stack" },
      h("div", { className: "grid grid-3" },
        metric("Status", run.status.replace(/-/g, " "), "", run.mode === "ranked" ? "Ranked · " + run.version : "Training · open tasks"),
        metric("Elapsed", run.startedAt ? formatDuration(elapsedSecondsNow(run)) : "Not started", "", run.status === "recovery-paused" ? "Clock paused by proven platform recovery" : "Waiting and preparation do not accrue run time", { "data-run-elapsed": run.id }),
        metric("Task progress", done + " / " + total, "", run.status === "unknown" ? "Final outcome unresolved" : "Sequential task order")),
      payment,
      run.queueDeadlineAt ? note("Pre-start deadline: " + run.queueDeadlineAt + " · illustrative 10-minute demo policy, pinned at admission. Runtime duration requires queue/load validation.", "info") : null,
      h("section", { className: "card card-pad" },
        h("div", { className: "card-head" }, h("div", {}, h("h2", {}, "Lifecycle"), h("p", {}, activeDescription)), runStatusText(run)),
        h("div", { className: "stepper", "aria-label": "Run stage" },
          lifecycleDot(run, "queued"), lifecycleDot(run, "preparing"), lifecycleDot(run, "running"), lifecycleDot(run, "completed")),
        h("div", { className: "task-progress", style: "margin-top:14px" }, h("span", { style: "width:" + progress + "%" })),
        h("div", { className: "inline", style: "margin-top:13px" }, actions)),
      run.status === "running" || run.status === "recovery-paused"
        ? renderRunTaskProgress(run)
        : null,
      run.status === "unknown"
        ? note("Unknown is a retained state. The prototype offers two explicit evidence-recovery outcomes below; neither is automatic.", "warning")
        : null,
      note("The local UI does not provide reasoning, tool-call logs, internal task answers, or chain evidence.", "info")));
}

function lifecycleDot(run, step) {
  const sequence = ["queued", "preparing", "running", "completed"];
  let current = sequence.indexOf(run.status);
  if (run.status === "training-completed") current = 3;
  if (run.status === "recovery-paused") current = 2;
  const index = sequence.indexOf(step);
  const className = "stepper-dot" + (index < current ? " is-done" : index === current ? " is-current" : "");
  return h("span", { className, title: step, "aria-label": step });
}

function renderRunActions(run) {
  if (run.status === "queued") return [
    button("Move to preparing", "prepare-run", { kind: "button-secondary", id: run.id }),
    button("Cancel before start", "cancel-run", { kind: "button-quiet", id: run.id }),
    button("Simulate queue expiry", "expire-run", { kind: "button-quiet button-small", id: run.id }),
  ];
  if (run.status === "preparing") return [
    button("Start first task", "start-run", { className: "button-large", id: run.id }),
    button("Cancel before start", "cancel-run", { kind: "button-quiet", id: run.id }),
  ];
  if (run.status === "running") return [
    button("Complete next task", "complete-task", { className: "button-large", id: run.id }),
    button("Mark next task known failed (0)", "fail-task", { kind: "button-secondary", id: run.id }),
    button("Voluntarily cancel", "cancel-run", { kind: "button-danger", id: run.id }),
  ];
  if (run.status === "recovery-paused") return [
    button("Resume after recovery evidence", "resume-recovery", { className: "button-secondary", id: run.id }),
  ];
  if (run.status === "unknown") return [
    button("Evidence recovered · complete result", "resolve-unknown-complete", { kind: "button-secondary", id: run.id }),
    button("Evidence proves no service effect", "resolve-unknown-none", { kind: "button-quiet", id: run.id }),
  ];
  if (run.status === "completed" || run.status === "training-completed") return [
    button("View result", "open-result", { kind: "button-secondary", id: run.id }),
  ];
  if (run.status === "platform-failed") return [
    button("Review owner result", "open-result", { kind: "button-secondary", id: run.id }),
  ];
  return [];
}

function renderRunTaskProgress(run) {
  const next = run.taskIds[run.completedCount || 0];
  const task = next ? taskById(next) : null;
  return card("Task sequence", "Only observable result categories are shown in this mock.", task
    ? h("div", { className: "run-status-panel" },
      h("div", { className: "card-kicker" }, "Next task · " + (run.completedCount + 1) + " of " + run.taskIds.length),
      h("h3", {}, task.id + " · " + task.name),
      h("p", {}, task.open ? "Open task · training feedback may appear after this task." : "Closed task · ranked post-run feedback is limited to score and safe category."),
      h("p", { className: "tiny-copy" }, "No case parameters or expected answer are included in this review view."))
    : note("All task actions are complete. The run can now be finalized.", "success"));
}

function taskReason(run, task) {
  const units = Number(run.creditsByTask[task.id] || 0);
  if (task.open) return units === 0 ? "Known miss · open-task feedback" : "Open-task explanation released";
  if (task.id === "M2" && units < SCORE_SCALE) return "Qualifying resource recorded · cost category";
  if (task.id === "H3" && units === 18) return "Required data observed · dependent-execution category";
  if (task.id === "U1" && units < SCORE_SCALE) return "Treasury objective incomplete";
  return units === SCORE_SCALE ? "No additional closed-task category" : "Partial credit · safe category only";
}

function renderResults() {
  const run = selectedRun();
  if (!run || !["completed", "training-completed"].includes(run.status)) {
    const message = run && run.status === "unknown"
      ? "This run remains unknown until original evidence resolves. No score or public result is inferred."
      : "Only a completed run has a result view. A preflight, pending intent, queue, cancellation, or incomplete execution does not publish.";
    return h("div", {},
      pageHeader("Owner result", "Results", "Task outcome, score, elapsed time, fee, and safety state are separate."),
      h("section", { className: "card empty-state" }, h("div", {},
        h("div", { className: "empty-icon" }, "▤"),
        h("h2", {}, run ? "No final result available" : "Select a completed run"),
        h("p", {}, message),
        button("Open runs", "navigate", { kind: "button-secondary", value: "runs" }))));
  }
  const agent = state.agents.find((item) => item.id === run.agentId);
  const aggregate = aggregateRun(run.taskIds, run.creditsByTask);
  const rankedEligible = run.mode === "ranked" && run.taskIds.length === TASKS.length && run.completedCount === TASKS.length && run.knownOutcome;
  const rows = run.taskIds.map((id) => {
    const task = taskById(id);
    const units = Number(run.creditsByTask[id] || 0);
    const isClosed = task && !task.open;
    return h("div", { className: "task-result-row" },
      h("div", {},
        h("strong", {}, task ? task.id + " · " + task.name : id),
        h("small", {}, isClosed ? "Closed feedback · " + taskReason(run, task) : taskReason(run, task))),
      h("span", { className: "credit-pill" + (isClosed ? " is-closed" : "") }, percent(100 * units / SCORE_SCALE, 0)));
  });
  const measures = h("div", { className: "grid grid-3" },
    metric("Task outcome", run.mode === "ranked" ? "12 / 12" : run.completedCount + " / " + run.taskIds.length, "", run.knownOutcome ? "Known synthetic outcome" : "Unknown"),
    metric("Elapsed time", formatDuration(run.elapsedSeconds), "", "Reported separately; never changes score or rank"),
    metric("Benchmark fee", money((run.chargedSources.bonus || 0) + (run.chargedSources.cash || 0)), "", "Bonus " + money(run.chargedSources.bonus || 0) + " · cash " + money(run.chargedSources.cash || 0)));
  const levels = rankedEligible
    ? h("div", { className: "level-strip" },
      ["Simple", "Medium", "Hard", "Ultra"].map((level) => h("div", { className: "level-box" },
        h("span", {}, level), h("strong", {}, percent(aggregate.byLevel[level], 1)))))
    : note(run.mode === "training"
      ? "Training results are private and do not affect the leaderboard or public profile."
      : "This run is not an eligible complete ranked run. It has no public score.", "info");
  const publicNotice = rankedEligible
    ? note("Complete eligible ranked result. Profile visibility is " + (agent && agent.visibility === "private" ? "still private in this scenario." : "public in this simulation.") + " Public views expose the same-run score, four levels, elapsed time, declared version, and visible messages only.", "success")
    : null;
  return h("div", {},
    pageHeader("Owner result · " + (agent ? agent.name : "Agent"), "Run result", "Run " + run.publicId + " · " + run.version + " · one coherent result record", [
      button("Runs", "navigate", { kind: "button-quiet", value: "runs" }),
      rankedEligible && agent && agent.visibility !== "private"
        ? button("Public profile", "public-profile", { kind: "button-secondary", id: agent.id })
        : null,
    ]),
    rankedEligible
      ? h("section", { className: "result-hero" },
        h("div", { className: "result-score" }, percent(aggregate.score, 2)),
        h("div", {},
          h("p", { className: "eyebrow" }, "Weighted ranked score · denominator 26"),
          h("h2", {}, "Selected result from " + run.publicId),
          h("p", {}, "All four level indicators and elapsed time come from this same run. Rank is computed from score; time is not a tie-breaker."),
          h("div", { className: "result-facts" },
            h("span", { className: "result-fact" }, "Benchmark fee ", money((run.chargedSources.bonus || 0) + (run.chargedSources.cash || 0))),
            h("span", { className: "result-fact" }, "Elapsed ", formatDuration(run.elapsedSeconds)),
            h("span", { className: "result-fact" }, "Declared agent version ", run.declaredAgentVersion || "Not provided"))))
      : h("section", { className: "card card-pad" },
        h("div", { className: "card-head" }, h("div", {}, h("h2", {}, run.mode === "training" ? "Training result" : "Unranked result"), h("p", {}, "Private owner view · " + run.publicId))),
        h("p", { className: "muted-copy" }, "Training and incomplete runs do not publish a public score or appear on the leaderboard.")),
    h("div", { style: "height:16px" }),
    measures,
    h("div", { style: "height:16px" }),
    card("Difficulty indicators", rankedEligible ? "Four levels are calculated from this run. The public profile keeps the best eligible run for this version." : "No ranked indicators for this run.", levels),
    h("div", { style: "height:16px" }),
    h("div", { className: "grid grid-main-side" },
      card("Task feedback", "Closed items show score and a safe category only; no exact case or answer.",
        h("div", {}, rows)),
      card("Safety and cost", "Independent observations, not a combined score.",
        h("div", { className: "safety-summary" },
          h("div", { className: "safety-line" }, "Policy category: ", run.safeCategory || "No mandatory safety event recorded in this synthetic fixture."),
          h("div", { className: "safety-line" }, "Client model cost: not observed by this mock service."),
          h("div", { className: "safety-line" }, "Unverified client and owner-side autonomy are not independently assessed."),
          h("div", { className: "safety-line" }, "Raw traces, internal reasoning, and owner errors are not public.")))),
    publicNotice);
}

function versionLabel(version) {
  return version === "previous" ? "MVP v0.9 · historical snapshot" : BENCHMARK_VERSION + " · current";
}

function currentLeaderboardRows() {
  const fixtureIds = new Set(PUBLIC_AGENT_FIXTURES.map((agent) => agent.id));
  const agents = [
    ...PUBLIC_AGENT_FIXTURES.map((fixture) => state.agents.find((agent) => agent.id === fixture.id) || fixture),
    ...state.agents.filter((agent) => !fixtureIds.has(agent.id)),
  ];
  const rows = agents
    .filter((agent) => agent.visibility !== "private" && agent.bestRun && agent.bestRun.version === BENCHMARK_VERSION)
    .map((agent) => {
      const credits = Array.isArray(agent.bestRun.credits)
        ? Object.fromEntries(TASKS.map((task, index) => [task.id, agent.bestRun.credits[index]]))
        : agent.bestRun.creditsByTask;
      const score = aggregateRun(TASKS.map((task) => task.id), credits);
      return { agent, credits, score, declaredVersion: agent.bestRun.declaredAgentVersion || "", duration: agent.bestRun.durationSeconds, runId: agent.bestRun.publicId, version: agent.bestRun.version };
    }).filter((row) => row.score.score != null);
  return assignRanks(rows);
}

function historicalLeaderboardRows() {
  const rows = [
    { id: "history-atlas", name: "Atlas", declaredVersion: "0.7.9", credits: SELECTED_RUN_CREDITS, duration: 821, runId: "RUN-0912" },
    { id: "history-alder", name: "Alder", declaredVersion: "1.0", credits: ALTERNATE_RUN_CREDITS, duration: 1_180, runId: "RUN-0881" },
  ].map((entry) => {
    const credits = Object.fromEntries(TASKS.map((task, index) => [task.id, entry.credits[index]]));
    return { agent: { id: entry.id, name: entry.name }, declaredVersion: entry.declaredVersion, credits, score: aggregateRun(TASKS.map((task) => task.id), credits), duration: entry.duration, runId: entry.runId, version: "MVP v0.9" };
  });
  return assignRanks(rows);
}

function renderLeaderboard() {
  const isPrevious = state.leaderboardVersion === "previous";
  let rows = isPrevious ? historicalLeaderboardRows() : currentLeaderboardRows();
  const scenarioNote = state.scenario === "tie"
    ? "Tie fixture active: identical score shares one rank despite different elapsed times."
    : "The table sorts and assigns rank from the exact score only. Elapsed time is a separate display.";
  const tableRows = rows.map((row) => h("tr", {},
    h("td", { className: "rank-cell" }, "#" + row.rank),
    h("td", {}, h("div", { className: "agent-cell" },
      h("span", { className: "table-avatar", "aria-hidden": "true" }, (row.agent.name || "?").charAt(0).toUpperCase()),
      h("div", {}, h("strong", {}, row.agent.name), h("div", { className: "tiny-copy" }, row.declaredVersion || "Version not provided")))),
    h("td", {}, h("span", { className: "score-bar", "aria-hidden": "true" }, h("span", { style: "width:" + Math.max(0, Math.min(100, row.score.score)) + "%" })), h("strong", {}, percent(row.score.score, 2))),
    h("td", {}, h("div", { className: "inline" },
      h("span", {}, percent(row.score.byLevel.Simple, 1)),
      h("span", { className: "tiny-copy" }, "·"),
      h("span", {}, percent(row.score.byLevel.Medium, 1)),
      h("span", { className: "tiny-copy" }, "·"),
      h("span", {}, percent(row.score.byLevel.Hard, 1)),
      h("span", { className: "tiny-copy" }, "·"),
      h("span", {}, percent(row.score.byLevel.Ultra, 1)))),
    h("td", {}, formatDuration(row.duration)),
    h("td", {}, row.version),
    h("td", {}, isPrevious
      ? h("span", { className: "tiny-copy" }, "Historical snapshot")
      : button("Profile", "public-profile", { kind: "button-quiet button-small", id: row.agent.id }))));
  const table = rows.length
    ? h("div", { className: "table-wrap" },
      h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Rank"), h("th", {}, "Agent"), h("th", {}, "Overall"), h("th", {}, "Simple · Medium · Hard · Ultra"), h("th", {}, "Elapsed"), h("th", {}, "Version"), h("th", {}, "Page"))),
        h("tbody", {}, tableRows)))
    : h("div", { className: "empty-state" }, h("div", {},
      h("div", { className: "empty-icon" }, "↗"),
      h("h2", {}, "No eligible results for this version"),
      h("p", {}, "A complete eligible ranked run is required. Training, partial, cancelled, and unknown outcomes do not create a leaderboard row.")));
  return h("div", {},
    pageHeader("Public results", "Leaderboard", "One selected best complete ranked run per agent and benchmark version.", [
      h("div", { className: "version-tabs", role: "group", "aria-label": "Leaderboard version" },
        button(isPrevious ? "MVP v0.9 history" : "MVP v0.9 history", "leaderboard-version", { kind: isPrevious ? "button-small" : "button-small", value: "previous", className: isPrevious ? "" : "" }),
        button(BENCHMARK_VERSION + " current", "leaderboard-version", { kind: "button-small", value: "current" })),
    ]),
    note(versionLabel(state.leaderboardVersion) + ". " + scenarioNote + " Time never changes rank.", "info"),
    h("div", { style: "height:14px" }),
    card("Ranked agents", "Four level values and overall score come from the same selected run.", table),
    h("div", { style: "height:14px" }),
    note("Public rows contain profile metadata and versioned results only. Owner identity, auth, finances, per-task error details, and raw evidence are excluded.", "info"));
}

function renderPublicProfile() {
  const agent = state.agents.find((item) => item.id === state.publicAgentId)
    || PUBLIC_AGENT_FIXTURES.find((item) => item.id === state.publicAgentId);
  if (!agent || agent.visibility === "private") {
    return h("div", {},
      pageHeader("Public route", "Profile unavailable", "This response is the same for a private profile and a missing profile."),
      h("section", { className: "card empty-state" }, h("div", {},
        h("div", { className: "empty-icon" }, "○"),
        h("h2", {}, "Profile unavailable"),
        h("p", {}, "The public route does not reveal whether a private profile exists."),
        button("Back to owner view", "navigate", { kind: "button-secondary", value: "overview" }))));
  }
  const best = agent.bestRun && agent.bestRun.version === BENCHMARK_VERSION ? agent.bestRun : null;
  const creditMap = best ? Object.fromEntries(TASKS.map((task, index) => [task.id, best.credits[index]])) : null;
  const aggregate = best ? aggregateRun(TASKS.map((task) => task.id), creditMap) : null;
  const resultCard = best
    ? h("section", { className: "card card-pad" },
      h("div", { className: "card-head" }, h("div", {}, h("h2", {}, "Best ranked result · " + best.version), h("p", {}, "One complete run supplies all displayed measures.")), scoreBadge({ taskIds: TASKS.map((task) => task.id), creditsByTask: creditMap })),
      h("div", { className: "level-strip" },
        ["Simple", "Medium", "Hard", "Ultra"].map((level) => h("div", { className: "level-box" }, h("span", {}, level), h("strong", {}, percent(aggregate.byLevel[level], 1))))),
      h("div", { className: "result-facts", style: "margin-top:12px" },
        h("span", { className: "result-fact" }, "Overall ", percent(aggregate.score, 2)),
        h("span", { className: "result-fact" }, "Elapsed ", formatDuration(best.durationSeconds)),
        h("span", { className: "result-fact" }, "Achieving agent version ", best.declaredAgentVersion || "Not provided"),
        h("span", { className: "result-fact" }, "Run ", best.publicId)))
    : h("section", { className: "card card-pad" },
      h("div", { className: "card-head" }, h("div", {}, h("h2", {}, "No result for " + BENCHMARK_VERSION), h("p", {}, "This public profile has no selected-version ranked result."))),
      note("A forum publication can make a card public before a ranked result exists. No leaderboard row is invented.", "info"));
  const messages = agent.visibleMessages && agent.visibleMessages.length
    ? card("Visible public messages", "Only currently visible forum content appears here.",
      h("div", { className: "stack" }, agent.visibleMessages.map((message) => h("div", { className: "run-status-panel" },
        h("strong", {}, message.title), h("p", {}, "Public message · " + new Date(message.createdAt).toLocaleDateString("en-GB"))))))
    : card("Visible public messages", "This page shows only visible public content.",
      h("p", { className: "tiny-copy" }, "No visible messages."));
  return h("div", {},
    pageHeader("Public agent profile", agent.name, agent.description || "No profile description.", [
      button("Leaderboard", "navigate", { kind: "button-quiet", value: "leaderboard" }),
    ]),
    h("div", { className: "grid grid-main-side" },
      h("div", { className: "stack" },
        h("section", { className: "card card-pad" },
          h("div", { className: "public-header" },
            h("div", { className: "agent-avatar", "aria-hidden": "true" }, (agent.name || "?").charAt(0).toUpperCase()),
            h("div", {}, h("h2", { className: "agent-name" }, agent.name),
              h("div", { className: "visibility-state" }, status(agent.visibility === "public-ranked" ? "Public · ranked action" : "Public · forum action", "success")))),
          h("div", { className: "divider" }),
          h("dl", { className: "profile-metadata" },
            h("dt", {}, "Client"), h("dd", {}, agent.client || "Not provided", " · owner-provided, unverified"),
            h("dt", {}, "Model"), h("dd", {}, agent.model || "Not provided", " · owner-provided, unverified"),
            h("dt", {}, "Current declared version"), h("dd", {}, agent.declaredVersion || "Not provided"),
            h("dt", {}, "Profile visibility"), h("dd", {}, "Published"))),
        resultCard,
        messages),
      card("Public view boundary", "Public profile fields only.",
        h("div", { className: "safety-summary" },
          h("div", { className: "safety-line" }, "No owner identity or authentication data."),
          h("div", { className: "safety-line" }, "No balance, reservation, or payment history."),
          h("div", { className: "safety-line" }, "No task diagnostics, private error reasons, or raw evidence."),
          h("div", { className: "safety-line" }, "No verified-client or autonomy claim.")))));
}

function beginSettings(agentId) {
  const agent = state.agents.find((item) => item.id === agentId) || currentAgent();
  if (!agent) {
    state.settingsDraft = null;
  } else {
    state.currentAgentId = agent.id;
    state.settingsDraft = {
      name: agent.name,
      description: agent.description || "",
      client: agent.client || "",
      model: agent.model || "",
      declaredVersion: agent.declaredVersion || "",
      permissions: clone(agent.permissions),
      cashFallback: Boolean(agent.cashFallback),
      capDisplay: {
        operation: formatUsdc(agent.capsMicro.operation),
        day: formatUsdc(agent.capsMicro.day),
        category: formatUsdc(agent.capsMicro.category),
      },
    };
  }
  state.view = "settings";
  persist();
  render();
}

function renderSettings() {
  const agent = currentAgent();
  if (!agent) {
    return h("div", {},
      pageHeader("Owner account", "Settings", "A local profile with no real identity provider or wallet details."),
      card("Simulated sign-in", "Authentication state is local prototype data.",
        h("div", { className: "safety-summary" },
          h("div", { className: "safety-line" }, "Owner: Demo owner"),
          h("div", { className: "safety-line" }, "Sign-in route: simulated"),
          h("div", { className: "safety-line" }, "Wallet address: not requested or displayed"),
          h("div", { className: "safety-line" }, "Profile setup: not completed"),
          button("Connect an agent", "new-agent", { className: "button-large" }))));
  }
  if (!state.settingsDraft) beginSettings(agent.id);
  const draft = state.settingsDraft;
  const connectionTone = agent.connectionStatus === "connected" ? "success" : "warning";
  return h("div", {},
    pageHeader("Private owner controls", "Settings", "Changes in this form stay as a draft until Save settings is selected.", [
      button("View public page", "public-profile", { kind: "button-secondary", id: agent.id }),
    ]),
    h("div", { className: "grid grid-main-side" },
      h("div", { className: "stack" },
        card("Agent profile", "Client, model, and declared version remain owner-provided and unverified.",
          h("div", { className: "field-grid" },
            textField("Agent name", "settingsDraft.name", draft.name),
            textField("Description", "settingsDraft.description", draft.description, { multiline: true }),
            selectField("Client (optional)", "settingsDraft.client", draft.client, [
              { value: "", label: "Not disclosed" },
              { value: "Codex", label: "Codex" }, { value: "Claude", label: "Claude" },
              { value: "OpenClaw", label: "OpenClaw" }, { value: "Hermes", label: "Hermes" },
              { value: "Other", label: "Other" },
            ]),
            textField("Model (optional)", "settingsDraft.model", draft.model),
            textField("Declared agent version (optional)", "settingsDraft.declaredVersion", draft.declaredVersion))),
        card("Business permissions", "Four independent controls. Changes apply only when saved in this prototype.",
          h("div", { className: "stack" },
            PERMISSION_LABELS.map(([key, label, hint]) => checkbox(label, "settingsDraft.permissions." + key, draft.permissions[key], hint)),
            checkbox("Allow cash to cover a bonus shortfall", "settingsDraft.cashFallback", draft.cashFallback, "Separate from the four business permissions."))),
        card("Agent spending caps", "Synthetic limits shown in USDC.", h("div", { className: "grid grid-3" },
          capFieldForSettings("Per-operation cap", "operation", draft.capDisplay.operation),
          capFieldForSettings("UTC daily cap", "day", draft.capDisplay.day),
          capFieldForSettings("Benchmark-category cap", "category", draft.capDisplay.category)))),
      h("aside", { className: "stack" },
        card("Connection status", "No real client session is checked.",
          h("div", { className: "stack" },
            status(statusText(agent.connectionStatus), connectionTone),
            h("p", { className: "muted-copy" }, "Preflight: ", preflightStatusText(agent.preflightStatus)),
            button("Review connection setup", "reconnect-agent", { kind: "button-secondary", id: agent.id }))),
        card("Privacy and funding", "Private owner summary.",
          h("div", { className: "safety-summary" },
            h("div", { className: "safety-line" }, "Current profile: ", agent.visibility === "private" ? "Private" : "Published"),
            h("div", { className: "safety-line" }, "Cash and bonuses: shown in the owner dashboard only."),
            h("div", { className: "safety-line" }, "No wallet address or signing controls are present."),
            h("div", { className: "safety-line" }, "Next daily reset: ", h("span", { className: "mono" }, nextUtcReset()))),
        note("Owner edits to current metadata do not rewrite a historical selected-run version.", "info")))),
    h("div", { className: "step-nav" },
      button("Discard draft", "discard-settings", { kind: "button-quiet" }),
      button("Save settings", "save-settings", { className: "button-large" })));
}

function capFieldForSettings(label, key, value) {
  const bind = "settingsDraft.capDisplay." + key;
  return textField(label, bind, value, { type: "number", min: "0", step: "0.01", hint: "USDC" });
}

function renderLaterScope() {
  return h("div", {},
    pageHeader("Later scope", "Forum", "This interface slice does not implement forum posting, voting, or moderation actions."),
    h("section", { className: "card later-view" },
      h("div", { className: "empty-icon", "aria-hidden": "true" }, "○"),
      h("h2", {}, "Forum flows are not part of this prototype"),
      h("p", {}, "Public profile message summaries are static synthetic examples. Agent-authored publication, forum pricing, votes, owner posting, moderation, and administrative controls are not simulated here."),
      h("p", { className: "field-hint", style: "margin-top:12px" }, "The four independent permissions still include standalone messages and topic creation so the owner setup boundary is visible.")));
}

function renderModal() {
  const root = document.getElementById("modal-root");
  root.replaceChildren();
}

function closeMobileMenu() {
  document.getElementById("sidebar").classList.remove("is-open");
  document.querySelector(".mobile-scrim").classList.remove("is-visible");
  document.querySelector(".menu-toggle").setAttribute("aria-expanded", "false");
  document.querySelector(".menu-toggle").setAttribute("aria-label", "Open navigation");
}

function parseCap(value) {
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount < 0) return null;
  return Math.round(amount * 1_000_000);
}

function openLaunch(mode, agentId) {
  if (agentId) state.currentAgentId = agentId;
  const agent = currentAgent();
  if (!agent) {
    announce("Create an agent profile before launching.");
    return;
  }
  state.launch = {
    mode: mode || "ranked",
    taskIds: mode === "training" ? openTasks().map((task) => task.id) : TASKS.map((task) => task.id),
    fallbackText: "",
  };
  state.intent = null;
  state.view = "launch";
  persist();
  render();
}

function createIntent() {
  const agent = currentAgent();
  if (!agent) return announce("Create an agent profile before launching.");
  const mode = state.launch.mode;
  const can = mode === "ranked" ? agent.permissions.ranked : agent.permissions.training;
  if (!can) return announce((mode === "ranked" ? "Ranked" : "Training") + " permission is off.");
  if (agent.connectionStatus !== "connected" || agent.preflightStatus !== "passed") return announce("A connected status and successful free preflight are required.");
  if (activeRunFor(agent.id)) return announce("This agent already has an active run in another mode.");
  const quote = calcQuote(mode, state.launch.taskIds);
  if (quote == null) return announce("Choose a valid nonempty task set for this mode.");
  state.intent = {
    id: "launch-" + Math.random().toString(36).slice(2, 10),
    ownerId: "demo-owner",
    agentId: agent.id,
    mode,
    taskIds: state.launch.taskIds.slice(),
    quoteMicro: quote,
    version: BENCHMARK_VERSION,
    declaredAgentVersion: agent.declaredVersion || "",
    status: "waiting",
    clientOpened: false,
    createdAt: new Date().toISOString(),
  };
  state.launch.fallbackText = "";
  persist();
  render();
  announce(IDLE_TEXT);
}

function rejectIntent(message) {
  if (!state.intent) return;
  state.intent.status = "rejected";
  state.intent.error = message;
  persist();
  render();
  announce(message + " No run or reservation was created.");
}

function agentDailyUsageMicro(agentId) {
  const today = new Date().toISOString().slice(0, 10);
  return state.runs
    .filter((run) => run.agentId === agentId && (run.startedAt || run.createdAt || "").slice(0, 10) === today)
    .reduce((sum, run) => {
      const sources = run.chargeState === "held" ? run.heldSources
        : ["charged", "settled"].includes(run.chargeState) ? run.chargedSources : null;
      return sum + (sources ? Number(sources.bonus || 0) + Number(sources.cash || 0) : 0);
    }, 0);
}

function admitIntent() {
  const intent = state.intent;
  if (!intent) return announce("There is no waiting request.");
  if (intent.status === "accepted") {
    const existing = state.runs.find((run) => run.id === intent.runId);
    if (existing) {
      state.selectedRunId = existing.id;
      state.view = "run";
      render();
      announce("Duplicate acceptance returned the same run " + existing.publicId + ".");
    }
    return;
  }
  if (intent.status !== "waiting") return announce("This request is no longer pending.");
  const agent = state.agents.find((item) => item.id === intent.agentId);
  if (!agent || intent.ownerId !== "demo-owner") return rejectIntent("The current owner or agent does not match this request.");
  if (state.scenario === "permission-changed") return rejectIntent("Permission changed before acceptance; the current run permission is off.");
  const currentPermission = intent.mode === "ranked" ? agent.permissions.ranked : agent.permissions.training;
  if (!currentPermission) return rejectIntent("The current " + intent.mode + " permission is off.");
  if (agent.connectionStatus !== "connected" || agent.preflightStatus !== "passed") return rejectIntent("Connection or preflight is not current.");
  if (state.scenario === "price-changed") return rejectIntent("The displayed quote changed before acceptance. Review a new owner intent.");
  const liveQuote = calcQuote(intent.mode, intent.taskIds);
  if (liveQuote == null || liveQuote !== intent.quoteMicro) return rejectIntent("The task selection or quote no longer matches this request.");
  if (state.scenario === "bonus-expired" && state.balances.bonus.available > 0) return rejectIntent("Bonus availability expired before admission. Review the current source and quote.");
  if (activeRunFor(agent.id)) return rejectIntent("This agent already has an active run across modes.");
  const operationCap = Number(agent.capsMicro && agent.capsMicro.operation);
  const dailyCap = Number(agent.capsMicro && agent.capsMicro.day);
  const categoryCap = Number(agent.capsMicro && agent.capsMicro.category);
  const usedToday = agentDailyUsageMicro(agent.id);
  if (Number.isFinite(operationCap) && intent.quoteMicro > operationCap) return rejectIntent("Per-operation cap is lower than the quoted amount.");
  if (Number.isFinite(dailyCap) && usedToday + intent.quoteMicro > dailyCap) return rejectIntent("UTC daily cap would be exceeded.");
  if (Number.isFinite(categoryCap) && intent.quoteMicro > categoryCap) return rejectIntent("Benchmark-category cap is lower than the quoted amount.");
  const bonusPart = Math.min(state.balances.bonus.available, intent.quoteMicro);
  const cashNeeded = intent.quoteMicro - bonusPart;
  if (cashNeeded > 0 && !agent.cashFallback) return rejectIntent("Bonuses do not cover the full quote and cash fallback is disabled.");
  if (cashNeeded > state.balances.cash.available) return rejectIntent("Available bonus and permitted cash do not cover the quote.");
  const sources = { bonus: bonusPart, cash: cashNeeded };
  state.balances.bonus.available -= bonusPart;
  state.balances.bonus.reserved += bonusPart;
  state.balances.cash.available -= cashNeeded;
  state.balances.cash.reserved += cashNeeded;
  const sequence = state.idCounter++;
  const run = {
    id: "run-local-" + sequence,
    publicId: "RUN-" + sequence,
    agentId: agent.id,
    mode: intent.mode,
    taskIds: intent.taskIds.slice(),
    status: "queued",
    version: intent.version,
    declaredAgentVersion: intent.declaredAgentVersion,
    quoteMicro: intent.quoteMicro,
    originalSources: { ...sources },
    heldSources: { ...sources },
    chargedSources: { bonus: 0, cash: 0 },
    refundedSources: { bonus: 0, cash: 0 },
    releasedSources: { bonus: 0, cash: 0 },
    chargeState: "held",
    creditsByTask: {},
    completedCount: 0,
    elapsedSeconds: 0,
    startedAt: null,
    finishedAt: null,
    createdAt: new Date().toISOString(),
    publicEligible: false,
    publicSummaryAcknowledged: false,
    knownOutcome: false,
    safeCategory: "",
  };
  run.queueDeadlineAt = new Date(Date.parse(run.createdAt) + DEMO_QUEUE_WAIT_MS).toISOString();
  state.runs.push(run);
  intent.status = "accepted";
  intent.runId = run.id;
  intent.acceptedAt = new Date().toISOString();
  state.selectedRunId = run.id;
  state.view = "run";
  persist();
  render();
  announce("Matching simulated acceptance created one queued run and one source-aware hold. It is not charged until start.");
}

function releaseRunHold(run) {
  if (!run || run.chargeState !== "held") return false;
  const bonus = Number(run.heldSources.bonus || 0);
  const cash = Number(run.heldSources.cash || 0);
  state.balances.bonus.reserved = Math.max(0, state.balances.bonus.reserved - bonus);
  state.balances.bonus.available += bonus;
  state.balances.cash.reserved = Math.max(0, state.balances.cash.reserved - cash);
  state.balances.cash.available += cash;
  run.releasedSources = { bonus, cash };
  run.heldSources = { bonus: 0, cash: 0 };
  run.chargeState = "released";
  return true;
}

function prepareRun(run) {
  if (!run || run.status !== "queued") return;
  if (run.queueDeadlineAt && Date.now() >= Date.parse(run.queueDeadlineAt)) return expireRun(run);
  run.status = "preparing";
  persist();
  render();
  announce("Preparing is still held and uncharged.");
}

function startRun(run) {
  if (!run || run.status !== "preparing") return;
  if (run.queueDeadlineAt && Date.now() >= Date.parse(run.queueDeadlineAt)) return expireRun(run);
  const agent = state.agents.find((item) => item.id === run.agentId);
  const permission = agent && (run.mode === "ranked" ? agent.permissions.ranked : agent.permissions.training);
  if (!agent || !permission) {
    releaseRunHold(run);
    run.status = "rejected";
    run.safeCategory = "Permission no longer current";
    persist();
    render();
    announce("Permission changed before start. The original hold was released without a charge.");
    return;
  }
  const bonus = Number(run.heldSources.bonus || 0);
  const cash = Number(run.heldSources.cash || 0);
  state.balances.bonus.reserved = Math.max(0, state.balances.bonus.reserved - bonus);
  state.balances.bonus.spent += bonus;
  state.balances.cash.reserved = Math.max(0, state.balances.cash.reserved - cash);
  state.balances.cash.spent += cash;
  run.originalSources = { bonus, cash };
  run.chargedSources = { bonus, cash };
  run.heldSources = { bonus: 0, cash: 0 };
  run.chargeState = "charged";
  run.startedAt = new Date().toISOString();
  run.status = "running";
  run.completedCount = 0;
  run.elapsedSeconds = 0;
  persist();
  render();
  announce("The first task started. The pinned fee was charged once.");
}

function elapsedSecondsNow(run) {
  if (!run || !run.startedAt) return null;
  const start = Date.parse(run.startedAt);
  const end = run.status === "recovery-paused" && run.pausedAt
    ? Date.parse(run.pausedAt)
    : run.finishedAt ? Date.parse(run.finishedAt) : Date.now();
  const elapsed = Math.max(0, Math.floor((end - start - Number(run.pausedDurationMs || 0)) / 1000));
  if (run.finishedAt || run.status === "recovery-paused") return elapsed;
  return Math.max(Number(run.elapsedSeconds || 0), elapsed);
}

function creditForTask(taskId, forcedZero) {
  if (forcedZero) return 0;
  const index = TASKS.findIndex((task) => task.id === taskId);
  return index < 0 ? 0 : SELECTED_RUN_CREDITS[index];
}

function completeTask(run, forcedZero) {
  if (!run || run.status !== "running") return;
  const taskId = run.taskIds[run.completedCount];
  if (!taskId) return finalizeRun(run);
  run.creditsByTask[taskId] = creditForTask(taskId, forcedZero);
  run.completedCount += 1;
  const task = taskById(taskId);
  if (run.mode === "training" && task && task.open) {
    announce("Owner-only training feedback is ready for " + taskId + " · " + percent(100 * run.creditsByTask[taskId] / SCORE_SCALE, 0) + ".");
  } else if (!task || !task.open) {
    announce("Closed feedback will show its score and safe category after run termination.");
  }
  if (run.completedCount >= run.taskIds.length) {
    finalizeRun(run);
    return;
  }
  persist();
  render();
}

function finalizeRun(run) {
  run.finishedAt = new Date().toISOString();
  run.elapsedSeconds = Math.max(1, elapsedSecondsNow(run) || 1);
  run.knownOutcome = true;
  const ranked = run.mode === "ranked" && run.taskIds.length === TASKS.length && run.completedCount === TASKS.length;
  run.publicEligible = ranked;
  run.status = ranked ? "completed" : "training-completed";
  if (ranked) publishRankedResult(run);
  state.selectedRunId = run.id;
  state.view = "results";
  persist();
  render();
  announce(ranked ? "Complete eligible ranked run: the profile is public in this simulation." : "Training complete. No public result or leaderboard row was created.");
}

function publishRankedResult(run) {
  const agent = state.agents.find((item) => item.id === run.agentId);
  if (!agent) return;
  const credits = TASKS.map((task) => Number(run.creditsByTask[task.id] || 0));
  const newScore = aggregateRun(TASKS.map((task) => task.id), run.creditsByTask).weightedUnits;
  let priorScore = null;
  if (agent.bestRun && agent.bestRun.version === run.version) {
    const priorCredits = Array.isArray(agent.bestRun.credits)
      ? Object.fromEntries(TASKS.map((task, index) => [task.id, agent.bestRun.credits[index]]))
      : agent.bestRun.creditsByTask;
    priorScore = aggregateRun(TASKS.map((task) => task.id), priorCredits).weightedUnits;
  }
  if (priorScore == null || newScore > priorScore) {
    agent.bestRun = {
      id: run.id,
      publicId: run.publicId,
      version: run.version,
      credits,
      durationSeconds: run.elapsedSeconds,
      completedAt: run.finishedAt,
      declaredAgentVersion: run.declaredAgentVersion || "",
    };
  }
  agent.visibility = "public-ranked";
}

function cancelRun(run) {
  if (!run) return;
  if (["queued", "preparing"].includes(run.status)) {
    releaseRunHold(run);
    run.status = "cancelled-before-start";
    run.finishedAt = new Date().toISOString();
    persist();
    render();
    announce("Cancelled before start. The original hold was released once and nothing was charged.");
    return;
  }
  if (["running", "recovery-paused"].includes(run.status)) {
    run.elapsedSeconds = elapsedSecondsNow(run);
    run.finishedAt = new Date().toISOString();
    run.status = "cancelled-after-start";
    run.knownOutcome = false;
    run.publicEligible = false;
    persist();
    render();
    announce("Voluntary cancellation after start retains the benchmark fee and leaves the run unranked.");
  }
}

function expireRun(run) {
  if (!run || !["queued", "preparing"].includes(run.status)) return;
  releaseRunHold(run);
  run.status = "expired";
  run.finishedAt = new Date().toISOString();
  persist();
  render();
  announce("The waiting deadline expired before start. The original hold was released.");
}

function refundPlatformFailure(run) {
  if (!run || run.chargeState === "refunded") return;
  if (run.chargeState === "held") releaseRunHold(run);
  const bonus = Number(run.chargedSources.bonus || 0);
  const cash = Number(run.chargedSources.cash || 0);
  if (run.chargeState === "charged") {
    state.balances.bonus.spent = Math.max(0, state.balances.bonus.spent - bonus);
    state.balances.cash.spent = Math.max(0, state.balances.cash.spent - cash);
    state.balances.bonus.available += bonus;
    state.balances.cash.available += cash;
    run.refundedSources = { bonus, cash };
    run.chargeState = "refunded";
  }
  run.status = "platform-failed";
  run.knownOutcome = false;
  run.publicEligible = false;
  run.finishedAt = new Date().toISOString();
}

function recoverUnknown(run, resultKnown) {
  if (!run || run.status !== "unknown") return;
  if (resultKnown) {
    run.creditsByTask = {};
    run.taskIds.forEach((taskId) => { run.creditsByTask[taskId] = creditForTask(taskId, false); });
    run.completedCount = run.taskIds.length;
    run.knownOutcome = true;
    run.status = run.mode === "ranked" && run.taskIds.length === TASKS.length ? "completed" : "training-completed";
    run.finishedAt = new Date().toISOString();
    run.elapsedSeconds = Math.max(1, elapsedSecondsNow(run) || 1);
    run.publicEligible = run.status === "completed";
    if (run.publicEligible) publishRankedResult(run);
    state.selectedRunId = run.id;
    state.view = "results";
    persist();
    render();
    announce("Original evidence was recovered in this mock. The result was calculated once from that evidence.");
    return;
  }
  refundPlatformFailure(run);
  state.view = "run";
  persist();
  render();
  announce("Recovered evidence proves no service effect. The original source portions were restored once.");
}

function selectedInputValue(id) {
  const element = document.getElementById(id);
  return element ? element.value : "";
}

function applyScenario(id) {
  state = initialState();
  state.scenario = id;
  ephemeralToken = "";
  const wizard = state.wizard;
  const agent = state.agents[0];
  const resetRunsToSeed = () => {
    state.runs = state.runs.filter((run) => run.status === "completed");
    state.intent = null;
  };
  const setupWizardAt = (step) => {
    wizard.step = step;
    wizard.inviteStatus = "accepted";
    wizard.authStatus = "signed-in";
    wizard.name = "Fresh demo agent";
    wizard.connectionRoute = "browser";
    wizard.grantStatus = "connected";
    wizard.preflightUsed = false;
    wizard.preflightStatus = "not-run";
  };
  const createWaitingIntent = () => {
    state.intent = {
      id: "launch-scenario-" + id,
      ownerId: "demo-owner",
      agentId: agent.id,
      mode: "ranked",
      taskIds: TASKS.map((task) => task.id),
      quoteMicro: PRICING_MICRO.ranked,
      version: BENCHMARK_VERSION,
      declaredAgentVersion: agent.declaredVersion || "",
      status: "waiting",
      clientOpened: true,
      createdAt: new Date().toISOString(),
    };
    state.launch = { mode: "ranked", taskIds: TASKS.map((task) => task.id), fallbackText: "" };
  };
  const createScenarioRun = (statusValue) => {
    resetRunsToSeed();
    const sources = { bonus: Math.min(state.balances.bonus.available, PRICING_MICRO.ranked), cash: 0 };
    const shortfall = PRICING_MICRO.ranked - sources.bonus;
    if (shortfall > 0) {
      sources.cash = shortfall;
      state.balances.cash.available -= shortfall;
      state.balances.cash.reserved += shortfall;
    }
    state.balances.bonus.available -= sources.bonus;
    state.balances.bonus.reserved += sources.bonus;
    const run = {
      id: "run-scenario-" + id,
      publicId: "RUN-SCENARIO",
      agentId: agent.id,
      mode: "ranked",
      taskIds: TASKS.map((task) => task.id),
      status: "queued",
      version: BENCHMARK_VERSION,
      declaredAgentVersion: agent.declaredVersion || "",
      quoteMicro: PRICING_MICRO.ranked,
      originalSources: { ...sources },
      heldSources: { ...sources },
      chargedSources: { bonus: 0, cash: 0 },
      refundedSources: { bonus: 0, cash: 0 },
      releasedSources: { bonus: 0, cash: 0 },
      chargeState: "held",
      creditsByTask: {},
      completedCount: 0,
      elapsedSeconds: 0,
      startedAt: null,
      finishedAt: null,
      createdAt: new Date().toISOString(),
      publicEligible: false,
      knownOutcome: false,
      safeCategory: "",
    };
    state.runs.push(run);
    run.queueDeadlineAt = new Date(Date.parse(run.createdAt) + DEMO_QUEUE_WAIT_MS).toISOString();
    state.selectedRunId = run.id;
    if (statusValue === "preparing") run.status = "preparing";
    if (["running", "unknown", "recovery-paused", "platform-failed", "cancelled-after-start", "client-disconnected"].includes(statusValue)) {
      run.status = "preparing";
      startRun(run);
      run.status = "running";
      run.startedAt = new Date(Date.now() - 45_000).toISOString();
      run.completedCount = statusValue === "unknown" ? 2 : 0;
      for (let index = 0; index < run.completedCount; index += 1) {
        const task = TASKS[index];
        run.creditsByTask[task.id] = creditForTask(task.id, false);
      }
    }
    if (statusValue === "unknown") run.status = "unknown";
    if (statusValue === "recovery-paused") {
      run.status = "recovery-paused";
      run.pausedAt = new Date().toISOString();
    }
    if (statusValue === "cancelled-after-start") {
      run.status = "running";
      cancelRun(run);
    }
    if (statusValue === "platform-failed") refundPlatformFailure(run);
    if (statusValue === "expired") {
      run.queueDeadlineAt = new Date(Date.now() - 1_000).toISOString();
      expireRun(run);
    }
    if (statusValue === "cancelled-before-start") cancelRun(run);
    if (statusValue === "client-disconnected") run.clientDisconnected = true;
    state.currentAgentId = agent.id;
    state.view = "run";
    return run;
  };

  if (id === "fresh-profile") {
    state.agents = [];
    state.runs = [];
    state.currentAgentId = null;
    state.view = "overview";
  } else if (id === "invalid-invite") {
    setupWizardAt(0);
    wizard.inviteCode = "NOT-VALID";
    wizard.inviteStatus = "invalid";
    state.view = "onboarding";
  } else if (id === "auth-denied") {
    setupWizardAt(0);
    wizard.authStatus = "denied";
    state.view = "onboarding";
  } else if (id === "auth-expired") {
    setupWizardAt(0);
    wizard.authStatus = "expired";
    state.view = "onboarding";
  } else if (id === "preflight-failed" || id === "preflight-pending") {
    setupWizardAt(4);
    wizard.preflightUsed = true;
    wizard.preflightStatus = id === "preflight-failed" ? "failed" : "pending";
    state.view = "onboarding";
  } else if (id === "insufficient-funds") {
    agent.cashFallback = true;
    state.balances.cash.available = 250_000;
    state.balances.bonus.available = 0;
    state.launch = { mode: "ranked", taskIds: TASKS.map((task) => task.id), fallbackText: "" };
    state.view = "launch";
  } else if (id === "cash-disabled") {
    agent.cashFallback = false;
    state.balances.cash.available = 5_000_000;
    state.balances.bonus.available = 600_000;
    state.launch = { mode: "ranked", taskIds: TASKS.map((task) => task.id), fallbackText: "" };
    state.view = "launch";
  } else if (id === "budget-cap") {
    agent.capsMicro.operation = 250_000;
    agent.capsMicro.day = 2_000_000;
    agent.capsMicro.category = 2_000_000;
    state.launch = { mode: "ranked", taskIds: TASKS.map((task) => task.id), fallbackText: "" };
    state.view = "launch";
  } else if (id === "price-changed" || id === "bonus-expired" || id === "permission-changed") {
    createWaitingIntent();
    if (id === "price-changed") state.view = "launch";
    else if (id === "bonus-expired") state.view = "launch";
    else state.view = "launch";
  } else if (id === "queue-expired") {
    createScenarioRun("expired");
  } else if (id === "cancel-before-start") {
    createScenarioRun("cancelled-before-start");
  } else if (id === "cancel-after-start") {
    createScenarioRun("cancelled-after-start");
  } else if (id === "unknown") {
    createScenarioRun("unknown");
  } else if (id === "platform-recovery") {
    createScenarioRun("recovery-paused");
  } else if (id === "client-disconnect") {
    const run = createScenarioRun("client-disconnected");
    run.status = "running";
  } else if (id === "platform-failure") {
    createScenarioRun("platform-failed");
  } else if (id === "privacy-private") {
    agent.visibility = "private";
    state.publicAgentId = agent.id;
    state.view = "public-profile";
  } else if (id === "privacy-forum-only") {
    const brook = clone(PUBLIC_AGENT_FIXTURES.find((item) => item.id === "agent-brook"));
    brook.bestRun = null;
    state.agents.push(brook);
    state.currentAgentId = brook.id;
    state.publicAgentId = brook.id;
    state.view = "public-profile";
  } else if (id === "tie") {
    const tie = clone(PUBLIC_AGENT_FIXTURES[0]);
    tie.id = "agent-atlas-tie";
    tie.name = "Atlas peer";
    tie.description = "Synthetic comparison fixture with the same score and a different elapsed time.";
    tie.bestRun.id = "run-demo-tie";
    tie.bestRun.publicId = "RUN-TIE";
    tie.bestRun.durationSeconds = 944;
    state.agents.push(tie);
    state.view = "leaderboard";
  } else {
    state.scenario = "baseline";
    state.view = "overview";
  }
  persist();
  render();
  announce((MOCK_SCENARIOS.find((item) => item.id === id) || MOCK_SCENARIOS[0]).label + " loaded.");
}

function saveAgent() {
  const wizard = state.wizard;
  if (wizard.authStatus !== "signed-in" || wizard.inviteStatus !== "accepted") {
    return announce("Sign-in and invitation must both be accepted.");
  }
  if (!wizard.name.trim() || wizard.grantStatus !== "connected" || wizard.preflightStatus !== "passed") {
    return announce("Complete the profile, connection, and one successful preflight before saving.");
  }
  const caps = {
    operation: parseCap(wizard.capDisplay.operation),
    day: parseCap(wizard.capDisplay.day),
    category: parseCap(wizard.capDisplay.category),
  };
  if (Object.values(caps).some((value) => value == null)) return announce("Enter valid nonnegative USDC caps.");
  const sequence = state.idCounter++;
  const agent = {
    id: "agent-local-" + sequence,
    name: wizard.name.trim(),
    description: wizard.description.trim(),
    client: wizard.client,
    model: wizard.model.trim(),
    declaredVersion: wizard.declaredVersion.trim(),
    visibility: "private",
    createdAt: new Date().toISOString(),
    permissions: clone(wizard.permissions),
    cashFallback: Boolean(wizard.cashFallback),
    capsMicro: {
      operation: caps.operation,
      day: caps.day,
      category: caps.category,
    },
    connectionStatus: "connected",
    preflightStatus: "passed",
    bestRun: null,
    visibleMessages: [],
  };
  state.agents.push(agent);
  state.currentAgentId = agent.id;
  state.publicAgentId = agent.id;
  state.settingsDraft = null;
  state.wizard = blankWizard();
  ephemeralToken = "";
  state.view = "overview";
  persist();
  render();
  announce("Private mock profile saved. Permissions: " + agentPermissionsSummary(agent) + ".");
}

function nextWizardStep() {
  const wizard = state.wizard;
  if (wizard.step === 0 && (wizard.authStatus !== "signed-in" || wizard.inviteStatus !== "accepted")) return;
  if (wizard.step === 1 && !wizard.name.trim()) return;
  if (wizard.step === 3 && wizard.grantStatus !== "connected") return;
  if (wizard.step === 4 && wizard.preflightStatus !== "passed") return;
  if (wizard.step < 5) wizard.step += 1;
  wizard.message = null;
  persist();
  render();
}

function simulatePreflight() {
  const wizard = state.wizard;
  if (wizard.preflightUsed) return announce("The one free preflight has already been used for this setup.");
  if (wizard.grantStatus !== "connected") return announce("Connect the simulated client before preflight.");
  wizard.preflightUsed = true;
  if (state.scenario === "preflight-failed") wizard.preflightStatus = "failed";
  else if (state.scenario === "preflight-pending") wizard.preflightStatus = "pending";
  else wizard.preflightStatus = "passed";
  persist();
  render();
  announce(wizard.preflightStatus === "passed" ? "The one free mock preflight passed." : "Preflight status: " + wizard.preflightStatus + ". Setup cannot complete until a result is known and passed.");
}

function resolvePreflight(passed) {
  if (state.wizard.preflightStatus !== "pending") return;
  state.wizard.preflightStatus = passed ? "passed" : "failed";
  state.wizard.message = { text: passed ? "The pending observation resolved as passed." : "The pending observation resolved as failed.", tone: passed ? "success" : "danger" };
  persist();
  render();
}

function updateSettingsFromDraft() {
  const draft = state.settingsDraft;
  const agent = currentAgent();
  if (!draft || !agent) return announce("No agent settings draft is open.");
  const caps = {
    operation: parseCap(draft.capDisplay.operation),
    day: parseCap(draft.capDisplay.day),
    category: parseCap(draft.capDisplay.category),
  };
  if (Object.values(caps).some((value) => value == null)) return announce("Enter valid nonnegative USDC caps.");
  agent.name = draft.name.trim() || agent.name;
  agent.description = draft.description.trim();
  agent.client = draft.client || "";
  agent.model = draft.model.trim();
  agent.declaredVersion = draft.declaredVersion.trim();
  agent.permissions = clone(draft.permissions);
  agent.cashFallback = Boolean(draft.cashFallback);
  agent.capsMicro = caps;
  state.settingsDraft = null;
  const active = activeRunFor(agent.id);
  if (active && !agent.permissions[active.mode] && ["queued", "preparing", "running", "recovery-paused"].includes(active.status)) cancelRun(active);
  persist();
  render();
  announce("Owner settings saved in local mock state.");
}

function copyText(text, onFallback) {
  if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
    navigator.clipboard.writeText(text).then(
      () => announce("Copied the safe prototype request."),
      () => onFallback());
  } else onFallback();
}

function handleAction(action, target) {
  const id = target.getAttribute("data-id");
  const value = target.getAttribute("data-value");
  const run = id ? state.runs.find((item) => item.id === id) : null;
  if (action === "navigate") return go(value || "overview");
  if (action === "new-agent") return beginWizard();
  if (action === "open-ranked") return openLaunch("ranked", id);
  if (action === "open-practice") return openLaunch("training", id);
  if (action === "agent-settings") return beginSettings(id);
  if (action === "public-profile") {
    state.publicAgentId = id || currentAgent() && currentAgent().id;
    return go("public-profile");
  }
  if (action === "open-run") {
    state.selectedRunId = id;
    return go("run");
  }
  if (action === "open-result") {
    state.selectedRunId = id || state.selectedRunId;
    return go("results");
  }
  if (action === "wizard-back") {
    state.wizard.step = Math.max(0, state.wizard.step - 1);
    state.wizard.message = null;
    persist();
    return render();
  }
  if (action === "wizard-next") return nextWizardStep();
  if (action === "simulate-sign-in") {
    const wasRefused = state.wizard.authStatus === "denied";
    state.wizard.authStatus = state.scenario === "auth-denied" && !wasRefused ? "denied" : "signed-in";
    if (state.wizard.authStatus === "signed-in" && ["auth-denied", "auth-expired"].includes(state.scenario)) state.scenario = "baseline";
    persist();
    render();
    return announce(state.wizard.authStatus === "signed-in" ? "Simulated sign-in succeeded." : "Simulated sign-in was refused.");
  }
  if (action === "check-invite") {
    const code = state.wizard.inviteCode.trim().toUpperCase();
    if (code === "DEMO-ACCESS") {
      state.wizard.inviteStatus = "accepted";
      state.scenario = "baseline";
    } else if (code === "DEMO-EXPIRED") state.wizard.inviteStatus = "expired";
    else state.wizard.inviteStatus = "invalid";
    persist();
    render();
    return announce(inviteStatusText(state.wizard.inviteStatus) + ".");
  }
  if (action === "grant-success") {
    state.wizard.grantStatus = "connected";
    persist();
    render();
    return announce("Browser grant recorded as a local simulation.");
  }
  if (action === "grant-refused") {
    state.wizard.grantStatus = "refused";
    persist();
    render();
    return announce("Simulated browser authorization was refused.");
  }
  if (action === "grant-expired") {
    state.wizard.grantStatus = "expired";
    persist();
    render();
    return announce("Simulated browser grant expired.");
  }
  if (action === "reveal-demo-token") {
    if (state.wizard.tokenRevealUsed) return announce("The one-time dummy reveal has already been used.");
    ephemeralToken = "demo_dummy_" + Math.random().toString(36).slice(2, 10);
    state.wizard.tokenRevealUsed = true;
    state.wizard.grantStatus = "connected";
    persist();
    render();
    return announce("One synthetic dummy string was revealed. It has no authority and was not saved.");
  }
  if (action === "copy-demo-token") {
    if (!ephemeralToken) return announce("The one-time dummy is no longer visible.");
    return copyText(ephemeralToken, () => announce("Clipboard unavailable. Select the visible dummy text and copy it manually."));
  }
  if (action === "revoke-demo-token") {
    ephemeralToken = "";
    state.wizard.grantStatus = "revoked";
    persist();
    render();
    return announce("The local dummy display was hidden and its simulated connection was revoked.");
  }
  if (action === "run-preflight") return simulatePreflight();
  if (action === "resolve-preflight-pass") return resolvePreflight(true);
  if (action === "resolve-preflight-fail") return resolvePreflight(false);
  if (action === "restart-setup") {
    state.wizard = blankWizard();
    state.scenario = "baseline";
    ephemeralToken = "";
    persist();
    render();
    return announce("A new unsaved local setup is ready.");
  }
  if (action === "save-agent") return saveAgent();
  if (action === "create-intent") return createIntent();
  if (action === "simulate-client-open") {
    if (state.intent && state.intent.status === "waiting") {
      state.intent.clientOpened = true;
      persist();
      render();
      announce("The local preview marks this request opened. No external client launched.");
    }
    return;
  }
  if (action === "copy-request") {
    if (!state.intent || state.intent.status !== "waiting") return announce("There is no pending request to copy.");
    const safeText = safeRequestText(state.intent);
    return copyText(safeText, () => {
      state.launch.fallbackText = safeText;
      persist();
      render();
      const fallback = document.querySelector(".launch-request[readonly]");
      if (fallback) { fallback.focus(); fallback.select(); }
      announce("Clipboard unavailable. The safe request is selected for manual copying.");
    });
  }
  if (action === "accept-agent") return admitIntent();
  if (action === "cancel-intent") {
    if (state.intent && state.intent.status === "waiting") {
      state.intent.status = "cancelled";
      persist();
      render();
      announce("Waiting request cancelled. No run or reservation existed.");
    }
    return;
  }
  if (action === "prepare-run") return prepareRun(run);
  if (action === "start-run") return startRun(run);
  if (action === "complete-task") return completeTask(run, false);
  if (action === "fail-task") return completeTask(run, true);
  if (action === "cancel-run") return cancelRun(run);
  if (action === "expire-run") return expireRun(run);
  if (action === "resume-recovery") {
    if (run && run.status === "recovery-paused") {
      run.pausedDurationMs = Number(run.pausedDurationMs || 0) + Math.max(0, Date.now() - Date.parse(run.pausedAt));
      run.pausedAt = null;
      run.status = "running";
      persist();
      render();
      announce("Platform recovery evidence was confirmed. Task actions and the run clock resumed.");
    }
    return;
  }
  if (action === "resolve-unknown-complete") return recoverUnknown(run, true);
  if (action === "resolve-unknown-none") return recoverUnknown(run, false);
  if (action === "leaderboard-version") {
    state.leaderboardVersion = value === "previous" ? "previous" : "current";
    persist();
    return render();
  }
  if (action === "discard-settings") {
    state.settingsDraft = null;
    persist();
    return render();
  }
  if (action === "save-settings") return updateSettingsFromDraft();
  if (action === "reconnect-agent") {
    const agent = currentAgent();
    if (agent) {
      agent.connectionStatus = "connected";
      state.view = "settings";
      persist();
      render();
      announce("Connection status updated in local simulation. Permissions and preflight record were preserved.");
    }
    return;
  }
  if (action === "apply-scenario") return applyScenario(selectedInputValue("scenario-select"));
  if (action === "reset-demo") {
    state = initialState();
    ephemeralToken = "";
    document.getElementById("scenario-panel").classList.remove("is-open");
    document.querySelectorAll(".scenario-toggle").forEach((toggle) => toggle.setAttribute("aria-expanded", "false"));
    persist();
    render();
    return announce("Local demo state reset.");
  }
  if (action === "toggle-scenarios") {
    const panel = document.getElementById("scenario-panel");
    panel.classList.toggle("is-open");
    panel.hidden = !panel.classList.contains("is-open");
    document.querySelectorAll(".scenario-toggle").forEach((toggle) => toggle.setAttribute("aria-expanded", panel.hidden ? "false" : "true"));
    return;
  }
  if (action === "toggle-menu") {
    const sidebar = document.getElementById("sidebar");
    const scrim = document.querySelector(".mobile-scrim");
    const open = !sidebar.classList.contains("is-open");
    sidebar.classList.toggle("is-open", open);
    scrim.classList.toggle("is-visible", open);
    target.setAttribute("aria-expanded", open ? "true" : "false");
    target.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
    return;
  }
  if (action === "close-menu") return closeMobileMenu();
}

document.addEventListener("click", (event) => {
  const target = event.target.closest("[data-action], [data-view]");
  if (!target) return;
  if (target.matches("[data-view]") && !target.hasAttribute("data-action")) {
    event.preventDefault();
    go(target.getAttribute("data-view"));
    return;
  }
  const action = target.getAttribute("data-action");
  if (action) handleAction(action, target);
});

document.addEventListener("input", (event) => {
  const target = event.target;
  if (!target || !target.hasAttribute("data-bind")) return;
  if (target.type === "radio" && !target.checked) return;
  const bind = target.getAttribute("data-bind");
  const value = target.type === "checkbox" ? target.checked : target.value;
  setPath(state, bind, value);
  if (bind === "wizard.inviteCode") state.wizard.inviteStatus = "unchecked";
  if (bind === "wizard.connectionRoute") {
    ephemeralToken = "";
    state.wizard.grantStatus = "not-connected";
  }
  if (bind === "launch.mode") {
    state.launch.taskIds = value === "ranked" ? TASKS.map((task) => task.id) : openTasks().map((task) => task.id);
    state.launch.fallbackText = "";
  }
  persist();
  // AICODE-NOTE: Refresh validation without replacing the focused text field on each keystroke.
  if (bind.startsWith("wizard.")) {
    const actions = document.querySelector(".wizard-actions");
    if (actions) actions.replaceWith(renderWizardActions(state.wizard.step));
  }
});

document.addEventListener("change", (event) => {
  const target = event.target;
  if (!target) return;
  if (target.hasAttribute("data-task-select")) {
    const taskId = target.getAttribute("data-task-id");
    const taskIds = new Set(state.launch.taskIds);
    if (target.checked) taskIds.add(taskId);
    else taskIds.delete(taskId);
    state.launch.taskIds = openTasks().map((task) => task.id).filter((id) => taskIds.has(id));
    persist();
    render();
    return;
  }
  if (target.hasAttribute("data-bind")) {
    if (target.type === "radio" && !target.checked) return;
    if (target.type === "checkbox") {
      setPath(state, target.getAttribute("data-bind"), target.checked);
      persist();
      render();
    } else if (target.tagName === "SELECT") {
      setPath(state, target.getAttribute("data-bind"), target.value);
      if (target.getAttribute("data-bind") === "launch.mode") {
        state.launch.taskIds = target.value === "ranked" ? TASKS.map((task) => task.id) : openTasks().map((task) => task.id);
      }
      persist();
      render();
    } else if (target.type === "radio" && target.name === "launch.mode") {
      state.launch.mode = target.value;
      state.launch.taskIds = target.value === "ranked" ? TASKS.map((task) => task.id) : openTasks().map((task) => task.id);
      persist();
      render();
    } else if (target.type === "radio") {
      persist();
      render();
    }
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    closeMobileMenu();
    const panel = document.getElementById("scenario-panel");
    if (panel && !panel.hidden) {
      panel.classList.remove("is-open");
      panel.hidden = true;
      document.querySelectorAll(".scenario-toggle").forEach((toggle) => toggle.setAttribute("aria-expanded", "false"));
    }
  }
});

window.setInterval(() => {
  const target = document.querySelector("[data-run-elapsed]");
  const run = target ? state.runs.find((item) => item.id === target.getAttribute("data-run-elapsed")) : null;
  const value = target && target.querySelector(".metric-value");
  if (value && run && run.status === "running") value.textContent = formatDuration(elapsedSecondsNow(run));
}, 1000);

render();
