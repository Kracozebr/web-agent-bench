"use client";

import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { ApiError, apiRequest, errorText, newOperationId, type AgentFinancialPolicy, type AgentFinancialPolicyResponse } from "@/lib/api";

type CapDraft = { unlimited: boolean; amount: string };
interface FinancialPolicyDraft {
  allowCashShortfall: boolean;
  operationLimit: CapDraft;
  utcDayLimit: CapDraft;
  benchmarkLimit: CapDraft;
  forumLimit: CapDraft;
}

interface PendingPolicy {
  payload: string;
  operationId: string;
}

interface FinancialPolicyValues {
  allowCashShortfall: boolean;
  operationLimit: string | null;
  utcDayLimit: string | null;
  categoryLimits: { benchmark: string | null; forum: string | null };
}

function capDraft(value: string | null): CapDraft {
  return value === null ? { unlimited: true, amount: "0.000000" } : { unlimited: false, amount: value };
}

function draftFromPolicy(policy: AgentFinancialPolicy): FinancialPolicyDraft {
  return {
    allowCashShortfall: policy.allowCashShortfall,
    operationLimit: capDraft(policy.operationLimit),
    utcDayLimit: capDraft(policy.utcDayLimit),
    benchmarkLimit: capDraft(policy.categoryLimits.benchmark),
    forumLimit: capDraft(policy.categoryLimits.forum),
  };
}

function valuesFromDraft(draft: FinancialPolicyDraft): FinancialPolicyValues {
  return {
    allowCashShortfall: draft.allowCashShortfall,
    operationLimit: draft.operationLimit.unlimited ? null : draft.operationLimit.amount.trim(),
    utcDayLimit: draft.utcDayLimit.unlimited ? null : draft.utcDayLimit.amount.trim(),
    categoryLimits: {
      benchmark: draft.benchmarkLimit.unlimited ? null : draft.benchmarkLimit.amount.trim(),
      forum: draft.forumLimit.unlimited ? null : draft.forumLimit.amount.trim(),
    },
  };
}

function validCap(cap: CapDraft): boolean {
  return cap.unlimited || /^(?:0|[1-9]\d*)(?:\.\d{1,6})?$/.test(cap.amount.trim());
}

function isUncertain(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status >= 500;
}

function CapField({
  id,
  testId,
  label,
  value,
  disabled,
  onChange,
}: {
  id: string;
  testId: string;
  label: string;
  value: CapDraft;
  disabled: boolean;
  onChange: (next: CapDraft) => void;
}) {
  const unlimitedId = `${id}-unlimited`;
  return (
    <div className="field financial-cap-field">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        data-testid={testId}
        type="text"
        inputMode="decimal"
        autoComplete="off"
        value={value.amount}
        onChange={(event) => onChange({ ...value, amount: event.target.value })}
        disabled={disabled || value.unlimited}
        aria-describedby={`${id}-help`}
      />
      <label className="financial-cap-unlimited" htmlFor={unlimitedId}>
        <input
          id={unlimitedId}
          data-testid={`${testId.replace(/-limit-/, "-unlimited-")}`}
          type="checkbox"
          checked={value.unlimited}
          onChange={(event) => onChange({ ...value, unlimited: event.target.checked })}
          disabled={disabled}
        />
        No limit
      </label>
      <small id={`${id}-help`} className="fine">Six-decimal USDC service value; zero blocks usage under this cap.</small>
    </div>
  );
}

export function FinancialPolicy({ agentId }: { agentId: string }) {
  const [policy, setPolicy] = useState<AgentFinancialPolicy | null>(null);
  const [draft, setDraft] = useState<FinancialPolicyDraft | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState(false);
  const pending = useRef<PendingPolicy | null>(null);
  const endpoint = `/api/owner/agents/${encodeURIComponent(agentId)}/financial-policy` as const;

  const loadPolicy = useCallback(async (announce = false) => {
    try {
      const response = await apiRequest<AgentFinancialPolicyResponse>(endpoint);
      setPolicy(response);
      setDraft(draftFromPolicy(response));
      if (announce) {
        setError(false);
        setMessage("Loaded the current financial policy from the server.");
      }
      return response;
    } catch (cause) {
      if (announce) {
        setError(true);
        setMessage(errorText(cause));
      }
      throw cause;
    } finally {
      setLoading(false);
    }
  }, [agentId, endpoint]);

  useEffect(() => {
    let active = true;
    void apiRequest<AgentFinancialPolicyResponse>(endpoint).then((response) => {
      if (!active) return;
      setPolicy(response);
      setDraft(draftFromPolicy(response));
    }).catch((cause: unknown) => {
      if (active) {
        setError(true);
        setMessage(errorText(cause));
      }
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => { active = false; };
  }, [agentId, endpoint]);

  function updateDraft(key: keyof FinancialPolicyDraft, value: boolean | CapDraft) {
    setDraft((current) => current ? { ...current, [key]: value } as FinancialPolicyDraft : current);
  }

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!policy || !draft) return;
    const policyValues = valuesFromDraft(draft);
    const requestBody = { expectedRevision: policy.revision, ...policyValues };
    const payload = JSON.stringify(requestBody);
    const operationId = pending.current?.payload === payload ? pending.current.operationId : newOperationId();
    pending.current = { payload, operationId };

    setBusy(true);
    setError(false);
    setMessage(`Saving the financial policy at revision ${policy.revision}…`);
    try {
      const response = await apiRequest<AgentFinancialPolicyResponse>(endpoint, {
        method: "PUT",
        body: JSON.stringify({ operationId, ...requestBody }),
      });
      setPolicy(response);
      setDraft(draftFromPolicy(response));
      pending.current = null;
      setError(false);
      setMessage(`The server saved the financial policy at revision ${response.revision}.`);
    } catch (cause) {
      if (cause instanceof ApiError && cause.status < 500) pending.current = null;
      if (cause instanceof ApiError && (cause.code === "REVISION_CONFLICT" || cause.code === "POLICY_REVISION_CONFLICT")) {
        try {
          await loadPolicy();
          pending.current = null;
          setMessage("Another session changed this policy. The latest server values are loaded; review them before saving again.");
        } catch {
          setMessage("This policy changed in another session, and the latest server values could not be loaded. Refresh before saving again.");
        }
      } else {
        setMessage(isUncertain(cause)
          ? "The save outcome is not confirmed. Retry the same values to recover the same operation."
          : errorText(cause));
      }
      setError(true);
    } finally {
      setBusy(false);
    }
  }

  const changed = Boolean(policy && draft && JSON.stringify(valuesFromDraft(draft)) !== JSON.stringify({
    allowCashShortfall: policy.allowCashShortfall,
    operationLimit: policy.operationLimit,
    utcDayLimit: policy.utcDayLimit,
    categoryLimits: policy.categoryLimits,
  }));
  const valid = Boolean(draft && validCap(draft.operationLimit) && validCap(draft.utcDayLimit) && validCap(draft.benchmarkLimit) && validCap(draft.forumLimit));

  return (
    <section className="financial-policy-section" aria-labelledby={`financial-policy-title-${agentId}`}>
      <div className="section-heading">
        <div>
          <h4 id={`financial-policy-title-${agentId}`}>Financial policy</h4>
          <p className="fine">Owner-controlled cash permission and service caps. Business-action permissions remain separate.</p>
        </div>
        <button className="button button-small" data-testid={`financial-policy-refresh-${agentId}`} type="button" onClick={() => { setLoading(true); void loadPolicy(true).catch(() => undefined); }} disabled={busy || loading}>
          {loading ? "Loading…" : "Refresh"}
        </button>
      </div>
      {loading && !policy ? <p className="loading" role="status">Loading this agent’s financial policy…</p> : null}
      {!loading && !policy ? (
        <div>
          <p className={`status-box ${error ? "status-error" : ""}`} data-testid={`financial-policy-status-${agentId}`} role={error ? "alert" : "status"}>{message || "The current server policy is unavailable; no values are assumed."}</p>
          <button className="button button-small" type="button" onClick={() => { setLoading(true); void loadPolicy(true).catch(() => undefined); }} disabled={busy}>Try again</button>
        </div>
      ) : null}
      {policy && draft ? (
        <form className="form financial-policy-form" data-testid={`financial-policy-form-${agentId}`} onSubmit={(event) => void save(event)}>
          <label className="permission-switch" htmlFor={`financial-policy-cash-${agentId}`}>
            <span className="permission-copy">
              <strong>Allow cash shortfall</strong>
              <small>When enabled, this agent may use owner cash after eligible bonus credit. Saved off by default.</small>
            </span>
            <input
              id={`financial-policy-cash-${agentId}`}
              data-testid={`financial-policy-cash-${agentId}`}
              type="checkbox"
              role="switch"
              aria-checked={draft.allowCashShortfall}
              checked={draft.allowCashShortfall}
              onChange={(event) => updateDraft("allowCashShortfall", event.target.checked)}
              disabled={busy || loading}
            />
          </label>
          <div className="notice notice-warning">Bonuses count toward these full-price limits. A zero cap blocks use under that limit; select “No limit” explicitly to remove a cap. Every change takes effect only after Save.</div>
          <div className="financial-cap-grid">
            <CapField id={`financial-policy-operation-limit-${agentId}`} testId={`financial-policy-operation-limit-${agentId}`} label="Per operation" value={draft.operationLimit} disabled={busy || loading} onChange={(value) => updateDraft("operationLimit", value)} />
            <CapField id={`financial-policy-utc-day-limit-${agentId}`} testId={`financial-policy-utc-day-limit-${agentId}`} label="Per UTC day" value={draft.utcDayLimit} disabled={busy || loading} onChange={(value) => updateDraft("utcDayLimit", value)} />
            <CapField id={`financial-policy-benchmark-limit-${agentId}`} testId={`financial-policy-benchmark-limit-${agentId}`} label="Benchmark category" value={draft.benchmarkLimit} disabled={busy || loading} onChange={(value) => updateDraft("benchmarkLimit", value)} />
            <CapField id={`financial-policy-forum-limit-${agentId}`} testId={`financial-policy-forum-limit-${agentId}`} label="Forum category" value={draft.forumLimit} disabled={busy || loading} onChange={(value) => updateDraft("forumLimit", value)} />
          </div>
          <div className="button-row">
            <button className="button button-primary" data-testid={`financial-policy-save-${agentId}`} type="submit" disabled={busy || loading || !changed || !valid}>
              {busy ? "Saving…" : "Save financial policy"}
            </button>
          </div>
          <p className={`status-box ${error ? "status-error" : ""}`} data-testid={`financial-policy-status-${agentId}`} role={error ? "alert" : "status"} aria-live="polite">{message}</p>
        </form>
      ) : null}
    </section>
  );
}
