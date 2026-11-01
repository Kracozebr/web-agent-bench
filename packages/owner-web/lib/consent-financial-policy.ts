import { moneyDisplay } from "./money";

export interface ConsentFinancialPolicy {
  revision: number;
  configured: boolean;
  allowCashShortfall: boolean;
  operationLimit: string | null;
  utcDayLimit: string | null;
  categoryLimits: { benchmark: string | null; forum: string | null };
  token: "USDC";
  precision: 6;
}

// AICODE-NOTE: Consent presents the server policy snapshot; never round limits or infer new authority.
export function exactPolicyLimit(value: string | null): string {
  if (value === null) return "Unlimited by this policy limit";
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)\.[0-9]{6}$/.test(value)) return "Unavailable";
  const display = moneyDisplay(value);
  return display ? `${value} USDC / ${display.units} micro-USDC` : "Unavailable";
}
