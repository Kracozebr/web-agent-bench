/** Presentation only: keep micro-USDC integer arithmetic out of floating point. */
export function moneyDisplay(amount: string): { summary: string; units: string } | null {
  const match = /^(-?)(0|[1-9][0-9]*)(?:\.([0-9]{1,6}))?$/.exec(amount);
  if (!match) return null;
  const magnitude = BigInt(match[2]!) * BigInt(1000000) + BigInt((match[3] ?? "").padEnd(6, "0") || "0");
  const sign = match[1] && magnitude !== BigInt(0) ? "-" : "";
  const cents = (magnitude + BigInt(5000)) / BigInt(10000);
  return { summary: magnitude > BigInt(0) && magnitude < BigInt(10000) ? `${sign}<0.01` : `${sign}${cents / BigInt(100)}.${(cents % BigInt(100)).toString().padStart(2, "0")}`, units: `${sign}${magnitude}` };
}

/** Ledger magnitudes remain positive; a debit's display direction is presentation only. */
export function ledgerDisplayAmount(type: string, amount: string): string {
  return type === "debit" ? `-${amount}` : amount;
}
