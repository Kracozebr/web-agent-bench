"use client";
import { useId, useState } from "react";
import { moneyDisplay } from "@/lib/money";

export function Money({ amount }: { amount: string }) {
  const [expanded, setExpanded] = useState(false);
  const id = useId();
  const display = moneyDisplay(amount);
  if (!display) return <span>Amount unavailable</span>;
  return <span className="money"><span>{display.summary} USDC</span>{" "}<button className="money-toggle" type="button" aria-expanded={expanded} aria-controls={id} onClick={() => setExpanded((current) => !current)}>Exact amount</button><span id={id} hidden={!expanded} className="money-detail">{amount} USDC · {display.units} micro-USDC</span></span>;
}
