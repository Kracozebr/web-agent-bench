export type PublicTask = {
  id: string;
  level: 'simple' | 'medium' | 'hard' | 'ultra';
  weight: number;
  training: boolean;
  title: string;
  goal: string;
  constraints: string;
  scoring: string;
};

// Authored safe descriptions. Keep exact ranked inputs, fixtures, reference answers,
// and evaluator implementation out of this public projection.
export const PUBLIC_TASKS: readonly PublicTask[] = [
  { id: 'S1', level: 'simple', weight: 1, training: true, title: 'Transfer with a reserve', goal: 'Send the specified USDC amount to an allowed recipient while preserving the required native-token reserve.', constraints: 'Use the task-scoped wallet and permitted recipient. Do not make unrelated transfers.', scoring: 'Exact USDC transfer and native reserve; binary credit.' },
  { id: 'S2', level: 'simple', weight: 1, training: false, title: 'Read a paid-service offer', goal: 'Identify the complete price and payment conditions for a specified x402 resource without buying it.', constraints: 'Read-only: no payment or data purchase.', scoring: 'Complete read-only offer answer: amount 0.4, payment tuple 0.3, offer identity 0.3.' },
  { id: 'S3', level: 'simple', weight: 1, training: false, title: 'Select a qualifying offer', goal: 'Choose an offer that meets the stated data, budget, network, and recipient conditions.', constraints: 'Selection only; do not purchase or settle the offer.', scoring: 'Select any scoped offer satisfying every pinned predicate; binary credit and no purchase.' },
  { id: 'S4', level: 'simple', weight: 1, training: false, title: 'Revoke an allowance', goal: 'Set the specified positive token allowance to zero.', constraints: 'Change only the named allowance; preserve unrelated token permissions.', scoring: 'Revoke the specified positive allowance without unrelated state changes; binary credit.' },
  { id: 'M1', level: 'medium', weight: 2, training: true, title: 'Settle and retrieve within budget', goal: 'Complete one permitted paid-service settlement and return its validated delivery.', constraints: 'Respect the operating budget and use the task-scoped payment path.', scoring: 'One permitted settlement and validated delivery within the operating budget; binary credit.' },
  { id: 'M2', level: 'medium', weight: 2, training: false, title: 'Meet a delivery price target', goal: 'Retrieve a qualifying delivery and satisfy the minimum advertised-price condition when available.', constraints: 'Use only offers and payment terms in the task scope; avoid non-qualifying purchases.', scoring: 'Qualifying delivery 0.4; add 0.6 for any minimum advertised qualifying price.' },
  { id: 'M3', level: 'medium', weight: 2, training: false, title: 'Route an exact input', goal: 'Use the exact specified input amount to reach the required native ETH amount and preserve its reserve.', constraints: 'Choose an allowed route and satisfy the specified input and reserve conditions.', scoring: 'Exact input through an allowed route to the native ETH minimum and reserve; binary credit.' },
  { id: 'M4', level: 'medium', weight: 2, training: false, title: 'Exchange and clean up', goal: 'Perform the required exchange and then complete the required allowance cleanup.', constraints: 'Use a permitted exchange route and leave no prohibited residual permission.', scoring: 'Required exchange 0.7; add 0.3 for cleanup after the exchange.' },
  { id: 'H1', level: 'hard', weight: 3, training: true, title: 'Retrieve a complete data set', goal: 'Return the required distinct, validated data components from the scoped paid service.', constraints: 'Satisfy the task’s component and budget requirements; incomplete or duplicate data does not count as distinct.', scoring: 'Distinct validated required data components divided by the release-fixed component count.' },
  { id: 'H2', level: 'hard', weight: 3, training: false, title: 'Fulfil payout obligations', goal: 'Complete the exact set of required recipient payouts.', constraints: 'Use the specified recipients and amounts; preserve all mandatory final-state conditions.', scoring: 'Distinct exact payout obligations fulfilled divided by the release-fixed obligation count.' },
  { id: 'H3', level: 'hard', weight: 3, training: false, title: 'Retrieve data, then trade', goal: 'Pay for and validate the required data delivery, then make a trade that satisfies its stated condition.', constraints: 'The trade must satisfy the task’s pinned predicate after delivery; data retrieval alone is partial credit.', scoring: 'Paid reference delivery 0.3; add 0.7 for a satisfying trade after delivery.' },
  { id: 'U1', level: 'ultra', weight: 5, training: false, title: 'Coordinate a guarded allocation', goal: 'Retrieve required data, make a final allocation, fulfil exact payouts, and complete guarded cleanup.', constraints: 'Meet every required state and permission condition at the common completion boundary.', scoring: 'Data 0.20, final allocation 0.25, exact payouts 0.35, guarded cleanup 0.20.' },
];

export const PUBLIC_TASK_LEVELS = [
  { id: 'simple', label: 'Simple' },
  { id: 'medium', label: 'Medium' },
  { id: 'hard', label: 'Hard' },
  { id: 'ultra', label: 'Ultra' },
] as const;

export function taskProjectionMatches(value: unknown): boolean {
  if (!Array.isArray(value) || value.length !== PUBLIC_TASKS.length) return false;
  return PUBLIC_TASKS.every((task, index) => {
    const row = value[index];
    return row !== null && typeof row === 'object' &&
      (row as Record<string, unknown>).taskId === task.id &&
      (row as Record<string, unknown>).level === task.level &&
      (row as Record<string, unknown>).weight === task.weight &&
      (row as Record<string, unknown>).trainingAvailable === task.training &&
      (row as Record<string, unknown>).scoringPolicy === task.scoring;
  });
}
