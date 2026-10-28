/** Local U1 planning only: pin allocation before submitting any task action. */
export type U1LocalAllocationInput = {
  initialUsdcUnits: string;
  initialNativeWei: string;
  paidServiceUnits: string;
  payoutUnits: readonly string[];
  swapInputUsdcUnits: string;
  minimumNativeOutputWei: string;
  quotedNativeOutputWei: string;
  maximumParticipantGasWei: string;
  ethUsdcRateNumerator: string;
  ethUsdcRateDenominator: string;
};

function integer(value: string, positive = false): bigint {
  if (!/^(?:0|[1-9][0-9]{0,77})$/.test(value)) throw new Error('task_u1_invalid_planning_quantity');
  const result = BigInt(value);
  if (positive && result === 0n) throw new Error('task_u1_zero_planning_quantity');
  return result;
}

/** Exact share comparisons; no floating point or rounded portfolio valuations. */
export function u1UsdcShareWithin(input: {
  usdcUnits: bigint; nativeWei: bigint; rateNumerator: bigint; rateDenominator: bigint;
  targetShareBps: number; toleranceBps: number;
}): boolean {
  const { usdcUnits, nativeWei, rateNumerator, rateDenominator, targetShareBps, toleranceBps } = input;
  if (usdcUnits < 0n || nativeWei < 0n || rateNumerator <= 0n || rateDenominator <= 0n ||
      !Number.isSafeInteger(targetShareBps) || !Number.isSafeInteger(toleranceBps) ||
      targetShareBps < 0 || targetShareBps > 10000 || toleranceBps < 0 || toleranceBps > 10000) {
    throw new Error('task_u1_invalid_allocation_band');
  }
  const usdcValue = usdcUnits * rateDenominator;
  const total = usdcValue + nativeWei * rateNumerator;
  if (total === 0n) return false;
  return usdcValue * 10000n >= total * BigInt(Math.max(0, targetShareBps - toleranceBps)) &&
    usdcValue * 10000n <= total * BigInt(Math.min(10000, targetShareBps + toleranceBps));
}

/**
 * AICODE-NOTE: This local profile's 40 +/- 1 bps USDC target is fixed before
 * execution. Never derive a target from the achieved final balance to call a
 * reference path solvable. A fresh quote for the exact selected input is required.
 */
export function planU1LocalAllocation(input: U1LocalAllocationInput) {
  const initialUsdc = integer(input.initialUsdcUnits, true);
  const initialNative = integer(input.initialNativeWei, true);
  const service = integer(input.paidServiceUnits, true);
  if (input.payoutUnits.length < 2) throw new Error('task_u1_payout_set_too_small');
  const payout = input.payoutUnits.reduce((sum, value) => sum + integer(value, true), 0n);
  const swapInput = integer(input.swapInputUsdcUnits, true);
  const minimumOutput = integer(input.minimumNativeOutputWei, true);
  const quotedOutput = integer(input.quotedNativeOutputWei, true);
  const maximumGas = integer(input.maximumParticipantGasWei, true);
  const rateNumerator = integer(input.ethUsdcRateNumerator, true);
  const rateDenominator = integer(input.ethUsdcRateDenominator, true);
  if (minimumOutput > quotedOutput || maximumGas >= initialNative || service + payout + swapInput >= initialUsdc) {
    throw new Error('task_u1_planning_bounds_invalid');
  }
  const targetShareBps = 40, toleranceBps = 1;
  const inBand = (usdcUnits: bigint, nativeWei: bigint) => u1UsdcShareWithin({
    usdcUnits, nativeWei, rateNumerator, rateDenominator, targetShareBps, toleranceBps,
  });
  if (inBand(initialUsdc, initialNative)) throw new Error('task_u1_allocation_initially_solved');
  const finalUsdc = initialUsdc - service - payout - swapInput;
  const minimumNative = initialNative + minimumOutput - maximumGas;
  const maximumNative = initialNative + quotedOutput;
  if (!inBand(finalUsdc, minimumNative) || !inBand(finalUsdc, maximumNative)) {
    throw new Error('task_u1_projected_allocation_outside_target');
  }
  return {
    schemaVersion: 'bts-u1-local-allocation-plan/v1' as const,
    classification: 'pre_execution_local_reference_plan_not_release_or_execution_proof' as const,
    initiallySolved: false as const,
    plannedInput: structuredClone(input),
    allocationAssets: [
      { assetId: 'USDC', usdcBaseUnitsPerAssetBaseUnit: { numerator: '1', denominator: '1' }, targetShareBps, toleranceBps },
      { assetId: 'ETH', usdcBaseUnitsPerAssetBaseUnit: { numerator: rateNumerator.toString(), denominator: rateDenominator.toString() },
        targetShareBps: 10000 - targetShareBps, toleranceBps },
    ],
    projectedBounds: { finalUsdcUnits: finalUsdc.toString(), minimumNativeWei: minimumNative.toString(), maximumNativeWei: maximumNative.toString() },
    nativeReserveWei: (initialNative - maximumGas).toString(),
    requiresExactInputPublicQuote: true as const,
  };
}
