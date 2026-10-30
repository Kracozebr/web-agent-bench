type RecordValue = Record<string, unknown>;

function record(value: unknown): value is RecordValue {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function stringFields(value: unknown, fields: readonly string[]): boolean {
  return record(value) && Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field) && typeof value[field] === 'string');
}

// AICODE-NOTE: The executor emits optional typed diagnostics alongside the pinned
// identity. They are provenance metadata, not independent chain-success evidence.
export function observationHealthMatches(value: unknown, expected: {
  environmentId: unknown;
  manifestSha256: unknown;
  applicationSourceSha256: unknown;
}): boolean {
  if (value === undefined) return true; // Older action documents omitted health.
  if (!record(value)) return false;
  const allowed = ['boundary', 'envId', 'manifestSha256', 'applicationSourceSha256',
    'facilitatorAddress', 'anvil', 'sdkVersions'];
  if (!Object.keys(value).every((key) => allowed.includes(key)) ||
      value.boundary !== 'benchmark-environment-api' ||
      typeof value.envId !== 'string' || value.envId !== expected.environmentId ||
      typeof value.manifestSha256 !== 'string' || value.manifestSha256 !== expected.manifestSha256 ||
      typeof value.applicationSourceSha256 !== 'string' || value.applicationSourceSha256 !== expected.applicationSourceSha256) return false;
  if (Object.hasOwn(value, 'facilitatorAddress') &&
      (typeof value.facilitatorAddress !== 'string' || !/^0x[0-9a-f]{40}$/i.test(value.facilitatorAddress))) return false;
  if (Object.hasOwn(value, 'anvil') && !stringFields(value.anvil,
    ['clientVersion', 'chainId', 'executionNetwork', 'hardFork', 'forkBlockNumber', 'forkBlockHash'])) return false;
  return !Object.hasOwn(value, 'sdkVersions') || stringFields(value.sdkVersions, ['core', 'evm', 'viem']);
}
