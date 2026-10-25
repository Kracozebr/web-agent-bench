const PACKAGE_BY_ALIAS = {
  fastify: 'fastify',
  x402Core: '@x402/core',
  x402Evm: '@x402/evm',
  x402Fastify: '@x402/fastify',
  viem: 'viem',
  postgresDriver: 'pg',
} as const;

/** Normalize dependency version metadata without substituting declared pins for observations. */
export function normalizeObservedDependencyVersions(value: unknown): Record<string, unknown> {
  if (value === undefined || value === null) return {};
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('probe_dependency_version_observation_invalid');
  }

  const observed = value as Record<string, unknown>;
  const normalized: Record<string, unknown> = {};
  for (const [alias, packageName] of Object.entries(PACKAGE_BY_ALIAS)) {
    const aliasPresent = Object.hasOwn(observed, alias);
    const packagePresent = packageName !== alias && Object.hasOwn(observed, packageName);
    const aliasVersion = aliasPresent ? observed[alias] : undefined;
    const packageVersion = packagePresent ? observed[packageName] : undefined;

    for (const candidate of [aliasVersion, packageVersion]) {
      if (candidate !== undefined && (typeof candidate !== 'string' || !candidate.trim() || candidate.length > 128)) {
        throw new Error('probe_dependency_version_observation_invalid');
      }
    }
    if (aliasPresent && packagePresent && aliasVersion !== packageVersion) {
      throw new Error('probe_dependency_version_alias_conflict');
    }
    const version = aliasPresent ? aliasVersion : packageVersion;
    if (version !== undefined) normalized[alias] = version;
  }
  return normalized;
}
