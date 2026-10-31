/** AICODE-NOTE: Limits include maximum S2 authFields (128 pairs) and JSON escaping.
 * Eight recursive SDK elements rejected even the minimum valid swap (11).
 * 512 KiB accommodates worst-case escaped bounded S2 strings, not unbounded input.
 */
export const AGENT_MCP_BODY_BYTES = 512 * 1024;
export const AGENT_MCP_INPUT_ELEMENTS = 512;
export const AGENT_MCP_INPUT_DEPTH = 8;

export function boundedMcpArguments(body: unknown): boolean {
  if (!body || typeof body !== 'object') return true;
  const params = (body as { params?: unknown }).params;
  if (!params || typeof params !== 'object') return true;
  const args = (params as { arguments?: unknown }).arguments;
  const stack = [{ value: args, depth: 0 }];
  let elements = 0;
  while (stack.length) {
    const { value, depth } = stack.pop()!;
    if (!value || typeof value !== 'object') continue;
    if (depth > AGENT_MCP_INPUT_DEPTH) return false;
    for (const child of Object.values(value)) {
      if (++elements > AGENT_MCP_INPUT_ELEMENTS) return false;
      if (child && typeof child === 'object') stack.push({ value: child, depth: depth + 1 });
    }
  }
  return true;
}
