/** Static registry audit only. Never used to admit a runtime error code. */
export const PARTICIPANT_ERROR_SOURCES=['agents.ts','run-routes.ts','run-service.ts','task-action-service.ts','report-mcp.ts','report-service.ts','mcp-diagnostics-service.ts','mcp-diagnostics-oauth.ts','mcp-diagnostics-routes.ts'];
export function declaredParticipantErrorCodes(source,name){
  const codes=new Set();
  for(const match of source.matchAll(/\b(?:new\s+HttpError|reportError|fail|error)\s*\(\s*(?:\d{3}|[A-Za-z_$][\w.$]*)\s*,\s*['"]([A-Z][A-Z0-9_]+)['"]/g))codes.add(match[1]);
  // Finite response/fallback/rate-bucket literals are also public error causes.
  for(const match of source.matchAll(/\bcode\s*:\s*['"]([A-Z][A-Z0-9_]+)['"]/g))codes.add(match[1]);
  if(['run-routes.ts','run-service.ts'].includes(name))for(const match of source.matchAll(/\b(?:uuid|parseUuid)\s*\([^,\n]+,\s*['"]([A-Za-z][A-Za-z0-9_]*)['"]\s*\)/g))codes.add('INVALID_'+match[1].toUpperCase());
  if(name==='report-service.ts'){
    for(const match of source.matchAll(/\bnormalizeReportText\s*\([^,\n]+,\s*['"]([A-Za-z]+)['"]\s*\)/g))codes.add('INVALID_REPORT_'+match[1].toUpperCase());
    for(const match of source.matchAll(/\bconst code\s*=\s*error instanceof HttpError\s*\?\s*error\.code\s*:\s*['"]([A-Z][A-Z0-9_]+)['"]/g))codes.add(match[1]);
  }
  return [...codes].sort();
}
