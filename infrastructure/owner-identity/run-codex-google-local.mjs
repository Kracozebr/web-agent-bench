import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createReadStream } from 'node:fs';
import { access, link, lstat, mkdir, mkdtemp, readFile, realpath, rename, rm, stat, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { fileURLToPath } from 'node:url';

const EXPECTED_VERSION = 'codex-cli 0.165.0';
const EXPECTED_EXE_SHA256 = 'D4B2E6A054EA1DFE53217F9D8942C5F8A9F4B76171A1E0BB76CED5759915300A';
const EXPECTED_CODE_MODE_HOST_SHA256 = 'C15B0EC7C44BE4BEF2516C251CC8B9F3F4AB9F8727CF2D567D1F183FD415EF2D';
const EXPECTED_PACKAGE_MANIFEST_SHA256 = 'C185C29FB98569B72922445466320BBB767C7FB87ACAE90D96C4E315D80CB524';
const EXPECTED_PACKAGE_TARGET = 'x86_64-pc-windows-msvc';
const ENDPOINT = 'http://127.0.0.1:3000/api/agent/mcp';
const MAX_PROMPT_BYTES = 64 * 1024;
const MAX_CREDENTIAL_BYTES = 16 * 1024;
const MAX_STDOUT_BYTES = 16 * 1024 * 1024;
const MAX_STDERR_BYTES = 2 * 1024 * 1024;
// MCP requests can contain 64 KiB before the CLI adds event/result metadata.
const MAX_JSONL_LINE_CHARS = 256 * 1024;
const MAX_RUN_MS = 60 * 60 * 1000;
const EVENT_TYPES = new Set(['thread.started', 'turn.started', 'turn.completed', 'turn.failed', 'turn.cancelled', 'item.started', 'item.updated', 'item.completed', 'mcp_tool_call', 'error', 'warning']);
const ITEM_TYPES = new Set([
  'agent_message', 'reasoning', 'mcp_tool_call', 'mcp_tool_call_begin', 'mcp_tool_call_end',
  'command_execution', 'file_change', 'web_search_call', 'image_view', 'code_interpreter_call',
  'function_call', 'function_call_output', 'error', 'todo_list', 'tool_search_call', 'tool_search',
  'reasoning_summary',
]);
const RESPONSE_CLASSIFICATIONS = new Set(['MCP_UNAVAILABLE', 'REQUEST_FAILED', 'READY', 'OTHER']);
const DIAGNOSTIC_KEYWORDS = new Set([
  'mcp', 'failed', 'connection', 'profile', 'permission', 'invalid', 'enabled', 'disabled', 'listing',
  'initialization', 'auth', 'approval', 'unauthorized', 'forbidden', 'tool', 'tools', 'available',
  'protocol', 'version', 'unsupported', 'name', 'function', 'schema', 'search', 'deferred', 'catalog',
  'sandbox', 'readonly', 'error', 'configuration', 'credential', 'authentication', 'server', 'missing',
  'unknown', 'cannot', 'unable', 'not', 'unavailable', 'preflight', 'client', 'code', 'mode', 'host',
]);
const RESPONSE_KEYWORDS = new Set([
  'cannot', 'unable', 'mcp', 'tool', 'tools', 'available', 'unavailable', 'configuration', 'disabled', 'permission', 'approval',
  'instructions', 'project', 'policy', 'server', 'credential', 'invalid', 'error', 'schema', 'function', 'name', 'unsupported',
  'network', 'authentication', 'profile', 'restricted', 'status', 'allowed', 'denied', 'request', 'ready', 'no', 'not', 'missing',
  'client', 'preflight', 'id', 'не', 'могу', 'инструмент', 'инструменты', 'доступен', 'недоступен', 'нет', 'политика',
  'инструкции', 'разрешение', 'контекст', 'проверка',
]);
const PUBLIC_TOOLS = new Set([
  'identity.preflight', 'runs.task_action', 'runs.task_action_status', 'runs.finish_task', 'runs.current_task', 'runs.accept_launch_intent',
  'support.report', 'support.report_receipt', 'support.screenshot.begin', 'support.screenshot.chunk', 'support.screenshot.finish',
]);
const SAFE_CODE = new Set([
  'codex_binary_hash_mismatch', 'codex_version_mismatch', 'codex_auth_not_found',
  'credential_file_unavailable', 'credential_format_invalid', 'credential_in_prompt', 'prompt_file_unavailable',
  'prompt_file_invalid', 'output_path_invalid', 'output_limit_exceeded', 'run_timeout',
  'mcp_handshake_error', 'mcp_transport_error', 'http_401', 'http_403', 'http_429',
  'econnrefused', 'enotfound', 'etimedout', 'turn_failed', 'process_nonzero_exit',
  'runner_internal_error', 'output_write_failed', 'progress_write_failed', 'auth_link_unavailable',
  'auth_source_replaced', 'codex_home_invalid', 'codex_home_cleanup_failed',
  'codex_bundle_component_missing', 'codex_bundle_hash_mismatch', 'codex_bundle_manifest_invalid',
  'client_item_error', 'mcp_tool_error',
]);

function argsFrom(argv) {
  const values = new Map();
  for (let i = 2; i < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!key?.startsWith('--') || !value || values.has(key)) throw new Error('arguments_invalid');
    values.set(key, value);
  }
  const required = ['--private-credential-file', '--nonsensitive-prompt-file', '--sanitized-output-path', '--codex-executable', '--workspace', '--enabled-mcp-tools'];
  if (required.some(key => !values.has(key)) || [...values.keys()].some(key => !required.includes(key))) throw new Error('arguments_invalid');
  const paths = Object.fromEntries(required.map(key => [key.slice(2).replaceAll('-', ''), resolve(values.get(key))]));
  if (values.has('--enabled-mcp-tools')) {
    let tools;
    try { tools = JSON.parse(values.get('--enabled-mcp-tools')); } catch { throw new Error('arguments_invalid'); }
    if (!Array.isArray(tools) || tools.length < 1 || tools.length > PUBLIC_TOOLS.size || tools.some(tool => typeof tool !== 'string' || !PUBLIC_TOOLS.has(tool)) || new Set(tools).size !== tools.length) {
      throw new Error('arguments_invalid');
    }
    paths.enabledmcptools = tools;
  }
  return paths;
}

function mcpServerConfig(tools) {
  if (!Array.isArray(tools) || tools.length < 1 || tools.length > PUBLIC_TOOLS.size
    || tools.some(tool => typeof tool !== 'string' || !PUBLIC_TOOLS.has(tool))
    || new Set(tools).size !== tools.length) throw new Error('arguments_invalid');
  const enabledTools = JSON.stringify(tools);
  const perToolApproval = tools.map(tool => `${JSON.stringify(tool)} = { approval_mode = "approve" }`).join(', ');
  return `mcp_servers={ owner_identity = { url = "${ENDPOINT}", bearer_token_env_var = "OID_CODEX_MCP_BEARER_TOKEN", startup_timeout_sec = 15, tool_timeout_sec = 60, default_tools_approval_mode = "auto", required = true, enabled = true, enabled_tools = ${enabledTools}, tools = { ${perToolApproval} } } }`;
}

function safeCode(code) { return SAFE_CODE.has(code) ? code : null; }

function appendDiagnosticKeywords(target, value) {
  if (typeof value !== 'string' || target.length >= 40) return;
  for (const word of value.toLocaleLowerCase('en-US').match(/\p{L}+/gu) || []) {
    if (DIAGNOSTIC_KEYWORDS.has(word)) target.push(word);
    if (target.length >= 40) break;
  }
}

function preflightStatusFromResult(result) {
  const status = result?.structuredContent?.status;
  if (status === 'allowed' || status === 'denied') return status;
  if (!Array.isArray(result?.content)) return null;
  for (const part of result.content) {
    if (typeof part?.text !== 'string' || part.text.length > 4096) continue;
    try {
      const parsed = JSON.parse(part.text);
      if (parsed?.status === 'allowed' || parsed?.status === 'denied') return parsed.status;
    } catch { /* Only a strict structured enum is retained. */ }
  }
  return null;
}

function normalizeMcpToolStatus(status) {
  if (status === 'inProgress' || status === 'in_progress') return 'inProgress';
  if (status === 'completed') return 'completed';
  if (status === 'failed') return 'failed';
  return null;
}

async function sha256(file) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex').toUpperCase();
}

async function verifyPinnedRegularFile(file, expectedHash) {
  const metadata = await lstat(file).catch(() => null);
  if (!metadata?.isFile() || metadata.isSymbolicLink()) throw new Error('codex_bundle_component_missing');
  if (await sha256(file) !== expectedHash) throw new Error('codex_bundle_hash_mismatch');
}

async function verifyExecutableBundle(executable) {
  const exePath = resolve(executable);
  const binDirectory = dirname(exePath);
  const platformRoot = resolve(binDirectory, '..');
  const hostPath = join(binDirectory, 'codex-code-mode-host.exe');
  const manifestPath = join(platformRoot, 'codex-package.json');
  if (process.platform !== 'win32'
    || basename(exePath).toLowerCase() !== 'codex.exe'
    || basename(binDirectory).toLowerCase() !== 'bin'
    || basename(platformRoot).toLowerCase() !== EXPECTED_PACKAGE_TARGET) {
    throw new Error('codex_bundle_component_missing');
  }
  await verifyPinnedRegularFile(exePath, EXPECTED_EXE_SHA256);
  await verifyPinnedRegularFile(hostPath, EXPECTED_CODE_MODE_HOST_SHA256);
  await verifyPinnedRegularFile(manifestPath, EXPECTED_PACKAGE_MANIFEST_SHA256);
  let manifest;
  try { manifest = JSON.parse(await readFile(manifestPath, 'utf8')); }
  catch { throw new Error('codex_bundle_manifest_invalid'); }
  if (manifest?.layoutVersion !== 1
    || manifest?.version !== '0.165.0'
    || manifest?.target !== EXPECTED_PACKAGE_TARGET
    || manifest?.variant !== 'codex'
    || manifest?.entrypoint !== 'bin/codex.exe'
    || manifest?.resourcesDir !== 'codex-resources'
    || manifest?.pathDir !== 'codex-path') {
    throw new Error('codex_bundle_manifest_invalid');
  }
  for (const directory of [manifest.resourcesDir, manifest.pathDir]) {
    const path = join(platformRoot, directory);
    const metadata = await lstat(path).catch(() => null);
    if (!metadata?.isDirectory() || metadata.isSymbolicLink()) throw new Error('codex_bundle_component_missing');
  }
  return { platformRoot, hostPath, manifestPath };
}

function cleanEnvironment({ includeBearer = false, bearer = '', codexHome = '' } = {}) {
  const env = {};
  for (const key of ['PATH', 'PATHEXT', 'SystemRoot', 'WINDIR', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP', 'COMSPEC']) {
    if (process.env[key]) env[key] = process.env[key];
  }
  if (codexHome) env.CODEX_HOME = codexHome;
  if (includeBearer) env.OID_CODEX_MCP_BEARER_TOKEN = bearer;
  return env;
}

function pathEqual(left, right) {
  const a = resolve(left);
  const b = resolve(right);
  return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function pathIsWithin(parent, candidate) {
  const rel = relative(resolve(parent), resolve(candidate));
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

async function verifyPrivateCodexHomeDirectory(home) {
  const tempRoot = await realpath(home.tempRoot);
  if (!pathEqual(tempRoot, home.tempRoot)
    || !pathEqual(dirname(resolve(home.path)), home.tempRoot)
    || basename(home.path) !== home.basename
    || !/^web3-agent-bench-codex-[a-z0-9]{6}$/i.test(home.basename)) {
    throw new Error('codex_home_invalid');
  }
  const directory = await lstat(home.path);
  if (!directory.isDirectory() || directory.isSymbolicLink() || !pathEqual(await realpath(home.path), home.path)) {
    throw new Error('codex_home_invalid');
  }
  const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
  if (pathIsWithin(repoRoot, home.path) || !pathIsWithin(tempRoot, home.path)) throw new Error('codex_home_invalid');
}

async function verifyPrivateCodexHome(home) {
  await verifyPrivateCodexHomeDirectory(home);
  const [source, alias] = await Promise.all([
    lstat(home.authSource, { bigint: true }),
    lstat(home.authAlias, { bigint: true }),
  ]);
  if (!source.isFile() || source.isSymbolicLink() || !alias.isFile() || alias.isSymbolicLink()
    || source.dev === 0n || source.ino === 0n || alias.dev === 0n || alias.ino === 0n
    || source.dev !== alias.dev || source.ino !== alias.ino || source.nlink < 2n || alias.nlink < 2n
    || (home.authFileId && (source.dev !== home.authFileId.dev || source.ino !== home.authFileId.ino))) {
    throw new Error('auth_source_replaced');
  }
}

async function createPrivateCodexHome() {
  const originalHome = process.env.CODEX_HOME?.trim()
    ? resolve(process.env.CODEX_HOME.trim())
    : (process.env.USERPROFILE ? resolve(process.env.USERPROFILE, '.codex') : '');
  if (!originalHome) throw new Error('codex_auth_not_found');
  const authSource = resolve(originalHome, 'auth.json');
  const sourceStat = await lstat(authSource).catch(() => null);
  if (!sourceStat?.isFile() || sourceStat.isSymbolicLink()) throw new Error('codex_auth_not_found');
  const tempRoot = await realpath(tmpdir());
  const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
  if (pathIsWithin(repoRoot, tempRoot) || pathIsWithin(repoRoot, authSource)) throw new Error('codex_home_invalid');
  const path = await mkdtemp(join(tempRoot, 'web3-agent-bench-codex-'));
  const home = { path, tempRoot, basename: basename(path), authAlias: join(path, 'auth.json'), authSource, authFileId: null };
  try {
    await verifyPrivateCodexHomeDirectory(home);
    await link(authSource, home.authAlias);
    const linked = await lstat(home.authSource, { bigint: true });
    home.authFileId = { dev: linked.dev, ino: linked.ino };
    await verifyPrivateCodexHome(home);
    return home;
  } catch (error) {
    const cleanup = await cleanupPrivateCodexHome(home);
    if (!cleanup.succeeded) throw new Error('codex_home_cleanup_failed');
    if (error?.message === 'codex_home_invalid' || error?.message === 'auth_source_replaced') throw error;
    throw new Error('auth_link_unavailable');
  }
}

async function cleanupPrivateCodexHome(home) {
  if (!home) return { succeeded: true, authAliasPreserved: false, errorCode: null };
  let authAliasPreserved = false;
  let errorCode = null;
  try {
    await verifyPrivateCodexHomeDirectory(home);
    const aliasStat = await lstat(home.authAlias, { bigint: true }).catch(error => error?.code === 'ENOENT' ? null : Promise.reject(error));
    if (aliasStat?.isFile() && !aliasStat.isSymbolicLink()) {
      try { await verifyPrivateCodexHome(home); authAliasPreserved = true; }
      catch { errorCode = 'auth_source_replaced'; }
    } else if (aliasStat) errorCode = 'auth_source_replaced';
    else errorCode = 'auth_source_replaced';
    if (aliasStat) await unlink(home.authAlias);
    await verifyPrivateCodexHomeDirectory(home);
    await rm(home.path, { recursive: true, force: false, maxRetries: 0 });
    return { succeeded: true, authAliasPreserved, errorCode };
  } catch (error) {
    return { succeeded: false, authAliasPreserved, errorCode: safeCode(error?.message) || 'codex_home_cleanup_failed' };
  }
}

function captureSmall(stream, limit = 4096) {
  return new Promise(resolvePromise => {
    let bytes = 0;
    let text = '';
    stream.on('data', chunk => {
      bytes += chunk.length;
      if (Buffer.byteLength(text) < limit) text += chunk.toString('utf8').slice(0, limit - text.length);
    });
    stream.on('end', () => resolvePromise({ bytes, text }));
    stream.on('error', () => resolvePromise({ bytes, text: '' }));
  });
}

async function checkVersion(executable, cwd, codexHome) {
  const child = spawn(executable, ['--version'], { cwd, env: cleanEnvironment({ codexHome }), windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  const out = captureSmall(child.stdout);
  const err = captureSmall(child.stderr);
  const code = await new Promise((resolvePromise, reject) => {
    child.once('error', reject);
    child.once('exit', (exitCode, signal) => resolvePromise(signal ? 1 : (exitCode ?? 1)));
  });
  const [stdout] = await Promise.all([out, err]);
  const versionLine = stdout.text.split(/\r?\n/).find(line => line.trim() === EXPECTED_VERSION);
  if (code !== 0 || !versionLine) throw new Error('codex_version_mismatch');
  return versionLine.trim();
}

class EventSummary {
  constructor(kill) {
    this.kill = kill;
    this.decoder = new StringDecoder('utf8');
    this.pending = '';
    this.dropLine = false;
    this.stdoutBytes = 0;
    this.skippedLines = 0;
    this.parseFailures = 0;
    this.eventCounts = Object.create(null);
    this.itemTypeCounts = Object.fromEntries([...ITEM_TYPES, 'other'].map(name => [name, 0]));
    this.toolNames = new Set();
    this.seenToolCallIds = new Set();
    this.seenItemIds = new Set();
    this.mcpToolCalls = 0;
    this.unknownMcpToolCalls = 0;
    this.mcpToolStatusById = new Map();
    this.mcpToolStatusCounts = { inProgress: 0, completed: 0, failed: 0 };
    this.mcpToolErrorIds = new Set();
    this.mcpToolErrorCount = 0;
    this.preflightResultIds = new Set();
    this.preflightAllowed = 0;
    this.preflightDenied = 0;
    this.preflightUnclassified = 0;
    this.localToolCalls = 0;
    this.unknownEvents = 0;
    this.terminalEvent = 'unknown';
    this.errorCodes = new Set();
    this.tokenUsage = null;
    this.responseClassification = 'OTHER';
    this.finalAgentMessageChars = 0;
    this.responseKeywordSequence = [];
    this.errorKeywordSequence = [];
    this.stderrKeywordSequence = [];
    this.enumMentionFlags = { mcpUnavailable: false, requestFailed: false, ready: false, other: false };
    this.stderrClassifications = { mcpStartupFailed: false, configParseFailed: false, unknownFeature: false };
    this.stderrWindow = '';
  }
  feed(chunk) {
    this.stdoutBytes += chunk.length;
    if (this.stdoutBytes > MAX_STDOUT_BYTES) {
      this.errorCodes.add('output_limit_exceeded');
      this.kill();
      return;
    }
    const text = this.decoder.write(chunk);
    for (const char of text) {
      if (char === '\n') {
        if (this.dropLine) this.skippedLines += 1;
        else this.consume(this.pending);
        this.pending = '';
        this.dropLine = false;
      } else if (!this.dropLine) {
        if (this.pending.length < MAX_JSONL_LINE_CHARS) this.pending += char;
        else { this.pending = ''; this.dropLine = true; }
      }
    }
  }
  consume(line) {
    if (!line) return;
    let event;
    try { event = JSON.parse(line); }
    catch { this.parseFailures += 1; return; }
    const type = typeof event?.type === 'string' ? event.type : '';
    if (EVENT_TYPES.has(type)) {
      this.eventCounts[type] = (this.eventCounts[type] || 0) + 1;
    } else this.unknownEvents += 1;
    if (type === 'turn.completed') this.terminalEvent = 'turn.completed';
    if (type === 'turn.failed') { this.terminalEvent = 'turn.failed'; this.errorCodes.add('turn_failed'); }
    const hasNestedItem = event?.item && typeof event.item === 'object';
    const item = hasNestedItem ? event.item : event;
    const itemType = typeof item?.type === 'string' ? item.type.toLowerCase() : '';
    const eventType = type.toLowerCase();
    const isMcpToolCall = itemType.includes('mcp_tool_call') || eventType.includes('mcp_tool_call');
    const toolValue = item?.tool;
    const candidate = [item?.tool_name, item?.name, item?.toolName,
      typeof toolValue === 'string' ? toolValue : toolValue?.name ?? toolValue?.toolName]
      .find(value => typeof value === 'string') || '';
    const server = [item?.server, item?.server_name, item?.serverName]
      .find(value => typeof value === 'string') || '';
    const itemExists = hasNestedItem || isMcpToolCall;
    const countedItemType = isMcpToolCall ? (ITEM_TYPES.has(itemType) ? itemType : 'mcp_tool_call') : itemType;
    if (itemExists && countedItemType) {
      const normalizedType = ITEM_TYPES.has(countedItemType) ? countedItemType : 'other';
      const itemId = typeof item?.call_id === 'string' ? item.call_id
        : (typeof item?.id === 'string' ? item.id : (typeof event?.id === 'string' ? event.id : ''));
      const itemKey = itemId ? JSON.stringify([itemId, normalizedType]) : '';
      const countItem = itemKey ? !this.seenItemIds.has(itemKey) : type === 'item.started' || isMcpToolCall;
      if (countItem) {
        if (itemKey && this.seenItemIds.size < 10000) this.seenItemIds.add(itemKey);
        this.itemTypeCounts[normalizedType] += 1;
      }
      if (normalizedType === 'agent_message') {
        const parts = [];
        if (typeof item?.text === 'string') parts.push(item.text);
        if (Array.isArray(item?.content)) for (const part of item.content) if (typeof part?.text === 'string') parts.push(part.text);
        if (Array.isArray(item?.parts)) for (const part of item.parts) if (typeof part?.text === 'string') parts.push(part.text);
        const messageText = parts.join('');
        const text = messageText.trim();
        if (text) {
          this.finalAgentMessageChars = Array.from(messageText).length;
          this.responseKeywordSequence = (text.toLocaleLowerCase('en-US').match(/\p{L}+/gu) || [])
            .filter(word => RESPONSE_KEYWORDS.has(word))
            .slice(0, 40);
          this.enumMentionFlags = {
            mcpUnavailable: /\bMCP_UNAVAILABLE\b/i.test(text),
            requestFailed: /\bREQUEST_FAILED\b/i.test(text),
            ready: /\bREADY\b/i.test(text),
            other: /\bOTHER\b/i.test(text),
          };
        }
        this.responseClassification = RESPONSE_CLASSIFICATIONS.has(text) ? text : 'OTHER';
      }
      if (itemType === 'error') {
        this.errorCodes.add('client_item_error');
        appendDiagnosticKeywords(this.errorKeywordSequence, item?.message);
        appendDiagnosticKeywords(this.errorKeywordSequence, item?.error?.message);
      }
    }
    if (isMcpToolCall) {
      const id = typeof item?.call_id === 'string' ? item.call_id
        : (typeof item?.id === 'string' ? item.id : (typeof event?.id === 'string' ? event.id : ''));
      const isFirst = id ? !this.seenToolCallIds.has(id) : type === 'item.started' || isMcpToolCall;
      if (isFirst) {
        if (id && this.seenToolCallIds.size < 10000) this.seenToolCallIds.add(id);
        this.mcpToolCalls += 1;
        if (server === 'owner_identity' && PUBLIC_TOOLS.has(candidate)) this.toolNames.add(candidate);
        else this.unknownMcpToolCalls += 1;
      }
      const toolStatus = normalizeMcpToolStatus(item?.status);
      if (toolStatus && id && (this.mcpToolStatusById.has(id) || this.mcpToolStatusById.size < 10000)) {
        const previousStatus = this.mcpToolStatusById.get(id);
        if (previousStatus !== toolStatus) {
          if (previousStatus) this.mcpToolStatusCounts[previousStatus] -= 1;
          this.mcpToolStatusCounts[toolStatus] += 1;
          this.mcpToolStatusById.set(id, toolStatus);
        }
      } else if (toolStatus && !id && (type === 'item.completed' || toolStatus === 'failed')) {
        this.mcpToolStatusCounts[toolStatus] += 1;
      }
      const toolHasError = toolStatus === 'failed' || item?.result?.isError === true || typeof item?.error?.message === 'string';
      if (toolHasError) {
        const firstError = id ? !this.mcpToolErrorIds.has(id) : (type === 'item.completed' || toolStatus === 'failed');
        if (firstError) {
          if (id && this.mcpToolErrorIds.size < 10000) this.mcpToolErrorIds.add(id);
          this.mcpToolErrorCount += 1;
          this.errorCodes.add('mcp_tool_error');
        }
        appendDiagnosticKeywords(this.errorKeywordSequence, item?.error?.message);
      }
      if (server === 'owner_identity' && candidate === 'identity.preflight'
        && (toolStatus === 'completed' || toolStatus === 'failed')) {
        const firstResult = id ? !this.preflightResultIds.has(id) : type === 'item.completed';
        if (firstResult) {
          if (id && this.preflightResultIds.size < 10000) this.preflightResultIds.add(id);
          const resultStatus = toolStatus === 'completed' && item?.result?.isError !== true
            ? preflightStatusFromResult(item?.result) : null;
          if (resultStatus === 'allowed') this.preflightAllowed += 1;
          else if (resultStatus === 'denied') this.preflightDenied += 1;
          else this.preflightUnclassified += 1;
        }
      }
    } else if (itemType === 'shell_command' || itemType === 'local_shell_call' || itemType === 'command_execution') {
      this.localToolCalls += 1;
    }
    const errorCode = typeof event?.error?.code === 'string' ? safeCode(event.error.code.toLowerCase()) : null;
    if (errorCode) this.errorCodes.add(errorCode);
    const status = Number(event?.error?.status ?? event?.status_code);
    if (status === 401 || status === 403 || status === 429) this.errorCodes.add(`http_${status}`);
    if (type === 'turn.completed') {
      const usage = event?.usage ?? event?.info?.usage ?? event?.info?.last_token_usage ?? null;
      if (usage && typeof usage === 'object') {
        const safeUsage = {};
        for (const key of ['input_tokens', 'cached_input_tokens', 'output_tokens', 'reasoning_tokens', 'total_tokens']) {
          const value = usage[key];
          if (Number.isSafeInteger(value) && value >= 0 && value <= 1_000_000_000) safeUsage[key] = value;
        }
        if (Object.keys(safeUsage).length) this.tokenUsage = safeUsage;
      }
    }
  }
  observeStderr(chunk) {
    const stderrText = chunk.toString('utf8');
    appendDiagnosticKeywords(this.stderrKeywordSequence, stderrText);
    this.stderrWindow = (this.stderrWindow + stderrText).slice(-1024).toLowerCase();
    const hasAny = patterns => patterns.some(pattern => this.stderrWindow.includes(pattern));
    if (hasAny(['mcp_handshake_error', 'mcp_transport_error', 'failed to initialize mcp server', 'failed to start mcp server'])) {
      this.stderrClassifications.mcpStartupFailed = true;
      if (this.stderrWindow.includes('mcp_handshake_error')) this.errorCodes.add('mcp_handshake_error');
      if (this.stderrWindow.includes('mcp_transport_error')) this.errorCodes.add('mcp_transport_error');
    }
    if (hasAny(['failed to parse config', 'config parse error', 'invalid toml', 'failed to load config'])) this.stderrClassifications.configParseFailed = true;
    if (hasAny(['unknown feature', 'unrecognized feature', 'invalid feature name'])) this.stderrClassifications.unknownFeature = true;
    if (/\b401\b/.test(this.stderrWindow)) this.errorCodes.add('http_401');
    if (/\b403\b/.test(this.stderrWindow)) this.errorCodes.add('http_403');
    if (/\b429\b/.test(this.stderrWindow)) this.errorCodes.add('http_429');
    if (this.stderrWindow.includes('econnrefused')) this.errorCodes.add('econnrefused');
    if (this.stderrWindow.includes('enotfound')) this.errorCodes.add('enotfound');
    if (this.stderrWindow.includes('etimedout')) this.errorCodes.add('etimedout');
  }
  sanitizedSnapshot() {
    return {
      jsonEventCounts: { ...this.eventCounts },
      itemTypeCounts: { ...this.itemTypeCounts },
      mcpToolCallCount: this.mcpToolCalls,
      mcpToolNames: [...this.toolNames].sort(),
      unknownMcpToolCallCount: this.unknownMcpToolCalls,
      mcpToolStatusCounts: { ...this.mcpToolStatusCounts },
      mcpToolErrorCount: this.mcpToolErrorCount,
      preflightAllowed: this.preflightAllowed,
      preflightDenied: this.preflightDenied,
      preflightUnclassified: this.preflightUnclassified,
      localToolCallCount: this.localToolCalls,
      unknownEventCount: this.unknownEvents,
      skippedOversizeLines: this.skippedLines,
      unparsedJsonLines: this.parseFailures,
      tokenUsage: this.tokenUsage,
      errorCodes: [...this.errorCodes].sort(),
      responseClassification: this.responseClassification,
      finalAgentMessageChars: this.finalAgentMessageChars,
      responseKeywordSequence: [...this.responseKeywordSequence],
      errorKeywordSequence: [...this.errorKeywordSequence],
      stderrKeywordSequence: [...this.stderrKeywordSequence],
      enumMentionFlags: { ...this.enumMentionFlags },
      stderrClassifications: { ...this.stderrClassifications },
    };
  }
}

async function writeSummary(file, summary) {
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(summary, null, 2)}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
}

export async function writeProgressAtomic(file, summary) {
  const temporary = `${file}.${process.pid}.${Date.now()}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(summary, null, 2)}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    await rename(temporary, file);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

async function main() {
  let paths;
  try { paths = argsFrom(process.argv); }
  catch { process.stdout.write('{"status":"blocked","errorCode":"arguments_invalid"}\n'); process.exitCode = 2; return; }

  const outputPath = paths.sanitizedoutputpath;
  const progressPath = `${outputPath}.progress.json`;
  const base = {
    schemaVersion: 'codex-google-local-run/v1', taskOutcome: 'unknown', rawTranscriptPersisted: false,
    isolatedCodexHome: false, authLinked: false, authAliasKind: null, authAliasPreserved: false, codexHomeCleanupSucceeded: true,
    executableBundleVerified: false, codeModeHostVerified: false, packageManifestVerified: false,
  };
  const lifecycleErrorCodes = new Set();
  let privateHome = null;
  let child = null;
  let childClosed = true;
  let childClosePromise = null;
  let runTimer = null;
  let progressTimer = null;
  let progressWrites = Promise.resolve();
  let progressWriteErrors = 0;
  let summaryReader = null;
  let stderrBytes = 0;
  let runSummary = null;
  let failureCode = 'runner_internal_error';
  let runExitCode = 2;
  try {
    const inputPaths = [paths.privatecredentialfile, paths.nonsensitivepromptfile, paths.codexexecutable].map(p => resolve(p).toLowerCase());
    if (inputPaths.includes(outputPath.toLowerCase()) || inputPaths.includes(progressPath.toLowerCase())) throw new Error('output_path_invalid');
    if (await access(outputPath).then(() => true).catch(() => false)) throw new Error('output_path_invalid');
    if (await access(progressPath).then(() => true).catch(() => false)) throw new Error('output_path_invalid');
    await mkdir(dirname(outputPath), { recursive: true });
    await access(dirname(outputPath), (await import('node:fs')).constants.W_OK);
    await verifyExecutableBundle(paths.codexexecutable);
    base.executableBundleVerified = true;
    base.codeModeHostVerified = true;
    base.packageManifestVerified = true;
    const credentialStat = await stat(paths.privatecredentialfile).catch(() => null);
    const promptStat = await stat(paths.nonsensitivepromptfile).catch(() => null);
    if (!credentialStat?.isFile()) throw new Error('credential_file_unavailable');
    if (!promptStat?.isFile()) throw new Error('prompt_file_unavailable');
    if (credentialStat.size < 20 || credentialStat.size > MAX_CREDENTIAL_BYTES) throw new Error('credential_file_unavailable');
    if (promptStat.size < 1 || promptStat.size > MAX_PROMPT_BYTES) throw new Error('prompt_file_invalid');
    const bearer = (await readFile(paths.privatecredentialfile, 'utf8')).replace(/^\uFEFF/, '').trim();
    if (bearer.length < 20 || bearer.length > 8192 || /\s/.test(bearer)) throw new Error('credential_format_invalid');
    const prompt = (await readFile(paths.nonsensitivepromptfile, 'utf8')).replace(/^\uFEFF/, '');
    if (!prompt.trim() || Buffer.byteLength(prompt, 'utf8') > MAX_PROMPT_BYTES) throw new Error('prompt_file_invalid');
    if (prompt.includes(bearer)) throw new Error('credential_in_prompt');
    privateHome = await createPrivateCodexHome();
    base.isolatedCodexHome = true;
    base.authLinked = true;
    base.authAliasKind = 'hardlink';
    base.codexHomeCleanupSucceeded = false;
    await mkdir(paths.workspace, { recursive: true });
    const version = await checkVersion(paths.codexexecutable, paths.workspace, privateHome.path);

    const cliArgs = [
      'exec', '--ephemeral', '--json', '--sandbox', 'read-only', '--skip-git-repo-check',
      '--ignore-user-config', '--ignore-rules',
      '--config', 'project_doc_max_bytes=0',
      '--config', 'cli_auth_credentials_store="file"',
      '--disable', 'apps', '--disable', 'plugins', '--disable', 'multi_agent',
      '--disable', 'shell_tool', '--disable', 'unified_exec', '--disable', 'shell_snapshot',
      '--disable', 'browser_use', '--disable', 'browser_use_external', '--disable', 'browser_use_full_cdp_access',
      '--disable', 'computer_use', '--disable', 'browser_annotation_api',
      '--config', mcpServerConfig(paths.enabledmcptools),
      '-'
    ];
    const childEnv = cleanEnvironment({ includeBearer: true, bearer, codexHome: privateHome.path });
    childEnv.CODEX_MANAGED_PACKAGE_ROOT = resolve(dirname(paths.codexexecutable), '../../..');
    childEnv.CODEX_MANAGED_BY_NPM = '1';
    const startedAt = Date.now();
    summaryReader = new EventSummary(() => child?.kill('SIGTERM'));
    let authCheckInProgress = false;
    const checkAuthAliasDuringRun = async () => {
      if (authCheckInProgress || childClosed || !privateHome) return;
      authCheckInProgress = true;
      try { await verifyPrivateCodexHome(privateHome); }
      catch (error) {
        const code = safeCode(error?.message) || 'auth_source_replaced';
        summaryReader.errorCodes.add(code);
        child?.kill('SIGTERM');
      } finally { authCheckInProgress = false; }
    };
    const enqueueProgress = (status, stage, failClosed = false) => {
      progressWrites = progressWrites.then(() => writeProgressAtomic(progressPath, {
        schemaVersion: 'codex-google-local-progress/v1',
        status,
        stage,
        elapsedMs: Date.now() - startedAt,
        progressWriteErrors,
        taskOutcome: 'unknown',
        rawTranscriptPersisted: false,
        isolatedCodexHome: base.isolatedCodexHome,
        authLinked: base.authLinked,
        authAliasKind: base.authAliasKind,
        ...summaryReader.sanitizedSnapshot(),
      })).catch(() => {
        progressWriteErrors += 1;
        summaryReader.errorCodes.add('progress_write_failed');
        if (failClosed) throw new Error('progress_write_failed');
      });
      return progressWrites;
    };
    await enqueueProgress('running', 'preparing', true);
    await verifyPrivateCodexHome(privateHome);
    child = spawn(paths.codexexecutable, cliArgs, { cwd: paths.workspace, env: childEnv, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    childClosed = false;
    let childSpawnFailed = false;
    childClosePromise = new Promise(resolvePromise => {
      let finished = false;
      const finish = value => {
        if (finished) return;
        finished = true;
        childClosed = true;
        resolvePromise(value);
      };
      child.once('error', () => {
        childSpawnFailed = true;
        if (!child.pid) finish({ code: 1, signal: null, spawnFailed: true });
      });
      child.once('close', (code, signal) => finish({ code, signal, spawnFailed: false }));
    });
    child.stdout.on('data', chunk => summaryReader.feed(chunk));
    child.stderr.on('data', chunk => {
      stderrBytes += chunk.length;
      summaryReader.observeStderr(chunk);
      if (stderrBytes > MAX_STDERR_BYTES || summaryReader.errorCodes.has('output_limit_exceeded')) {
        child.kill('SIGTERM');
      }
    });
    child.stdin.end(prompt, 'utf8');
    runTimer = setTimeout(() => { summaryReader.errorCodes.add('run_timeout'); child.kill('SIGTERM'); }, MAX_RUN_MS);
    progressTimer = setInterval(() => {
      void checkAuthAliasDuringRun().then(() => enqueueProgress('running', 'model_run'));
    }, 15 * 1000);
    const closeResult = await childClosePromise;
    const exitCode = closeResult.signal || closeResult.spawnFailed || childSpawnFailed ? 1 : (closeResult.code ?? 1);
    runExitCode = exitCode;
    clearTimeout(runTimer); runTimer = null;
    clearInterval(progressTimer); progressTimer = null;
    if (childSpawnFailed) summaryReader.errorCodes.add('runner_internal_error');
    await progressWrites;
    await enqueueProgress(exitCode === 0 ? 'closed' : 'failed', 'process_closed');
    if (exitCode !== 0 && summaryReader.terminalEvent !== 'turn.failed') summaryReader.errorCodes.add('process_nonzero_exit');
    const hasClientItemErrors = summaryReader.itemTypeCounts.error > 0;
    const status = summaryReader.terminalEvent === 'turn.completed'
      ? (hasClientItemErrors ? 'turn_completed_with_client_errors'
        : summaryReader.mcpToolErrorCount > 0 ? 'turn_completed_with_tool_errors' : 'turn_completed')
      : (exitCode === 0 ? 'process_exited_without_terminal_event' : 'process_failed');
    const summary = {
      ...base, status, cliVersion: version, exitCode, endpoint: ENDPOINT,
      sandbox: 'read-only', ephemeral: true, promptBytes: Buffer.byteLength(prompt, 'utf8'),
      stdoutBytes: summaryReader.stdoutBytes, stderrBytes,
      ...summaryReader.sanitizedSnapshot(),
      durationMs: Date.now() - startedAt,
      progressWriteErrors,
      errorCodes: [...summaryReader.errorCodes].sort(),
      outputLimitKilled: summaryReader.errorCodes.has('output_limit_exceeded') || stderrBytes > MAX_STDERR_BYTES,
    };
    runSummary = summary;
  } catch (error) {
    failureCode = safeCode(error?.message) || 'runner_internal_error';
    if (privateHome && !childClosed && child) child.kill('SIGTERM');
  } finally {
    clearTimeout(runTimer);
    clearInterval(progressTimer);
    if (child && !childClosed && childClosePromise) {
      let timeout;
      await Promise.race([
        childClosePromise,
        new Promise(resolvePromise => { timeout = setTimeout(() => resolvePromise(null), 5000); }),
      ]).finally(() => clearTimeout(timeout));
    }
    await progressWrites.catch(() => {});
    if (privateHome) {
      if (childClosed) {
        try { await verifyPrivateCodexHome(privateHome); }
        catch (error) { lifecycleErrorCodes.add(safeCode(error?.message) || 'auth_source_replaced'); }
      }
      const cleanup = childClosed
        ? await cleanupPrivateCodexHome(privateHome)
        : { succeeded: false, authAliasPreserved: false, errorCode: 'codex_home_cleanup_failed' };
      base.authAliasPreserved = cleanup.authAliasPreserved;
      base.codexHomeCleanupSucceeded = cleanup.succeeded;
      if (cleanup.errorCode) lifecycleErrorCodes.add(cleanup.errorCode);
    }
  }

  if (runSummary) {
    Object.assign(runSummary, base);
    runSummary.errorCodes = [...new Set([...(runSummary.errorCodes || []), ...lifecycleErrorCodes])].sort();
    try {
      await writeSummary(outputPath, runSummary);
      process.stdout.write(`${JSON.stringify(runSummary)}\n`);
      process.exitCode = base.codexHomeCleanupSucceeded
        && !lifecycleErrorCodes.has('auth_source_replaced')
        && !runSummary.errorCodes.includes('client_item_error') ? runExitCode : 2;
      return;
    } catch {
      failureCode = 'output_write_failed';
    }
  }
  const summary = {
    ...base,
    status: 'blocked',
    errorCodes: [...new Set([failureCode, ...lifecycleErrorCodes])].sort(),
  };
  try { await writeSummary(outputPath, summary); } catch { }
  process.stdout.write(`${JSON.stringify(summary)}\n`);
  process.exitCode = 2;
}

export {
  EventSummary, argsFrom, createPrivateCodexHome, verifyPrivateCodexHome, cleanupPrivateCodexHome,
  verifyExecutableBundle, mcpServerConfig,
};
if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) main();
