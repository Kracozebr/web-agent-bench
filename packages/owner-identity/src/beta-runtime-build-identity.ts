import { createHash } from 'node:crypto';
import { execFile as execFileCallback } from 'node:child_process';
import { readdir, readFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import { relative, resolve, sep } from 'node:path';

const execFile = promisify(execFileCallback);
const HASH = /^[0-9a-f]{64}$/i;
const COMMIT = /^[0-9a-f]{40,64}$/i;

export type BetaBuildPins = {
  commit: string;
  applicationBuildSha256: string;
  evaluatorSourceSha256: string;
};
export type BetaBuildObservation = BetaBuildPins & { sourceClean: true };
export type BetaBuildObservationDependencies = {
  runGit?: (args: string[], cwd: string) => Promise<string>;
  buildDirectories?: readonly string[];
};

async function defaultGit(args: string[], cwd: string): Promise<string> {
  const result = await execFile('git', args, { cwd, timeout: 5000, windowsHide: true, maxBuffer: 64 * 1024 });
  return result.stdout.trim();
}

async function listFiles(root: string, directory: string): Promise<string[]> {
  const absolute = resolve(root, directory);
  const results: string[] = [];
  async function visit(path: string): Promise<void> {
    const entries = await readdir(path, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name, 'en'));
    for (const entry of entries) {
      if (entry.name === 'cache' && directory.endsWith('.next')) continue;
      const child = resolve(path, entry.name);
      if (entry.isSymbolicLink()) throw new Error('beta_build_identity_symlink_unverifiable');
      if (entry.isDirectory()) await visit(child);
      else if (entry.isFile()) results.push(child);
    }
  }
  try { await visit(absolute); }
  catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') throw new Error('beta_build_identity_output_missing');
    throw error;
  }
  return results;
}

export async function hashBetaApplicationBuild(
  repositoryRoot: string,
  buildDirectories: readonly string[] = ['packages/owner-identity/dist', 'packages/owner-web/.next'],
): Promise<string> {
  const root = resolve(repositoryRoot);
  const files = (await Promise.all(buildDirectories.map((directory) => listFiles(root, directory)))).flat()
    .sort((a, b) => relative(root, a).split(sep).join('/').localeCompare(relative(root, b).split(sep).join('/'), 'en'));
  if (files.length === 0) throw new Error('beta_build_identity_output_missing');
  const digest = createHash('sha256');
  for (const file of files) {
    const name = relative(root, file).split(sep).join('/');
    const bytes = await readFile(file);
    digest.update(name, 'utf8'); digest.update('\0', 'utf8');
    digest.update(String(bytes.byteLength), 'utf8'); digest.update('\0', 'utf8');
    digest.update(bytes); digest.update('\n', 'utf8');
  }
  return digest.digest('hex');
}

/** Observe source/build/evaluator pins independently; manifest fields never attest themselves. */
export async function observeBetaBuildIdentity(input: {
  repositoryRoot: string;
  evaluatorSourceSha256: string;
  expected: BetaBuildPins;
  dependencies?: BetaBuildObservationDependencies;
}): Promise<BetaBuildObservation> {
  const root = resolve(input.repositoryRoot);
  const runGit = input.dependencies?.runGit ?? defaultGit;
  if (!HASH.test(input.evaluatorSourceSha256) || !COMMIT.test(input.expected.commit) ||
      !HASH.test(input.expected.applicationBuildSha256) || !HASH.test(input.expected.evaluatorSourceSha256)) {
    throw new Error('beta_build_identity_pin_invalid');
  }
  let commit: string;
  let dirty: string;
  try {
    [commit, dirty] = await Promise.all([
      runGit(['rev-parse', '--verify', 'HEAD^{commit}'], root),
      runGit(['status', '--porcelain=v1', '--untracked-files=all'], root),
    ]);
  } catch { throw new Error('beta_build_identity_git_unavailable'); }
  if (!COMMIT.test(commit) || dirty !== '') throw new Error('beta_build_identity_source_not_clean');
  const applicationBuildSha256 = await hashBetaApplicationBuild(root, input.dependencies?.buildDirectories);
  const observed = { commit: commit.toLowerCase(), applicationBuildSha256, evaluatorSourceSha256: input.evaluatorSourceSha256.toLowerCase() };
  if (observed.commit !== input.expected.commit.toLowerCase() ||
      observed.applicationBuildSha256 !== input.expected.applicationBuildSha256.toLowerCase() ||
      observed.evaluatorSourceSha256 !== input.expected.evaluatorSourceSha256.toLowerCase()) {
    throw new Error('beta_build_identity_pin_mismatch');
  }
  return { ...observed, sourceClean: true };
}
