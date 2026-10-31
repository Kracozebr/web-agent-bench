/** Normalize declared child-output paths only; readers still verify realpath containment and byte hashes. */
export function qualificationArtifactPath(value, prefix = 'artifacts/runs/') {
  if (typeof value !== 'string') throw new Error('qualification_output_path_invalid');
  const path = value.startsWith('/workspace/') ? value.slice('/workspace/'.length) : value;
  if (path.length > 512 || !/^[A-Za-z0-9_./-]+$/.test(path) ||
      path.split('/').some((part) => !part || part === '.' || part === '..') || !path.startsWith(prefix)) {
    throw new Error('qualification_output_path_invalid');
  }
  return path;
}
