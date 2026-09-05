import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const exec = promisify(execFile);

// Parse an owner/repo out of the many shapes a user might pass:
//   https://github.com/owner/repo(.git)   git@github.com:owner/repo.git
//   github.com/owner/repo                  owner/repo
export function parseRepoRef(input) {
  if (!input) return null;
  const s = input.trim().replace(/\.git$/i, '');
  let m = s.match(/github\.com[/:]([^/]+)\/([^/#?]+)/i);
  if (m) return { owner: m[1], repo: m[2], host: 'github.com' };
  m = s.match(/^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/);
  if (m) return { owner: m[1], repo: m[2], host: 'github.com' };
  return null;
}

function looksRemote(input) {
  return /^(https?:\/\/|git@)/i.test(input) || /github\.com/i.test(input);
}

async function isDirectory(p) {
  try {
    return (await stat(p)).isDirectory();
  } catch {
    return false;
  }
}

/**
 * Resolve a scan target to a working directory.
 * Returns { dir, kind: 'local'|'remote', ref, cleanup }.
 * `ref` is { owner, repo, host } when it can be determined, else null.
 * The caller must await cleanup() when done.
 */
export async function resolveTarget(input, { onLog } = {}) {
  const log = onLog || (() => {});

  // A bare owner/repo could also be a real local dir named like that; prefer
  // a directory that actually exists on disk.
  if (!looksRemote(input) && (await isDirectory(input))) {
    let ref = null;
    try {
      const { stdout } = await exec('git', ['-C', input, 'remote', 'get-url', 'origin'], { timeout: 5000 });
      ref = parseRepoRef(stdout.trim());
    } catch {
      // not a git repo, or no origin - fine, scan the directory as-is.
    }
    return { dir: input, kind: 'local', ref, cleanup: async () => {} };
  }

  const ref = parseRepoRef(input);
  if (!ref) {
    throw new Error(
      `Could not resolve target "${input}". Pass a local directory, a GitHub URL, or owner/repo.`,
    );
  }

  const url = /^https?:\/\//i.test(input) ? input : `https://github.com/${ref.owner}/${ref.repo}.git`;
  const dir = await mkdtemp(join(tmpdir(), 'repo-recon-'));
  log(`Cloning ${ref.owner}/${ref.repo} (shallow, latest commit only)...`);
  try {
    await exec('git', ['clone', '--depth', '1', '--quiet', url, dir], { timeout: 120000 });
  } catch (err) {
    await rm(dir, { recursive: true, force: true });
    throw new Error(`git clone failed for ${url}: ${err.stderr || err.message}`);
  }
  return {
    dir,
    kind: 'remote',
    ref,
    cleanup: async () => {
      await rm(dir, { recursive: true, force: true });
    },
  };
}

// Latest commit message only (we clone --depth 1, so history isn't available -
// the report is explicit about that limitation).
export async function latestCommit(dir) {
  try {
    const { stdout } = await exec('git', ['-C', dir, 'log', '-1', '--pretty=%H%n%an%n%s'], {
      timeout: 5000,
    });
    const [hash, author, ...subj] = stdout.trim().split('\n');
    return { hash, author, subject: subj.join('\n') };
  } catch {
    return null;
  }
}
