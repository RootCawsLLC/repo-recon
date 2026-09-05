import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { makeFinding, maskSecret } from '../finding.mjs';
import { STRONG } from './keyscan.mjs';

const exec = promisify(execFile);

// Scan the full git history for high-confidence secrets. The default scan reads
// only the working tree (a shallow clone), so a credential that was committed
// and later "removed" still sits in history, reachable by anyone who clones -
// the classic leak. This walks every commit's added lines for provider-format
// secrets (only the STRONG formats, to keep history noise-free) and reports the
// commit that introduced each.
//
// Runs only when the caller asks (ctx.history) and the target is a real git repo
// with history present (a full clone, or a local checkout).

export async function scan(ctx) {
  if (!ctx.history) return { findings: [], summary: { scanned: false, reason: 'not requested (use --history)' } };

  let out;
  try {
    const res = await exec('git', ['-C', ctx.dir, 'log', '--all', '-p', '-U0', '--no-color'], {
      timeout: 120000,
      maxBuffer: 128 * 1024 * 1024,
    });
    out = res.stdout;
  } catch (err) {
    return { findings: [], summary: { scanned: false, reason: `git log failed: ${err.message}` } };
  }

  const findings = [];
  const seen = new Set();
  let commit = null;
  let file = null;
  let commits = 0;

  for (const line of out.split('\n')) {
    if (line.startsWith('commit ')) {
      commit = line.slice(7, 47);
      commits++;
      continue;
    }
    const bpath = line.match(/^\+\+\+ b\/(.+)$/);
    if (bpath) {
      file = bpath[1];
      continue;
    }
    if (line[0] !== '+' || line.startsWith('+++')) continue; // only added content
    for (const pat of STRONG) {
      pat.re.lastIndex = 0;
      let m;
      while ((m = pat.re.exec(line)) != null) {
        const raw = pat.group ? m[pat.group] : m[0];
        if (/EXAMPLE/.test(raw)) continue; // AWS documentation placeholders
        const key = `${pat.name}|${maskSecret(raw)}|${commit}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push(
          makeFinding({
            tool: 'secrets-history',
            severity: pat.sev,
            confidence: 'high',
            title: `Secret in git history: ${pat.name}`,
            owasp: 'A02',
            cwe: 'CWE-798',
            location: { file, line: null, snippet: `${maskSecret(raw)} @ ${commit ? commit.slice(0, 10) : 'unknown'}` },
            detail: `A ${pat.name} appears in a past commit${commit ? ` (${commit.slice(0, 10)})` : ''}${file ? ` in ${file}` : ''}. Even if it is no longer in the current tree, anyone who clones the repo can read it from history.`,
            remediation:
              'Treat this credential as compromised: revoke/rotate it now. Removing it from the current files is not enough - purge it from history (git filter-repo / BFG) and force-push, then rotate.',
          }),
        );
      }
    }
  }

  return { findings, summary: { scanned: true, commits, secretsInHistory: findings.length } };
}
