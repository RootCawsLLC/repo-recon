import { resolveTarget, latestCommit } from './clone.mjs';
import { walk, isTextCandidate, readText } from './walk.mjs';
import { sortFindings, countBySeverity } from './severity.mjs';
import { owaspBreakdown } from './owasp.mjs';
import { grade, recommendation } from './grade.mjs';

import * as keyscan from './scanners/keyscan.mjs';
import * as deps from './scanners/deps.mjs';
import * as heuristics from './scanners/heuristics.mjs';
import * as author from './scanners/author.mjs';
import * as issues from './scanners/issues.mjs';
import * as privacy from './scanners/privacy.mjs';
import * as agent from './scanners/agent.mjs';
import * as infra from './scanners/infra.mjs';
import * as code from './scanners/code.mjs';
import * as history from './scanners/history.mjs';

// Tool label -> module. Order here is the order they run and report in.
// `secrets-history` runs only when --history is passed (it is a no-op otherwise).
const SCANNERS = [
  ['secrets', keyscan],
  ['secrets-history', history],
  ['dep-check', deps],
  ['heuristics', heuristics],
  ['code', code],
  ['infra', infra],
  ['author-check', author],
  ['issues-check', issues],
  ['privacy', privacy],
  ['agent-targeting', agent],
];

/**
 * Run every scanner against a target and return a structured report object.
 * The raw report is intentionally un-verified: the `verified` flag on each
 * finding is false until the AI-review layer (the Claude skill) confirms it
 * against the real file.
 *
 * @param {string} input  local dir, GitHub URL, or owner/repo
 * @param {object} opts   { offline, onLog }
 */
export async function scanRepo(input, opts = {}) {
  const log = opts.onLog || (() => {});
  const target = await resolveTarget(input, { onLog: log, history: Boolean(opts.history) });
  try {
    log('Walking files...');
    const { files, count } = await walk(target.dir);

    // Read text candidates once, share across content scanners.
    log(`Reading ${count} files...`);
    const textFiles = [];
    for (const f of files) {
      if (!isTextCandidate(f)) continue;
      const text = await readText(f.abs);
      if (text != null) textFiles.push({ ...f, text });
    }

    const ctx = {
      dir: target.dir,
      files,
      textFiles,
      ref: target.ref,
      kind: target.kind,
      offline: Boolean(opts.offline),
      history: Boolean(opts.history),
      onLog: log,
    };

    const commit = await latestCommit(target.dir);

    const findings = [];
    const scanners = {};
    for (const [label, mod] of SCANNERS) {
      log(`Scanning: ${label}...`);
      try {
        const { findings: fs = [], summary = {} } = await mod.scan(ctx);
        for (const f of fs) findings.push(f);
        scanners[label] = summary;
      } catch (err) {
        scanners[label] = { error: err.message };
        log(`  ! ${label} failed: ${err.message}`);
      }
    }

    const sorted = sortFindings(findings);
    const g = grade(sorted);

    return {
      tool: 'repo-recon',
      version: '0.1.0',
      generatedAt: new Date().toISOString(),
      target: {
        input,
        kind: target.kind,
        ref: target.ref,
        url: target.ref ? `https://github.com/${target.ref.owner}/${target.ref.repo}.git` : null,
      },
      stats: {
        filesScanned: count,
        textFilesScanned: textFiles.length,
        dependenciesChecked: scanners['dep-check']?.packagesChecked ?? 0,
        findings: sorted.length,
        tools: SCANNERS.map(([l]) => l),
      },
      grade: g,
      recommendation: recommendation(g.letter),
      severityCounts: countBySeverity(sorted),
      owaspBreakdown: owaspBreakdown(sorted),
      latestCommit: commit,
      scanners,
      findings: sorted,
    };
  } finally {
    await target.cleanup();
  }
}
