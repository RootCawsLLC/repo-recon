#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { scanRepo } from '../src/index.mjs';
import { renderJson } from '../src/report/json.mjs';
import { renderMarkdown } from '../src/report/markdown.mjs';
import { renderTerminal } from '../src/report/terminal.mjs';
import { severityRank } from '../src/severity.mjs';

const HELP = `repo-recon - reconnaissance on a Git repository before you trust it

Usage:
  repo-recon <target> [options]

Target:
  A local directory, a GitHub URL, or owner/repo.
  Examples:  repo-recon .              repo-recon https://github.com/owner/repo
             repo-recon owner/repo     repo-recon ../some/checkout

Options:
  -f, --format <fmt>   terminal (default) | json | markdown
  -o, --out <file>     write the report to a file instead of stdout
      --offline        skip network scanners (OSV.dev, GitHub API)
      --history        also scan full git history for leaked secrets
                       (clones full history for a remote target; slower)
      --fail-under <n> exit non-zero if the grade score is below n (CI gate)
      --fail-on <sev>  exit non-zero if any finding is at or above this severity
                       (CRITICAL|HIGH|MEDIUM|LOW)
  -q, --quiet          suppress progress output on stderr
  -h, --help           show this help
      --version        print version

Notes:
  Raw scan output is un-verified: each finding is confirmed against the real
  file by the repo-recon Claude skill, which also downgrades false positives.
  Set GITHUB_TOKEN to raise the GitHub API rate limit.
`;

function parseArgs(argv) {
  const opts = { format: 'terminal', offline: false, quiet: false };
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '-h':
      case '--help':
        opts.help = true;
        break;
      case '--version':
        opts.version = true;
        break;
      case '-f':
      case '--format':
        opts.format = argv[++i];
        break;
      case '-o':
      case '--out':
        opts.out = argv[++i];
        break;
      case '--offline':
        opts.offline = true;
        break;
      case '--history':
        opts.history = true;
        break;
      case '--fail-under':
        opts.failUnder = Number(argv[++i]);
        break;
      case '--fail-on':
        opts.failOn = String(argv[++i]).toUpperCase();
        break;
      case '-q':
      case '--quiet':
        opts.quiet = true;
        break;
      default:
        if (a.startsWith('-')) {
          console.error(`Unknown option: ${a}`);
          opts.help = true;
        } else {
          positional.push(a);
        }
    }
  }
  opts.target = positional[0];
  return opts;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.version) {
    console.log('repo-recon 0.1.0');
    return 0;
  }
  if (opts.help || !opts.target) {
    console.log(HELP);
    return opts.target ? 0 : 1;
  }
  if (!['terminal', 'json', 'markdown'].includes(opts.format)) {
    console.error(`Invalid --format "${opts.format}". Use terminal, json, or markdown.`);
    return 1;
  }

  const log = opts.quiet ? () => {} : (m) => process.stderr.write(`  ${m}\n`);
  let report;
  try {
    report = await scanRepo(opts.target, { offline: opts.offline, history: opts.history, onLog: log });
  } catch (err) {
    console.error(`repo-recon: ${err.message}`);
    return 2;
  }

  const rendered =
    opts.format === 'json' ? renderJson(report) : opts.format === 'markdown' ? renderMarkdown(report) : renderTerminal(report);

  if (opts.out) {
    await writeFile(opts.out, rendered, 'utf8');
    log(`Report written to ${opts.out}`);
  } else {
    process.stdout.write(rendered + '\n');
  }

  // CI gating
  let exitCode = 0;
  if (opts.failUnder != null && report.grade.score < opts.failUnder) {
    log(`Grade score ${report.grade.score} is below --fail-under ${opts.failUnder}`);
    exitCode = 3;
  }
  if (opts.failOn) {
    const threshold = severityRank(opts.failOn);
    const worst = report.findings.some((f) => severityRank(f.severity) <= threshold && !f.contextOnly);
    if (worst) {
      log(`A finding at or above ${opts.failOn} was found (--fail-on)`);
      exitCode = 3;
    }
  }
  return exitCode;
}

main().then((code) => process.exit(code)).catch((err) => {
  console.error(err);
  process.exit(2);
});
