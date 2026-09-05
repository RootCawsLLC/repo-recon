import { makeFinding } from '../finding.mjs';
import { ghFetch } from '../github.mjs';

const DAY = 24 * 60 * 60 * 1000;

function daysBetween(a, b) {
  return Math.round((new Date(b) - new Date(a)) / DAY);
}

export async function scan(ctx) {
  const summary = { available: false, note: null };
  const findings = [];

  if (ctx.offline || !ctx.ref) {
    summary.note = ctx.offline
      ? 'offline mode: author/repo metadata not checked'
      : 'local target with no GitHub origin: author/repo metadata not checked';
    return { findings, summary };
  }

  const { owner, repo } = ctx.ref;
  const repoRes = await ghFetch(`/repos/${owner}/${repo}`);
  if (!repoRes.ok) {
    summary.note = repoRes.rateLimited
      ? 'GitHub API rate-limited (set GITHUB_TOKEN to raise the limit)'
      : `repo metadata unavailable (HTTP ${repoRes.status})`;
    return { findings, summary };
  }
  const r = repoRes.data;
  const ownerRes = await ghFetch(`/users/${owner}`);
  const u = ownerRes.ok ? ownerRes.data : null;

  const now = new Date().toISOString();
  const repoAgeDays = daysBetween(r.created_at, now);
  const accountAgeDays = u ? daysBetween(u.created_at, now) : null;

  summary.available = true;
  summary.repo = {
    fullName: r.full_name,
    createdAt: r.created_at,
    updatedAt: r.pushed_at || r.updated_at,
    stars: r.stargazers_count,
    forks: r.forks_count,
    license: r.license?.spdx_id || r.license?.name || 'none',
    archived: r.archived,
    openIssues: r.open_issues_count,
    ageDays: repoAgeDays,
  };
  summary.author = u
    ? {
        login: u.login,
        type: u.type,
        createdAt: u.created_at,
        followers: u.followers,
        publicRepos: u.public_repos,
        accountAgeDays,
      }
    : { login: owner, note: 'account details unavailable' };

  // A brand-new repo from a brand-new account with no community track record is
  // not a vulnerability, but it is context worth weighing - INFO, like the
  // reference report's "Newly created repository" line.
  if (repoAgeDays <= 30 || (accountAgeDays != null && accountAgeDays <= 60)) {
    findings.push(
      makeFinding({
        tool: 'author-check',
        severity: 'INFO',
        title: 'Newly created repository / account - limited track record',
        owasp: 'A08',
        cwe: null,
        location: { file: null, line: null, snippet: `${r.full_name}` },
        detail:
          `Repository created ${repoAgeDays} day(s) ago` +
          (accountAgeDays != null ? `, owner account ${accountAgeDays} day(s) old` : '') +
          `, ${r.stargazers_count} stars, ${r.forks_count} forks. No community track record yet. This is context for due diligence, not itself a flaw.`,
        remediation: 'Weigh this alongside the other findings before trusting the repo. Prefer a sandbox for first use.',
      }),
    );
  }

  return { findings, summary };
}
