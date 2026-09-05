import { ghFetch } from '../github.mjs';

// Keyword match on open-issue titles - a cheap signal that someone has already
// reported a security or data problem. Not verified by us (the report is
// explicit that each is just a keyword hit on a title someone else filed).
const SECURITY_WORDS =
  /\b(vuln|vulnerability|cve|exploit|security|xss|sql\s*inject|csrf|ssrf|rce|malware|backdoor|data\s*(leak|breach)|exposed\s+(secret|key|token)|credential)\b/i;

export async function scan(ctx) {
  const summary = { available: false, checked: 0, flagged: [], note: null };
  const findings = [];

  if (ctx.offline || !ctx.ref) {
    summary.note = ctx.offline ? 'offline mode: open issues not checked' : 'no GitHub origin: open issues not checked';
    return { findings, summary };
  }

  const { owner, repo } = ctx.ref;
  const res = await ghFetch(`/repos/${owner}/${repo}/issues?state=open&per_page=50&sort=updated`);
  if (!res.ok) {
    summary.note = res.rateLimited ? 'GitHub API rate-limited' : `issues unavailable (HTTP ${res.status})`;
    return { findings, summary };
  }

  // The issues endpoint also returns PRs; filter those out.
  const issues = (res.data || []).filter((i) => !i.pull_request);
  summary.available = true;
  summary.checked = issues.length;
  for (const issue of issues) {
    if (SECURITY_WORDS.test(issue.title || '')) {
      summary.flagged.push({ number: issue.number, title: issue.title, url: issue.html_url });
    }
  }
  return { findings, summary };
}
