import { owaspLabel } from '../owasp.mjs';

function esc(s) {
  return String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

export function renderMarkdown(report) {
  const g = report.grade;
  const t = report.target;
  const sc = report.severityCounts;
  const L = [];

  L.push(`# repo-recon Safety Report`);
  L.push('');
  L.push(`**${t.ref ? `${t.ref.owner}/${t.ref.repo}` : t.input}**`);
  if (t.url) L.push(t.url);
  L.push('');
  L.push(`Generated: ${report.generatedAt}`);
  L.push('');
  L.push(`## Grade ${g.letter} — ${g.score}/100 (${g.blurb})`);
  L.push('');
  L.push(report.recommendation);
  L.push('');
  L.push('> Grade scale: A 90-100 (Looks safe to use) · B 75-89 (Mostly safe) · C 60-74 (Use with caution) · D 40-59 (Risky) · F 0-39 (Not recommended right now)');
  L.push('');

  // ---------- FOR EVERYONE ----------
  L.push('## For everyone — no security background needed');
  L.push('');
  L.push(
    `Findings: **${report.stats.findings}** — ` +
      ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((s) => `${s} ${sc[s]}`).join(' · '),
  );
  L.push('');
  const kevCount = report.scanners['dep-check']?.knownExploited || 0;
  if (kevCount > 0) {
    L.push(
      `> ⚠ **${kevCount} dependency ${kevCount === 1 ? 'vulnerability is' : 'vulnerabilities are'} in CISA's Known Exploited Vulnerabilities catalog** — confirmed exploited in the wild. Patch ${kevCount === 1 ? 'it' : 'these'} before anything else; see the \`[KEV]\` findings below.`,
    );
    L.push('');
  }
  const agentFindings = report.findings.filter((f) => f.tool === 'agent-targeting').length;
  const ag = report.scanners['agent-targeting'];
  L.push('### AI agent-targeting content');
  L.push('');
  L.push(
    agentFindings === 0
      ? `Clear — nothing in the ${ag?.filesChecked ?? 0} files checked reads like an attempt to manipulate an AI agent (prompt-injection phrasing, hidden/invisible Unicode, or MCP configs pointing at untrusted remote endpoints).`
      : `**${agentFindings} item(s) flagged** across ${ag?.filesChecked ?? 0} files — prompt-injection phrasing, hidden Unicode, or untrusted MCP endpoints. See findings below.`,
  );
  L.push('');

  // ---------- FOR GRC / COMPLIANCE ----------
  L.push('## For GRC / compliance — due diligence, privacy, framework mapping');
  L.push('');
  const au = report.scanners['author-check'];
  L.push('### Repository & author — due diligence');
  L.push('');
  if (au?.available) {
    const r = au.repo;
    const a = au.author;
    L.push(`- Repo: created ${r.createdAt?.slice(0, 10)}, last pushed ${r.updatedAt?.slice(0, 10)}, ${r.stars} stars, ${r.forks} forks, license: ${r.license}${r.archived ? ' (archived)' : ''}`);
    L.push(`- Author: "${a.login}" (${a.type || 'user'})${a.createdAt ? `, on GitHub since ${a.createdAt.slice(0, 10)}` : ''}${a.followers != null ? `, ${a.followers} followers, ${a.publicRepos} public repos` : ''}`);
  } else {
    L.push(`- ${au?.note || 'Author/repo metadata not checked.'}`);
  }
  L.push('');

  const iss = report.scanners['issues-check'];
  L.push('### Community-reported vulnerabilities');
  L.push('');
  if (iss?.available) {
    if (iss.flagged.length === 0) {
      L.push(`Clear — none of the ${iss.checked} open issues checked read like an unresolved security or data report. (Keyword match on issue titles, not verified.)`);
    } else {
      for (const f of iss.flagged) L.push(`- #${f.number}: ${esc(f.title)} — ${f.url}`);
    }
  } else {
    L.push(iss?.note || 'Open issues not checked.');
  }
  L.push('');

  const pv = report.scanners.privacy;
  if (pv?.categories) {
    L.push(`### Data handling & privacy (${pv.flagged}/${pv.total} flagged)`);
    L.push('');
    L.push('| Category | Status | Detail |');
    L.push('| --- | --- | --- |');
    for (const cat of pv.categories) {
      L.push(`| ${esc(cat.category)} | ${cat.status} | ${esc(cat.detail)}${cat.location ? ` (${esc(cat.location)})` : ''} |`);
    }
    L.push('');
  }

  if (report.owaspBreakdown.length) {
    L.push('### Findings by OWASP Top 10 category');
    L.push('');
    L.push('| OWASP category | Count |');
    L.push('| --- | --- |');
    for (const row of report.owaspBreakdown) L.push(`| ${esc(row.category)} | ${row.count} |`);
    L.push('');
  }

  // ---------- FOR DEVELOPERS ----------
  L.push('## For developers — file-level findings & remediation');
  L.push('');
  L.push(
    `Files scanned: ${report.stats.filesScanned} · Dependencies checked: ${report.stats.dependenciesChecked} · Findings: ${report.stats.findings} · Tools: ${report.stats.tools.join(', ')}`,
  );
  L.push('');
  L.push('### Findings by severity');
  L.push('');
  L.push('| Severity | Count |');
  L.push('| --- | --- |');
  for (const s of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) L.push(`| ${s} | ${sc[s]} |`);
  L.push('');

  L.push('### Detailed findings');
  L.push('');
  if (report.findings.length === 0) {
    L.push('No findings.');
  } else {
    L.push('| Severity | Title | OWASP / CWE | Location | Remediation |');
    L.push('| --- | --- | --- | --- | --- |');
    for (const f of report.findings) {
      const loc = f.location.file ? `${f.location.file}${f.location.line ? ':' + f.location.line : ''}` : '(repo)';
      const owaspCwe = [f.owasp && owaspLabel(f.owasp), f.cwe].filter(Boolean).join(' / ');
      L.push(`| ${f.severity} | ${esc(f.title)} | ${esc(owaspCwe)} | ${esc(loc)} | ${esc(f.remediation)} |`);
    }
  }
  L.push('');
  L.push('---');
  L.push('_Generated by repo-recon. This is a raw scan — findings are not yet verified against the source file. Run it through the repo-recon Claude skill for per-finding verification and false-positive downgrade._');
  L.push('');
  return L.join('\n');
}
