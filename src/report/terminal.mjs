import { owaspLabel } from '../owasp.mjs';

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code, s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const bold = (s) => c('1', s);
const dim = (s) => c('2', s);
const SEV_COLOR = { CRITICAL: '41;97', HIGH: '31', MEDIUM: '33', LOW: '36', INFO: '2' };
const sev = (s) => c(SEV_COLOR[s] || '0', s.padEnd(8));
const GRADE_COLOR = { A: '32', B: '32', C: '33', D: '33', F: '31' };

function rule(char = '-') {
  return char.repeat(Math.min(process.stdout.columns || 78, 78));
}

export function renderTerminal(report) {
  const out = [];
  const g = report.grade;
  out.push('');
  out.push(bold(`repo-recon  ${report.target.ref ? report.target.ref.owner + '/' + report.target.ref.repo : report.target.input}`));
  if (report.target.url) out.push(dim(report.target.url));
  out.push(dim(`Generated ${report.generatedAt}`));
  out.push('');
  out.push(`  ${c(GRADE_COLOR[g.letter] || '0', bold(`Grade ${g.letter}`))}  ${bold(`${g.score}/100`)}  ${g.blurb}`);
  out.push(`  ${report.recommendation}`);
  out.push('');
  out.push(rule());

  const sc = report.severityCounts;
  out.push(
    `Findings: ${bold(report.stats.findings)}   ` +
      ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((s) => `${sev(s).trim()} ${sc[s]}`).join('  '),
  );
  out.push(dim(`Files scanned: ${report.stats.filesScanned}   Dependencies checked: ${report.stats.dependenciesChecked}   Tools: ${report.stats.tools.join(', ')}`));
  out.push('');

  if (report.owaspBreakdown.length) {
    out.push(bold('By OWASP category'));
    for (const row of report.owaspBreakdown) out.push(`  ${String(row.count).padStart(4)}  ${row.category}`);
    out.push('');
  }

  // Agent-targeting one-liner
  const ag = report.scanners['agent-targeting'];
  if (ag && typeof ag.filesChecked === 'number') {
    const agentFindings = report.findings.filter((f) => f.tool === 'agent-targeting').length;
    out.push(bold('AI agent-targeting'));
    out.push(
      agentFindings === 0
        ? dim(`  Clear - nothing in the ${ag.filesChecked} files checked reads like an attempt to manipulate an AI agent.`)
        : `  ${agentFindings} item(s) flagged across ${ag.filesChecked} files - see findings below.`,
    );
    out.push('');
  }

  // Privacy table
  const pv = report.scanners.privacy;
  if (pv && pv.categories) {
    out.push(bold(`Data handling & privacy (${pv.flagged}/${pv.total} flagged)`));
    for (const cat of pv.categories) {
      const mark = cat.status === 'flagged' ? c('33', 'flagged') : cat.status === 'clear' ? c('32', 'clear') : dim('n/d');
      out.push(`  ${mark.padEnd(18)} ${cat.category}`);
    }
    out.push('');
  }

  out.push(rule());
  out.push(bold('Detailed findings'));
  out.push('');
  if (report.findings.length === 0) {
    out.push(c('32', '  No findings.'));
  } else {
    for (const f of report.findings) {
      const loc = f.location.file ? `${f.location.file}${f.location.line ? ':' + f.location.line : ''}` : '(repo)';
      out.push(`${sev(f.severity)} ${bold(f.title)}`);
      out.push(dim(`         ${[f.owasp && owaspLabel(f.owasp), f.cwe].filter(Boolean).join('  ')}   ${loc}`));
      if (f.location.snippet) out.push(dim(`         ${f.location.snippet}`));
      out.push(`         ${f.remediation}`);
      out.push('');
    }
  }
  out.push(dim('Raw scan - findings are not yet verified against the file. Run through the repo-recon skill for AI verification and the tiered report.'));
  out.push('');
  return out.join('\n');
}
