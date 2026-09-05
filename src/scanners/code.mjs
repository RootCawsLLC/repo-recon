import { makeFinding } from '../finding.mjs';
import { lineAt } from '../walk.mjs';

// Dangerous "sink" detection for the taint-sensitive classes a purely static
// scan can otherwise miss (raw SQL, XSS, command execution, eval). A full
// dataflow engine (Semgrep/CodeQL) is still the right tool for proving a taint
// path; this narrows the gap by surfacing the sink *when it is fed something
// non-literal* - i.e. a variable, a template interpolation, or a concatenation,
// which is where injection lives. Every hit is confidence:medium: it flags a
// place to look, not a proven bug.

const CODE_FILE = /\.(js|mjs|cjs|jsx|ts|tsx)$/i;

// A value expression that is NOT a plain string/number literal - the signal that
// something dynamic reaches the sink.
const DYN = String.raw`(?![\s'"\`)\d])`; // next char isn't a quote, close-paren, digit, or space

const PATTERNS = [
  {
    key: 'sql-raw-unsafe',
    re: /\$(?:query|execute)RawUnsafe\s*\(|\bPrisma\.raw\s*\(/,
    severity: 'HIGH',
    owasp: 'A03',
    cwe: 'CWE-89',
    title: 'Raw SQL via an *Unsafe/raw API',
    detail: 'A raw, unparameterized SQL API is used. If any interpolated value is attacker-controlled, this is SQL injection.',
    remediation: 'Use parameterized queries ($queryRaw with tagged-template parameters, or bound parameters); never build SQL by interpolation.',
  },
  {
    key: 'sql-template',
    re: /`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|WHERE)\b[^`]*\$\{/i,
    // Prisma's $queryRaw / $executeRaw tagged templates and postgres.js `sql``
    // parameterize their interpolations - those are safe, so skip them.
    exclude: /\$(?:query|execute)Raw`|\bsql`|Prisma\.sql/,
    severity: 'MEDIUM',
    owasp: 'A03',
    cwe: 'CWE-89',
    title: 'SQL built from an interpolated template string',
    detail: 'A SQL statement is assembled with a template literal that interpolates a value. If the value is user input, this is SQL injection.',
    remediation: 'Parameterize the query. Keep user values out of the SQL string itself.',
  },
  {
    key: 'xss-dangerously',
    re: new RegExp(String.raw`dangerouslySetInnerHTML\s*=\s*\{\{\s*__html:\s*` + DYN),
    severity: 'MEDIUM',
    owasp: 'A03',
    cwe: 'CWE-79',
    title: 'dangerouslySetInnerHTML fed a non-literal value',
    detail: 'React HTML injection with a computed value. If the value derives from user input or untrusted data, this is stored/reflected XSS.',
    remediation: 'Render as text, or sanitize the HTML (e.g. DOMPurify) before injecting. Confirm the source is trusted.',
  },
  {
    key: 'xss-innerhtml',
    re: new RegExp(String.raw`\.(?:inner|outer)HTML\s*=\s*` + DYN),
    severity: 'MEDIUM',
    owasp: 'A03',
    cwe: 'CWE-79',
    title: 'innerHTML/outerHTML assigned a non-literal value',
    detail: 'Direct DOM HTML assignment from a computed value. Untrusted input here is XSS.',
    remediation: 'Use textContent, or sanitize before assignment.',
  },
  {
    key: 'cmd-exec',
    re: /\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+|[A-Za-z_$][\w$]*\s*\+)/,
    severity: 'HIGH',
    owasp: 'A03',
    cwe: 'CWE-78',
    title: 'Shell command built from dynamic input',
    detail: 'child_process exec/execSync runs a command string assembled from a variable or interpolation. Attacker-controlled input here is command injection.',
    remediation: 'Use execFile/spawn with an argument array (no shell), and never concatenate untrusted input into a command string.',
  },
  {
    key: 'eval-dynamic',
    re: new RegExp(String.raw`\beval\s*\(\s*` + DYN),
    severity: 'HIGH',
    owasp: 'A03',
    cwe: 'CWE-95',
    title: 'eval() of a non-literal expression',
    detail: 'eval executes a computed expression. If any part is untrusted, this is arbitrary code execution.',
    remediation: 'Remove eval. Parse data with JSON.parse; dispatch on a fixed map rather than evaluating strings.',
  },
];

export async function scan(ctx) {
  const findings = [];
  let filesScanned = 0;
  for (const file of ctx.textFiles) {
    if (!CODE_FILE.test(file.rel)) continue;
    filesScanned++;
    const lines = file.text.split('\n');
    for (const p of PATTERNS) {
      const seen = new Set();
      lines.forEach((l, i) => {
        if (!p.re.test(l)) return;
        if (p.exclude && p.exclude.test(l)) return;
        const line = i + 1;
        if (seen.has(line)) return;
        seen.add(line);
        findings.push(
          makeFinding({
            tool: 'code',
            severity: p.severity,
            confidence: 'medium',
            title: p.title,
            owasp: p.owasp,
            cwe: p.cwe,
            location: { file: file.rel, line, snippet: l.trim().slice(0, 120) },
            detail: p.detail + ' A static scan sees the sink, not the source - confirm whether the input is actually attacker-controlled.',
            remediation: p.remediation,
          }),
        );
      });
    }
  }
  return { findings, summary: { filesScanned } };
}
