import { makeFinding, maskSecret } from '../finding.mjs';
import { lineAt } from '../walk.mjs';

// High-confidence provider credential formats. A hit here is almost never a
// false positive, so it carries real severity on its own.
const STRONG = [
  { name: 'AWS access key id', re: /\bAKIA[0-9A-Z]{16}\b/g, sev: 'HIGH' },
  { name: 'AWS secret access key', re: /\baws_secret_access_key\s*[:=]\s*["']?([A-Za-z0-9/+]{40})["']?/gi, sev: 'CRITICAL', group: 1 },
  { name: 'GitHub token', re: /\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b/g, sev: 'HIGH' },
  { name: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, sev: 'HIGH' },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, sev: 'HIGH' },
  { name: 'Stripe live secret key', re: /\bsk_live_[0-9A-Za-z]{24,}\b/g, sev: 'CRITICAL' },
  { name: 'Private key block', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, sev: 'CRITICAL' },
  { name: 'JSON Web Token', re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, sev: 'MEDIUM' },
];

// Generic `secret-ish name = "literal"` assignments. Lower confidence, so
// MEDIUM - and left in on purpose even for dev defaults (postgres/postgres),
// because confirming those are harmless is the verification layer's job.
const ASSIGN = /\b(passwd|password|pwd|secret|token|api[_-]?key|access[_-]?key|auth[_-]?token|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*["'`]([^"'`\n]{4,})["'`]/gi;

// Values that are obviously not real secrets - env lookups, placeholders, refs.
const NOT_A_SECRET = /^(process\.env|import\.meta|os\.environ|getenv|\$\{|\{\{|<%|<[a-z]|null|undefined|true|false|none|your[_-]|change[_-]?me$|example|placeholder|redacted|xxx+|\.\.\.|\*+|\d+)$/i;

function isEnvOrRef(v) {
  const s = v.trim();
  if (NOT_A_SECRET.test(s)) return true;
  if (/\benv\b|process\.env|getenv|secret[_-]?manager|vault/i.test(s)) return true;
  if (s.includes('${') || s.includes('{{')) return true;
  return false;
}

export async function scan(ctx) {
  const findings = [];
  for (const file of ctx.textFiles) {
    const text = file.text;

    for (const pat of STRONG) {
      pat.re.lastIndex = 0;
      let m;
      while ((m = pat.re.exec(text)) != null) {
        const raw = pat.group ? m[pat.group] : m[0];
        findings.push(
          makeFinding({
            tool: 'secrets',
            severity: pat.sev,
            title: `Possible hardcoded secret: ${pat.name}`,
            owasp: 'A02',
            cwe: 'CWE-798',
            location: { file: file.rel, line: lineAt(text, m.index), snippet: maskSecret(raw) },
            detail: `A value matching the ${pat.name} format is committed to the source. If it is a live credential, anyone with the repo can use it.`,
            remediation:
              'Confirm whether this is a real credential. If so, revoke/rotate it, remove it from git history, and load it from an environment variable or secret manager instead.',
          }),
        );
      }
    }

    ASSIGN.lastIndex = 0;
    let a;
    while ((a = ASSIGN.exec(text)) != null) {
      const value = a[2];
      if (isEnvOrRef(value)) continue;
      findings.push(
        makeFinding({
          tool: 'secrets',
          severity: 'MEDIUM',
          title: 'Possible hardcoded secret: Password/Secret Assignment',
          owasp: 'A02',
          cwe: 'CWE-798',
          location: { file: file.rel, line: lineAt(text, a.index), snippet: `${a[1]}=${maskSecret(value)}` },
          detail:
            'A secret-shaped variable is assigned a string literal in source. It may be a real credential, or a harmless local/dev default - verify against the file before acting.',
          remediation:
            'If it is a real credential, revoke/rotate it and load it from an environment variable or secret manager. If it is only a local/dev default, confirm it is never used against a real system.',
        }),
      );
    }
  }
  return { findings, summary: { filesScanned: ctx.textFiles.length } };
}
