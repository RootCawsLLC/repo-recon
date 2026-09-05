import { createHash } from 'node:crypto';

/**
 * Build a normalized finding. Every scanner emits these so the report layer
 * and the AI-verification layer have one shape to work with.
 *
 * Fields:
 *   tool         which scanner produced it (secrets, deps, heuristics, ...)
 *   severity     CRITICAL|HIGH|MEDIUM|LOW|INFO
 *   title        short human title
 *   owasp        OWASP code (A01..A10) or null
 *   cwe          CWE id string or null
 *   location     { file, line, snippet } - snippet should already be masked
 *   detail       one or two sentences of explanation
 *   remediation  concrete next step
 *   contextOnly  true = informational, excluded from the numeric grade
 */
export function makeFinding(f) {
  const location = f.location || {};
  const id =
    f.id ||
    createHash('sha1')
      .update([f.tool, f.title, location.file || '', location.line || '', f.cwe || ''].join('|'))
      .digest('hex')
      .slice(0, 12);
  return {
    id,
    tool: f.tool,
    severity: f.severity,
    title: f.title,
    owasp: f.owasp || null,
    cwe: f.cwe || null,
    location: {
      file: location.file || null,
      line: location.line ?? null,
      snippet: location.snippet ?? null,
    },
    detail: f.detail || '',
    remediation: f.remediation || '',
    contextOnly: Boolean(f.contextOnly),
    // Filled in by the AI-verification layer (the skill). Raw CLI output leaves
    // these at their defaults - nothing is "verified" until a reviewer confirms it.
    verified: false,
    verificationNote: null,
    originalSeverity: null,
  };
}

// Mask the middle of a secret so a finding can name it without leaking it.
export function maskSecret(value) {
  const s = String(value);
  if (s.length <= 8) return '*'.repeat(s.length);
  return `${s.slice(0, 4)}${'*'.repeat(Math.max(4, s.length - 8))}${s.slice(-4)}`;
}
