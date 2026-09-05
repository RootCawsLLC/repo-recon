// OWASP Top 10 (2021) category labels, so every finding is comparable to what
// security teams already use. Keyed by the short code a scanner attaches.

export const OWASP = Object.freeze({
  A01: 'A01:2021 - Broken Access Control',
  A02: 'A02:2021 - Cryptographic Failures',
  A03: 'A03:2021 - Injection',
  A04: 'A04:2021 - Insecure Design',
  A05: 'A05:2021 - Security Misconfiguration',
  A06: 'A06:2021 - Vulnerable and Outdated Components',
  A07: 'A07:2021 - Identification and Authentication Failures',
  A08: 'A08:2021 - Software and Data Integrity Failures',
  A09: 'A09:2021 - Security Logging and Monitoring Failures',
  A10: 'A10:2021 - Server-Side Request Forgery',
});

export function owaspLabel(code) {
  return OWASP[code] || code || '';
}

// Roll findings up into an OWASP category count table (like the report's
// "Findings by OWASP Top 10 Category" section).
export function owaspBreakdown(findings) {
  const counts = new Map();
  for (const f of findings) {
    if (!f.owasp) continue;
    const label = owaspLabel(f.owasp);
    counts.set(label, (counts.get(label) || 0) + 1);
  }
  return [...counts.entries()]
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count);
}
