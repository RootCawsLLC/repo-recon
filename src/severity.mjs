// Severity model shared across scanners.
// Order matters: index is used for sorting and for score weighting.

export const SEVERITY = Object.freeze({
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFO: 'INFO',
});

export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export function severityRank(sev) {
  const i = SEVERITY_ORDER.indexOf(sev);
  return i === -1 ? SEVERITY_ORDER.length : i;
}

// Map a numeric CVSS base score to our band. Used by the dependency scanner
// when OSV hands back a CVSS vector/score.
export function cvssToSeverity(score) {
  if (score == null || Number.isNaN(score)) return SEVERITY.MEDIUM;
  if (score >= 9.0) return SEVERITY.CRITICAL;
  if (score >= 7.0) return SEVERITY.HIGH;
  if (score >= 4.0) return SEVERITY.MEDIUM;
  if (score > 0.0) return SEVERITY.LOW;
  return SEVERITY.INFO;
}

// Sort findings most-severe first, then by tool, then by location for stable output.
export function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const r = severityRank(a.severity) - severityRank(b.severity);
    if (r !== 0) return r;
    const t = (a.tool || '').localeCompare(b.tool || '');
    if (t !== 0) return t;
    return (a.location?.file || '').localeCompare(b.location?.file || '');
  });
}

export function countBySeverity(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) {
    if (counts[f.severity] != null) counts[f.severity] += 1;
  }
  return counts;
}
