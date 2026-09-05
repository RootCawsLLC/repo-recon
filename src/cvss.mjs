// Compact CVSS v3.0/3.1 base-score calculator. OSV records often carry a CVSS
// vector but not a numeric score; this turns the vector into a 0.0-10.0 score
// so the dependency scanner can band it. Returns null for anything unparseable.

const M = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  PR_U: { N: 0.85, L: 0.62, H: 0.27 }, // scope unchanged
  PR_C: { N: 0.85, L: 0.68, H: 0.5 }, // scope changed
  CIA: { N: 0, L: 0.22, H: 0.56 },
};

function roundUp1(x) {
  // CVSS "roundup": smallest 1-decimal number >= x (with float tolerance).
  const i = Math.round(x * 100000);
  if (i % 10000 === 0) return i / 100000;
  return (Math.floor(i / 10000) + 1) / 10;
}

export function cvssScore(vector) {
  if (!vector || typeof vector !== 'string') return null;
  const parts = Object.fromEntries(
    vector
      .replace(/^CVSS:3\.[01]\//i, '')
      .split('/')
      .map((p) => p.split(':'))
      .filter((p) => p.length === 2),
  );
  const { AV, AC, PR, UI, S, C, I, A } = parts;
  if (!AV || !AC || !PR || !UI || !S || !C || !I || !A) return null;
  const av = M.AV[AV];
  const ac = M.AC[AC];
  const ui = M.UI[UI];
  const changed = S === 'C';
  const pr = (changed ? M.PR_C : M.PR_U)[PR];
  const c = M.CIA[C];
  const i = M.CIA[I];
  const a = M.CIA[A];
  if ([av, ac, ui, pr, c, i, a].some((v) => v == null)) return null;

  const iscBase = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed
    ? 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15)
    : 6.42 * iscBase;
  if (impact <= 0) return 0;
  const exploit = 8.22 * av * ac * pr * ui;
  const raw = changed ? 1.08 * (impact + exploit) : impact + exploit;
  return roundUp1(Math.min(raw, 10));
}
