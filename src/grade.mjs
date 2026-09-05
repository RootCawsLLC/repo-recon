import { countBySeverity } from './severity.mjs';

// Per-finding score deductions. Weighted so a single CRITICAL alone (50) plus
// its severity cap already forces an F, while a scatter of LOWs barely moves.
const WEIGHTS = { CRITICAL: 50, HIGH: 8, MEDIUM: 2, LOW: 0.5, INFO: 0 };

// A finding of a given band caps the maximum achievable grade, so a repo with
// an open CRITICAL can never present as anything but "Not recommended", no
// matter how clean the rest is. Mirrors how RepoSentry lands trust-center at F.
const CAPS = { CRITICAL: 39, HIGH: 59, MEDIUM: 89, LOW: 100, INFO: 100 };

export const GRADE_SCALE = [
  { letter: 'A', min: 90, blurb: 'Looks safe to use' },
  { letter: 'B', min: 75, blurb: 'Mostly safe, minor notes' },
  { letter: 'C', min: 60, blurb: 'Use with caution' },
  { letter: 'D', min: 40, blurb: 'Risky - proceed carefully' },
  { letter: 'F', min: 0, blurb: 'Not recommended right now' },
];

export function letterFor(score) {
  return GRADE_SCALE.find((g) => score >= g.min) || GRADE_SCALE.at(-1);
}

// Findings that only add context (author age, privacy notes) should not, on
// their own, tank a score. Scanners mark these with contextOnly: true.
function scoreable(findings) {
  return findings.filter((f) => !f.contextOnly);
}

export function grade(findings) {
  const scored = scoreable(findings);
  const counts = countBySeverity(scored);

  let score = 100;
  for (const [sev, n] of Object.entries(counts)) {
    score -= (WEIGHTS[sev] || 0) * n;
  }
  score = Math.max(0, Math.round(score));

  // Apply the tightest cap any present band imposes.
  let cap = 100;
  for (const [sev, n] of Object.entries(counts)) {
    if (n > 0) cap = Math.min(cap, CAPS[sev] ?? 100);
  }
  score = Math.min(score, cap);

  const band = letterFor(score);
  return {
    score,
    letter: band.letter,
    blurb: band.blurb,
    counts: countBySeverity(findings), // report full counts, incl. context-only
  };
}

// One-line recommendation string keyed off the letter, echoing the report's tone.
export function recommendation(letter) {
  switch (letter) {
    case 'A':
    case 'B':
      return 'Reasonable to use after a normal review of the findings below.';
    case 'C':
      return 'Use with caution - clear the flagged items before relying on it.';
    case 'D':
      return 'Risky - proceed carefully and resolve the findings before deploying.';
    default:
      return 'Not recommended right now - serious problems were found. Resolve the issues below before running this beyond a sandbox.';
  }
}
