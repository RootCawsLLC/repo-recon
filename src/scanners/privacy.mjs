import { lineAt } from '../walk.mjs';

// Every category returns an explicit status every scan - including
// "not-determinable" where that is the honest answer for a static source scan.

const PII_EMAIL = /\b[A-Za-z0-9._%+-]+@(?!example\.(com|org|net)|test\.|localhost)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/;
const PII_SSN = /\b\d{3}-\d{2}-\d{4}\b/;
const PII_CARD = /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/;

const FIXTURE_FILE = /(fixture|seed|mock|sample|\.test\.|__tests__|testdata)/i;
const PERSONAL_VARNAME = /\b(email|ssn|social_?security|password|passwd|phone|dob|date_?of_?birth|first_?name|last_?name|full_?name|home_?address|credit_?card)\b/i;
const LOG_CALL = /\b(console\.(log|info|warn|error|debug)|logger?\.(info|warn|error|debug|log)|log\.(info|warn|error|debug))\s*\(/i;
const TELEMETRY = [
  'segment', 'analytics-node', 'mixpanel', 'amplitude', '@amplitude', 'posthog',
  '@sentry', 'sentry', 'hotjar', 'fullstory', 'datadog', 'dd-trace', 'newrelic',
  'newrelic', 'bugsnag', 'google-analytics', 'react-ga', 'gtag',
];
const REGION = /\b(us|eu|ap|sa|ca|me|af)-(east|west|central|north|south|northeast|southeast)-[123]\b/i;
const RETENTION = /\b(ttl|expire[sd]?|expiry|retention|purge|gdpr|ccpa|right\s+to\s+be\s+forgotten|deleteMany|onDelete|cascade)\b/i;
const ENCRYPTION = /\b(bcrypt|argon2|scrypt|pbkdf2|createHash|createCipheriv|crypto\.subtle|tls|https-only|hsts|strict-transport-security|sslmode=require)\b/i;
const DISK_WRITE = /\b(writeFileSync|writeFile|createWriteStream|appendFile|localStorage|sessionStorage|indexedDB)\b/;
const OUTBOUND = /\b(fetch|axios\.(get|post|put|delete)|https?\.request|got\()\s*\(?\s*[`'"]https?:\/\/(?!localhost|127\.0\.0\.1)([a-z0-9.-]+)/i;
const PRIVACY_DOC = /(^|\/)(PRIVACY(\.md)?|privacy-policy(\.md)?)$/i;

function cat(category, status, detail, location = null) {
  return { category, status, detail, location };
}

export async function scan(ctx) {
  const files = ctx.textFiles;
  const findText = (re, filter = () => true) => {
    for (const f of files) {
      if (!filter(f)) continue;
      const m = f.text.match(re);
      if (m) return { file: f.rel, line: lineAt(f.text, m.index), match: m[0] };
    }
    return null;
  };

  // 1. Real-looking PII in fixtures/seeds
  const piiHit = findText(new RegExp(`${PII_SSN.source}|${PII_CARD.source}`), (f) => FIXTURE_FILE.test(f.rel)) ||
    (() => {
      for (const f of files) {
        if (!FIXTURE_FILE.test(f.rel)) continue;
        const m = f.text.match(PII_EMAIL);
        if (m) return { file: f.rel, line: lineAt(f.text, m.index), match: m[0] };
      }
      return null;
    })();
  const c1 = piiHit
    ? cat('Real-looking data in test fixtures/seeds', 'flagged', `Fixture/seed data contains values matching common PII patterns. Verify it is synthetic.`, `${piiHit.file}:${piiHit.line}`)
    : cat('Real-looking data in test fixtures/seeds', 'clear', 'No fixture/seed/mock files with data matching common PII patterns (emails, SSNs, card numbers) were found.');

  // 2. Personal data in logs
  const logHit = (() => {
    for (const f of files) {
      const lines = f.text.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (LOG_CALL.test(lines[i]) && PERSONAL_VARNAME.test(lines[i])) {
          return { file: f.rel, line: i + 1 };
        }
      }
    }
    return null;
  })();
  const c2 = logHit
    ? cat('Personal data in logs or error handling', 'flagged', 'A logging call references personal-data-shaped variable names. Confirm PII is not written to logs.', `${logHit.file}:${logHit.line}`)
    : cat('Personal data in logs or error handling', 'clear', 'No logging calls referencing personal-data-shaped variable names were found.');

  // 3. Telemetry SDKs
  const pkg = files.find((f) => f.rel === 'package.json');
  let telemetry = null;
  if (pkg) {
    try {
      const j = JSON.parse(pkg.text);
      const deps = Object.keys({ ...j.dependencies, ...j.devDependencies });
      telemetry = deps.find((d) => TELEMETRY.some((t) => d === t || d.startsWith(t)));
    } catch {
      /* ignore */
    }
  }
  const c3 = telemetry
    ? cat('Telemetry / analytics SDKs present', 'flagged', `A known telemetry/analytics package ("${telemetry}") is a dependency. Confirm what it collects and whether users consent.`, 'package.json')
    : cat('Telemetry / analytics SDKs present', 'clear', 'No known telemetry/analytics package was found in package.json.');

  // 4. Outbound third-party calls
  const outbound = findText(OUTBOUND);
  const c4 = outbound
    ? cat('Outbound calls to third-party services', 'flagged', `Source makes a hardcoded outbound call to an external host. Verify what data is sent.`, `${outbound.file}:${outbound.line}`)
    : cat('Outbound calls to third-party services', 'clear', 'No hardcoded third-party API calls were found in source (calls built from runtime config/env vars are not visible to a static scan).');

  // 5. Data written to disk / browser storage
  const disk = findText(DISK_WRITE);
  const c5 = disk
    ? cat('Data written to disk or cached', 'flagged', 'Code writes to the filesystem and/or browser storage. Verify what is stored and whether it needs encryption or an expiry.', `${disk.file}:${disk.line}`)
    : cat('Data written to disk or cached', 'clear', 'No filesystem or browser-storage writes were found in source.');

  // 6. Retention / deletion
  const retention = findText(RETENTION);
  const c6 = retention
    ? cat('Retention and deletion handling', 'clear', 'Found retention/deletion-related code (e.g. TTL, purge, cascade, GDPR references).', `${retention.file}:${retention.line}`)
    : cat('Retention and deletion handling', 'not-determinable', 'No explicit retention/deletion handling was found in source. It may be handled outside the codebase.');

  // 7. Encryption in transit / at rest
  const enc = findText(ENCRYPTION);
  const c7 = enc
    ? cat('Encryption in transit and at rest', 'clear', 'Found encryption-related code (hashing, HTTPS enforcement, or similar).', `${enc.file}:${enc.line}`)
    : cat('Encryption in transit and at rest', 'not-determinable', 'No encryption/hashing/TLS-enforcement code was found in source. It may be handled by the platform.');

  // 8. Data in repo metadata - always not-determinable for a shallow scan
  const c8 = cat(
    "Data in the repo's own metadata",
    'not-determinable',
    'This scan clones only the latest commit (--depth 1), so full commit history is not checked for leaked data - only the most recent commit. Issues/PRs and images are not scanned.',
  );

  // 9. Cross-border transfer implied by regions
  const region = findText(REGION);
  const c9 = region
    ? cat('Cross-border transfer implied by hosted dependencies', 'flagged', `Found references to specific cloud regions/hosts in code: ${region.match}. Actual data residency depends on how this is deployed.`, `${region.file}:${region.line}`)
    : cat('Cross-border transfer implied by hosted dependencies', 'clear', 'No specific cloud region/host references were found in source.');

  // 10. Documentation of collection
  const hasPrivacyDoc = files.some((f) => PRIVACY_DOC.test(f.rel));
  const readme = files.find((f) => /(^|\/)README(\.md)?$/i.test(f.rel));
  const readmePrivacy = readme && /#+\s*privacy/i.test(readme.text);
  const c10 = hasPrivacyDoc || readmePrivacy
    ? cat('Documentation of what the code collects', 'clear', 'A privacy policy file or README privacy section was found.', hasPrivacyDoc ? files.find((f) => PRIVACY_DOC.test(f.rel)).rel : readme.rel)
    : cat('Documentation of what the code collects', 'flagged', 'No PRIVACY.md, privacy policy file, or a "Privacy" section in the README was found describing what data this project collects.');

  const categories = [c1, c2, c3, c4, c5, c6, c7, c8, c9, c10];
  const flagged = categories.filter((c) => c.status === 'flagged').length;

  return { findings: [], summary: { categories, flagged, total: categories.length } };
}
