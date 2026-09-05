import { makeFinding } from '../finding.mjs';
import { lineAt } from '../walk.mjs';

// Content patterns that, when present, warrant a hard look. Each is written to
// favour precision over recall - the goal is few, real, explainable hits.
const PATTERNS = [
  {
    key: 'pipe-to-shell',
    re: /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|k)?sh\b/gi,
    severity: 'HIGH',
    owasp: 'A08',
    cwe: 'CWE-494',
    title: 'Remote script piped straight into a shell',
    detail:
      'Code downloads a script and executes it in one step (curl | bash). Whatever the remote server returns runs with the current user\'s privileges, and the content can change after review.',
    remediation: 'Download to a file, inspect it, pin it by checksum, then run it - never pipe a live URL into a shell.',
  },
  {
    key: 'eval-decoded',
    re: /\beval\s*\(\s*(atob|Buffer\.from|decodeURIComponent|unescape)\s*\(/gi,
    severity: 'HIGH',
    owasp: 'A08',
    cwe: 'CWE-95',
    title: 'Obfuscated code: eval of a decoded string',
    detail:
      'Source evaluates a decoded/deobfuscated string at runtime. This is a common way to hide what code actually does from a reviewer.',
    remediation: 'Decode the payload and review what it does. Legitimate code rarely needs to eval a base64/URI-decoded blob.',
  },
  {
    key: 'remote-require',
    re: /\b(require|import)\s*\(\s*[`'"]https?:\/\//gi,
    severity: 'HIGH',
    owasp: 'A08',
    cwe: 'CWE-829',
    title: 'Code loaded from a remote URL at runtime',
    detail: 'A module is imported/required directly from a remote URL, so the executed code is whatever that server serves at run time.',
    remediation: 'Vendor the dependency and pin it, or install it through the package manager with an integrity hash.',
  },
  {
    key: 'read-cloud-creds',
    re: /(\.ssh\/(id_rsa|id_ed25519|id_dsa|authorized_keys)|\.aws\/credentials|\.aws\/config|\.netrc|\.docker\/config\.json|\.kube\/config)\b/gi,
    severity: 'MEDIUM',
    owasp: 'A08',
    cwe: 'CWE-522',
    title: 'Reference to on-disk SSH / cloud credential files',
    detail:
      'The code references files where SSH keys or cloud credentials normally live. Benign tooling sometimes does this, but it is also how credential-stealers find keys.',
    remediation: 'Confirm why the code reads these paths and that it does not exfiltrate their contents.',
  },
  {
    key: 'cryptomining',
    re: /\b(stratum\+tcp:|xmrig|coinhive|cryptonight|minergate|nicehash|coin-?hive)\b/gi,
    severity: 'HIGH',
    owasp: 'A08',
    cwe: 'CWE-506',
    title: 'Cryptomining indicator',
    detail: 'A string associated with cryptocurrency mining pools or miners appears in the source.',
    remediation: 'Investigate - legitimate application code does not usually reference mining pools or miner binaries.',
  },
];

// package.json install-lifecycle scripts that reach out or execute code are a
// classic supply-chain vector (they run automatically on `npm install`).
const RISKY_SCRIPT_HOOK = /^(pre|post)?install$/;
const RISKY_SCRIPT_BODY = /\b(curl|wget|node\s+-e|eval|base64\s+-d|python\s+-c|powershell|iwr|invoke-expression)\b/i;

// A small set of very-popular npm names to catch obvious typosquats (edit
// distance 1). Not exhaustive - a signal, not a verdict.
const POPULAR = [
  'react', 'react-dom', 'lodash', 'axios', 'express', 'chalk', 'commander',
  'debug', 'next', 'vue', 'webpack', 'dotenv', 'moment', 'uuid', 'jest',
  'typescript', 'eslint', 'prettier', 'nanoid', 'zod', 'prisma',
];

function editDistance1(a, b) {
  if (Math.abs(a.length - b.length) > 1) return false;
  if (a === b) return false;
  let i = 0;
  let j = 0;
  let diff = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      i++;
      j++;
      continue;
    }
    if (++diff > 1) return false;
    if (a.length > b.length) i++;
    else if (a.length < b.length) j++;
    else {
      i++;
      j++;
    }
  }
  if (i < a.length || j < b.length) diff++;
  return diff === 1;
}

function isWorkflow(rel) {
  return /^\.github\/workflows\/.+\.ya?ml$/.test(rel) || /\.github\/workflows\//.test(rel);
}

export async function scan(ctx) {
  const findings = [];

  for (const file of ctx.textFiles) {
    const text = file.text;

    for (const p of PATTERNS) {
      p.re.lastIndex = 0;
      let m;
      let hits = 0;
      while ((m = p.re.exec(text)) != null && hits < 20) {
        hits++;
        findings.push(
          makeFinding({
            tool: 'heuristics',
            severity: p.severity,
            title: p.title,
            owasp: p.owasp,
            cwe: p.cwe,
            location: { file: file.rel, line: lineAt(text, m.index), snippet: m[0].slice(0, 120) },
            detail: p.detail,
            remediation: p.remediation,
          }),
        );
      }
    }

    // pull_request_target + secrets exposure in a workflow file
    if (isWorkflow(file.rel) && /pull_request_target/.test(text) && /\bsecrets\./.test(text)) {
      findings.push(
        makeFinding({
          tool: 'heuristics',
          severity: 'HIGH',
          title: 'Workflow uses pull_request_target with access to secrets',
          owasp: 'A08',
          cwe: 'CWE-829',
          location: { file: file.rel, line: lineAt(text, text.indexOf('pull_request_target')), snippet: 'pull_request_target + secrets.*' },
          detail:
            'A pull_request_target workflow runs with repository secrets available while checking out untrusted PR code. A malicious PR can exfiltrate those secrets.',
          remediation:
            'Do not check out or run untrusted PR code in a pull_request_target job that has secrets. Split trusted and untrusted steps, or use pull_request without secrets.',
        }),
      );
    }
  }

  // package.json: risky install hooks + typosquat check
  const pkgFile = ctx.textFiles.find((f) => f.rel === 'package.json' || f.rel.endsWith('/package.json'));
  if (pkgFile) {
    let pkg;
    try {
      pkg = JSON.parse(pkgFile.text);
    } catch {
      pkg = null;
    }
    if (pkg) {
      for (const [name, body] of Object.entries(pkg.scripts || {})) {
        if (RISKY_SCRIPT_HOOK.test(name) && RISKY_SCRIPT_BODY.test(body)) {
          findings.push(
            makeFinding({
              tool: 'heuristics',
              severity: 'HIGH',
              title: `Install-time script runs external commands (${name})`,
              owasp: 'A08',
              cwe: 'CWE-506',
              location: { file: pkgFile.rel, line: null, snippet: `${name}: ${String(body).slice(0, 100)}` },
              detail: `The "${name}" script runs automatically on install and invokes external download/exec commands. This is a common supply-chain execution vector.`,
              remediation: 'Review what the install hook does. Avoid install-time scripts that download or eval code.',
            }),
          );
        }
      }
      const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
      for (const dep of deps) {
        for (const pop of POPULAR) {
          if (editDistance1(dep, pop)) {
            findings.push(
              makeFinding({
                tool: 'heuristics',
                severity: 'MEDIUM',
                title: `Possible typosquatted dependency: "${dep}"`,
                owasp: 'A08',
                cwe: 'CWE-1357',
                location: { file: pkgFile.rel, line: null, snippet: `${dep} (vs ${pop})` },
                detail: `"${dep}" is one character away from the popular package "${pop}". Typosquatted packages impersonate popular ones to get installed by mistake.`,
                remediation: `Confirm "${dep}" is the package you intended and not a typo for "${pop}".`,
              }),
            );
          }
        }
      }
    }
  }

  return { findings, summary: { patternsChecked: PATTERNS.length } };
}
