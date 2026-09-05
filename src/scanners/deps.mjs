import { join } from 'node:path';
import { readFile } from 'node:fs/promises';
import { makeFinding } from '../finding.mjs';
import { cvssToSeverity } from '../severity.mjs';
import { cvssScore } from '../cvss.mjs';

const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN = 'https://api.osv.dev/v1/vulns/';

// Map GitHub's advisory severity words to our bands, used as a fallback when
// no CVSS vector is present on the OSV record.
const GH_SEVERITY = { LOW: 'LOW', MODERATE: 'MEDIUM', MEDIUM: 'MEDIUM', HIGH: 'HIGH', CRITICAL: 'CRITICAL' };

// --- lockfile parsers: return [{ name, version, ecosystem }] ---

function parseNpmLock(text) {
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    return [];
  }
  const out = [];
  const seen = new Set();
  const add = (name, version) => {
    if (!name || !version) return;
    const key = `${name}@${version}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ name, version, ecosystem: 'npm' });
  };
  // lockfileVersion 2/3
  if (json.packages) {
    for (const [path, info] of Object.entries(json.packages)) {
      if (!path) continue; // "" is the root project
      const name = info.name || path.split('node_modules/').pop();
      add(name, info.version);
    }
  }
  // lockfileVersion 1
  const walkDeps = (deps) => {
    for (const [name, info] of Object.entries(deps || {})) {
      add(name, info.version);
      if (info.dependencies) walkDeps(info.dependencies);
    }
  };
  if (json.dependencies) walkDeps(json.dependencies);
  return out;
}

function parseYarnLock(text) {
  const out = [];
  const seen = new Set();
  const blocks = text.split(/\n(?=\S)/);
  for (const block of blocks) {
    const header = block.split('\n')[0];
    const vMatch = block.match(/\n\s+version:?\s+"?([^"\n]+)"?/);
    if (!header || !vMatch) continue;
    const nameMatch = header.match(/^"?(@?[^@"\s]+)@/);
    if (!nameMatch) continue;
    const name = nameMatch[1];
    const version = vMatch[1].trim();
    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ name, version, ecosystem: 'npm' });
  }
  return out;
}

function parseRequirements(text) {
  const out = [];
  for (const line of text.split('\n')) {
    const m = line.match(/^\s*([A-Za-z0-9._-]+)\s*==\s*([0-9][^\s;#]*)/);
    if (m) out.push({ name: m[1], version: m[2], ecosystem: 'PyPI' });
  }
  return out;
}

function parseGoMod(text) {
  const out = [];
  const re = /^\s*([a-z0-9./-]+)\s+v([0-9][^\s]*)/gim;
  let m;
  while ((m = re.exec(text)) != null) {
    out.push({ name: m[1], version: `v${m[2]}`, ecosystem: 'Go' });
  }
  return out;
}

const LOCKFILES = [
  { file: 'package-lock.json', parse: parseNpmLock },
  { file: 'npm-shrinkwrap.json', parse: parseNpmLock },
  { file: 'yarn.lock', parse: parseYarnLock },
  { file: 'pnpm-lock.yaml', parse: parseYarnLock }, // header shape differs; best-effort
  { file: 'requirements.txt', parse: parseRequirements },
  { file: 'go.mod', parse: parseGoMod },
];

async function collectPackages(dir, files) {
  const byRel = new Map(files.map((f) => [f.rel, f]));
  const packages = [];
  for (const lf of LOCKFILES) {
    // match at repo root or one level deep (monorepos)
    const hits = files.filter((f) => f.rel === lf.file || f.rel.endsWith(`/${lf.file}`));
    for (const hit of hits) {
      try {
        const text = await readFile(hit.abs, 'utf8');
        for (const pkg of lf.parse(text)) packages.push({ ...pkg, source: hit.rel });
      } catch {
        /* ignore unreadable lockfile */
      }
    }
  }
  // dedupe by name@version@ecosystem, keep first source
  const seen = new Map();
  for (const p of packages) {
    const key = `${p.ecosystem}|${p.name}|${p.version}`;
    if (!seen.has(key)) seen.set(key, p);
  }
  void byRel;
  return [...seen.values()];
}

function severityOfVuln(vuln) {
  // Prefer a CVSS vector -> numeric score -> band.
  const vec = (vuln.severity || []).find((s) => /CVSS_V3/i.test(s.type))?.score;
  const score = cvssScore(vec);
  if (score != null) return { severity: cvssToSeverity(score), score };
  // Fallback: GitHub database_specific.severity word.
  const word = vuln.database_specific?.severity?.toUpperCase();
  if (word && GH_SEVERITY[word]) return { severity: GH_SEVERITY[word], score: null };
  return { severity: 'MEDIUM', score: null };
}

async function fetchJson(url, opts, timeoutMs = 20000) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...opts, signal: ac.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(t);
  }
}

export async function scan(ctx) {
  const findings = [];
  const packages = await collectPackages(ctx.dir, ctx.files);
  const summary = { packagesChecked: packages.length, vulnerabilities: 0, network: false, error: null };

  if (packages.length === 0) return { findings, summary };
  if (ctx.offline) {
    summary.error = 'offline mode: dependency advisories not checked';
    return { findings, summary };
  }

  // Batch query OSV for vulnerable (package, version) pairs.
  let batch;
  try {
    batch = await fetchJson(OSV_BATCH, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        queries: packages.map((p) => ({
          package: { name: p.name, ecosystem: p.ecosystem },
          version: p.version,
        })),
      }),
    });
    summary.network = true;
  } catch (err) {
    summary.error = `OSV query failed: ${err.message}`;
    return { findings, summary };
  }

  // Collect unique vuln ids and which package each maps to.
  const idToPkgs = new Map();
  batch.results?.forEach((result, i) => {
    const pkg = packages[i];
    for (const v of result?.vulns || []) {
      if (!idToPkgs.has(v.id)) idToPkgs.set(v.id, { id: v.id, pkgs: [] });
      idToPkgs.get(v.id).pkgs.push(pkg);
    }
  });

  // Fetch details for each unique vuln (bounded concurrency).
  const ids = [...idToPkgs.keys()];
  const details = new Map();
  const CONCURRENCY = 8;
  for (let i = 0; i < ids.length; i += CONCURRENCY) {
    const slice = ids.slice(i, i + CONCURRENCY);
    const got = await Promise.all(
      slice.map(async (id) => {
        try {
          return [id, await fetchJson(OSV_VULN + id, {})];
        } catch {
          return [id, null];
        }
      }),
    );
    for (const [id, vuln] of got) if (vuln) details.set(id, vuln);
  }

  for (const [id, { pkgs }] of idToPkgs) {
    const vuln = details.get(id) || { id };
    const { severity } = severityOfVuln(vuln);
    // one finding per (advisory, package) pair, like the report
    const uniquePkgs = new Map(pkgs.map((p) => [`${p.name}@${p.version}`, p]));
    for (const p of uniquePkgs.values()) {
      findings.push(
        makeFinding({
          tool: 'deps',
          severity,
          title: `Vulnerable dependency: ${p.name}@${p.version} (${id})`,
          owasp: 'A06',
          cwe: 'CWE-1104',
          location: { file: p.source, line: null, snippet: `${p.name}@${p.version}` },
          detail:
            (vuln.summary || `Known advisory ${id} affects ${p.name}@${p.version}.`) +
            ` Source: OSV.dev advisory database.`,
          remediation: `Upgrade "${p.name}" to a patched version. See https://osv.dev/vulnerability/${id}`,
        }),
      );
    }
  }

  summary.vulnerabilities = findings.length;
  return { findings, summary };
}
