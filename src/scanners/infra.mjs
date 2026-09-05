import { makeFinding } from '../finding.mjs';
import { lineAt } from '../walk.mjs';

// Container & infrastructure-as-code misconfigurations. Mirrors the manual
// review a careful reader does on a Dockerfile / compose file / Terraform before
// running or deploying an unfamiliar repo: does the container run as root, are
// base images pinned, is anything exposed to the whole internet, is the cloud
// storage public. High-precision, line-anchored checks.

const isDockerfile = (rel) => /(^|\/)Dockerfile(\.[\w.-]+)?$/i.test(rel) || /\.dockerfile$/i.test(rel);
const isCompose = (rel) => /(^|\/)(docker-)?compose(\.[\w.-]+)?\.ya?ml$/i.test(rel);
const isTerraform = (rel) => /\.tf$/i.test(rel);

function lines(text) {
  return text.split('\n');
}

function scanDockerfile(file, push) {
  const ls = lines(file.text);
  const stageNames = new Set();
  let hasNonRootUser = false;
  let sawFrom = false;

  // First pass: collect build-stage names so `FROM builder` isn't "unpinned".
  for (const l of ls) {
    const m = l.match(/^\s*FROM\s+\S+\s+AS\s+([\w.-]+)/i);
    if (m) stageNames.add(m[1].toLowerCase());
  }

  ls.forEach((l, i) => {
    const line = i + 1;
    const from = l.match(/^\s*FROM\s+(--platform=\S+\s+)?(\S+)/i);
    if (from) {
      sawFrom = true;
      const ref = from[2];
      if (stageNames.has(ref.toLowerCase())) return; // referencing a prior stage
      const pinned = /@sha256:[0-9a-f]{64}/i.test(ref);
      const tagged = ref.includes(':') && !ref.endsWith(':latest');
      if (!pinned && (!tagged || ref.endsWith(':latest'))) {
        push({
          severity: 'MEDIUM',
          title: `Unpinned container base image: ${ref}`,
          owasp: 'A06',
          cwe: 'CWE-1104',
          line,
          snippet: l.trim().slice(0, 100),
          detail:
            'The base image is untagged or uses :latest, so the build is not reproducible and can silently pull a changed (or compromised) image.',
          remediation: 'Pin the base image to a specific version tag and ideally a @sha256 digest.',
        });
      }
    }
    const user = l.match(/^\s*USER\s+([\w.$-]+)/i);
    if (user) {
      const u = user[1].toLowerCase();
      if (u !== 'root' && u !== '0') hasNonRootUser = true;
    }
    if (/^\s*ADD\s+https?:\/\//i.test(l)) {
      push({
        severity: 'MEDIUM',
        title: 'Dockerfile ADD fetches a remote URL',
        owasp: 'A08',
        cwe: 'CWE-494',
        line,
        snippet: l.trim().slice(0, 100),
        detail: 'ADD with a URL downloads remote content into the image at build time, unverified and mutable.',
        remediation: 'Download explicitly, verify a checksum, then COPY it in - or use a pinned package instead of ADD <url>.',
      });
    }
    const envSecret = l.match(/^\s*(ENV|ARG)\s+([\w.]*(?:PASSWORD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY)[\w.]*)\s*[= ]\s*(\S+)/i);
    if (envSecret && !/^\$\{?/.test(envSecret[3]) && !/^["']?(changeme|example|xxx|<)/i.test(envSecret[3])) {
      push({
        severity: 'MEDIUM',
        title: `Secret-shaped ${envSecret[1].toUpperCase()} in Dockerfile: ${envSecret[2]}`,
        owasp: 'A02',
        cwe: 'CWE-798',
        line,
        snippet: `${envSecret[1]} ${envSecret[2]}=***`,
        detail: 'A secret-shaped build ARG/ENV is baked into the image, where it persists in image layers and history.',
        remediation: 'Pass secrets at runtime (env/secret manager) or use BuildKit secret mounts; never bake them into layers.',
      });
    }
  });

  // "Runs as root" - only meaningful if the file actually builds a runnable image.
  if (sawFrom && !hasNonRootUser) {
    push({
      severity: 'MEDIUM',
      title: 'Container image runs as root (no non-root USER)',
      owasp: 'A05',
      cwe: 'CWE-250',
      line: null,
      snippet: file.rel,
      detail: 'No USER instruction drops privileges, so the container process runs as root. A container escape or app compromise then has root in the container.',
      remediation: 'Add a non-root USER (create a dedicated user/group and switch to it before the entrypoint).',
    });
  }
}

const COMPOSE_PATTERNS = [
  {
    re: /privileged:\s*true/i,
    severity: 'HIGH',
    owasp: 'A05',
    cwe: 'CWE-250',
    title: 'Compose service runs privileged',
    detail: 'A privileged container has near-host capabilities; a compromise is effectively a host compromise.',
    remediation: 'Remove privileged: true; grant only the specific capabilities the service needs.',
  },
  {
    re: /\/var\/run\/docker\.sock/i,
    severity: 'HIGH',
    owasp: 'A05',
    cwe: 'CWE-250',
    title: 'Docker socket mounted into a container',
    detail: 'Mounting /var/run/docker.sock gives the container full control of the Docker daemon - equivalent to root on the host.',
    remediation: 'Avoid mounting the docker socket. If unavoidable, use a hardened socket proxy with a minimal allowlist.',
  },
  {
    re: /network_mode:\s*["']?host/i,
    severity: 'MEDIUM',
    owasp: 'A05',
    cwe: 'CWE-16',
    title: 'Compose service uses host networking',
    detail: 'host networking removes network isolation between the container and the host.',
    remediation: 'Use the default bridge network and publish only the ports you need.',
  },
];

const TF_PATTERNS = [
  {
    re: /publicly_accessible\s*=\s*true/i,
    severity: 'HIGH',
    owasp: 'A05',
    cwe: 'CWE-1188',
    title: 'RDS/instance is publicly accessible',
    detail: 'publicly_accessible = true puts the database on a public endpoint reachable from the internet.',
    remediation: 'Set publicly_accessible = false and reach it through a private subnet / bastion / VPC peering.',
  },
  {
    re: /acl\s*=\s*"public-read(-write)?"/i,
    severity: 'HIGH',
    owasp: 'A05',
    cwe: 'CWE-732',
    title: 'S3 bucket ACL is public',
    detail: 'A public-read(-write) ACL exposes bucket objects (or lets anyone write) to the internet.',
    remediation: 'Remove the public ACL; use a bucket policy scoped to specific principals and enable Block Public Access.',
  },
  {
    re: /block_public_acls\s*=\s*false|ignore_public_acls\s*=\s*false|restrict_public_buckets\s*=\s*false/i,
    severity: 'MEDIUM',
    owasp: 'A05',
    cwe: 'CWE-732',
    title: 'S3 Block Public Access is disabled',
    detail: 'A Block Public Access control is turned off, allowing a bucket or object to become public.',
    remediation: 'Leave all four Block Public Access settings enabled unless a specific, reviewed reason requires otherwise.',
  },
  {
    re: /"Action"\s*[:=]\s*"\*"|Action\s*=\s*\[?\s*"\*"/i,
    severity: 'MEDIUM',
    owasp: 'A05',
    cwe: 'CWE-732',
    title: 'IAM policy allows all actions ("*")',
    detail: 'An IAM statement grants Action "*" - far broader than least privilege.',
    remediation: 'Scope the policy to the specific actions (and resources) the principal needs.',
  },
  {
    re: /cidr_blocks\s*=\s*\[?\s*"0\.0\.0\.0\/0"/i,
    severity: 'MEDIUM',
    owasp: 'A05',
    cwe: 'CWE-284',
    title: 'Security group open to the entire internet (0.0.0.0/0)',
    detail: 'An ingress rule allows 0.0.0.0/0. If it fronts SSH/RDP/a database port, the service is exposed to the whole internet.',
    remediation: 'Restrict the CIDR to known ranges; never expose management or database ports to 0.0.0.0/0.',
  },
];

function scanPatterns(file, patterns, tool, push) {
  const ls = lines(file.text);
  for (const p of patterns) {
    const seen = new Set();
    ls.forEach((l, i) => {
      if (!p.re.test(l)) return;
      const line = i + 1;
      if (seen.has(line)) return;
      seen.add(line);
      push({
        severity: p.severity,
        title: p.title,
        owasp: p.owasp,
        cwe: p.cwe,
        line,
        snippet: l.trim().slice(0, 100),
        detail: p.detail,
        remediation: p.remediation,
      });
    });
  }
}

export async function scan(ctx) {
  const findings = [];
  let dockerfiles = 0;
  let composeFiles = 0;
  let tfFiles = 0;

  for (const file of ctx.textFiles) {
    const push = (f) =>
      findings.push(
        makeFinding({
          tool: 'infra',
          severity: f.severity,
          title: f.title,
          owasp: f.owasp,
          cwe: f.cwe,
          location: { file: file.rel, line: f.line ?? null, snippet: f.snippet },
          detail: f.detail,
          remediation: f.remediation,
        }),
      );

    if (isDockerfile(file.rel)) {
      dockerfiles++;
      scanDockerfile(file, push);
    } else if (isCompose(file.rel)) {
      composeFiles++;
      scanPatterns(file, COMPOSE_PATTERNS, 'infra', push);
    } else if (isTerraform(file.rel)) {
      tfFiles++;
      scanPatterns(file, TF_PATTERNS, 'infra', push);
    }
  }

  return { findings, summary: { dockerfiles, composeFiles, terraformFiles: tfFiles } };
}
