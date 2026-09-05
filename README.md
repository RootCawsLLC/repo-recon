# repo-recon

[![CI](https://github.com/RootCawsLLC/repo-recon/actions/workflows/ci.yml/badge.svg)](https://github.com/RootCawsLLC/repo-recon/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**Reconnaissance on a Git repository before you trust it.**

`repo-recon` clones a repository (or reads a local checkout), runs seven scanners,
and emits a graded safety report: secrets, vulnerable dependencies, malicious-code
heuristics, author/repo due-diligence, privacy posture, and AI-agent-targeting
content — each finding tagged with an OWASP category and a CWE, with a concrete
remediation.

It is designed to run two ways:

1. **As a CLI** — a fast, self-contained first pass. No heavy binaries to install;
   it hits the public [OSV.dev](https://osv.dev) advisory database and the GitHub
   REST API directly.
2. **As a Claude Code skill** — the CLI produces raw findings; the skill opens each
   flagged file, verifies the finding against the real source (downgrading false
   positives the way a human reviewer would), and writes a tiered
   *Everyone / GRC / Developer* report. It also works as a **pre-deploy gate** on
   your own repo.

> Raw CLI output is deliberately **un-verified**: every finding carries
> `verified: false` until the review layer confirms it against the file. A grep
> sees a `password = "..."` line; only a reviewer knows whether it is a live
> credential or a local dev default.

## Install

```bash
git clone https://github.com/RootCawsLLC/repo-recon
cd repo-recon
node --test                      # optional: run the suite
```

Requires Node ≥ 20. No `npm install` needed — the tool has no runtime dependencies.

## Usage

```bash
# scan a remote repo
node bin/repo-recon.mjs https://github.com/owner/repo

# scan a local checkout (e.g. your own repo before deploying)
node bin/repo-recon.mjs .

# machine-readable output for the skill / CI
node bin/repo-recon.mjs owner/repo --format json --out report.json

# the full tiered report
node bin/repo-recon.mjs owner/repo --format markdown --out report.md

# offline: skip the network scanners (OSV.dev, GitHub API)
node bin/repo-recon.mjs . --offline
```

### CI gating

```bash
# fail the build if the grade drops below 60, or any HIGH+ finding appears
node bin/repo-recon.mjs . --fail-under 60
node bin/repo-recon.mjs . --fail-on HIGH
```

Exit codes: `0` clean · `2` scan error · `3` gate threshold breached.

Set `GITHUB_TOKEN` (or `REPO_RECON_GITHUB_TOKEN`) to raise the GitHub API rate limit.

## What it checks

| Scanner | Looks for | OWASP |
| --- | --- | --- |
| `secrets` | hardcoded credentials — AWS/GitHub/Slack/Stripe/Google keys, private-key blocks, JWTs, `secret = "literal"` assignments | A02 |
| `dep-check` | known-vulnerable dependency versions, via the OSV.dev advisory DB (npm, PyPI, Go), **enriched with CISA KEV** (known-exploited → escalated to CRITICAL, tagged `[KEV]`) and **EPSS** (30-day exploitation probability) | A06 |
| `heuristics` | `curl \| bash`, `eval(atob(...))`, remote `require()`, install-time scripts that fetch/exec, `pull_request_target` + secrets, cloud-credential file reads, cryptominer strings, typosquatted deps | A08 |
| `infra` | container & IaC misconfigs — unpinned/`:latest` base images, containers running as root, `ADD <url>`, secrets baked into image layers, privileged compose services, mounted docker socket, public RDS, public S3 ACLs, `0.0.0.0/0` security groups, `Action:"*"` IAM | A05 |
| `author-check` | repo age, stars/forks, license, owner account age and track record | A08 |
| `issues-check` | open issues whose titles read like unresolved security/data reports | — |
| `privacy` | 10 data-handling categories — PII in fixtures, personal data in logs, telemetry SDKs, outbound calls, disk/browser writes, retention/deletion, encryption, cross-border regions, privacy docs | A09 |
| `agent-targeting` | prompt-injection phrasing aimed at an AI agent, hidden/invisible Unicode (zero-width, bidi, Unicode-Tag), MCP configs pointing at untrusted remote endpoints | A03 |

## Grading

Score starts at 100 and is reduced per finding (weighted by severity). The band a
finding falls in also **caps** the maximum grade, so an open issue can never be
hidden by an otherwise-clean repo:

| Grade | Score | Meaning | Cap trigger |
| --- | --- | --- | --- |
| A | 90–100 | Looks safe to use | — |
| B | 75–89 | Mostly safe, minor notes | — |
| C | 60–74 | Use with caution | — |
| D | 40–59 | Risky — proceed carefully | any **HIGH** |
| F | 0–39 | Not recommended right now | any **CRITICAL** |

Context-only findings (repo age, privacy notes) are reported but do not lower the score.

## Limitations

- A shallow (`--depth 1`) clone: full commit history is not scanned for leaked data.
- A static scan sees sinks, not always sources. For taint-sensitive classes (raw
  SQL, XSS, `exec`, LLM output) pair it with Semgrep or CodeQL before trusting a pass.
- The dependency scanner reads lockfiles; a repo with no lockfile has no resolved
  versions to check.
- Findings are heuristic until verified. Run through the skill (or review by hand)
  before acting on any single one.

## Prior art

`repo-recon` orchestrates commodity scanning primitives into one verified, tiered
report — the part that no single tool bundles. For the individual jobs, mature
tools exist and are worth knowing:
[OpenSSF Scorecard](https://github.com/ossf/scorecard) (repo hygiene),
[OSV-Scanner](https://github.com/google/osv-scanner) (dependencies),
[TruffleHog](https://github.com/trufflesecurity/trufflehog) / Gitleaks (secrets),
[Semgrep](https://semgrep.dev) (SAST),
[Snyk agent-scan](https://github.com/snyk/agent-scan) (AI-agent threats).

## License

Apache-2.0 © RootCawsLLC
