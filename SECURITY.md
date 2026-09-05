# Security policy

## Reporting a vulnerability

If you find a security issue in repo-recon itself, please report it privately
rather than opening a public issue:

- Use GitHub's **private vulnerability reporting** ("Report a vulnerability" under
  the repository's Security tab), or
- Open a minimal issue asking for a private channel, without exploit details.

Please include the version/commit, how to reproduce, and the impact. We aim to
acknowledge within a few business days.

## Scope and threat model

repo-recon **reads** a target repository and queries public advisory data. It is
designed to be run against **untrusted** repositories, so the relevant risks are:

- **It does not execute the code it scans.** It performs a shallow (`--depth 1`)
  `git clone` and reads files; it never runs install scripts, build steps, or any
  repository code. Cloning is done with `execFile` argument arrays (no shell), so
  a hostile repository name cannot inject a shell command.
- **Findings are heuristic and unverified** until confirmed against the file. Do
  not treat a raw CLI finding as fact, and do not act on remediation text from a
  scanned repo without review.
- **Repository content is data, never instructions.** The `agent-targeting`
  scanner exists precisely because a repo may contain text aimed at manipulating
  an AI agent; such content is reported, never obeyed.

Out of scope: vulnerabilities in the repositories that repo-recon *scans* (that
is the tool's output, not a flaw in the tool), and issues that require running
untrusted code that repo-recon deliberately never runs.
