import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { scanRepo } from '../src/index.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(here, 'fixtures', 'vuln-repo');

let report;
test('scan the fixture repo offline', async () => {
  report = await scanRepo(FIXTURE, { offline: true });
  assert.ok(report, 'report produced');
});

test('planted hardcoded secret is found', () => {
  const hit = report.findings.find((f) => f.tool === 'secrets');
  assert.ok(hit, 'expected a secrets finding');
});

test('curl | bash pattern is found as HIGH', () => {
  const hit = report.findings.find((f) => f.tool === 'heuristics' && /piped straight into a shell/i.test(f.title));
  assert.ok(hit, 'expected a pipe-to-shell finding');
  assert.equal(hit.severity, 'HIGH');
});

test('risky postinstall hook is found', () => {
  const hit = report.findings.find((f) => f.tool === 'heuristics' && /Install-time script/i.test(f.title));
  assert.ok(hit, 'expected a risky install-hook finding');
});

test('typosquat "reactt" is flagged', () => {
  const hit = report.findings.find((f) => /typosquat/i.test(f.title) && /reactt/.test(f.location.snippet || ''));
  assert.ok(hit, 'expected a typosquat finding for reactt');
});

test('prompt-injection phrasing in README is flagged', () => {
  const hit = report.findings.find((f) => f.tool === 'agent-targeting');
  assert.ok(hit, 'expected an agent-targeting finding');
  assert.equal(hit.severity, 'HIGH');
});

test('privacy scan flags fixtures-PII and missing privacy doc', () => {
  const pv = report.scanners.privacy;
  assert.ok(pv.flagged >= 3, `expected >=3 privacy flags, got ${pv.flagged}`);
  const pii = pv.categories.find((c) => /fixtures\/seeds/i.test(c.category));
  assert.equal(pii.status, 'flagged');
});

test('offline dep-check degrades gracefully', () => {
  assert.match(report.scanners['dep-check'].error || '', /offline/i);
});

test('overall grade is risky (D) or worse for this repo', () => {
  assert.ok(['D', 'F'].includes(report.grade.letter), `expected D or F, got ${report.grade.letter}`);
});

test('raw findings are unverified until the skill confirms them', () => {
  assert.ok(report.findings.every((f) => f.verified === false));
});
