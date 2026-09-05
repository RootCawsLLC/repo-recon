import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cvssScore } from '../src/cvss.mjs';
import { cvssToSeverity } from '../src/severity.mjs';

test('classic critical vector scores 9.8', () => {
  const s = cvssScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  assert.equal(s, 9.8);
  assert.equal(cvssToSeverity(s), 'CRITICAL');
});

test('a lower-impact vector bands below high', () => {
  const s = cvssScore('CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N');
  assert.ok(s < 7.0, `expected < 7, got ${s}`);
});

test('incomplete or junk vector returns null', () => {
  assert.equal(cvssScore('CVSS:3.1/AV:N/AC:L'), null);
  assert.equal(cvssScore('not-a-vector'), null);
  assert.equal(cvssScore(null), null);
});
