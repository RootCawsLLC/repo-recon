import { test } from 'node:test';
import assert from 'node:assert/strict';
import { grade } from '../src/grade.mjs';

const f = (severity, contextOnly = false) => ({ severity, contextOnly });

test('a clean scan grades A / 100', () => {
  const g = grade([]);
  assert.equal(g.score, 100);
  assert.equal(g.letter, 'A');
});

test('any CRITICAL forces an F, no matter what', () => {
  const g = grade([f('CRITICAL')]);
  assert.equal(g.letter, 'F');
  assert.ok(g.score <= 39);
});

test('a single HIGH caps the grade at D or below', () => {
  const g = grade([f('HIGH')]);
  assert.ok(g.score <= 59, `expected <= 59, got ${g.score}`);
  assert.ok(['D', 'F'].includes(g.letter));
});

test('context-only findings do not lower the grade', () => {
  const g = grade([f('INFO', true), f('HIGH', true)]);
  assert.equal(g.score, 100);
  assert.equal(g.letter, 'A');
});

test('many findings drive the score toward 0', () => {
  const findings = [f('CRITICAL'), f('CRITICAL'), ...Array(14).fill(f('HIGH')), ...Array(15).fill(f('MEDIUM'))];
  const g = grade(findings);
  assert.equal(g.letter, 'F');
  assert.equal(g.score, 0);
});
