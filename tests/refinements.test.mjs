import { test } from 'node:test';
import assert from 'node:assert/strict';

import * as infra from '../src/scanners/infra.mjs';
import * as keyscan from '../src/scanners/keyscan.mjs';
import * as agent from '../src/scanners/agent.mjs';

function ctxWith(files) {
  const textFiles = files.map(([rel, text]) => ({ rel, abs: rel, size: text.length, text }));
  return { textFiles, files: textFiles, dir: '.', ref: null, offline: true };
}

const sg = (port) => `resource "aws_security_group" "x" {
  ingress {
    protocol    = "tcp"
    from_port   = ${port}
    to_port     = ${port}
    cidr_blocks = ["0.0.0.0/0"]
  }
}`;

test('0.0.0.0/0 on port 443 is INFO/context-only (public web is expected)', async () => {
  const { findings } = await infra.scan(ctxWith([['main.tf', sg(443)]]));
  const f = findings.find((x) => /0\.0\.0\.0\/0/.test(x.title));
  assert.ok(f, 'expected a SG finding');
  assert.equal(f.severity, 'INFO');
  assert.equal(f.contextOnly, true);
});

test('0.0.0.0/0 on port 22 is HIGH (management port)', async () => {
  const { findings } = await infra.scan(ctxWith([['main.tf', sg(22)]]));
  const f = findings.find((x) => /0\.0\.0\.0\/0/.test(x.title));
  assert.ok(f && f.severity === 'HIGH', `expected HIGH, got ${f?.severity}`);
});

test('adjacent ingress blocks attribute the right port to each 0.0.0.0/0', async () => {
  const tf = `resource "aws_security_group" "x" {
  ingress {
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}`;
  const { findings } = await infra.scan(ctxWith([['main.tf', tf]]));
  const sgs = findings.filter((f) => /0\.0\.0\.0\/0/.test(f.title));
  assert.ok(sgs.some((f) => f.severity === 'INFO' && /443/.test(f.title)), 'expected 443 -> INFO');
  assert.ok(sgs.some((f) => f.severity === 'HIGH'), 'expected 22 -> HIGH');
});

test('IAM Action "*" with a Condition is downgraded to context-only', async () => {
  const tf = `resource "aws_iam_policy" "p" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*",
      Condition = { StringEquals = { "aws:PrincipalTag/break-glass" = "true" } } }]
  })
}`;
  const { findings } = await infra.scan(ctxWith([['iam.tf', tf]]));
  const f = findings.find((x) => /allows all actions/i.test(x.title));
  assert.ok(f, 'expected an IAM finding');
  assert.equal(f.contextOnly, true);
  assert.match(f.title, /condition-gated/i);
});

test('IAM Action "*" without a Condition stays MEDIUM', async () => {
  const tf = `resource "aws_iam_policy" "p" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
}`;
  const { findings } = await infra.scan(ctxWith([['iam.tf', tf]]));
  const f = findings.find((x) => /allows all actions/i.test(x.title));
  assert.ok(f && f.severity === 'MEDIUM' && !f.contextOnly);
});

test('the canonical AWS example key is not flagged', async () => {
  const src = `const id = "AKIAIOSFODNN7EXAMPLE";\nconst secret = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY";`;
  const { findings } = await keyscan.scan(ctxWith([['t.mjs', src]]));
  assert.equal(findings.length, 0, `expected no findings, got ${findings.map((f) => f.title)}`);
});

test('a real (non-EXAMPLE) AWS key id is still flagged', async () => {
  const src = `const id = "AKIA1234567890ABCDEF";`;
  const { findings } = await keyscan.scan(ctxWith([['t.mjs', src]]));
  assert.ok(findings.some((f) => /AWS access key id/.test(f.title)));
});

test('a lone leading BOM is not flagged', async () => {
  const text = String.fromCodePoint(0xfeff) + 'supplier_id,name\nS1,Acme\n';
  const { findings } = await agent.scan(ctxWith([['data.csv', text]]));
  assert.equal(findings.filter((f) => /BOM|invisible/i.test(f.title)).length, 0);
});

test('a mid-file BOM is LOW, not HIGH', async () => {
  const text = 'const clean = text.replace(/^' + String.fromCodePoint(0xfeff) + "/, '');";
  const { findings } = await agent.scan(ctxWith([['csv.mjs', text]]));
  const f = findings.find((x) => /BOM/i.test(x.title));
  assert.ok(f && f.severity === 'LOW', `expected LOW BOM finding, got ${f?.severity}`);
});

test('a zero-width space is still HIGH', async () => {
  const text = 'hello' + String.fromCodePoint(0x200b) + 'world';
  const { findings } = await agent.scan(ctxWith([['readme.md', text]]));
  const f = findings.find((x) => /invisible Unicode/i.test(x.title));
  assert.ok(f && f.severity === 'HIGH');
});
