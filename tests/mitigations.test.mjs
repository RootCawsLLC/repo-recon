import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import * as code from '../src/scanners/code.mjs';
import * as history from '../src/scanners/history.mjs';

const exec = promisify(execFile);

function ctxWith(files, extra = {}) {
  const textFiles = files.map(([rel, text]) => ({ rel, abs: rel, size: text.length, text }));
  return { textFiles, files: textFiles, dir: '.', ref: null, offline: true, ...extra };
}

// ---- code scanner (limitation: sinks, not sources) ----

test('code scanner flags eval / exec / innerHTML / dangerouslySetInnerHTML / raw SQL', async () => {
  const src = [
    'const x = eval(userInput);',
    'exec(`rm -rf ${dir}`);',
    'el.innerHTML = untrusted;',
    'return <div dangerouslySetInnerHTML={{ __html: body }} />;',
    'db.$queryRawUnsafe("SELECT * FROM u WHERE id = " + id);',
    'const q = `SELECT * FROM t WHERE name = ${name}`;',
  ].join('\n');
  const { findings } = await code.scan(ctxWith([['h.tsx', src]]));
  const cwes = new Set(findings.map((f) => f.cwe));
  assert.ok(cwes.has('CWE-95'), 'eval');
  assert.ok(cwes.has('CWE-78'), 'exec');
  assert.ok(cwes.has('CWE-79'), 'xss');
  assert.ok(cwes.has('CWE-89'), 'sql');
  assert.ok(findings.every((f) => f.confidence === 'medium'));
});

test('code scanner does not flag safe literals / parameterized queries', async () => {
  const src = [
    "const x = eval('1 + 1');", // literal
    "el.innerHTML = '';", // literal
    'db.$queryRaw`SELECT * FROM u WHERE id = ${id}`;', // Prisma tagged template is safe
    'execFile("ls", ["-la"]);', // arg array, no shell
  ].join('\n');
  const { findings } = await code.scan(ctxWith([['safe.ts', src]]));
  assert.equal(findings.length, 0, `expected no findings, got ${findings.map((f) => f.title)}`);
});

test('code scanner ignores non-code files', async () => {
  const { findings } = await code.scan(ctxWith([['README.md', 'run eval(x) in your head']]));
  assert.equal(findings.length, 0);
});

// ---- history scanner (limitation: shallow clone misses history) ----

test('history scanner finds a secret that was committed then deleted', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'recon-hist-'));
  try {
    await exec('git', ['-C', dir, 'init', '-q']);
    await exec('git', ['-C', dir, 'config', 'user.email', 't@example.com']);
    await exec('git', ['-C', dir, 'config', 'user.name', 'Test']);
    // commit a real-format (non-EXAMPLE) AWS key, then remove it
    await writeFile(join(dir, 'config.js'), 'const k = "AKIA1234567890ABCDEF";\n');
    await exec('git', ['-C', dir, 'add', '-A']);
    await exec('git', ['-C', dir, 'commit', '-q', '-m', 'add key']);
    await writeFile(join(dir, 'config.js'), 'const k = process.env.AWS_KEY;\n');
    await exec('git', ['-C', dir, 'add', '-A']);
    await exec('git', ['-C', dir, 'commit', '-q', '-m', 'remove key']);

    const { findings, summary } = await history.scan({ dir, history: true });
    assert.equal(summary.scanned, true);
    assert.ok(
      findings.some((f) => f.tool === 'secrets-history' && /AWS access key id/i.test(f.title)),
      'expected the historical AWS key to be found',
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('history scanner is a no-op unless requested', async () => {
  const { findings, summary } = await history.scan({ dir: '.', history: false });
  assert.equal(findings.length, 0);
  assert.equal(summary.scanned, false);
});
