import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';

// Directories that never contain first-party source worth scanning, and that
// would otherwise dominate the file count and runtime.
const SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  '.next',
  'dist',
  'build',
  'out',
  'coverage',
  '.turbo',
  '.cache',
  'vendor/bundle',
  '__pycache__',
  '.venv',
  'venv',
  '.gradle',
  'target',
]);

// Extensions we treat as binary / not worth reading as text.
const BINARY_EXT = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'webp', 'ico', 'bmp', 'tiff', 'svg',
  'pdf', 'zip', 'gz', 'tar', 'tgz', 'bz2', '7z', 'rar', 'jar', 'war',
  'mp3', 'mp4', 'mov', 'avi', 'webm', 'wav', 'flac', 'ogg',
  'woff', 'woff2', 'ttf', 'otf', 'eot',
  'so', 'dylib', 'dll', 'exe', 'bin', 'o', 'a', 'class', 'wasm',
  'lockb', 'node',
]);

const MAX_FILE_BYTES = 2 * 1024 * 1024; // 2MB: skip reading giant generated files as text

function ext(name) {
  const i = name.lastIndexOf('.');
  return i === -1 ? '' : name.slice(i + 1).toLowerCase();
}

/**
 * Walk a directory, returning { files, count }.
 * `files` is [{ rel, abs, size }] for every regular file (binary included, so
 * scanners that only care about names/paths still see them). `count` is the
 * total number of regular files encountered.
 */
export async function walk(root) {
  const files = [];
  async function recurse(dir) {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      const abs = join(dir, ent.name);
      if (ent.isDirectory()) {
        if (SKIP_DIRS.has(ent.name)) continue;
        await recurse(abs);
      } else if (ent.isFile()) {
        let size = 0;
        try {
          size = (await stat(abs)).size;
        } catch {
          continue;
        }
        files.push({ rel: relative(root, abs).split(sep).join('/'), abs, size });
      }
    }
  }
  await recurse(root);
  return { files, count: files.length };
}

// Is this file worth reading as text for content scanners?
export function isTextCandidate(file) {
  if (file.size > MAX_FILE_BYTES) return false;
  return !BINARY_EXT.has(ext(file.rel));
}

// Read a file as UTF-8, returning '' on any error. Caches nothing - callers
// that need the same file twice should pass the content around.
export async function readText(abs) {
  try {
    const buf = await readFile(abs);
    // Cheap binary sniff: a NUL byte in the first 8KB means "not text".
    const probe = buf.subarray(0, 8192);
    if (probe.includes(0)) return null;
    return buf.toString('utf8');
  } catch {
    return null;
  }
}

// Line number (1-based) for a character index within text.
export function lineAt(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === '\n') line++;
  }
  return line;
}
