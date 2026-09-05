// Minimal GitHub REST helper. Unauthenticated by default (60 req/hr/IP, plenty
// for a single scan); honours a token from the environment when present to
// raise the limit. Never throws for a normal "missing repo / rate limited" -
// returns null so the scanner can degrade gracefully.

const API = 'https://api.github.com';

export function githubToken() {
  return process.env.REPO_RECON_GITHUB_TOKEN || process.env.GITHUB_TOKEN || process.env.GH_TOKEN || null;
}

export async function ghFetch(path, { token = githubToken(), timeoutMs = 15000 } = {}) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const headers = {
      accept: 'application/vnd.github+json',
      'user-agent': 'repo-recon',
      'x-github-api-version': '2022-11-28',
    };
    if (token) headers.authorization = `Bearer ${token}`;
    const res = await fetch(`${API}${path}`, { headers, signal: ac.signal });
    if (res.status === 404) return { ok: false, status: 404, data: null };
    if (res.status === 403 && res.headers.get('x-ratelimit-remaining') === '0') {
      return { ok: false, status: 403, data: null, rateLimited: true };
    }
    if (!res.ok) return { ok: false, status: res.status, data: null };
    return { ok: true, status: res.status, data: await res.json() };
  } catch (err) {
    return { ok: false, status: 0, data: null, error: err.message };
  } finally {
    clearTimeout(t);
  }
}
