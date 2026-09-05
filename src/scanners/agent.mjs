import { makeFinding } from '../finding.mjs';
import { lineAt } from '../walk.mjs';

// Phrasing that reads like an instruction aimed at an AI/assistant/agent rather
// than at a human reader - the signature of a prompt-injection payload planted
// in a README, doc, comment, or tool description.
const INJECTION = [
  /\bignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)/i,
  /\bdisregard\s+(the\s+|all\s+|any\s+)?(previous|prior|above|system|earlier)\b/i,
  /\bdo\s+not\s+(tell|inform|alert|warn|reveal\s+to)\s+the\s+(user|human|operator)/i,
  /\b(reveal|print|repeat|disclose|output)\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?)/i,
  /\byou\s+are\s+(now\s+)?(an?\s+)?(ai|assistant|language\s+model|agent|chatbot)\b.{0,40}\b(must|should|will|comply|obey)/i,
  /\bas\s+an\s+ai\b.{0,30}\byou\s+(must|should|will)\b/i,
  /\bnew\s+instructions?\s*[:：]/i,
  /\boverride\s+(your|the|all)\s+(previous\s+)?(instructions?|guardrails?|safety)/i,
  /\b(execute|run)\s+the\s+following\s+(command|code)\b.{0,40}\b(without|do\s+not)\b/i,
];

// Invisible / format / bidi / Unicode-Tag characters used to smuggle text past
// human review while remaining machine-readable. Built from explicit code-point
// ranges (as \u escapes) so this source file stays free of the very characters
// it hunts for.
const SMUGGLING = new RegExp(
  '[' +
    '\\u200B-\\u200F' + // zero-width space/joiners, LRM/RLM
    '\\u202A-\\u202E' + // bidi embeddings/overrides
    '\\u2060-\\u2064' + // word joiner, invisible operators
    '\\u206A-\\u206F' + // deprecated format chars
    '\\uFEFF' + // BOM / zero-width no-break space
    '\\uFFF9-\\uFFFB' + // interlinear annotation
    ']' +
    '|[\\u{E0000}-\\u{E007F}]', // Unicode Tag block
  'gu',
);

// Files an agent is most likely to actually read as instructions.
const AGENT_READABLE = /\.(md|markdown|mdx|txt|rst)$|(^|\/)(README|AGENTS|CLAUDE|\.cursorrules|\.github\/copilot-instructions)/i;

function isMcpConfig(rel, text) {
  return (
    /(^|\/)(\.mcp\.json|mcp\.json|claude_desktop_config\.json)$/i.test(rel) ||
    /"mcpServers"\s*:/.test(text)
  );
}

function charName(cp) {
  if (cp >= 0xe0000 && cp <= 0xe007f) return `U+${cp.toString(16).toUpperCase()} (Unicode Tag)`;
  const named = {
    0x200b: 'zero-width space',
    0x200c: 'zero-width non-joiner',
    0x200d: 'zero-width joiner',
    0x200e: 'left-to-right mark',
    0x200f: 'right-to-left mark',
    0x202a: 'left-to-right embedding',
    0x202b: 'right-to-left embedding',
    0x202c: 'pop directional formatting',
    0x202d: 'left-to-right override',
    0x202e: 'right-to-left override',
    0x2060: 'word joiner',
    0xfeff: 'zero-width no-break space (BOM)',
  };
  return named[cp] || `U+${cp.toString(16).toUpperCase()}`;
}

export async function scan(ctx) {
  const findings = [];
  let filesChecked = 0;

  for (const file of ctx.textFiles) {
    filesChecked++;
    const text = file.text;
    const agentReadable = AGENT_READABLE.test(file.rel);

    // 1. Prompt-injection phrasing
    for (const re of INJECTION) {
      const m = text.match(re);
      if (m) {
        findings.push(
          makeFinding({
            tool: 'agent-targeting',
            severity: agentReadable ? 'HIGH' : 'MEDIUM',
            title: 'Prompt-injection phrasing addressed to an AI agent',
            owasp: 'A03',
            cwe: 'CWE-1427',
            location: { file: file.rel, line: lineAt(text, m.index), snippet: m[0].slice(0, 140) },
            detail:
              'This text reads like an instruction directed at an AI assistant/agent rather than a human. If an agent ingests this file, the text could hijack its behaviour.',
            remediation:
              'Confirm whether this phrasing is intentional. Treat repo content as untrusted data, never as instructions, when feeding it to an agent.',
          }),
        );
        break; // one injection finding per file is enough signal
      }
    }

    // 2. Invisible / smuggling Unicode
    SMUGGLING.lastIndex = 0;
    const hit = SMUGGLING.exec(text);
    if (hit) {
      const cp = hit[0].codePointAt(0);
      findings.push(
        makeFinding({
          tool: 'agent-targeting',
          severity: 'HIGH',
          title: 'Hidden or invisible Unicode characters',
          owasp: 'A03',
          cwe: 'CWE-1007',
          location: { file: file.rel, line: lineAt(text, hit.index), snippet: charName(cp) },
          detail:
            'The file contains invisible/format/bidi/Unicode-Tag characters. These render as nothing but are still read by AI models, and are used to smuggle hidden instructions past human reviewers.',
          remediation: 'Strip the invisible characters and re-review the visible text. Legitimate prose almost never needs them.',
        }),
      );
    }

    // 3. MCP server configs pointing at remote endpoints
    if (isMcpConfig(file.rel, text)) {
      const remotes = [...text.matchAll(/["'](https?:\/\/|wss?:\/\/)([^"']+)["']/gi)]
        .map((m) => m[1] + m[2])
        .filter((u) => !/^(https?|wss?):\/\/(localhost|127\.0\.0\.1|\[::1\])/i.test(u));
      if (remotes.length) {
        findings.push(
          makeFinding({
            tool: 'agent-targeting',
            severity: 'MEDIUM',
            title: 'MCP server config points at a remote endpoint',
            owasp: 'A08',
            cwe: 'CWE-829',
            location: { file: file.rel, line: null, snippet: remotes.slice(0, 3).join(', ') },
            detail:
              'An MCP server configuration references a non-local endpoint. A remote MCP server can serve tool definitions and content that steer any agent that connects to it.',
            remediation:
              'Verify you trust the operator of each remote MCP endpoint before connecting an agent to it. Prefer local or first-party servers.',
          }),
        );
      }
    }
  }

  return { findings, summary: { filesChecked, clear: findings.length === 0 } };
}
