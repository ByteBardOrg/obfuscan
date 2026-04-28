/**
 * obf.python-setup-side-effect — Manifest detector for `setup.py`.
 *
 * Flags top-level executable code in `setup.py` other than the import,
 * `setup(...)` call, and a small allowlist of bookkeeping. Real-world
 * malicious `setup.py` files run network/shell side effects at install time.
 */

import type { Detector, FileContext, Finding } from "../types.js";
import { truncateSnippet } from "../internal/text.js";

function isSetupPy(p: string): boolean {
  return p === "setup.py" || p.endsWith("/setup.py");
}

// Lines that are allowed at module scope without flagging.
const ALLOWED_LINE_RE =
  /^(?:\s*$|\s*#|from\s+\S+\s+import\s+|import\s+\S+|setup\s*\(|\)\s*$|\s*[\w]+\s*=\s*[^=].*$)/;

// Suspicious side-effect markers at module scope.
const SUSPICIOUS_RE =
  /(urllib\.request|requests\.|httpx\.|urlretrieve|os\.system|subprocess\.|Popen|socket\.|exec\s*\(|eval\s*\(|base64\.b64decode\s*\()/;

export const pythonSetupSideEffect: Detector = {
  id: "obf.python-setup-side-effect",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfpython-setup-side-effect",

  applies(ctx: FileContext): boolean {
    return isSetupPy(ctx.path);
  },

  run(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const lines = ctx.source.split("\n");
    let inSetupCall = false;
    let parenDepth = 0;

    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i] ?? "";
      const line = raw;

      if (inSetupCall) {
        for (const c of line) {
          if (c === "(") parenDepth++;
          else if (c === ")") {
            parenDepth--;
            if (parenDepth <= 0) {
              inSetupCall = false;
              parenDepth = 0;
              break;
            }
          }
        }
        continue;
      }

      if (/^\s*setup\s*\(/.test(line)) {
        inSetupCall = true;
        parenDepth = 0;
        for (const c of line) {
          if (c === "(") parenDepth++;
          else if (c === ")") parenDepth--;
        }
        if (parenDepth <= 0) inSetupCall = false;
        continue;
      }

      // Indented lines are inside def/class/if blocks — skip; we only flag
      // module-scope side-effects.
      if (/^\s/.test(line)) continue;

      if (SUSPICIOUS_RE.test(line)) {
        findings.push({
          ruleId: pythonSetupSideEffect.id,
          severity: "block",
          score: 9,
          file: ctx.path,
          line: i + 1,
          snippet: truncateSnippet(line.trim()),
          reason:
            `setup.py contains code outside the \`setup()\` call that performs ` +
            `network, shell, or eval-like side effects at install time. This is ` +
            `the canonical \`pip install\` malware shape.`,
          evidence: {},
        });
        // First match per file is enough.
        break;
      }

      // Otherwise: only flag if it's a function call that's NOT in our
      // allowlist (imports, simple assignments, comments).
      if (!ALLOWED_LINE_RE.test(line) && /\(/.test(line)) {
        // Skip — too noisy. The SUSPICIOUS_RE branch above is the real signal.
      }
    }
    return findings;
  },
};
