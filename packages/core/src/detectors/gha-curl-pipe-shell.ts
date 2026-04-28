/**
 * obf.gha-curl-pipe-shell — Manifest detector for GitHub Actions YAML.
 *
 * Flags any `run:` step in `.github/workflows/*.yml|yaml` whose command
 * pipes a network download directly into a shell. This is one of the
 * highest-yield supply-chain attack vectors — a CI run pulling and
 * executing remote code on every push.
 */

import type { Detector, FileContext, Finding } from "../types.js";
import { lineAtOffset } from "../internal/patterns.js";
import { truncateSnippet } from "../internal/text.js";

function isWorkflow(p: string): boolean {
  return /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/.test(p);
}

const CURL_PIPE_SHELL_RE =
  /(?:curl|wget|fetch)\b[^\n]{0,200}\|\s*(?:bash|sh|zsh|python|node|perl|powershell|pwsh)\b/g;

export const ghaCurlPipeShell: Detector = {
  id: "obf.gha-curl-pipe-shell",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfgha-curl-pipe-shell",

  applies(ctx: FileContext): boolean {
    return isWorkflow(ctx.path);
  },

  run(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const src = ctx.source;
    const re = new RegExp(CURL_PIPE_SHELL_RE.source, CURL_PIPE_SHELL_RE.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(src)) !== null) {
      findings.push({
        ruleId: ghaCurlPipeShell.id,
        severity: "block",
        score: 9,
        file: ctx.path,
        line: lineAtOffset(src, m.index),
        snippet: truncateSnippet(m[0]),
        reason:
          `GitHub Actions step pipes a network download into a shell. ` +
          `Pin the artifact (sha256) or fetch + verify before executing.`,
        evidence: { command: m[0] },
      });
    }
    return findings;
  },
};
