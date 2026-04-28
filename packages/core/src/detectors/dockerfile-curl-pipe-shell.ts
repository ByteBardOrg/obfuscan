/**
 * obf.dockerfile-curl-pipe-shell — Manifest detector for Dockerfiles.
 *
 * Flags `RUN curl|bash` and equivalents in Dockerfiles. Same shape as the
 * GHA detector — a network download piped into a shell — but in the image
 * build path.
 */

import type { Detector, FileContext, Finding } from "../types.js";
import { lineAtOffset } from "../internal/patterns.js";
import { truncateSnippet } from "../internal/text.js";

function isDockerfile(p: string): boolean {
  const base = p.slice(p.lastIndexOf("/") + 1);
  return base === "Dockerfile" || base.startsWith("Dockerfile.");
}

const RUN_CURL_PIPE_RE =
  /^\s*RUN\b[^\n]{0,500}(?:curl|wget|fetch)\b[^\n]{0,200}\|\s*(?:bash|sh|zsh|python|node|perl|powershell|pwsh)\b/gm;

export const dockerfileCurlPipeShell: Detector = {
  id: "obf.dockerfile-curl-pipe-shell",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfdockerfile-curl-pipe-shell",

  applies(ctx: FileContext): boolean {
    return isDockerfile(ctx.path);
  },

  run(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const src = ctx.source;
    const re = new RegExp(RUN_CURL_PIPE_RE.source, RUN_CURL_PIPE_RE.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(src)) !== null) {
      findings.push({
        ruleId: dockerfileCurlPipeShell.id,
        severity: "block",
        score: 9,
        file: ctx.path,
        line: lineAtOffset(src, m.index),
        snippet: truncateSnippet(m[0].trim()),
        reason:
          `Dockerfile RUN pipes a network download into a shell. ` +
          `Pin the artifact (sha256) or fetch + verify before executing.`,
        evidence: { command: m[0].trim() },
      });
    }
    return findings;
  },
};
