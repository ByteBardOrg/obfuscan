/**
 * obf.long-line — Layer A.
 *
 * Flags pathologically long source lines, which are the universal signal
 * of minified or hand-rolled-obfuscated code being slipped into a regular
 * source tree. We don't fire on bona-fide minified bundles — those usually
 * live under `dist/`, `vendor/`, or `node_modules/` and are excluded by
 * convention or allowlist.
 */

import type { Detector, FileContext, Finding } from "../types.js";
import { MAX_SOURCE_BYTES } from "../internal/patterns.js";
import { truncateSnippet } from "../internal/text.js";

const LONG_LINE_THRESHOLD = 2000;
const VERY_LONG_LINE_THRESHOLD = 10_000;

export const longLine: Detector = {
  id: "obf.long-line",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obflong-line",

  applies(ctx: FileContext): boolean {
    return ctx.source.length > LONG_LINE_THRESHOLD && ctx.source.length < MAX_SOURCE_BYTES;
  },

  run(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const src = ctx.source;
    let lineStart = 0;
    let lineNo = 1;
    const len = src.length;

    for (let i = 0; i <= len; i++) {
      if (i === len || src.charCodeAt(i) === 10) {
        const lineLen = i - lineStart;
        if (lineLen >= LONG_LINE_THRESHOLD) {
          const snippet = src.slice(lineStart, lineStart + 200);
          const score = lineLen >= VERY_LONG_LINE_THRESHOLD ? 8 : 5;
          const severity = lineLen >= VERY_LONG_LINE_THRESHOLD ? "warn" : "info";
          findings.push({
            ruleId: longLine.id,
            severity,
            score,
            file: ctx.path,
            line: lineNo,
            snippet: truncateSnippet(snippet),
            reason:
              `Line ${lineNo} is ${lineLen} characters long. This is the ` +
              `signature of minified or hand-obfuscated code. If the file is ` +
              `intentionally a bundle, suppress with a path allowlist entry.`,
            evidence: { lineLength: lineLen },
          });
        }
        lineStart = i + 1;
        lineNo++;
      }
    }
    return findings;
  },
};
