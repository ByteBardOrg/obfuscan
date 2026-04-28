/**
 * obf.bidi-control — Layer A.
 *
 * Flags Unicode bidirectional control characters in source code (Trojan
 * Source, CVE-2021-42574). These are invisible characters that can make
 * source code render differently than it executes.
 *
 * Always blocks: there is essentially no legitimate reason for these to
 * appear in source. They come up in localized strings rarely, but those
 * should be in resource files, not code.
 */

import type { Detector, FileContext, Finding } from "../types.js";
import { lineAtOffset, MAX_SOURCE_BYTES } from "../internal/patterns.js";
import { truncateSnippet } from "../internal/text.js";

// Listed individually for clarity. Same set as RFC + Rust's lint.
const BIDI_CHARS = [
  "\u202A", // LRE — Left-to-Right Embedding
  "\u202B", // RLE — Right-to-Left Embedding
  "\u202C", // PDF — Pop Directional Formatting
  "\u202D", // LRO — Left-to-Right Override
  "\u202E", // RLO — Right-to-Left Override
  "\u2066", // LRI — Left-to-Right Isolate
  "\u2067", // RLI — Right-to-Left Isolate
  "\u2068", // FSI — First Strong Isolate
  "\u2069", // PDI — Pop Directional Isolate
];

const BIDI_RE = new RegExp(`[${BIDI_CHARS.join("")}]`, "g");

const NAMES: Record<string, string> = {
  "\u202A": "LRE", "\u202B": "RLE", "\u202C": "PDF",
  "\u202D": "LRO", "\u202E": "RLO", "\u2066": "LRI",
  "\u2067": "RLI", "\u2068": "FSI", "\u2069": "PDI",
};

export const bidiControlChar: Detector = {
  id: "obf.bidi-control",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfbidi-control",

  applies(ctx: FileContext): boolean {
    return ctx.source.length > 0 && ctx.source.length < MAX_SOURCE_BYTES;
  },

  run(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const src = ctx.source;
    let m: RegExpExecArray | null;
    BIDI_RE.lastIndex = 0;
    while ((m = BIDI_RE.exec(src)) !== null) {
      const ch = m[0];
      const codePoint = ch.codePointAt(0)!;
      const line = lineAtOffset(src, m.index);
      // Take a small window of context around the bidi char for the snippet.
      const winStart = Math.max(0, m.index - 20);
      const winEnd = Math.min(src.length, m.index + 20);
      const snippet = src.slice(winStart, winEnd);

      findings.push({
        ruleId: bidiControlChar.id,
        severity: "block",
        score: 10,
        file: ctx.path,
        line,
        snippet: truncateSnippet(snippet),
        reason:
          `Unicode bidirectional control character ` +
          `${NAMES[ch] ?? "?"} (U+${codePoint.toString(16).toUpperCase().padStart(4, "0")}) ` +
          `found in source. This is a Trojan Source attack vector (CVE-2021-42574).`,
        evidence: { codePoint, name: NAMES[ch] ?? "unknown" },
      });
    }
    return findings;
  },
};
