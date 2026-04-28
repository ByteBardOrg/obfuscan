/**
 * obf.encoded-array-fingerprint — Layer A.
 *
 * Detects the lexical fingerprint of obfuscator.io / javascript-obfuscator
 * output: a long array of high-entropy strings, often assigned to a hex-style
 * identifier (`_0xabc12`). This fires before any AST analysis and is one of
 * the strongest single signals for packed JS payloads.
 */

import type { Detector, FileContext, Finding } from "../types.js";
import { lineAtOffset, MAX_SOURCE_BYTES } from "../internal/patterns.js";
import { truncateSnippet } from "../internal/text.js";

// `[ "...", "...", ... ]` arrays with at least N quoted-string elements.
// Backquotes excluded — template literals don't show up in obfuscator arrays.
const ARRAY_RE = /\[\s*((?:"[^"\n]{4,}"|'[^'\n]{4,}')(?:\s*,\s*(?:"[^"\n]{4,}"|'[^'\n]{4,}')){15,})\s*\]/g;

const MIN_BASE64_RATIO = 0.6;
const BASE64_CHAR = /[A-Za-z0-9+/=]/;

function looksBase64ish(s: string): boolean {
  if (s.length < 8) return false;
  let hits = 0;
  for (const c of s) if (BASE64_CHAR.test(c)) hits++;
  return hits / s.length >= MIN_BASE64_RATIO;
}

export const encodedArrayFingerprint: Detector = {
  id: "obf.encoded-array-fingerprint",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfencoded-array-fingerprint",

  applies(ctx: FileContext): boolean {
    return ctx.source.length > 0 && ctx.source.length < MAX_SOURCE_BYTES;
  },

  run(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const src = ctx.source;
    const re = new RegExp(ARRAY_RE.source, ARRAY_RE.flags);

    let m: RegExpExecArray | null;
    while ((m = re.exec(src)) !== null) {
      const elements = (m[1] ?? "")
        .split(/,/)
        .map(s => s.trim().replace(/^["']|["']$/g, ""));

      const base64ish = elements.filter(looksBase64ish).length;
      if (base64ish / elements.length < MIN_BASE64_RATIO) continue;

      const line = lineAtOffset(src, m.index);
      findings.push({
        ruleId: encodedArrayFingerprint.id,
        severity: "warn",
        score: 7,
        file: ctx.path,
        line,
        snippet: truncateSnippet(m[0]),
        reason:
          `Large array of encoded-looking strings (${elements.length} entries, ` +
          `${base64ish} base64-shaped). This is the obfuscator.io / ` +
          `javascript-obfuscator string-table fingerprint.`,
        evidence: { length: elements.length, base64ishCount: base64ish },
      });
    }
    return findings;
  },
};
