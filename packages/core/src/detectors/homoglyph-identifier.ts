/**
 * obf.homoglyph-identifier — Layer A.
 *
 * Flags identifiers that mix scripts in a way associated with homoglyph
 * attacks. The narrow definition: an identifier with a *majority* of ASCII
 * Latin letters but containing at least one confusable from another script.
 *
 * Negative cases:
 *   - Pure non-ASCII identifiers (e.g. all Cyrillic, all CJK) — legitimate
 *     non-English code.
 *   - Pure ASCII identifiers — by construction.
 *   - Strings, comments — not identifier contexts.
 */

import type { Detector, FileContext, Finding } from "../types.js";
import { lineAtOffset, MAX_SOURCE_BYTES } from "../internal/patterns.js";
import { truncateSnippet } from "../internal/text.js";

// Identifier tokenizer: ASCII-letter or non-space, non-punct unicode letters.
// We use a Unicode property escape here; supported in Node 12+.
const IDENT_RE = /[A-Za-z_$][\p{L}\p{N}_$]{2,}/gu;

// "Confusable script ranges" — characters that visually resemble Latin but
// belong to other scripts. Subset focused on Cyrillic + Greek which produce
// the highest-yield homoglyphs.
const CONFUSABLE_RE = /[\u0400-\u04FF\u0370-\u03FF]/;

// ASCII letters
const ASCII_LETTER_RE = /[A-Za-z]/;

export const homoglyphIdentifier: Detector = {
  id: "obf.homoglyph-identifier",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfhomoglyph-identifier",

  applies(ctx: FileContext): boolean {
    return ctx.source.length > 0 && ctx.source.length < MAX_SOURCE_BYTES;
  },

  run(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const src = ctx.source;
    const seen = new Set<string>();
    const re = new RegExp(IDENT_RE.source, IDENT_RE.flags);

    let m: RegExpExecArray | null;
    while ((m = re.exec(src)) !== null) {
      const ident = m[0];
      if (seen.has(ident)) continue;

      if (!CONFUSABLE_RE.test(ident)) continue;

      // Count ASCII vs confusable letters
      let ascii = 0;
      let confusable = 0;
      for (const c of ident) {
        if (ASCII_LETTER_RE.test(c)) ascii++;
        else if (CONFUSABLE_RE.test(c)) confusable++;
      }
      if (ascii === 0) continue; // pure non-ASCII identifier
      if (confusable === 0) continue;
      // Only flag mixed identifiers where ASCII is the majority.
      if (ascii < confusable) continue;

      seen.add(ident);
      const line = lineAtOffset(src, m.index);
      findings.push({
        ruleId: homoglyphIdentifier.id,
        severity: "block",
        score: 9,
        file: ctx.path,
        line,
        snippet: truncateSnippet(ident),
        reason:
          `Identifier mixes Latin letters with confusable characters from ` +
          `another script (Cyrillic/Greek). This is a homoglyph attack pattern.`,
        evidence: { identifier: ident, asciiCount: ascii, confusableCount: confusable },
      });
    }
    return findings;
  },
};
