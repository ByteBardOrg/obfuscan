/**
 * obf.high-entropy-literal — Layer A (source-level regex).
 *
 * Flags long string literals whose Shannon entropy exceeds a threshold tuned
 * against the Datadog malicious-packages corpus. Packed payloads, base64
 * blobs, and hex-encoded shellcode all surface here.
 *
 * Known false positives:
 *   - Hex-encoded SHA-256 hashes in tests (mean ~4.0 bits/char, length 64)
 *   - Base64 SVG data URIs in CSS-in-JS (often legitimate)
 *   - Long license keys / JWTs in fixtures
 *
 * Tune via the `MIN_LEN` and `ENTROPY_THRESHOLD` constants. Per-project
 * suppression should be done via `.obfuscan/allowlist.json`, not by
 * lowering the threshold globally.
 */

import type { Detector, FileContext, Finding } from "../types.js";
import { truncateSnippet } from "../internal/text.js";

/** Matches `"..."`, `'...'`, or backtick strings of at least MIN_LEN chars. */
const STRING_LITERAL_RE = /(["'`])((?:\\.|(?!\1).){40,}?)\1/g;

const MIN_LEN = 40;
const ENTROPY_THRESHOLD = 4.5; // bits/char
const MAX_SOURCE_BYTES = 2_000_000; // skip files larger than 2 MB
const MAX_FINDINGS_PER_FILE = 50; // protect the report from minified bundles

/** Shannon entropy in bits/char. */
function shannon(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Convert a 0-based character offset to a 1-based line number. */
function lineAt(source: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < source.length; i++) {
    if (source.charCodeAt(i) === 10 /* \n */) line++;
  }
  return line;
}

export const highEntropyLiteral: Detector = {
  id: "obf.high-entropy-literal",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfhigh-entropy-literal",

  applies(ctx: FileContext): boolean {
    // Source-level — runs on any text file under the size cap.
    return ctx.source.length > 0 && ctx.source.length < MAX_SOURCE_BYTES;
  },

  run(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const src = ctx.source;
    let match: RegExpExecArray | null;

    // Local regex copy so we don't share lastIndex across calls.
    const re = new RegExp(STRING_LITERAL_RE.source, STRING_LITERAL_RE.flags);

    while ((match = re.exec(src)) !== null) {
      if (findings.length >= MAX_FINDINGS_PER_FILE) break;

      const body = match[2];
      if (!body || body.length < MIN_LEN) continue;

      const entropy = shannon(body);
      if (entropy < ENTROPY_THRESHOLD) continue;

      const line = lineAt(src, match.index);
      const score = Math.min(10, Math.round(entropy * 1.5));

      findings.push({
        ruleId: highEntropyLiteral.id,
        severity: "warn",
        score,
        file: ctx.path,
        line,
        snippet: truncateSnippet(body),
        reason:
          `High-entropy string literal ` +
          `(Shannon ${entropy.toFixed(2)} bits/char, length ${body.length}) — ` +
          `possible packed payload.`,
        evidence: {
          entropy: Number(entropy.toFixed(3)),
          length: body.length,
        },
      });
    }

    return findings;
  },
};
