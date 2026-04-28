/**
 * obf.string-array-decoder.<lang> — Layer B.
 *
 * Two-step pattern: a high-entropy string array AND a decoder/sink wired to
 * it in the same file. This is the structural fingerprint of obfuscator.io
 * output beyond the lexical fingerprint of `encoded-array-fingerprint`.
 *
 * To fire, the file must contain BOTH:
 *   - A long array of base64-shaped string literals (≥16 elements), AND
 *   - A decoder call from the language config in the same file
 *   - A dynamic-exec sink call from the language config in the same file
 */

import type { Detector, FileContext, Finding, LanguageConfig } from "../types.js";
import {
  lineAtOffset,
  MAX_FINDINGS_PER_DETECTOR,
  MAX_SOURCE_BYTES,
  namedCallAlternation,
} from "../internal/patterns.js";
import { truncateSnippet } from "../internal/text.js";

const ARRAY_RE =
  /\[\s*((?:"[^"\n]{4,}"|'[^'\n]{4,}')(?:\s*,\s*(?:"[^"\n]{4,}"|'[^'\n]{4,}')){15,})\s*\]/g;

interface Compiled {
  decoder: RegExp;
  sink: RegExp;
}

const cache = new WeakMap<LanguageConfig, Compiled>();

function compile(config: LanguageConfig): Compiled {
  const cached = cache.get(config);
  if (cached) return cached;
  const compiled: Compiled = {
    decoder: new RegExp(`(?:${namedCallAlternation(config.decoders)})\\s*\\(`, "g"),
    sink: new RegExp(`(?:${namedCallAlternation(config.dynamic_exec_sinks)})\\s*\\(`, "g"),
  };
  cache.set(config, compiled);
  return compiled;
}

export const stringArrayDecoder: Detector = {
  id: "obf.string-array-decoder",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfstring-array-decoder",

  applies(ctx: FileContext): boolean {
    return (
      ctx.config !== null &&
      ctx.config.decoders.length > 0 &&
      ctx.config.dynamic_exec_sinks.length > 0 &&
      ctx.source.length > 0 &&
      ctx.source.length < MAX_SOURCE_BYTES
    );
  },

  run(ctx: FileContext): Finding[] {
    if (!ctx.config) return [];
    const src = ctx.source;
    const { decoder, sink } = compile(ctx.config);

    const arrRe = new RegExp(ARRAY_RE.source, ARRAY_RE.flags);
    const arrayMatch = arrRe.exec(src);
    if (!arrayMatch) return [];

    const decRe = new RegExp(decoder.source, decoder.flags);
    if (!decRe.exec(src)) return [];

    const sinkRe = new RegExp(sink.source, sink.flags);
    if (!sinkRe.exec(src)) return [];

    const findings: Finding[] = [];
    if (findings.length >= MAX_FINDINGS_PER_DETECTOR) return findings;

    findings.push({
      ruleId: `obf.string-array-decoder.${ctx.config.id}`,
      severity: "block",
      score: 9,
      file: ctx.path,
      line: lineAtOffset(src, arrayMatch.index),
      snippet: truncateSnippet(arrayMatch[0]),
      reason:
        `String-array + decoder + dynamic-exec sink present in the same file. ` +
        `This is the obfuscator.io / javascript-obfuscator structural fingerprint.`,
      evidence: { language: ctx.config.id },
    });
    return findings;
  },
};
