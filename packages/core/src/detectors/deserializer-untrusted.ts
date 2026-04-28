/**
 * obf.deserializer-untrusted.<lang> — Layer B.
 *
 * Fires when an unsafe deserializer (`pickle.loads`, `Marshal.load`,
 * `unserialize`, `BinaryFormatter.Deserialize`, `ObjectInputStream.readObject`)
 * is called with a non-literal argument. These are the canonical RCE-by-
 * deserialization sinks.
 *
 * Safe deserializers (e.g. `JSON.parse`, `json_decode`, `JSON.stringify`)
 * are skipped via an internal allowlist even if a `LanguageConfig` lists them,
 * so authors who include them for completeness don't pay an FP tax.
 */

import type { Detector, FileContext, Finding, LanguageConfig } from "../types.js";
import {
  lineAtOffset,
  MAX_FINDINGS_PER_DETECTOR,
  MAX_SOURCE_BYTES,
  namedCallAlternation,
} from "../internal/patterns.js";
import { truncateSnippet } from "../internal/text.js";

/**
 * Names that are deserializers but are *safe* against untrusted input. If a
 * `LanguageConfig` happens to list them (some do, for completeness), the
 * detector still skips them.
 */
const SAFE_DESERIALIZERS = new Set<string>([
  "JSON.parse",
  "v8.deserialize",
  "node:v8.deserialize",
  "json_decode",
]);

const cache = new WeakMap<LanguageConfig, RegExp>();

function compile(config: LanguageConfig): RegExp | null {
  const cached = cache.get(config);
  if (cached) return cached;
  const list = (config.deserializers ?? []).filter((d) => !SAFE_DESERIALIZERS.has(d));
  if (list.length === 0) return null;
  const alt = namedCallAlternation(list);
  // Match `deserializer( ... )` and capture a peek at the first argument.
  const re = new RegExp(`(?:^|[^A-Za-z0-9_$])((?:${alt}))\\s*\\(([\\s\\S]{0,16})`, "g");
  cache.set(config, re);
  return re;
}

/**
 * Skip definition contexts: `def name(`, `function name(`, `fn name(`,
 * `sub name`, `func name(`. The detector is otherwise too eager when a
 * deserializer's bare tail (e.g. `load`) collides with a function name.
 */
const DEFINITION_PREFIX_RE = /(?:\b(?:def|function|fn|func|sub)\s+|class\s+)$/;

function looksLikeLiteralCall(peek: string): boolean {
  const t = peek.replace(/^\s+/, "");
  if (t.length === 0) return false;
  const c = t[0]!;
  return c === '"' || c === "'" || (c >= "0" && c <= "9");
}

export const deserializerUntrusted: Detector = {
  id: "obf.deserializer-untrusted",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfdeserializer-untrusted",

  applies(ctx: FileContext): boolean {
    return (
      ctx.config !== null &&
      (ctx.config.deserializers?.length ?? 0) > 0 &&
      ctx.source.length > 0 &&
      ctx.source.length < MAX_SOURCE_BYTES
    );
  },

  run(ctx: FileContext): Finding[] {
    if (!ctx.config) return [];
    const cfg = ctx.config;
    const re = compile(cfg);
    if (!re) return [];

    const findings: Finding[] = [];
    const local = new RegExp(re.source, re.flags);
    let m: RegExpExecArray | null;
    while ((m = local.exec(ctx.source)) !== null) {
      if (findings.length >= MAX_FINDINGS_PER_DETECTOR) break;
      const name = m[1] ?? "";
      const peek = m[2] ?? "";
      if (looksLikeLiteralCall(peek)) continue;
      // Skip `def load(...)`, `function load(...)`, etc. — definitions, not calls.
      const lookback = ctx.source.slice(Math.max(0, m.index - 20), m.index + 1);
      if (DEFINITION_PREFIX_RE.test(lookback)) continue;
      const offset = m.index + (m[0].length - peek.length);
      findings.push({
        ruleId: `obf.deserializer-untrusted.${cfg.id}`,
        severity: "block",
        score: 9,
        file: ctx.path,
        line: lineAtOffset(ctx.source, offset),
        snippet: truncateSnippet(`${name}(${peek}`),
        reason:
          `Unsafe deserializer \`${name}\` called with a non-literal argument. ` +
          `Untrusted input here is RCE.`,
        evidence: { language: cfg.id, deserializer: name },
      });
    }
    return findings;
  },
};
