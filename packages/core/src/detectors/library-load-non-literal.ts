/**
 * obf.library-load-non-literal.<lang> — Layer B.
 *
 * Fires when a dynamic-library-load function (`require`, `importlib.import_module`,
 * `Assembly.Load`, `libloading::Library::new`, …) is called with a non-literal
 * argument.
 */

import type { Detector, FileContext, Finding, LanguageConfig } from "../types.js";
import {
  lineAtOffset,
  MAX_FINDINGS_PER_DETECTOR,
  MAX_SOURCE_BYTES,
  namedCallAlternation,
} from "../internal/patterns.js";
import { truncateSnippet } from "../internal/text.js";

const cache = new WeakMap<LanguageConfig, RegExp | null>();

function compile(config: LanguageConfig): RegExp | null {
  if (cache.has(config)) return cache.get(config) ?? null;
  const list = config.library_load ?? [];
  if (list.length === 0) {
    cache.set(config, null);
    return null;
  }
  const re = new RegExp(
    `(?:^|[^A-Za-z0-9_$])((?:${namedCallAlternation(list)}))\\s*\\(([\\s\\S]{0,12})`,
    "g",
  );
  cache.set(config, re);
  return re;
}

function looksLikeLiteral(peek: string): boolean {
  const t = peek.replace(/^\s+/, "");
  if (t.length === 0) return false;
  const c = t[0]!;
  return c === '"' || c === "'" || c === "`" && !t.includes("${");
}

export const libraryLoadNonLiteral: Detector = {
  id: "obf.library-load-non-literal",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obflibrary-load-non-literal",

  applies(ctx: FileContext): boolean {
    return (
      ctx.config !== null &&
      (ctx.config.library_load?.length ?? 0) > 0 &&
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
      if (looksLikeLiteral(peek)) continue;

      const offset = m.index + (m[0].length - peek.length);
      findings.push({
        ruleId: `obf.library-load-non-literal.${cfg.id}`,
        severity: "warn",
        score: 7,
        file: ctx.path,
        line: lineAtOffset(ctx.source, offset),
        snippet: truncateSnippet(`${name}(${peek}`),
        reason:
          `Dynamic library load \`${name}\` called with a non-literal argument. ` +
          `Module name flowing from a variable is suspicious.`,
        evidence: { language: cfg.id, loader: name },
      });
    }
    return findings;
  },
};
