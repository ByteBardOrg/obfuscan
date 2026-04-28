/**
 * obf.dynamic-exec-with-non-literal.<lang> — Layer B.
 *
 * Fires when a dynamic-exec sink is called with an argument that is not a
 * string/numeric literal. `eval("1+1")` is uninteresting; `eval(s)` is.
 *
 * The "is the argument a literal?" check is a syntactic approximation: we
 * peek at the first non-whitespace character after the sink's `(`. If it's
 * a quote or a digit, we treat the call as literal. Anything else — including
 * template strings with `${}` interpolation — is non-literal.
 *
 * Pure template strings without interpolation (e.g. `eval(\`1+1\`)`) are
 * treated as literal and not flagged.
 */

import type { Detector, FileContext, Finding, LanguageConfig } from "../types.js";
import {
  lineAtOffset,
  MAX_FINDINGS_PER_DETECTOR,
  MAX_SOURCE_BYTES,
  namedCallAlternation,
} from "../internal/patterns.js";
import { truncateSnippet } from "../internal/text.js";

interface Compiled {
  call: RegExp;
}

const cache = new WeakMap<LanguageConfig, Compiled>();

function compile(config: LanguageConfig): Compiled {
  const cached = cache.get(config);
  if (cached) return cached;
  const sinks = namedCallAlternation(config.dynamic_exec_sinks);
  // Capture the sink name and the first ~6 chars after `(` to inspect.
  const call = new RegExp(`(?:^|[^A-Za-z0-9_$])((?:${sinks}))\\s*\\(([\\s\\S]{0,12})`, "g");
  const compiled: Compiled = { call };
  cache.set(config, compiled);
  return compiled;
}

function isLiteralPeek(peek: string): boolean {
  const trimmed = peek.replace(/^\s+/, "");
  if (trimmed.length === 0) return false;
  const c = trimmed[0]!;
  // Numeric, single/double quote — definitely literal
  if (c === '"' || c === "'") return true;
  if (c >= "0" && c <= "9") return true;
  if (c === "-" && trimmed[1] && trimmed[1] >= "0" && trimmed[1] <= "9") return true;
  // Pure template literal with no `${`: still literal.
  if (c === "`") {
    return !trimmed.includes("${");
  }
  return false;
}

export const dynamicExecNonLiteral: Detector = {
  id: "obf.dynamic-exec-with-non-literal",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfdynamic-exec-with-non-literal",

  applies(ctx: FileContext): boolean {
    return (
      ctx.config !== null &&
      ctx.config.dynamic_exec_sinks.length > 0 &&
      ctx.source.length > 0 &&
      ctx.source.length < MAX_SOURCE_BYTES
    );
  },

  run(ctx: FileContext): Finding[] {
    if (!ctx.config) return [];
    const cfg = ctx.config;
    const src = ctx.source;
    const { call } = compile(cfg);

    const findings: Finding[] = [];
    const seen = new Set<number>();
    const re = new RegExp(call.source, call.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(src)) !== null) {
      if (findings.length >= MAX_FINDINGS_PER_DETECTOR) break;
      const sinkName = m[1] ?? "";
      const peek = m[2] ?? "";
      if (isLiteralPeek(peek)) continue;
      // Skip when the next thing looks like another decoder call — that's
      // the decode-then-exec detector's job.
      if (/^[A-Za-z_$][\w$.]*\s*\(/.test(peek.replace(/^\s+/, ""))) {
        // It's a function call argument; only flag if the function name is
        // not in this language's decoders list (otherwise decode-then-exec
        // owns the finding).
        const fnNameMatch = /^([A-Za-z_$][\w$.]*)/.exec(peek.replace(/^\s+/, ""));
        const fnName = fnNameMatch?.[1] ?? "";
        if (cfg.decoders.some(d => fnName === d || fnName.endsWith("." + d))) continue;
      }

      const offset = m.index + (m[0].length - peek.length);
      const line = lineAtOffset(src, offset);
      if (seen.has(line)) continue;
      seen.add(line);
      findings.push({
        ruleId: `obf.dynamic-exec-with-non-literal.${cfg.id}`,
        severity: "warn",
        score: 7,
        file: ctx.path,
        line,
        snippet: truncateSnippet(`${sinkName}(${peek}`),
        reason:
          `Dynamic-exec sink \`${sinkName}\` called with a non-literal argument. ` +
          `Confirm the input cannot be attacker-influenced.`,
        evidence: { language: cfg.id, sink: sinkName },
      });
    }
    return findings;
  },
};
