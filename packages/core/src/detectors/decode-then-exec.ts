/**
 * obf.decode-then-exec.<lang> — Layer B.
 *
 * Fires when a value flowing out of a *decoder* (base64, hex, gzip, …) flows
 * into a *dynamic-exec sink* (eval, exec, Function, …) — either as a direct
 * argument or via one intermediate variable.
 *
 * Implementation note: the bundled engine is regex-driven over `ctx.source`.
 * Each language config supplies the decoder + sink names; we build two
 * patterns per file:
 *
 *   1. Direct:   sink( ... decoder( ... ) ... )
 *   2. Indirect: var = decoder( ... ); ... sink(var)
 *
 * Hosts that want full scope analysis can replace this with a tree-sitter
 * implementation by supplying their own `Detector` via `ScanOptions.detectors`.
 */

import type { Detector, FileContext, Finding, LanguageConfig } from "../types.js";
import {
  escapeRegex,
  lineAtOffset,
  MAX_FINDINGS_PER_DETECTOR,
  MAX_SOURCE_BYTES,
  namedCallAlternation,
} from "../internal/patterns.js";
import { truncateSnippet } from "../internal/text.js";

interface CompiledPatterns {
  direct: RegExp;
  indirectAssign: RegExp;
  sinkUse: (varName: string) => RegExp;
  sinkCall: RegExp;
  decoderCall: RegExp;
}

const cache = new WeakMap<LanguageConfig, CompiledPatterns>();

function candidateTokens(names: readonly string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const n of names) {
    if (!n) continue;
    const tail = n.split(/[.\/:\s]+/).filter(Boolean).pop() ?? n;
    const token = tail.replace(/[^A-Za-z0-9_]/g, "");
    if (token.length < 3) continue;
    if (seen.has(token)) continue;
    seen.add(token);
    out.push(token);
  }
  return out;
}

function maybeRelevantSource(source: string, config: LanguageConfig): boolean {
  const sinkTokens = candidateTokens(config.dynamic_exec_sinks);
  const decoderTokens = candidateTokens(config.decoders);
  const hasSink = sinkTokens.some(t => source.includes(t));
  if (!hasSink) return false;
  return decoderTokens.some(t => source.includes(t));
}

function compile(config: LanguageConfig): CompiledPatterns {
  const cached = cache.get(config);
  if (cached) return cached;

  const decoders = namedCallAlternation(config.decoders);
  const sinks = namedCallAlternation(config.dynamic_exec_sinks);

  // Direct: sink( ... decoder( ... ) ... )
  // We allow up to ~400 chars between the sink open and the decoder call to
  // accommodate chained method calls (`.toString()`, `.text`, etc.).
  const direct = new RegExp(
    `(?:${sinks})\\s*\\(([^()]{0,400}(?:\\([^()]*\\)[^()]{0,200}){0,3}(?:${decoders})\\s*\\()`,
    "g",
  );

  // Bash-specific: `sink "$( ... | base64 -d)"`. Decoders are pipeline words,
  // not function calls. Require the sink to be followed (within ~400 chars)
  // by a `$( ... decoder ... )` subshell; the decoder appears as a bare word
  // possibly with args, e.g. `base64 -d`, `xxd -r -p`.
  const isShell = (config.id === "bash" || (config.aliases ?? []).includes("sh"));
  const bashSubshell = isShell
    ? new RegExp(
        `(?:${sinks})\\s+"?\\$\\([\\s\\S]{0,400}?(?:${decoders})(?:\\s|\\b)`,
        "g",
      )
    : null;
  const directUnion = bashSubshell
    ? new RegExp(`${direct.source}|${bashSubshell.source}`, "g")
    : direct;

  // Indirect-assign: `var X = decoder(...);` and tuple-style assignments.
  const indirectAssign = new RegExp(
    `([A-Za-z_$][\\w$]*)` +
    `\\s*(?:,\\s*[A-Za-z_$][\\w$]*)*\\s*` +
    `(?::=|=)\\s*` +
    `(?:await\\s+)?` +
    `(?:${decoders})\\s*\\(`,
    "g",
  );

  const sinkUse = (varName: string) =>
    new RegExp(
      `(?:${sinks})\\s*(?:\\(|\\s+)\\s*(?:[A-Za-z_][\\w$]*\\s*\\(\\s*){0,2}[&*]*\\s*${escapeRegex(varName)}\\b`,
      "g",
    );

  const sinkCall = new RegExp(`(?:${sinks})\\s*(?:\\(|\\s+)([\\s\\S]{0,24})`, "g");
  const decoderCall = new RegExp(`(?:${decoders})\\s*\\(`, "g");

  const compiled: CompiledPatterns = {
    direct: directUnion,
    indirectAssign,
    sinkUse,
    sinkCall,
    decoderCall,
  };
  cache.set(config, compiled);
  return compiled;
}

function isLiteralPeek(peek: string): boolean {
  const trimmed = peek.replace(/^\s+/, "");
  if (trimmed.length === 0) return false;
  const c = trimmed[0]!;
  if (c === '"' || c === "'") return true;
  if (c >= "0" && c <= "9") return true;
  if (c === "-" && trimmed[1] && trimmed[1] >= "0" && trimmed[1] <= "9") return true;
  if (c === "`") return !trimmed.includes("${");
  return false;
}

export const decodeThenExec: Detector = {
  id: "obf.decode-then-exec",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfdecode-then-exec",

  applies(ctx: FileContext): boolean {
    return (
      ctx.config !== null &&
      ctx.config.dynamic_exec_sinks.length > 0 &&
      ctx.config.decoders.length > 0 &&
      ctx.source.length > 0 &&
      ctx.source.length < MAX_SOURCE_BYTES &&
      maybeRelevantSource(ctx.source, ctx.config)
    );
  },

  run(ctx: FileContext): Finding[] {
    if (!ctx.config) return [];
    const cfg = ctx.config;
    const src = ctx.source;
    const { direct, indirectAssign, sinkUse, sinkCall, decoderCall } = compile(cfg);

    const findings: Finding[] = [];
    const seen = new Set<number>(); // (line) dedupe

    // Direct flow.
    let m: RegExpExecArray | null;
    const directRe = new RegExp(direct.source, direct.flags);
    while ((m = directRe.exec(src)) !== null) {
      if (findings.length >= MAX_FINDINGS_PER_DETECTOR) break;
      const line = lineAtOffset(src, m.index);
      if (seen.has(line)) continue;
      seen.add(line);
      findings.push(buildFinding(ctx, cfg.id, m[0], m.index, "direct"));
    }

    // Indirect flow: find decoder assignments, then look for sink(var) later.
    const assignRe = new RegExp(indirectAssign.source, indirectAssign.flags);
    while ((m = assignRe.exec(src)) !== null) {
      if (findings.length >= MAX_FINDINGS_PER_DETECTOR) break;
      const varName = m[1];
      if (!varName) continue;
      const after = src.slice(m.index + m[0].length);
      const useRe = sinkUse(varName);
      const useMatch = useRe.exec(after);
      if (!useMatch) continue;

      const useOffset = m.index + m[0].length + useMatch.index;
      const line = lineAtOffset(src, useOffset);
      if (seen.has(line)) continue;
      seen.add(line);
      findings.push(buildFinding(ctx, cfg.id, useMatch[0], useOffset, "indirect"));
    }

    // Fallback: if a file contains both a decoder call and a dynamic-exec sink
    // with a non-literal argument, flag it. This catches helper wrappers and
    // statement-style sinks that don't fit the simple assignment model.
    const hasDecoder = new RegExp(decoderCall.source, decoderCall.flags).test(src);
    if (hasDecoder) {
      const sinkRe = new RegExp(sinkCall.source, sinkCall.flags);
      while ((m = sinkRe.exec(src)) !== null) {
        if (findings.length >= MAX_FINDINGS_PER_DETECTOR) break;
        const peek = m[1] ?? "";
        if (isLiteralPeek(peek)) continue;

        const offset = m.index + (m[0].length - peek.length);
        const line = lineAtOffset(src, offset);
        if (seen.has(line)) continue;
        seen.add(line);
        findings.push(buildFinding(ctx, cfg.id, m[0], offset, "co-located"));
      }
    }

    return findings;
  },
};

function buildFinding(
  ctx: FileContext,
  langId: string,
  rawSnippet: string,
  offset: number,
  flow: "direct" | "indirect" | "co-located",
): Finding {
  const line = lineAtOffset(ctx.source, offset);
  return {
    ruleId: `obf.decode-then-exec.${langId}`,
    severity: "block",
    score: 9,
    file: ctx.path,
    line,
    snippet: truncateSnippet(rawSnippet),
    reason:
      `Decoded value flows into a dynamic-exec sink (${flow}). This is the ` +
      `canonical decode-then-exec obfuscation pattern.`,
    evidence: { language: langId, flow },
  };
}
