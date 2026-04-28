/**
 * obf.network-then-exec.<lang> — Layer B.
 *
 * Fires when network IO output flows into a dynamic-exec sink. The shape:
 *
 *   eval(await (await fetch(url)).text())
 *   exec(requests.get(url).text)
 *   IEX (New-Object Net.WebClient).DownloadString($u)
 *   eval "$(curl -s $URL)"
 *
 * Unlike decode-then-exec, the source of the executed string is *external*
 * — strictly worse, because the attacker doesn't even need to be in the
 * source tree. Always blocks.
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

interface Compiled {
  direct: RegExp;
  indirectAssign: RegExp;
  sinkUse: (v: string) => RegExp;
}

const cache = new WeakMap<LanguageConfig, Compiled>();

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
  const networkTokens = candidateTokens(config.network_io ?? []);
  const sinkTokens = candidateTokens(config.dynamic_exec_sinks);
  const hasNetwork = networkTokens.some(t => source.includes(t));
  if (!hasNetwork) return false;
  return sinkTokens.some(t => source.includes(t));
}

function compile(config: LanguageConfig): Compiled {
  const cached = cache.get(config);
  if (cached) return cached;
  const network = namedCallAlternation(config.network_io ?? []);
  const sinks = namedCallAlternation(config.dynamic_exec_sinks);

  // Direct: sink( ... network( ... ) ... )
  // Allow some method chaining (`.text()`, `.read()`) and up to two nested
  // call groups between the sink and the network call — e.g.
  // `eval(await (await fetch(url)).text())`. We use [\s\S] with a bounded
  // length cap to keep this O(n) and avoid catastrophic backtracking.
  const direct = new RegExp(
    `(?:${sinks})\\s*[("\\s][\\s\\S]{0,400}?(?:${network})\\s*[("\\s]`,
    "g",
  );

  // Bash-specific: `sink "$( ... pipe-decoder/network ... )"` where the inner
  // shell expansion contains a network command. The direct regex above can
  // miss this because the network name is a bare word (`curl`), not a call.
  const bashSubshell = new RegExp(
    `(?:${sinks})\\s+"?\\$\\([\\s\\S]{0,400}?(?:${network})\\b`,
    "g",
  );
  // Reuse `direct` as the union: tests use `direct` only, but if the language
  // is bash we want to fall back to the subshell shape below.
  const isShell = (config.id === "bash" || config.aliases?.includes("sh"));
  const directUnion = isShell
    ? new RegExp(`${direct.source}|${bashSubshell.source}`, "g")
    : direct;

  // Indirect: `var X = network(...);` followed by `sink(X)`.
  const indirectAssign = new RegExp(
    `(?:(?:const|let|var|my|local|\\$)\\s+)?` +
    `([A-Za-z_$][\\w$]*)` +
    `\\s*[:=]\\s*` +
    `(?:await\\s+)?` +
    `(?:${network})\\s*\\(`,
    "g",
  );

  const sinkUse = (v: string) =>
    new RegExp(`(?:${sinks})\\s*[("\\s][^()]{0,200}\\b${escapeRegex(v)}\\b`, "g");

  const compiled: Compiled = { direct: directUnion, indirectAssign, sinkUse };
  cache.set(config, compiled);
  return compiled;
}

export const networkThenExec: Detector = {
  id: "obf.network-then-exec",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfnetwork-then-exec",

  applies(ctx: FileContext): boolean {
    return (
      ctx.config !== null &&
      (ctx.config.network_io?.length ?? 0) > 0 &&
      ctx.config.dynamic_exec_sinks.length > 0 &&
      ctx.source.length > 0 &&
      ctx.source.length < MAX_SOURCE_BYTES &&
      maybeRelevantSource(ctx.source, ctx.config)
    );
  },

  run(ctx: FileContext): Finding[] {
    if (!ctx.config) return [];
    const cfg = ctx.config;
    const src = ctx.source;
    const { direct, indirectAssign, sinkUse } = compile(cfg);
    const findings: Finding[] = [];
    const seen = new Set<number>();

    let m: RegExpExecArray | null;
    const directRe = new RegExp(direct.source, direct.flags);
    while ((m = directRe.exec(src)) !== null) {
      if (findings.length >= MAX_FINDINGS_PER_DETECTOR) break;
      const line = lineAtOffset(src, m.index);
      if (seen.has(line)) continue;
      seen.add(line);
      findings.push(make(ctx, cfg.id, m[0], m.index, "direct"));
    }

    const assignRe = new RegExp(indirectAssign.source, indirectAssign.flags);
    while ((m = assignRe.exec(src)) !== null) {
      if (findings.length >= MAX_FINDINGS_PER_DETECTOR) break;
      const v = m[1];
      if (!v) continue;
      const after = src.slice(m.index + m[0].length);
      const u = sinkUse(v).exec(after);
      if (!u) continue;
      const offset = m.index + m[0].length + u.index;
      const line = lineAtOffset(src, offset);
      if (seen.has(line)) continue;
      seen.add(line);
      findings.push(make(ctx, cfg.id, u[0], offset, "indirect"));
    }
    return findings;
  },
};

function make(
  ctx: FileContext,
  langId: string,
  rawSnippet: string,
  offset: number,
  flow: "direct" | "indirect",
): Finding {
  return {
    ruleId: `obf.network-then-exec.${langId}`,
    severity: "block",
    score: 10,
    file: ctx.path,
    line: lineAtOffset(ctx.source, offset),
    snippet: truncateSnippet(rawSnippet),
    reason:
      `Network IO result flows into a dynamic-exec sink (${flow}). The ` +
      `executed code is fully attacker-controlled.`,
    evidence: { language: langId, flow },
  };
}
