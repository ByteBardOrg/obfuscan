/**
 * obf.shell-with-untrusted-input.<lang> — Layer B.
 *
 * Fires when a shell-exec sink (`child_process.exec`, `os.system`,
 * `Runtime.exec`, …) receives an argument built via string interpolation
 * or concatenation. Static-string commands are not flagged.
 */

import type { Detector, FileContext, Finding, LanguageConfig } from "../types.js";
import {
  lineAtOffset,
  MAX_FINDINGS_PER_DETECTOR,
  MAX_SOURCE_BYTES,
  namedCallAlternation,
} from "../internal/patterns.js";
import { truncateSnippet } from "../internal/text.js";

// Heuristic markers that the argument is built dynamically.
//   ${...}     — JS template / shell expansion
//   `..${`     — JS template start
//   f"..{..}"  — Python f-string with placeholder
//   "..%s.."   — printf-style
//   .. + ..    — concatenation (followed by an identifier)
//   $variable  — shell/perl/php interpolation
const DYNAMIC_ARG_RE =
  /(\$\{[^}]+\}|`[^`]*\$\{|f["'][^"']*\{[^}]+\}|"[^"]*%[sdif]"|\+\s*[A-Za-z_$][\w$]*|\$[A-Za-z_]\w*)/;

const cache = new WeakMap<LanguageConfig, RegExp | null>();

function compile(config: LanguageConfig): RegExp | null {
  if (cache.has(config)) return cache.get(config) ?? null;
  const list = config.shell_exec ?? [];
  if (list.length === 0) {
    cache.set(config, null);
    return null;
  }
  const alt = namedCallAlternation(list);
  // Capture sink + the first 80 chars of arguments
  const re = new RegExp(`(?:^|[^A-Za-z0-9_$])((?:${alt}))\\s*\\(([^)\\n]{0,200})`, "g");
  cache.set(config, re);
  return re;
}

export const shellUntrustedInput: Detector = {
  id: "obf.shell-with-untrusted-input",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfshell-with-untrusted-input",

  applies(ctx: FileContext): boolean {
    return (
      ctx.config !== null &&
      (ctx.config.shell_exec?.length ?? 0) > 0 &&
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
      const args = m[2] ?? "";
      if (!DYNAMIC_ARG_RE.test(args)) continue;

      const offset = m.index + (m[0].length - args.length);
      findings.push({
        ruleId: `obf.shell-with-untrusted-input.${cfg.id}`,
        severity: "warn",
        score: 7,
        file: ctx.path,
        line: lineAtOffset(ctx.source, offset),
        snippet: truncateSnippet(`${name}(${args}`),
        reason:
          `Shell-exec sink \`${name}\` called with an interpolated/concatenated ` +
          `argument. Confirm any user input is escaped or routed through an ` +
          `arg-array form.`,
        evidence: { language: cfg.id, sink: name },
      });
    }
    return findings;
  },
};
