/**
 * obf.perl-makefile-side-effect — Manifest detector for `Makefile.PL` and
 * `Build.PL`.
 *
 * CPAN distributions ship a `Makefile.PL` (or `Build.PL`) which is executed
 * verbatim by the user during `cpan install` / `cpanm`. The expected shape is
 * a small declarative call to `WriteMakefile(...)` (ExtUtils::MakeMaker) or
 * `Module::Build->new(...)->create_build_script` (Module::Build). Anything
 * else at module scope runs on the user's machine.
 *
 * This detector is the Perl counterpart to `obf.python-setup-side-effect`.
 *
 * Severity: `block` (score 9) — same calculus as setup.py.
 */

import type { Detector, FileContext, Finding } from "../types.js";
import { truncateSnippet } from "../internal/text.js";

function isPerlInstaller(p: string): boolean {
  const norm = p.replace(/\\/g, "/");
  const base = norm.slice(norm.lastIndexOf("/") + 1);
  return base === "Makefile.PL" || base === "Build.PL";
}

// Suspicious shapes at module scope: network, shell-out, eval-like, decoders.
const SUSPICIOUS_RE =
  /(\bsystem\s*\(|\bexec\s*\(|`[^`]*`|qx[\s({\[]|LWP::|HTTP::Tiny|IO::Socket|Net::|MIME::Base64|decode_base64|\beval\s*\{|\beval\s*['"]|use\s+inline\b)/i;

export const perlMakefileSideEffect: Detector = {
  id: "obf.perl-makefile-side-effect",
  docsUrl:
    "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfperl-makefile-side-effect",

  applies(ctx: FileContext): boolean {
    return isPerlInstaller(ctx.path);
  },

  run(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const lines = ctx.source.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i] ?? "";
      // Strip trailing comments before testing.
      const code = raw.replace(/(?<!\\)#.*$/, "");
      if (code.trim().length === 0) continue;

      // Skip indented lines — only flag module-scope side effects. (Code
      // inside a sub {} or block is indented in any reasonable style; this
      // mirrors the python-setup heuristic.)
      if (/^\s/.test(raw)) continue;

      // Skip pragmas, package declarations, simple use/require, and
      // declarative WriteMakefile / Module::Build calls.
      if (
        /^\s*(?:use|no|require|package|our|my)\b/.test(code) ||
        /^\s*(?:WriteMakefile|Module::Build)\b/.test(code) ||
        /^\s*\)/.test(code) // tail of a multi-line call
      ) {
        continue;
      }

      if (SUSPICIOUS_RE.test(code)) {
        findings.push({
          ruleId: perlMakefileSideEffect.id,
          severity: "block",
          score: 9,
          file: ctx.path,
          line: i + 1,
          snippet: truncateSnippet(code.trim()),
          reason:
            `${ctx.path} contains code outside the declarative ` +
            `\`WriteMakefile\` / \`Module::Build\` call that performs network, ` +
            `shell, or eval-like side effects. CPAN clients execute this file ` +
            `on the user's machine during \`cpan install\`.`,
          evidence: {},
        });
        // First match per file is enough to surface the issue.
        break;
      }
    }

    return findings;
  },
};
