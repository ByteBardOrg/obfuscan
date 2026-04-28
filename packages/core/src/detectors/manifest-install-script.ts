/**
 * obf.manifest-install-script — install/lifecycle hooks across package manifests.
 *
 * One detector covers every ecosystem whose manifest can run arbitrary code
 * during `install` (or the equivalent dependency-fetch phase). The shape is
 * consistent across ecosystems: a structured manifest declares a script /
 * command / file that the package manager will execute on the consumer's
 * machine when they pull the dependency. That's the supply-chain attack
 * surface; the ecosystem just changes the file format.
 *
 * Coverage:
 *
 *   ┌──────────────┬───────────────────────────────┬─────────────────────────┐
 *   │ ecosystem    │ manifest                      │ hooks flagged           │
 *   ├──────────────┼───────────────────────────────┼─────────────────────────┤
 *   │ npm/yarn/pnpm│ package.json                  │ scripts.preinstall,     │
 *   │              │                               │ scripts.install,        │
 *   │              │                               │ scripts.postinstall,    │
 *   │              │                               │ scripts.prepare         │
 *   │ composer (PHP│ composer.json                 │ scripts.pre-install-cmd,│
 *   │              │                               │ scripts.post-install-cmd│
 *   │              │                               │ scripts.pre-update-cmd, │
 *   │              │                               │ scripts.post-update-cmd,│
 *   │              │                               │ scripts.post-autoload-  │
 *   │              │                               │   dump                  │
 *   │ rubygems     │ *.gemspec                     │ extensions = [...]      │
 *   │              │                               │   (extconf.rb / Rakefile│
 *   │              │                               │    runs at gem install) │
 *   │ luarocks     │ *.rockspec                    │ build.type = "command", │
 *   │              │                               │ build.build_command,    │
 *   │              │                               │ build.install_command   │
 *   │ nuget        │ *.nuspec                      │ <files src=".../*.ps1"> │
 *   │              │                               │   for install.ps1 /     │
 *   │              │                               │   init.ps1              │
 *   └──────────────┴───────────────────────────────┴─────────────────────────┘
 *
 * Severity:
 *   - `warn` (score 6) for any install hook that runs a command on the user's
 *     machine. The mere presence of an install hook is not malicious — many
 *     legitimate packages ship them — but it is the right line to surface in
 *     a code review.
 *   - `block` (score 9) when the script body contains exfil-shaped commands:
 *     `curl|bash`, `wget ... | sh`, etc. — the shape behind the
 *     axios-2026 / chalk+debug-2025 incidents.
 *
 * Evidence:
 *   - `manifest`: which ecosystem (`npm`, `composer`, `gemspec`, `rockspec`, `nuspec`)
 *   - `hook`: which lifecycle hook fired
 *   - `command`: the hook body (truncated in `snippet`)
 *   - `curlPipeShell`: boolean — whether the command matched the curl|sh shape
 */

import type { Detector, FileContext, Finding } from "../types.js";
import { truncateSnippet } from "../internal/text.js";

// ─── Shape detection ────────────────────────────────────────────────────────

type ManifestKind = "npm" | "composer" | "gemspec" | "rockspec" | "nuspec";

function classify(p: string): ManifestKind | null {
  const norm = p.replace(/\\/g, "/");
  const base = norm.slice(norm.lastIndexOf("/") + 1);
  if (base === "package.json") return "npm";
  if (base === "composer.json") return "composer";
  if (base.endsWith(".gemspec")) return "gemspec";
  if (base.endsWith(".rockspec")) return "rockspec";
  if (base.endsWith(".nuspec")) return "nuspec";
  return null;
}

// ─── Severity escalation ────────────────────────────────────────────────────

const CURL_PIPE_SHELL_RE =
  /(?:curl|wget|fetch|Invoke-WebRequest|iwr)\b[^\n]{0,300}\|\s*(?:bash|sh|zsh|python|node|perl|powershell|pwsh|iex|Invoke-Expression)/i;

// PowerShell `iex (New-Object Net.WebClient).DownloadString(...)` — the
// canonical Windows install-time payload shape, no pipe involved.
const PS_IEX_DOWNLOAD_RE =
  /\b(?:iex|Invoke-Expression)\b[^\n]{0,300}\b(?:DownloadString|DownloadFile|Invoke-WebRequest|wget|curl)\b/i;

function isCurlPipeShape(s: string): boolean {
  return CURL_PIPE_SHELL_RE.test(s) || PS_IEX_DOWNLOAD_RE.test(s);
}

// ─── npm / package.json ─────────────────────────────────────────────────────
//
// `prepare` is included because npm runs it on `npm install` from a git URL
// and on `npm pack` — which is how malicious tarballs are constructed.

const NPM_INSTALL_HOOKS = ["preinstall", "install", "postinstall", "prepare"] as const;

interface NpmManifest {
  scripts?: Record<string, string>;
}

function scanNpm(ctx: FileContext, pkg: NpmManifest): Finding[] {
  if (!pkg.scripts || typeof pkg.scripts !== "object") return [];
  const findings: Finding[] = [];
  for (const hook of NPM_INSTALL_HOOKS) {
    const cmd = pkg.scripts[hook];
    if (typeof cmd !== "string" || cmd.length === 0) continue;
    findings.push(buildFinding(ctx, "npm", hook, cmd, lineOfJsonKey(ctx.source, hook)));
  }
  return findings;
}

// ─── composer / composer.json ───────────────────────────────────────────────

const COMPOSER_INSTALL_HOOKS = [
  "pre-install-cmd",
  "post-install-cmd",
  "pre-update-cmd",
  "post-update-cmd",
  "post-autoload-dump",
] as const;

interface ComposerManifest {
  scripts?: Record<string, string | string[]>;
}

function scanComposer(ctx: FileContext, pkg: ComposerManifest): Finding[] {
  if (!pkg.scripts || typeof pkg.scripts !== "object") return [];
  const findings: Finding[] = [];
  for (const hook of COMPOSER_INSTALL_HOOKS) {
    const raw = pkg.scripts[hook];
    if (raw == null) continue;
    const cmds = Array.isArray(raw) ? raw : [raw];
    for (const cmd of cmds) {
      if (typeof cmd !== "string" || cmd.length === 0) continue;
      findings.push(buildFinding(ctx, "composer", hook, cmd, lineOfJsonKey(ctx.source, hook)));
    }
  }
  return findings;
}

// ─── rubygems / *.gemspec ───────────────────────────────────────────────────
//
// Gemspecs are Ruby, not JSON. We don't need a Ruby parser — `extensions` is
// almost always assigned via a literal array of relative paths. Anything
// non-trivial is itself worth surfacing.

const GEMSPEC_EXTENSIONS_RE =
  /\b\w+\.extensions\s*(?:=|<<)\s*(\[[^\]]*\]|%w[\[\(][^\]\)]*[\]\)]|['"][^'"]+['"])/;

function scanGemspec(ctx: FileContext): Finding[] {
  const m = GEMSPEC_EXTENSIONS_RE.exec(ctx.source);
  if (!m) return [];
  const value = m[1] ?? "";
  return [buildFinding(ctx, "gemspec", "extensions", value, lineAt(ctx.source, m.index))];
}

// ─── luarocks / *.rockspec ──────────────────────────────────────────────────
//
// Rockspec is Lua data; the install-time hook is the `build` table. We grep
// for the high-risk shapes: build.type == "command" or any *_command field.

const ROCKSPEC_BUILD_TYPE_RE = /build\s*=\s*\{[^}]*?type\s*=\s*['"]command['"]/s;
const ROCKSPEC_COMMAND_FIELD_RE =
  /(\bbuild_command\b|\binstall_command\b|\bcommand\b)\s*=\s*['"]([^'"\n]{1,400})['"]/;

function scanRockspec(ctx: FileContext): Finding[] {
  const findings: Finding[] = [];
  const declaresCommand = ROCKSPEC_BUILD_TYPE_RE.test(ctx.source);
  const cmd = ROCKSPEC_COMMAND_FIELD_RE.exec(ctx.source);

  if (declaresCommand) {
    const where = ctx.source.search(ROCKSPEC_BUILD_TYPE_RE);
    findings.push(
      buildFinding(
        ctx,
        "rockspec",
        "build.type",
        "command",
        where >= 0 ? lineAt(ctx.source, where) : 1,
      ),
    );
  }
  if (cmd) {
    const field = cmd[1] ?? "command";
    const value = cmd[2] ?? "";
    findings.push(buildFinding(ctx, "rockspec", field, value, lineAt(ctx.source, cmd.index)));
  }
  return findings;
}

// ─── nuget / *.nuspec ───────────────────────────────────────────────────────
//
// .nuspec is XML. NuGet historically auto-ran `tools/install.ps1`,
// `tools/init.ps1`, `tools/uninstall.ps1` at package install. Those files are
// auto-discovered by path; the .nuspec is the place we can see *that they
// exist* without the rest of the package tree, because they're declared in
// `<files>` entries. We also surface direct PowerShell content inlined into
// the manifest.

// Matches the inner `<file src="tools/install.ps1" .../>` entry as well as a
// degenerate `<files src="...install.ps1" .../>` shorthand. NuGet historically
// auto-ran any tools/{install,init,uninstall}.ps1 inside the package.
const NUSPEC_FILES_PS1_RE =
  /<files?\b[^>]*\bsrc\s*=\s*['"]([^'"]*\b(?:install|init|uninstall)\.ps1)['"]/gi;

function scanNuspec(ctx: FileContext): Finding[] {
  const findings: Finding[] = [];
  let m: RegExpExecArray | null;
  NUSPEC_FILES_PS1_RE.lastIndex = 0;
  while ((m = NUSPEC_FILES_PS1_RE.exec(ctx.source)) !== null) {
    const ref = m[1] ?? "";
    findings.push(buildFinding(ctx, "nuspec", "files.install-ps1", ref, lineAt(ctx.source, m.index)));
  }
  return findings;
}

// ─── Finding builder ────────────────────────────────────────────────────────

function buildFinding(
  ctx: FileContext,
  manifest: ManifestKind,
  hook: string,
  command: string,
  line: number,
): Finding {
  const escalated = isCurlPipeShape(command);
  return {
    ruleId: "obf.manifest-install-script",
    severity: escalated ? "block" : "warn",
    score: escalated ? 9 : 6,
    file: ctx.path,
    line,
    snippet: truncateSnippet(`${manifest}:${hook} ${command}`),
    reason: escalated
      ? reasonEscalated(manifest, hook)
      : reasonBase(manifest, hook),
    evidence: { manifest, hook, command, curlPipeShell: escalated },
  };
}

function reasonBase(manifest: ManifestKind, hook: string): string {
  switch (manifest) {
    case "npm":
      return (
        `npm \`${hook}\` lifecycle script runs automatically on \`npm install\`. ` +
        `Review for network calls, decoders, or shell-exec patterns.`
      );
    case "composer":
      return (
        `Composer \`${hook}\` script runs during \`composer install\`/\`update\`. ` +
        `Review for network calls, decoders, or shell-exec patterns.`
      );
    case "gemspec":
      return (
        `Gemspec declares native extensions; \`gem install\` will execute the ` +
        `referenced \`extconf.rb\` / \`Rakefile\` on the user's machine.`
      );
    case "rockspec":
      return (
        `Rockspec declares a \`${hook}\` build hook; \`luarocks install\` will ` +
        `run this command on the user's machine.`
      );
    case "nuspec":
      return (
        `.nuspec ships an auto-run PowerShell file (\`${hook}\`); legacy NuGet ` +
        `clients execute these on package install.`
      );
  }
}

function reasonEscalated(manifest: ManifestKind, hook: string): string {
  return (
    `${manifest} \`${hook}\` hook pipes a network download into a shell. This ` +
    `is the exfil/payload-delivery shape behind the axios-2026 / ` +
    `chalk+debug-2025 supply-chain incidents.`
  );
}

// ─── Source helpers ─────────────────────────────────────────────────────────

function lineOfJsonKey(source: string, key: string): number {
  const re = new RegExp(`"${key.replace(/[.*+?^${}()|[\]\\-]/g, "\\$&")}"\\s*:`, "g");
  const m = re.exec(source);
  if (!m) return 1;
  return lineAt(source, m.index);
}

function lineAt(source: string, offset: number): number {
  let line = 1;
  const stop = Math.min(offset, source.length);
  for (let i = 0; i < stop; i++) {
    if (source.charCodeAt(i) === 10) line++;
  }
  return line;
}

// ─── Public detector ────────────────────────────────────────────────────────

export const manifestInstallScript: Detector = {
  id: "obf.manifest-install-script",
  docsUrl:
    "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfmanifest-install-script",

  applies(ctx: FileContext): boolean {
    return classify(ctx.path) !== null;
  },

  run(ctx: FileContext): Finding[] {
    const kind = classify(ctx.path);
    if (kind === null) return [];

    switch (kind) {
      case "npm": {
        let pkg: NpmManifest;
        try {
          pkg = JSON.parse(ctx.source) as NpmManifest;
        } catch {
          return [];
        }
        return scanNpm(ctx, pkg);
      }
      case "composer": {
        let pkg: ComposerManifest;
        try {
          pkg = JSON.parse(ctx.source) as ComposerManifest;
        } catch {
          return [];
        }
        return scanComposer(ctx, pkg);
      }
      case "gemspec":
        return scanGemspec(ctx);
      case "rockspec":
        return scanRockspec(ctx);
      case "nuspec":
        return scanNuspec(ctx);
    }
  },
};
