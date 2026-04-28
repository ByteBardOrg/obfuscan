# Language coverage

obfuscan runs on any readable text file. Coverage depth is determined by
whether a language has a config in `packages/rules/languages/*.json`.

The shipped engine is regex/config driven (no bundled tree-sitter runtime).

| Tier | Layer A (universal) | Layer B (config-driven regex) | Layer C (manifest/path) |
|---|---|---|---|
| **1 — full** | yes | yes | yes |
| **2 — full** | yes | yes | yes |
| **3 — universal only** | yes | no | yes where applicable |

## Tier 1

First-class coverage for the highest-frequency supply-chain languages.

| Language | Extensions | Config |
|---|---|---|
| JavaScript | `.js`, `.cjs`, `.mjs`, `.jsx` | `packages/rules/languages/javascript.json` |
| TypeScript | `.ts`, `.tsx` | `packages/rules/languages/typescript.json` |
| Python | `.py`, `.pyi`, `.pyw` | `packages/rules/languages/python.json` |
| PowerShell | `.ps1`, `.psm1`, `.psd1`, `.ps1xml` | `packages/rules/languages/powershell.json` |
| Bash/sh | `.sh`, `.bash`, `.zsh`, `.ksh` (+ shell dotfiles) | `packages/rules/languages/bash.json` |
| PHP | `.php`, `.phtml`, `.php3`, `.php4`, `.php5`, `.phar` | `packages/rules/languages/php.json` |
| Ruby | `.rb`, `.rake`, `.gemspec`, `.ru` | `packages/rules/languages/ruby.json` |

## Tier 2

Full Layer B + Layer C coverage with in-tree fixtures, but less production
traffic than Tier 1.

| Language | Extensions | Config |
|---|---|---|
| Go | `.go` | `packages/rules/languages/go.json` |
| Rust | `.rs` | `packages/rules/languages/rust.json` |
| C# | `.cs`, `.csx` | `packages/rules/languages/csharp.json` |
| Java | `.java` | `packages/rules/languages/java.json` |
| Kotlin | `.kt`, `.kts` | `packages/rules/languages/kotlin.json` |
| Lua | `.lua` | `packages/rules/languages/lua.json` |
| Perl | `.pl`, `.pm`, `.t` | `packages/rules/languages/perl.json` |
| VBScript | `.vbs`, `.vbe`, `.wsf`, `.hta` | `packages/rules/languages/vbscript.json` |

## Tier 3

Files without a matching language config still receive Layer A universal
detectors (entropy, bidi, homoglyph, long-line, encoded-array fingerprint),
plus path-based manifest detectors when filenames match.

## Manifest detectors (Layer C)

These run by path/filename, independent of language tier.

| Detector | File pattern |
|---|---|
| `obf.manifest-install-script` | `package.json`, `composer.json`, `*.gemspec`, `*.rockspec`, `*.nuspec` |
| `obf.python-setup-side-effect` | `setup.py` |
| `obf.perl-makefile-side-effect` | `Makefile.PL`, `Build.PL` |
| `obf.cargo-build-rs-network` | `build.rs` |
| `obf.gha-curl-pipe-shell` | `.github/workflows/*.{yml,yaml}` |
| `obf.dockerfile-curl-pipe-shell` | `Dockerfile`, `Dockerfile.*` |

## Adding language coverage

To move a language from Tier 3 to Tier 2:

1. Add `packages/rules/languages/<lang>.json` that matches `_schema.json`.
2. Add malicious + benign fixtures under `packages/core/test/fixtures/`.
3. Run unit + fixtures suites and tune lists (`dynamic_exec_sinks`,
   `decoders`, `network_io`, etc.) for precision.

No core engine code changes are required for most language additions.
