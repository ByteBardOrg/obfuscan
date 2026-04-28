# Contributing to obfuscan

Thanks for considering a contribution. This project lives or dies on **rule quality and rule churn**, so the most valuable contributions are usually small.

The fastest paths to merged PRs, in order:

1. **Add a sink/decoder** to an existing language config (1-line PR).
2. **Add a new language config** from `_template.json` (~50-line PR).
3. **Add a fixture** to the regression corpus showing a real attack we missed (~10-line PR + a comment with the source).
4. **Report a false positive** with a minimal reproducer (issue, not PR).
5. **Add a new manifest detector** (e.g. for a CI system we don't cover).
6. **Engine work** — last because it changes API surface.

## TL;DR for the common case

You spotted a sink we don't catch in language X. Open `packages/rules/languages/X.json`, add the fully-qualified name to the relevant array, run the tests, open a PR.

```bash
git clone https://github.com/bytebardorg/obfuscan
cd obfuscan
cd packages/core
npm ci --legacy-peer-deps
npm run test:all
```

If the core test suite passes, your PR is in good shape.

## What goes in `dynamic_exec_sinks` vs `decoders` vs ...

The lists in each language config are deliberately narrow. Use this as the test:

| List | Test |
|---|---|
| `dynamic_exec_sinks` | Does this function execute its first non-literal argument as code or bytecode? |
| `decoders` | Does this function turn opaque bytes/strings back into something an attacker would want to execute? Base64, hex, gunzip, decrypt, deserialize-to-string. |
| `deserializers` | Does this function materialize attacker-controlled objects/code? `pickle.loads`, `BinaryFormatter.Deserialize`, `ObjectInputStream.readObject`, `Marshal.load`, `yaml.load`. |
| `network_io` | Does this function make an outbound network connection? |
| `secrets_io` | Does this function read environment, credentials, keychains, or browser stores? |
| `shell_exec` | Does this function spawn an OS process? Distinct from in-process eval. |
| `library_load` | Does this function load a dynamic library or in-memory assembly? |

If you're unsure which list, **err on the side of leaving it out** rather than adding it to two. The detector framework boosts scores when sinks combine with decoders or network calls — duplication double-counts.

### What does *not* go in

- **Standard library functions that are merely common.** `console.log`, `print`, `String.prototype.replace`. These produce noise without signal.
- **Functions that *can* be misused but require a specific argument shape.** Those belong in language-specific detectors under `detectors/lang-specific/<lang>.ts`.
- **Functions only dangerous in old runtimes.** If `assert($s)` was deprecated in PHP 7.2 and removed in 8.0, document it but keep the rule — old shells still appear in audits.

### Naming convention

Use the **fully qualified name as users actually write it in source**, not the runtime name. For example:

- Python: `base64.b64decode` (not `b64decode` or `_pybase64.b64decode`).
- Node: `child_process.exec` (not `exec` or `cp.exec`).
- .NET: `System.Convert.FromBase64String` (full namespace).
- PowerShell: `[System.Convert]::FromBase64String` *and* `[Convert]::FromBase64String` if the short form is commonly used.

The FQN resolver handles import aliases, destructuring (`const { exec } = require('child_process')`), `using` directives, and `from x import y as z`. You don't need to enumerate aliases.

## Adding a new language

For the default scanner, adding a language is primarily a rules-and-fixtures change:

1. **`packages/rules/languages/<id>.json`** — copy `_template.json` and fill in the lists. The `id` must match the tree-sitter grammar's package name (`tree-sitter-<id>`).
2. **Fixtures** — add at least one malicious and one benign fixture under `packages/core/test/fixtures/`.

Tree-sitter query support is optional and host-provided. If you are maintaining a host integration or custom parser-backed detector, also add `packages/rules/queries/per-grammar/<id>.scm` to map that grammar's node names onto the normalized captures (`@call`, `@callee`, `@first-arg`, `@decoder`, `@netcall`, `@array`). `@obfuscan/rules` ships query text, not parser grammars, and the default `@obfuscan/core` engine does not execute these `.scm` queries by itself.

A complete checklist:

- [ ] `languages/<id>.json` follows `packages/rules/languages/_schema.json`.
- [ ] At least one malicious fixture shows the language's canonical malware shape.
- [ ] At least one benign-but-tricky fixture prevents obvious false positives.
- [ ] `cd packages/core && npm run test:all` passes.
- [ ] Add the language to the coverage table in `README.md`.

If the language has obfuscation patterns that don't fit the generic detectors (PowerShell backtick-escapes, bash `${!var}`, PHP `assert($dyn)`, Python `cmdclass`, Rust `build.rs`), open an issue or PR that explains the shape and includes fixtures. Keep language-specific detector code rare — every detector is maintenance debt.

## Fixture conventions

Every detector change needs a fixture. Two kinds:

```
fixtures/
  malicious/
    <lang>/
      <case>/
        input.<ext>          # the malicious source
        expected.json        # findings we expect
        SOURCE.md            # where this came from (URL, CVE, advisory)
  benign/
    <lang>/
      <case>/
        input.<ext>
        expected.json
        SOURCE.md            # why this looks suspicious but is benign
```

`expected.json` declares rule-id prefixes with `mustFlag`, `mustNotFlag`, `mustBlock`, or `expectClean`. Extra findings are tolerated unless a benign fixture emits a `block` finding.

For real-world malware samples, **never commit the live payload**. Truncate or replace the executable portion with a stub that preserves the syntactic shape. The detector's job is to flag the shape, not to run the malware.

## False-positive reports

False positives kill adoption faster than missed detections. To report one:

1. Open an issue with the **minimal source snippet** that triggers the wrong finding.
2. Include the **`ruleId`** and **`obfuscan` version**.
3. Explain **why this code is legitimate** — be specific, "it's our internal tool" is not enough. "It's the WebAssembly polyfill loader from `@stdlib/wasm`, used at module init" is.

We treat FPs as severity-1 bugs. The fix is usually one of:

- **Tighten the sink list**: remove an entry that fires on too much legitimate code.
- **Tighten a query**: add a path predicate (`#not-in-test-file?`) or scope the match.
- **Add a built-in suppression**: e.g. "skip `obf.high-entropy-literal` inside a `cryptography` test vector file with a known-good hash."
- **Lower the score**: demote a rule from `block` to `warn`.

## Engine contributions

Detector framework, scoring, aggregation, suppression, the flow walker. Higher bar than rule changes:

- API surface changes need an RFC issue first.
- All changes must be diff-aware: a finding on a line not in `addedRanges` is a bug.
- Performance: a 10k-line file should scan in < 500ms on a 2020 laptop. Add a benchmark fixture if you change anything in the parse / query / flow path.
- Memory: trees and queries are cached per-process; new caches need explicit eviction policy.

## Code style

- TypeScript strict mode, no `any` unless documented.
- Keep formatting consistent with the surrounding file. Dedicated lint/format tooling has not landed yet.
- Public API is exported only from `packages/core/src/index.ts`. Anything not re-exported there is internal and may change without notice.
- Detectors never throw to the pipeline — catch and log internally. One bad detector must not kill a scan.

## Commit and PR conventions

- Conventional Commits (`feat(rules): add Marshal.load to ruby deserializers`).
- One logical change per PR.
- Rule-only PRs: title prefix `rules:`. They go through a faster review path and ship in the next `@obfuscan/rules` patch.
- Engine PRs: title prefix `core:`. They wait for a `@obfuscan/core` minor release.

## Code of Conduct

We follow the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Be kind. Security communities are small and reputations are forever.

## Licensing of contributions

By submitting a PR you agree your contribution is licensed under Apache-2.0 (same as the project). No CLA required.

## Questions?

Open a discussion. Issues are for tracked work; discussions are for "is this even the right approach."
