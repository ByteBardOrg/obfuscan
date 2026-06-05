# Detectors

This file documents the detectors currently shipped in
`packages/core/src/detectors/`.

Rule-id format:

- Layer A + manifest/path rules: `obf.<name>`
- Layer B language-aware rules: `obf.<name>.<languageId>`

Example: `obf.decode-then-exec.python`.

## Layer A (universal text detectors)

These run on any readable text file.

### `obf.high-entropy-literal`
- Flags long string literals with high Shannon entropy.
- Severity: `warn`.

### `obf.bidi-control`
- Flags Unicode bidi control characters (Trojan Source family).
- Severity: `block`.

### `obf.homoglyph-identifier`
- Flags mixed-script identifiers (ASCII + confusable Cyrillic/Greek).
- Severity: `block`.

### `obf.long-line`
- Flags very long source lines.
- Thresholds: `>= 2000` chars (`info`), `>= 10000` chars (`warn`).

### `obf.encoded-array-fingerprint`
- Flags large arrays of encoded-looking string literals.
- Severity: `warn`.

## Layer B (language-aware, config-driven regex detectors)

These use `ctx.config` values from `packages/rules/languages/*.json`.

### `obf.decode-then-exec.<lang>`
- Flags decoder -> dynamic execution flow (direct, indirect, and co-located shapes).
- Severity: `block`.

### `obf.network-then-exec.<lang>`
- Flags network IO feeding dynamic execution.
- Severity: `block`.

### `obf.dynamic-exec-with-non-literal.<lang>`
- Flags dynamic execution with non-literal argument.
- Severity: `warn`.

### `obf.deserializer-untrusted.<lang>`
- Flags unsafe deserializer calls with non-literal arguments.
- Severity: `block`.

### `obf.suspicious-io-cluster.<lang>`
- Flags file-level cluster: secrets-path + network, or shell + network.
- Severity: `warn`.

### `obf.npm-c2-dropper`
- Flags JavaScript/TypeScript package code with C2 polling, decrypt-stage,
  write/chmod, and child-process launch signals.
- Severity: `block`.

### `obf.string-array-decoder.<lang>`
- Flags obfuscator-style string-array + decoder + sink pattern.
- Severity: `block`.

### `obf.shell-with-untrusted-input.<lang>`
- Flags shell execution with interpolated/concatenated command input.
- Severity: `warn`.

### `obf.library-load-non-literal.<lang>`
- Flags dynamic library/module loading with non-literal target.
- Severity: `warn`.

## Layer C (manifest/path detectors)

### `obf.manifest-install-script`
- Flags install/lifecycle hooks in:
  - `package.json`
  - `composer.json`
  - `*.gemspec`
  - `*.rockspec`
  - `*.nuspec`
- Severity: `warn`, escalates to `block` for network-pipe-shell shapes.

### `obf.python-setup-side-effect`
- Flags suspicious top-level side effects in `setup.py`.
- Severity: `block`.

### `obf.perl-makefile-side-effect`
- Flags suspicious top-level side effects in `Makefile.PL` / `Build.PL`.
- Severity: `block`.

### `obf.cargo-build-rs-network`
- Flags network behavior in `build.rs`.
- Severity: `block`.

### `obf.gha-curl-pipe-shell`
- Flags `curl|sh`-style execution in GitHub Actions workflows.
- Severity: `block`.

### `obf.dockerfile-curl-pipe-shell`
- Flags `RUN curl|sh`-style execution in Dockerfiles.
- Severity: `block`.

## Notes

- The shipped engine does not run tree-sitter queries by default.
- Hosts can add AST-based custom detectors via `ScanOptions.detectors` and
  optional `RuleSet.loadGrammar` overrides.
