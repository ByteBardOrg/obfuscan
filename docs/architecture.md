# Architecture

This document describes how `@obfuscan/core` turns a diff (or a set of files)
into a list of findings. (`dir` is an accepted input shape but is currently a
host-managed/reserved mode.) It is organized top-down: the public
entry point, then each pipeline stage, then the extension points.

The goal of this doc is to match the **shipped** code in
`packages/core/src/`. If you find a divergence, the code is the source of
truth — please file a docs bug.

## Pipeline

```
              ┌──────────────────────────────────────────────────┐
ScanInput ───►│  1. Validate input; resolve files & content      │
              ├──────────────────────────────────────────────────┤
              │  2. Build FileContext (path, languageId, config, │
              │     source, addedRanges, lazy grammar+tree)      │
              ├──────────────────────────────────────────────────┤
              │  3. Run detectors per file (concurrency-bounded) │
              │     ─ Layer A: regex / text                      │
              │     ─ Layer B: regex over ctx.source, gated by   │
              │                per-language config               │
              │     ─ Layer C: manifest-shaped detectors         │
              ├──────────────────────────────────────────────────┤
              │  4. Per-finding filtering: diff addedRanges,     │
              │     in-source disable directives, allowlist,     │
              │     minSeverity floor                            │
              ├──────────────────────────────────────────────────┤
              │  5. Sort by (severity desc, score desc, file,    │
              │     line) and freeze; return ScanResult          │
              └──────────────────────────────────────────────────┘
                                      │
                                      ▼
                                 ScanResult
```

Each stage is described below.

---

## 1. Input resolution

`ScanInput` accepts **exactly one of three** shapes — passing zero or more
than one throws `InvalidScanInputError`:

```ts
interface ScanInput {
  diff?: string;             // unified diff; scans only changed files
  paths?: readonly string[]; // explicit list of workspace-relative paths
  dir?: string;              // reserved input shape; see note below
}
```

Today, `dir` is accepted for API compatibility but core does not walk the
filesystem. `scan()` currently returns an empty target list for `dir` unless
the host expands files and calls with `paths`.

When `diff` is provided, `parseDiffToFiles()` extracts:
- The path of each modified file.
- Its `status`: `added` / `modified` / `deleted`.
- The `addedRanges`: 1-based, inclusive line ranges in the post-image.

The engine never reads from disk directly. All I/O goes through the
caller-supplied `fileResolver: (path) => Promise<string | null>`. This is
what makes the engine embeddable: the test harness uses an in-memory map,
the CLI uses `fs.readFile`, a Git GUI uses `git cat-file`. `fileResolver` is
**required** — including for `dir` input.

## 2. FileContext construction

For each file, the engine builds a `FileContext`. The shape is exactly:

```ts
interface FileContext {
  readonly path: string;
  readonly languageId: string | null;          // null when language unknown
  readonly config: LanguageConfig | null;      // null when no per-lang config
  readonly source: string;
  /** 1-based, inclusive line ranges added by the diff.
   *  Empty array (not undefined) when scanning a full file. */
  readonly addedRanges: ReadonlyArray<readonly [number, number]>;
  /** Lazily populated on first ctx.tree() call.
   *  Stays null with the default RuleSet (no parser bundled). */
  readonly grammar: GrammarHandle | null;
  /** Lazy parsed tree. Returns null unless a host RuleSet provides
   *  GrammarHandle.parse — see docs/tree-sitter.md. */
  tree(): Promise<unknown | null>;
}
```

`addedRanges` is the diff-awareness primitive. The aggregator drops any
finding whose `line` is outside `addedRanges` when the input was a diff —
detectors don't need to filter themselves, but they may use `addedRanges` to
short-circuit work (and several do).

## 3. Detector execution

Detectors implement:

```ts
interface Detector {
  readonly id: string;                              // "obf.decode-then-exec.javascript"
  readonly docsUrl?: string;
  applies(ctx: FileContext): boolean;               // cheap path/lang filter
  run(ctx: FileContext): Finding[] | Promise<Finding[]>;
}
```

Note: `run()` takes only `ctx`; it does not receive a `RuleSet`. Detectors
read the per-language config via `ctx.config`, which the engine has already
resolved.

The engine processes files concurrently up to `ScanOptions.concurrency`
(default `Math.max(2, defaultConcurrency())`, where `defaultConcurrency()`
uses `navigator.hardwareConcurrency` when available and falls back to `4`).
Within a file, detectors run
sequentially. Each detector is wrapped in a per-file timeout
(`ScanOptions.fileTimeoutMs`, default 5000ms); a timeout drops that
detector's findings for that file and records the detector id in
`ScanResult.failedDetectors`. Errors thrown by a detector are caught and
likewise recorded — they never propagate.

Note: timeout enforcement is strongest for async detector paths. Synchronous
regex work cannot be preempted mid-execution, so shipped detectors also use
size guards and cheap `applies()` filters.

`failedDetectors` is `readonly string[]` (deduplicated detector ids), not a
list of error objects. Detailed failures are routed through
`ScanOptions.logger`.

### Layer A — regex / text

Pure JavaScript. No grammar dependency. Each detector registers one or more
regexes plus a small post-filter (e.g. entropy threshold, length floor).
These detectors run on every `FileContext`, including files in languages
with no per-language config.

### Layer B — parameterized

The shipped Layer B detectors are **regex-driven over `ctx.source`**, gated
by the per-language JSON config supplied via `ctx.config` (sinks, decoders,
etc.). They emit IDs of the form `obf.<rule>.<lang>` and read names from
`rules/languages/<lang>.json`. No grammar is loaded by default — the engine
has zero native dependencies.

The `RuleSet` interface still exposes `loadGrammar(id) -> GrammarHandle`, and
`FileContext.tree()` is wired to call `grammar.parse(source)` if the host
supplied one. The shared `.scm` queries under `rules/queries/shared/*.scm` and
the per-grammar shims under `rules/queries/per-grammar/<grammar>.scm` are
shipped as a reference for hosts that want to author AST-based detectors;
the bundled engine does not load them. Full integration contract:
[`docs/tree-sitter.md`](./tree-sitter.md).

This is what makes "add a language" a config change: the regex shapes don't
move, the per-language config supplies the name lists, and the queries are
available verbatim for hosts who want to upgrade to AST precision.

### Layer C — manifest

Detectors keyed by filename, not language. `obf.manifest-install-script`
runs only on files whose path basename is `package.json`, `composer.json`,
`*.gemspec`, `*.rockspec`, or `*.nuspec`. They use simple JSON / XML / text
parsing — no tree-sitter.

## 4. Per-finding filtering

After a detector returns, each finding goes through four filters. A finding
that fails any filter is dropped — there is no synthetic "cluster" finding
or aggregate severity escalation. (If you need that, layer it on as a
post-processor over `ScanResult.findings`.)

1. **Diff filter.** If the input was a `diff`, the finding is kept only when
   its `line` falls inside one of the file's `addedRanges`.
2. **Disable directives.** `obfuscan-disable-line` and
   `obfuscan-disable-next-line <ruleId,ruleId>` are honored by a line-based
   regex parser. The parser does not currently validate language comment
   syntax; if the directive text appears on a line, it is treated as a
   directive.
3. **Allowlist.** Two entry types:
    - **Path entries** match the file path against a glob and optionally cap
      severity (findings at or below the cap are suppressed; findings above
      the cap are kept).
   - **Snippet entries** match `(ruleId, sha256(normalized snippet))`
     exactly. Snippet normalization collapses runs of whitespace before
     hashing, so suppressions survive reformatters.
4. **`minSeverity` floor.** Findings below `ScanOptions.minSeverity`
   (default `"info"`, i.e. keep everything) are dropped.

## 5. Output

`ScanResult` is sorted deterministically. The comparator is in `scan.ts`
and is asserted by `scan.contract.test.ts` — changing it is a SemVer
breaking change.

1. **Severity, descending by rank.** `block` first, then `warn`, then `info`.
2. **Score, descending.** Ties on severity break by score (0–10).
3. **File, ascending lexicographic.** Ties on score break by path.
4. **Line, ascending.** Final tiebreaker.

The full result shape is:

```ts
interface ScanResult {
  readonly findings: readonly Finding[];
  readonly files: ReadonlyArray<{ path: string; languageId: string | null }>;
  readonly durationMs: number;
  readonly failedDetectors: readonly string[];
  readonly rulesVersion: string;
  readonly engineVersion: string;
}
```

`findings` and `files` are frozen. There is no nested `stats` object; the
top-level fields are the entire surface.

---

## Extension points

### Custom detectors

Pass `ScanOptions.detectors = [...defaultDetectors(), myDetector]` to
extend. `defaultDetectors()` returns the engine's built-in list as a
frozen array; user detectors can be appended, prepended, or filtered. To
disable a built-in by id without rebuilding the array, use
`ScanOptions.disabledDetectors = ["obf.high-entropy-literal"]`.

The contract: a detector that throws gets caught and recorded. A detector
that exceeds `ScanOptions.fileTimeoutMs` is dropped for that file.

### Custom rule sets

`ScanOptions.rules` accepts a `RuleSet` built by `loadRuleSet({
languageDir })`. This loads per-language JSON configs from an arbitrary
directory and returns a `RuleSet` whose `loadGrammar` is a stub. Hosts that
want real parsing override `loadGrammar` themselves — see
[`docs/tree-sitter.md`](./tree-sitter.md).

`loadRuleSet` accepts an optional `queryDir` argument; today it is reserved
for forward compatibility and not consumed by the engine.

### Custom file resolver

`ScanOptions.fileResolver` is mandatory. The test harness uses one backed by an in-memory map.

### Allowlists

Allowlists are programmatic (`ScanOptions.allowlist`) or on-disk
(`.obfuscan/allowlist.json`). The on-disk file is **not** auto-loaded by
the core; callers (CLI, host integrations) read it with `loadAllowlist()`
and pass it via `ScanOptions.allowlist`. This keeps the engine I/O-free
beyond `fileResolver`.

---

## What's deliberately not in `@obfuscan/core`

These belong to separate packages so the core stays small and embeddable:

- **CLI** — `@obfuscan/cli` (separate package, not in this scaffold).
- **GitHub Action** — `obfuscan/obfuscan-action` (separate repo, not in
  this scaffold).
- **Default rule pack** — `@obfuscan/rules`. CalVer, releases more often
  than core. Resolved at runtime from a workspace sibling, an installed
  `node_modules/@obfuscan/rules`, or `OBFUSCAN_RULES_DIR`.

Splitting the rule pack from the engine is the most consequential
decision: it lets us ship rule updates without an engine release, and it
lets organizations pin to a specific rule version for reproducible audits.

---

## Performance model

The shipped engine has no tree-sitter dependency; wall-clock cost is
dominated by **regex evaluation over `ctx.source`**, file I/O via
`fileResolver`, and the per-file orchestrator overhead. Layer A is
trivially cheap; Layer C is dominated by I/O and JSON parsing.

The perf suite (`packages/core/test/perf/`) runs in two profiles:

- Default (`npm run test:perf`): 10k-line JS, 100KB single-line ReDoS shape,
  deep nesting, scaling ratio, and timeout behavior.
- Full (`OBFUSCAN_PERF_FULL=1 npm run test:perf`): adds the 100k-line budget.

Per-file timeouts (`ScanOptions.fileTimeoutMs`, default 5000ms) are the
failsafe: a pathological file's detector is aborted, the detector id is
added to `failedDetectors`, and the scan continues. Individual detectors
short-circuit on sources larger than `MAX_SOURCE_BYTES` (2 MB, defined in
`src/internal/patterns.ts`) so a single huge generated file can't blow up
any one detector's regex. The two together are the contract that lets
obfuscan run on every PR without ever hanging the build.

Hosts that wire in tree-sitter via `GrammarHandle.parse` shift the cost
profile — parsing then dominates Tier-1/Tier-2 files. See
[`docs/tree-sitter.md`](./tree-sitter.md) for the parser-caching pattern.
