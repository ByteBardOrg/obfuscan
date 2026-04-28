/**
 * Public type surface of @obfuscan/core.
 *
 * Anything exported from this file is part of the SemVer-stable API.
 * Internal types live in src/internal/* and may change without notice.
 */

// ─── Findings ──────────────────────────────────────────────────────────────

export type Severity = "info" | "warn" | "block";

export interface Finding {
  /** Stable rule id, e.g. "obf.decode-then-exec.python". */
  ruleId: string;
  /** Aggregated severity after scoring. */
  severity: Severity;
  /** 0..10. Aggregator clamps to 10. */
  score: number;
  /** Workspace-relative path. */
  file: string;
  /** 1-based line number where the finding starts. */
  line: number;
  /** 1-based line number where the finding ends. Optional; defaults to `line`. */
  endLine?: number;
  /** Up to 200 chars of the matched source. Truncated with ellipsis if longer. */
  snippet: string;
  /** Human-readable explanation suitable for direct display in a code review UI. */
  reason: string;
  /** Optional fully-qualified function name(s) the finding lives inside. Populated when the host provides a symbol resolver. */
  enclosingSymbol?: string;
  /** Detector-specific structured data. Stable per ruleId. */
  evidence?: Readonly<Record<string, unknown>>;
}

// ─── Configuration ─────────────────────────────────────────────────────────

/** Per-language config loaded from rules/languages/*.json. */
export interface LanguageConfig {
  readonly id: string;
  readonly aliases?: readonly string[];
  readonly extensions: readonly string[];
  readonly filenames?: readonly string[];

  readonly dynamic_exec_sinks: readonly string[];
  readonly decoders: readonly string[];
  readonly deserializers?: readonly string[];
  readonly network_io?: readonly string[];
  readonly secrets_io?: readonly string[];
  readonly shell_exec?: readonly string[];
  readonly library_load?: readonly string[];

  readonly obfuscator_id_patterns?: readonly string[];
  readonly min_mean_identifier_length?: number;
  readonly obfuscator_id_min_ratio?: number;

  readonly string_concat_operators?: readonly string[];
  readonly language_specific_detectors?: readonly string[];
  readonly manifests?: readonly string[];
  readonly notes?: string;
}

/** Provider for language configs and tree-sitter grammars/queries. */
export interface RuleSet {
  /** Language ids this ruleset supports. */
  languages(): readonly string[];
  /** Look up a config by language id. Returns null if unsupported. */
  configFor(languageId: string): LanguageConfig | null;
  /** Map a file path to a language id, or null if unknown. */
  detectLanguage(path: string): string | null;
  /** Load the parser+queries for a language. Implementations may cache. */
  loadGrammar(languageId: string): Promise<GrammarHandle>;
  /** Calver version of the rule pack (e.g. "2026.04.0"). */
  version(): string;
}

/**
 * Opaque handle to a loaded tree-sitter parser and (optionally) its compiled
 * queries. The default `RuleSet` returns a stub handle with no `parse` and no
 * `_internal` because the bundled detectors are regex-driven — see
 * `docs/tree-sitter.md` for how hosts plug in a real parser.
 */
export interface GrammarHandle {
  /** The tree-sitter grammar id (e.g. "javascript", "python"). */
  readonly id: string;
  /**
   * Internal field reserved for the engine. Hosts that wrap a real
   * tree-sitter `Language` typically stash it here.
   */
  readonly _internal: unknown;
  /**
   * Optional source -> tree parser. When present, `FileContext.tree()` calls
   * this on first access and caches the result. The returned value is
   * `unknown` to keep the engine parser-agnostic; hosts and host-supplied
   * detectors agree on its shape (typically a `Tree` from `web-tree-sitter`
   * or `tree-sitter`).
   */
  parse?: (source: string) => unknown | Promise<unknown>;
}

/** Path-pattern-based suppression. Matched against POSIX-style relative paths. */
export interface PathAllowlistEntry {
  /** Glob in minimatch syntax. */
  pattern: string;
  /** Severity ceiling: findings below this severity are suppressed entirely on matching files. */
  maxSeverity?: Severity;
  /** Optional rule id filter; if omitted, applies to all rules. */
  ruleId?: string;
  /** Optional reviewer-visible reason. */
  reason?: string;
}

/** Per-finding suppression keyed by `(ruleId, sha256(snippet))`. */
export interface SnippetAllowlistEntry {
  ruleId: string;
  /** sha256 hex of the matched snippet. */
  snippetHash: string;
  reason?: string;
  /** ISO-8601 timestamp set by the CLI when added. */
  added?: string;
  /** Optional GitHub login or email of the user who added it. */
  addedBy?: string;
}

export interface Allowlist {
  paths?: readonly PathAllowlistEntry[];
  snippets?: readonly SnippetAllowlistEntry[];
}

// ─── Scan input ────────────────────────────────────────────────────────────

/**
 * Reads file content for the scanner.
 *
 * `path` is workspace-relative. The resolver should return the **post-image**
 * (after the diff is applied) when scanning a diff. For a directory scan, it
 * returns the current file content.
 *
 * Return `null` for files that don't exist or that the host wants to skip
 * silently (e.g. binary files filtered upstream).
 */
export type FileResolver = (path: string) => Promise<string | null>;

/** Optional symbol resolver for `Finding.enclosingSymbol`. */
export type SymbolResolver = (
  path: string,
  line: number,
) => Promise<string | null>;

/** A source of files to scan. Exactly one of `diff`, `paths`, or `dir` must be set. */
export interface ScanInput {
  /** Unified diff content. The scanner extracts changed files and added line ranges. */
  diff?: string;
  /** Explicit file list (workspace-relative paths). The whole file is scanned. */
  paths?: readonly string[];
  /** Directory to scan recursively. */
  dir?: string;
}

export interface ScanOptions {
  /** Reads file content. Required when scanning a diff. */
  fileResolver: FileResolver;
  /** Optional symbol resolver for nicer findings. */
  symbolResolver?: SymbolResolver;
  /** Override the rules pack. Defaults to the built-in `@obfuscan/rules`. */
  rules?: RuleSet;
  /** Allowlist to apply. Merged with anything loaded from `.obfuscan/allowlist.json`. */
  allowlist?: Allowlist;
  /** Hard limit on concurrent file scans. Default: `Math.max(2, os.cpus().length - 1)`. */
  concurrency?: number;
  /** Per-file timeout in ms. Default: 5000. Files that time out emit a single `info` finding and are skipped. */
  fileTimeoutMs?: number;
  /** Severity threshold below which findings are dropped entirely. Default: `"info"`. */
  minSeverity?: Severity;
  /** Optional progress callback. */
  onProgress?: (progress: ScanProgress) => void;
  /** Optional logger; defaults to `console` for warnings, silent for everything else. */
  logger?: Logger;
  /** Disable specific detectors by id (e.g. `["obf.high-entropy-literal"]`). */
  disabledDetectors?: readonly string[];
  /**
   * Override the detector list entirely. When omitted, `defaultDetectors()` is used.
   * Provide an explicit list to extend (`[...defaultDetectors(), myDetector]`) or replace
   * the default set. `disabledDetectors` is applied on top of whichever list is in effect.
   */
  detectors?: readonly Detector[];
}

export interface ScanProgress {
  filesTotal: number;
  filesDone: number;
  currentFile?: string;
}

export interface Logger {
  debug(msg: string, meta?: unknown): void;
  info(msg: string, meta?: unknown): void;
  warn(msg: string, meta?: unknown): void;
  error(msg: string, meta?: unknown): void;
}

// ─── Detector plugin interface ─────────────────────────────────────────────

/** A file as the detectors see it. */
export interface FileContext {
  readonly path: string;
  readonly languageId: string | null;
  readonly config: LanguageConfig | null;
  readonly source: string;
  /** 1-based, inclusive line ranges that were added by the diff. Empty when scanning a full file. */
  readonly addedRanges: ReadonlyArray<readonly [number, number]>;
  /** Lazy parser handle. `null` when no grammar is available for this language. */
  readonly grammar: GrammarHandle | null;
  /** Convenience: the parsed tree, populated on first access. */
  tree(): Promise<unknown | null>;
}

/** Detectors are pure: same input → same output. They must not throw to the pipeline. */
export interface Detector {
  /** Stable detector id. Becomes part of `Finding.ruleId`. */
  readonly id: string;
  /** Documentation URL, optional. Surfaced in findings for users who want to learn more. */
  readonly docsUrl?: string;
  /** Whether this detector applies to a given file. Cheap; called once per file. */
  applies(ctx: FileContext): boolean;
  /** Run the detector. Must catch its own errors. Returns findings synchronously or as a promise. */
  run(ctx: FileContext): Finding[] | Promise<Finding[]>;
}

// ─── Aggregation ───────────────────────────────────────────────────────────

export interface ScanResult {
  /** Aggregated, sorted findings. Sorted by `(severity desc, score desc, file, line)`. */
  findings: readonly Finding[];
  /** Files scanned and their language. */
  files: ReadonlyArray<{ path: string; languageId: string | null }>;
  /** Total wall-clock time in ms. */
  durationMs: number;
  /** Detector ids that failed internally on at least one file (logged, not thrown). */
  failedDetectors: readonly string[];
  /** Rule pack version used. */
  rulesVersion: string;
  /** Engine version used. */
  engineVersion: string;
}
