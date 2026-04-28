/**
 * @obfuscan/core — public entry point.
 *
 * Stable API surface. Anything not re-exported here is internal and may
 * change without a major version bump.
 *
 * ## Quick start
 *
 * ```ts
 * import { scan } from "@obfuscan/core";
 * import * as fs from "node:fs/promises";
 *
 * const result = await scan(
 *   { diff: await fs.readFile("pr.diff", "utf8") },
 *   { fileResolver: (p) => fs.readFile(p, "utf8") },
 * );
 *
 * for (const f of result.findings) {
 *   console.log(`${f.severity.toUpperCase()} ${f.file}:${f.line} ${f.reason}`);
 * }
 * ```
 *
 * ## Custom rules
 *
 * ```ts
 * import { scan, loadRuleSet } from "@obfuscan/core";
 *
 * const rules = await loadRuleSet({
 *   languageDir: "./my-rules/languages",
 *   queryDir:    "./my-rules/queries",
 * });
 *
 * const result = await scan({ dir: "./src" }, { fileResolver, rules });
 * ```
 *
 * ## Custom detectors
 *
 * ```ts
 * import { scan, defaultDetectors, Detector } from "@obfuscan/core";
 *
 * const myDetector: Detector = {
 *   id: "my-org.no-fetch-in-tests",
 *   applies: (ctx) => /\.test\./.test(ctx.path),
 *   run: (ctx) => /* ... *\/ [],
 * };
 *
 * const result = await scan(input, {
 *   fileResolver,
 *   detectors: [...defaultDetectors(), myDetector],
 * });
 * ```
 */

// ─── Primary entry point ───────────────────────────────────────────────────

export { scan } from "./scan.js";

// ─── Types ─────────────────────────────────────────────────────────────────

export type {
  // findings
  Severity,
  Finding,
  // configuration
  LanguageConfig,
  RuleSet,
  GrammarHandle,
  PathAllowlistEntry,
  SnippetAllowlistEntry,
  Allowlist,
  // scan input/options
  ScanInput,
  ScanOptions,
  ScanProgress,
  ScanResult,
  FileResolver,
  SymbolResolver,
  Logger,
  // detector plugin
  Detector,
  FileContext,
} from "./types.js";

// ─── Rule loading ──────────────────────────────────────────────────────────

/**
 * Load a custom rule set from disk. Use this to point obfuscan at a fork of
 * `@obfuscan/rules` or at an internal extension. If you only need the
 * defaults, omit `rules` from `ScanOptions` and the built-in pack is used.
 */
export { loadRuleSet, defaultRuleSet } from "./rules.js";

// ─── Detectors ─────────────────────────────────────────────────────────────

/**
 * The shipped detector set. Use this as a base when you want to add or
 * filter detectors:
 *
 * ```ts
 * const dets = defaultDetectors().filter(d => d.id !== "obf.high-entropy-literal");
 * ```
 */
export { defaultDetectors } from "./detectors/index.js";

// ─── Allowlist helpers ─────────────────────────────────────────────────────

/**
 * Read/write `.obfuscan/allowlist.json`. The CLI uses these directly.
 * Programmatic users typically pass an inline `allowlist` to `scan()`
 * instead of touching disk.
 */
export {
  loadAllowlist,
  saveAllowlist,
  hashSnippet,
  matchesAllowlist,
} from "./allowlist.js";

// ─── Diff utilities ────────────────────────────────────────────────────────

/**
 * Parse a unified diff into the shape `scan()` consumes internally.
 * Exposed for hosts (e.g. a Git client) that already have a structured diff
 * representation and want to skip re-serializing.
 */
export { parseDiffToFiles } from "./diff.js";
export type { DiffFile } from "./diff.js";

// ─── In-source suppression directives ──────────────────────────────────────

/**
 * Parses `// obfuscan-disable-next-line <ruleId>` and similar comment
 * directives. Returns the set of (line, ruleId) pairs to suppress.
 * Used internally by the aggregator; exposed for tooling that wants to
 * surface them in a UI.
 */
export { extractDisableDirectives } from "./directives.js";
export type { DisableDirective } from "./directives.js";

// ─── Versions ──────────────────────────────────────────────────────────────

/** SemVer of the engine. Replaced at build time via `__ENGINE_VERSION__`. */
export { ENGINE_VERSION } from "./version.js";

// ─── Errors ────────────────────────────────────────────────────────────────

/**
 * `InvalidScanInputError` — thrown when `ScanInput` is missing all of
 * `diff`, `paths`, `dir`, or specifies more than one.
 *
 * `InvalidRuleSetError` — thrown when a custom rule set fails validation.
 * Includes a `details` array describing each problem.
 */
export { InvalidScanInputError, InvalidRuleSetError } from "./errors.js";
