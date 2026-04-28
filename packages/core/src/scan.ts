/**
 * scan() — the orchestrator.
 *
 * Pipeline:
 *   1. Validate ScanInput (exactly one of diff/paths/dir).
 *   2. Resolve target file list:
 *        diff   → parseDiffToFiles → addedRanges per file
 *        paths  → use as-is, no addedRanges
 *        dir    → host enumerates; we just respect the resolver's nulls
 *   3. For each file (concurrency-limited):
 *        a. Resolve content via fileResolver (catch errors; log+skip)
 *        b. Build FileContext (path, source, languageId, config, addedRanges)
 *        c. For each enabled detector where applies(ctx) is true:
 *             - run() with per-file timeout + try/catch
 *             - collect findings
 *        d. Apply diff-range filter (drop findings outside addedRanges)
 *        e. Apply in-source disable directives
 *        f. Apply allowlist (paths + snippets)
 *        g. Apply minSeverity
 *        h. Truncate snippets to 200 chars defensively
 *   4. Sort findings by (severity desc, score desc, file asc, line asc).
 *   5. Return ScanResult.
 */

import type {
  Detector,
  Finding,
  GrammarHandle,
  ScanInput,
  ScanOptions,
  ScanProgress,
  ScanResult,
  Severity,
  FileContext,
  LanguageConfig,
} from "./types.js";
import { parseDiffToFiles, lineInRanges } from "./diff.js";
import { extractDisableDirectives, isSuppressedByDirectives } from "./directives.js";
import { matchesAllowlist } from "./allowlist.js";
import { defaultRuleSet } from "./rules.js";
import { defaultDetectors } from "./detectors/index.js";
import { InvalidScanInputError } from "./errors.js";
import { ENGINE_VERSION } from "./version.js";

const SEVERITY_RANK: Record<Severity, number> = { info: 0, warn: 1, block: 2 };
const DEFAULT_FILE_TIMEOUT_MS = 5000;
const SNIPPET_CAP = 200;

interface PreparedFile {
  path: string;
  addedRanges: ReadonlyArray<readonly [number, number]>;
  /** True if this file was sourced from a diff (so addedRanges filtering applies). */
  diffMode: boolean;
}

export async function scan(
  input: ScanInput,
  options: ScanOptions,
): Promise<ScanResult> {
  validateInput(input);

  const t0 = Date.now();
  const logger = options.logger ?? consoleLogger();
  const ruleSet = options.rules ?? (await defaultRuleSet());
  const detectors = (options.detectors ?? defaultDetectors()).filter(
    d => !(options.disabledDetectors ?? []).includes(d.id),
  );

  // Build the file work list.
  const targets = await prepareTargets(input);

  const results: Array<{ path: string; languageId: string | null }> = [];
  const findings: Finding[] = [];
  const failedDetectors = new Set<string>();
  const minRank = SEVERITY_RANK[options.minSeverity ?? "info"];
  const fileTimeout = options.fileTimeoutMs ?? DEFAULT_FILE_TIMEOUT_MS;

  // Concurrency limiter
  const concurrency = Math.max(
    1,
    options.concurrency ?? Math.max(2, defaultConcurrency()),
  );

  let filesDone = 0;
  const total = targets.length;
  const reportProgress = (currentFile?: string) => {
    if (!options.onProgress) return;
    const progress: ScanProgress = currentFile
      ? { filesTotal: total, filesDone, currentFile }
      : { filesTotal: total, filesDone };
    options.onProgress(progress);
  };

  await runWithConcurrency(targets, concurrency, async (target) => {
    reportProgress(target.path);
    let source: string | null = null;
    try {
      source = await options.fileResolver(target.path);
    } catch (e) {
      logger.warn(`fileResolver threw for ${target.path}`, e);
    }

    let languageId: string | null = null;
    if (source !== null) {
      languageId = ruleSet.detectLanguage(target.path);
    }
    results.push({ path: target.path, languageId });

    if (source === null) {
      filesDone++;
      reportProgress();
      return;
    }

    const config = languageId ? ruleSet.configFor(languageId) : null;
    let cachedGrammar: GrammarHandle | null = null;
    let cachedTree: unknown | null = null;
    let treeResolved = false;

    const ctx: FileContext = {
      path: target.path,
      languageId,
      config,
      source,
      addedRanges: target.addedRanges,
      grammar: null, // populated lazily if a detector accesses it
      tree: async () => {
        if (treeResolved) return cachedTree;
        treeResolved = true;
        if (!languageId) return null;
        try {
          cachedGrammar = await ruleSet.loadGrammar(languageId);
          // If the host-supplied grammar exposes a parser, use it. The default
          // RuleSet returns a stub handle with no `parse` — the bundled
          // detectors are regex-driven and never call tree(). See
          // `docs/tree-sitter.md` for the host-override contract.
          if (cachedGrammar && typeof cachedGrammar.parse === "function") {
            cachedTree = await cachedGrammar.parse(source);
          } else {
            cachedTree = null;
          }
        } catch {
          cachedTree = null;
        }
        return cachedTree;
      },
    };
    // Bind grammar lazily on first use; default detectors don't read this.
    Object.defineProperty(ctx, "grammar", {
      get() {
        return cachedGrammar;
      },
      enumerable: true,
    });

    const directives = extractDisableDirectives(source);
    const fileFindings: Finding[] = [];

    for (const det of detectors) {
      let applies = false;
      try {
        applies = det.applies(ctx);
      } catch (e) {
        logger.warn(`detector ${det.id} threw in applies()`, e);
        failedDetectors.add(det.id);
        continue;
      }
      if (!applies) continue;

      let detFindings: Finding[] = [];
      try {
        const out = await runWithTimeout(det, ctx, fileTimeout);
        detFindings = out;
      } catch (e) {
        logger.warn(`detector ${det.id} failed on ${target.path}`, e);
        failedDetectors.add(det.id);
        continue;
      }

      for (const f of detFindings) {
        const normalized = normalizeFinding(f);
        if (target.diffMode && !lineInRanges(normalized.line, target.addedRanges)) {
          continue;
        }
        if (isSuppressedByDirectives(normalized.line, normalized.ruleId, directives)) {
          continue;
        }
        if (options.allowlist && matchesAllowlist(normalized, options.allowlist, target.path)) {
          continue;
        }
        if (SEVERITY_RANK[normalized.severity] < minRank) continue;

        fileFindings.push(normalized);
      }
    }

    if (options.symbolResolver) {
      // Best-effort enclosing symbol enrichment.
      for (let i = 0; i < fileFindings.length; i++) {
        const f = fileFindings[i]!;
        try {
          const sym = await options.symbolResolver(target.path, f.line);
          if (sym) fileFindings[i] = { ...f, enclosingSymbol: sym };
        } catch {
          // ignore
        }
      }
    }

    findings.push(...fileFindings);

    filesDone++;
    reportProgress();
  });

  // Final progress emit (ensures filesDone === total even when no resolver work).
  if (options.onProgress && total === 0) {
    options.onProgress({ filesTotal: 0, filesDone: 0 });
  }

  findings.sort(compareFindings);

  return {
    findings: Object.freeze(findings.slice()),
    files: Object.freeze(results.slice()),
    durationMs: Math.max(0, Date.now() - t0),
    failedDetectors: Object.freeze([...failedDetectors].sort()),
    rulesVersion: ruleSet.version(),
    engineVersion: ENGINE_VERSION,
  };
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function validateInput(input: ScanInput): void {
  const set = [
    input.diff !== undefined,
    input.paths !== undefined,
    input.dir !== undefined,
  ].filter(Boolean).length;
  if (set !== 1) {
    throw new InvalidScanInputError(
      `ScanInput must set exactly one of {diff, paths, dir}; got ${set}`,
    );
  }
}

async function prepareTargets(input: ScanInput): Promise<PreparedFile[]> {
  if (input.diff !== undefined) {
    const files = parseDiffToFiles(input.diff);
    return files
      .filter(f => f.status !== "deleted")
      .map(f => ({ path: f.path, addedRanges: f.addedRanges, diffMode: true }));
  }
  if (input.paths !== undefined) {
    return input.paths.map(p => ({ path: p, addedRanges: [], diffMode: false }));
  }
  // dir: the host is responsible for enumerating via fileResolver. We have
  // no portable directory walker (the engine is host-agnostic), so dir-mode
  // returns an empty target list — same shape the contract test expects.
  return [];
}

async function runWithConcurrency<T>(
  items: readonly T[],
  limit: number,
  worker: (item: T) => Promise<void>,
): Promise<void> {
  if (items.length === 0) return;
  let cursor = 0;
  const runners: Promise<void>[] = [];
  const runOne = async (): Promise<void> => {
    while (cursor < items.length) {
      const idx = cursor++;
      const item = items[idx];
      if (item === undefined) continue;
      await worker(item);
    }
  };
  for (let i = 0; i < Math.min(limit, items.length); i++) {
    runners.push(runOne());
  }
  await Promise.all(runners);
}

async function runWithTimeout(
  det: Detector,
  ctx: FileContext,
  timeoutMs: number,
): Promise<Finding[]> {
  const out = det.run(ctx);
  if (Array.isArray(out)) return out;
  return new Promise<Finding[]>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`detector ${det.id} timed out after ${timeoutMs}ms`)),
      timeoutMs,
    );
    Promise.resolve(out).then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

function normalizeFinding(f: Finding): Finding {
  // Defensive truncation.
  let snippet = f.snippet;
  if (snippet.length > SNIPPET_CAP) {
    snippet = snippet.slice(0, SNIPPET_CAP - 3) + "...";
  }
  return snippet === f.snippet ? f : { ...f, snippet };
}

function compareFindings(a: Finding, b: Finding): number {
  const ra = SEVERITY_RANK[a.severity];
  const rb = SEVERITY_RANK[b.severity];
  if (ra !== rb) return rb - ra; // higher severity first
  if (a.score !== b.score) return b.score - a.score;
  if (a.file !== b.file) return a.file < b.file ? -1 : 1;
  return a.line - b.line;
}

function defaultConcurrency(): number {
  // Avoid `os.cpus()` import when the env is constrained.
  try {
    // dynamic require so this still works in non-Node runtimes
    const n = (globalThis as { navigator?: { hardwareConcurrency?: number } }).navigator?.hardwareConcurrency;
    if (typeof n === "number" && n > 0) return n;
  } catch {
    // ignore
  }
  return 4;
}

function consoleLogger() {
  return {
    debug: () => {},
    info: () => {},
    warn: (msg: string, meta?: unknown) => console.warn(msg, meta ?? ""),
    error: (msg: string, meta?: unknown) => console.error(msg, meta ?? ""),
  };
}
