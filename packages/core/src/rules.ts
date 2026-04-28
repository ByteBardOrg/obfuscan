/**
 * Rule pack loader.
 *
 * Loads `LanguageConfig` JSON files from a directory (or from the bundled
 * @obfuscan/rules package) and exposes a `RuleSet` interface used by the
 * scan loop.
 *
 * No tree-sitter grammars are loaded eagerly — `loadGrammar()` is a stub that
 * returns a sentinel handle. The bundled detectors operate on raw source via
 * regex/AST-lite techniques and don't require a live parser. Hosts that want
 * full tree-sitter parsing can implement their own `RuleSet` and pass it via
 * `ScanOptions.rules`.
 */

import * as fs from "node:fs/promises";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import type { GrammarHandle, LanguageConfig, RuleSet } from "./types.js";
import { InvalidRuleSetError } from "./errors.js";

interface LoadOptions {
  /** Directory containing per-language *.json configs. */
  languageDir: string;
  /** Optional directory of .scm queries. Currently informational; reserved for future use. */
  queryDir?: string;
}

/** Build a RuleSet by scanning a directory of language configs. */
export async function loadRuleSet(opts: LoadOptions): Promise<RuleSet> {
  const { languageDir } = opts;
  const entries = await fs.readdir(languageDir).catch((e: unknown) => {
    throw new InvalidRuleSetError(
      `failed to read language directory: ${languageDir}`,
      [{ file: languageDir, problem: String(e) }],
    );
  });

  const configs = new Map<string, LanguageConfig>();
  const aliasIndex = new Map<string, string>();
  const extIndex = new Map<string, string>();
  const filenameIndex = new Map<string, string>();

  const problems: Array<{ file: string; problem: string }> = [];

  for (const file of entries) {
    if (!file.endsWith(".json")) continue;
    if (file.startsWith("_")) continue; // skip _schema.json, _template.json

    const full = path.join(languageDir, file);
    let raw: string;
    try {
      raw = await fs.readFile(full, "utf8");
    } catch (e) {
      problems.push({ file, problem: `read failed: ${String(e)}` });
      continue;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      problems.push({ file, problem: `invalid JSON: ${String(e)}` });
      continue;
    }

    const cfg = parsed as Partial<LanguageConfig>;
    if (typeof cfg.id !== "string") {
      problems.push({ file, problem: "missing string field: id" });
      continue;
    }
    if (!Array.isArray(cfg.extensions)) {
      problems.push({ file, problem: "missing array field: extensions" });
      continue;
    }
    if (!Array.isArray(cfg.dynamic_exec_sinks)) {
      problems.push({ file, problem: "missing array field: dynamic_exec_sinks" });
      continue;
    }
    if (!Array.isArray(cfg.decoders)) {
      problems.push({ file, problem: "missing array field: decoders" });
      continue;
    }

    const config = cfg as LanguageConfig;
    configs.set(config.id, config);
    aliasIndex.set(config.id, config.id);
    for (const alias of config.aliases ?? []) {
      aliasIndex.set(alias, config.id);
    }
    for (const ext of config.extensions) {
      extIndex.set(ext.toLowerCase(), config.id);
    }
    for (const fname of config.filenames ?? []) {
      filenameIndex.set(fname, config.id);
    }
  }

  if (problems.length > 0 && configs.size === 0) {
    throw new InvalidRuleSetError(
      `no valid language configs in ${languageDir}`,
      problems,
    );
  }

  return {
    languages: () => Array.from(configs.keys()).sort(),
    configFor: (id: string) => configs.get(aliasIndex.get(id) ?? id) ?? null,
    detectLanguage: (p: string) => detectLanguage(p, extIndex, filenameIndex),
    loadGrammar: async (id: string): Promise<GrammarHandle> => {
      // Stub: detectors that depend on a live parser would override this via
      // a host-supplied RuleSet. The bundled detectors don't need it.
      return Object.freeze({ id, _internal: null });
    },
    version: () => "0.0.0-source", // placeholder; defaultRuleSet() supplies real CalVer
  };
}

function detectLanguage(
  filePath: string,
  extIndex: Map<string, string>,
  filenameIndex: Map<string, string>,
): string | null {
  const norm = filePath.replace(/\\/g, "/");
  const base = norm.slice(norm.lastIndexOf("/") + 1);

  // Filename match first (Dockerfile, build.rs, package.json, setup.py, …)
  const exact = filenameIndex.get(base);
  if (exact) return exact;

  // Common manifests by basename when no language config claims them
  if (base === "package.json") return "json";
  if (base === "Dockerfile" || base.startsWith("Dockerfile.")) return "dockerfile";
  if (norm.includes("/.github/workflows/") && (base.endsWith(".yml") || base.endsWith(".yaml"))) {
    return "yaml";
  }

  // Extension match
  const lastDot = base.lastIndexOf(".");
  if (lastDot >= 0) {
    const ext = base.slice(lastDot).toLowerCase();
    const id = extIndex.get(ext);
    if (id) return id;
  }
  return null;
}

// ─── Default rule set ──────────────────────────────────────────────────────
//
// The bundled @obfuscan/rules package is resolved via Node's module resolver.
// We try several candidate locations in order so this works whether
// @obfuscan/rules is installed via npm, linked, or bundled in a workspace.

const RULES_VERSION_FALLBACK = "2026.04.0";
const here = path.dirname(fileURLToPath(import.meta.url));

let cachedDefault: RuleSet | null = null;

export async function defaultRuleSet(): Promise<RuleSet> {
  if (cachedDefault) return cachedDefault;

  const candidates = await locateBundledRules();
  for (const dir of candidates) {
    try {
      const rs = await loadRuleSet({ languageDir: dir });
      const version = await readPackageVersion(path.dirname(dir)) ?? RULES_VERSION_FALLBACK;
      cachedDefault = wrapWithVersion(rs, version);
      return cachedDefault;
    } catch {
      // try next candidate
    }
  }

  // Last resort: an empty rule set so the engine still runs.
  cachedDefault = emptyRuleSet();
  return cachedDefault;
}

async function locateBundledRules(): Promise<string[]> {
  const candidates: string[] = [];

  // 1. Sibling workspace package: ../rules/languages
  candidates.push(path.resolve(here, "..", "..", "rules", "languages"));

  // 2. Installed via npm: node_modules/@obfuscan/rules/languages
  try {
    const req = (await import("node:module")).createRequire(import.meta.url);
    const pkgPath = req.resolve("@obfuscan/rules/package.json");
    candidates.push(path.join(path.dirname(pkgPath), "languages"));
  } catch {
    // not resolvable; skip
  }

  // 3. Env override
  const envDir = process.env["OBFUSCAN_RULES_DIR"];
  if (envDir) candidates.unshift(envDir);

  return candidates;
}

async function readPackageVersion(dir: string): Promise<string | null> {
  try {
    const raw = await fs.readFile(path.join(dir, "package.json"), "utf8");
    const pkg = JSON.parse(raw) as { version?: string };
    return typeof pkg.version === "string" ? pkg.version : null;
  } catch {
    return null;
  }
}

function wrapWithVersion(rs: RuleSet, version: string): RuleSet {
  return {
    languages: () => rs.languages(),
    configFor: id => rs.configFor(id),
    detectLanguage: p => rs.detectLanguage(p),
    loadGrammar: id => rs.loadGrammar(id),
    version: () => version,
  };
}

function emptyRuleSet(): RuleSet {
  return {
    languages: () => [],
    configFor: () => null,
    detectLanguage: () => null,
    loadGrammar: async (id: string) => Object.freeze({ id, _internal: null }),
    version: () => RULES_VERSION_FALLBACK,
  };
}
