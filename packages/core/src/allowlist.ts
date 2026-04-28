/**
 * Allowlist load/save/match helpers.
 *
 * On-disk format: `.obfuscan/allowlist.json`
 *
 * ```json
 * {
 *   "paths":    [{ "pattern": "vendor/**", "maxSeverity": "warn", "reason": "third-party bundle" }],
 *   "snippets": [{ "ruleId": "obf.high-entropy-literal", "snippetHash": "abc...", "addedBy": "alice" }]
 * }
 * ```
 *
 * `hashSnippet()` normalizes whitespace before hashing so suppressions
 * survive reformatters.
 */

import { createHash } from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import type {
  Allowlist,
  Finding,
  PathAllowlistEntry,
  SnippetAllowlistEntry,
  Severity,
} from "./types.js";

const SEVERITY_RANK: Record<Severity, number> = { info: 0, warn: 1, block: 2 };

/** sha256(normalize(snippet)) as lowercase hex. */
export function hashSnippet(snippet: string): string {
  const normalized = normalizeSnippet(snippet);
  return createHash("sha256").update(normalized, "utf8").digest("hex");
}

function normalizeSnippet(s: string): string {
  // Collapse all whitespace to single spaces; strip leading/trailing.
  return s.replace(/\s+/g, " ").trim();
}

/** Load `.obfuscan/allowlist.json` from a workspace root. Returns `{}` if missing. */
export async function loadAllowlist(workspaceRoot: string): Promise<Allowlist> {
  const file = path.join(workspaceRoot, ".obfuscan", "allowlist.json");
  try {
    const raw = await fs.readFile(file, "utf8");
    return JSON.parse(raw) as Allowlist;
  } catch {
    return {};
  }
}

export async function saveAllowlist(
  workspaceRoot: string,
  allowlist: Allowlist,
): Promise<void> {
  const dir = path.join(workspaceRoot, ".obfuscan");
  await fs.mkdir(dir, { recursive: true });
  const file = path.join(dir, "allowlist.json");
  await fs.writeFile(file, JSON.stringify(allowlist, null, 2) + "\n", "utf8");
}

// ─── Matching ──────────────────────────────────────────────────────────────

/** True if `finding` should be suppressed by the given allowlist. */
export function matchesAllowlist(
  finding: Finding,
  allowlist: Allowlist,
  filePath: string,
): boolean {
  // Path entries
  for (const entry of allowlist.paths ?? []) {
    if (!matchesPathEntry(filePath, entry)) continue;
    if (entry.ruleId && !ruleMatches(finding.ruleId, entry.ruleId)) continue;
    if (entry.maxSeverity) {
      // Suppress only findings at or below the ceiling.
      if (SEVERITY_RANK[finding.severity] <= SEVERITY_RANK[entry.maxSeverity]) {
        return true;
      }
    } else {
      return true;
    }
  }

  // Snippet entries
  for (const entry of allowlist.snippets ?? []) {
    if (!ruleMatches(finding.ruleId, entry.ruleId)) continue;
    if (hashSnippet(finding.snippet) === entry.snippetHash) return true;
  }

  return false;
}

function ruleMatches(ruleId: string, entryRuleId: string): boolean {
  // Exact match, or prefix-with-dot match: `obf.decode-then-exec` matches
  // `obf.decode-then-exec.python`.
  return ruleId === entryRuleId || ruleId.startsWith(entryRuleId + ".");
}

function matchesPathEntry(filePath: string, entry: PathAllowlistEntry): boolean {
  return globMatch(entry.pattern, filePath);
}

// ─── Tiny minimatch-compatible glob ────────────────────────────────────────
//
// Supports the common subset:
//   *      matches any chars except /
//   **     matches any chars including /
//   ?      matches one char except /
//   [abc]  character class
//
// This is sufficient for allowlist patterns and avoids a runtime dependency.

function globMatch(pattern: string, str: string): boolean {
  const re = globToRegex(pattern);
  return re.test(str);
}

function globToRegex(pattern: string): RegExp {
  let out = "^";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "*") {
      if (pattern[i + 1] === "*") {
        // **  → match anything (incl. /)
        out += ".*";
        i++;
        // optional trailing slash collapse: `**/` matches zero or more dirs
        if (pattern[i + 1] === "/") {
          i++;
        }
      } else {
        out += "[^/]*";
      }
    } else if (c === "?") {
      out += "[^/]";
    } else if (c === "[") {
      // copy until ']'
      let j = i + 1;
      let cls = "[";
      while (j < pattern.length && pattern[j] !== "]") {
        cls += pattern[j];
        j++;
      }
      cls += "]";
      out += cls;
      i = j;
    } else if (c && /[.+^${}()|\\]/.test(c)) {
      out += "\\" + c;
    } else {
      out += c ?? "";
    }
  }
  out += "$";
  return new RegExp(out);
}

// Re-export for completeness / introspection in tests.
export type { PathAllowlistEntry, SnippetAllowlistEntry };
