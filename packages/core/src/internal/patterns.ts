/**
 * Pattern-building helpers shared by detectors.
 *
 * The bundled detectors are intentionally regex-driven rather than parse-tree
 * driven — that keeps the engine dependency-free and runnable in any Node
 * environment. The regexes are built dynamically from `LanguageConfig` so the
 * same detector covers every supported language.
 *
 * Tradeoff: regex matching is approximate (no full scope analysis). False
 * positives are mitigated by:
 *   - Severity ceilings + allowlist
 *   - The shape of the patterns (e.g. requiring an *immediate* call wrap)
 *   - The aggregator's `disabledDetectors` and in-source directives
 *
 * For airtight semantic analysis, hosts can override `defaultDetectors()`
 * with tree-sitter-backed implementations.
 */

/**
 * Escape a string for use as a literal inside a regex.
 * Handles the dotted/qualified names that appear in language configs
 * (e.g. `base64.b64decode`, `Buffer.from`, `[Convert]::FromBase64String`).
 */
export function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const UNSAFE_BARE_TAILS = new Set([
  "call",
  "compile",
  "constructor",
  "decode",
  "do",
  "exec",
  "execute",
  "from",
  "get",
  "import",
  "invoke",
  "load",
  "new",
  "open",
  "parse",
  "post",
  "request",
  "require",
  "run",
  "send",
  "source",
  "spawn",
  "start",
  "system",
  "use",
]);

function isUnsafeBareTail(tail: string): boolean {
  return UNSAFE_BARE_TAILS.has(tail.toLowerCase());
}

function qualifiedSuffix(raw: string): string | null {
  const parts = raw.split(/(\.|::)/);
  const segments = parts.filter((_, i) => i % 2 === 0 && parts[i] !== "");
  const separators = parts.filter((_, i) => i % 2 === 1);
  if (segments.length < 2 || separators.length < 1) return null;
  const a = segments[segments.length - 2];
  const b = segments[segments.length - 1];
  const sep = separators[separators.length - 1];
  if (!a || !b || !sep) return null;
  return `${a}${sep}${b}`;
}

/**
 * Build a regex source matching any of the configured names as a function
 * call. Accepts qualified names — for `base64.b64decode` the regex matches
 * either the bare `b64decode(...)` or fully-qualified `base64.b64decode(...)`.
 *
 * The boundary on the left tolerates common JS/TS/Py prefixes (`.`, `(`,
 * `=`, `,`, whitespace, start-of-line) so we don't miss expression contexts.
 *
 * Returns an inner alternation suitable for inclusion in a larger pattern.
 */
export function namedCallAlternation(
  names: readonly string[],
  options: { allowUnsafeBareTails?: boolean } = {},
): string {
  const alts: string[] = [];
  for (const raw of names) {
    if (!raw) continue;
    // Special-case PowerShell's `[Type]::Member` form
    if (/^\[.+\]::/.test(raw)) {
      alts.push(escapeRegex(raw));
      continue;
    }
    // Special-case Bash pipelines like `base64 -d` or `base64 --decode`
    if (/\s/.test(raw)) {
      alts.push(escapeRegex(raw));
      continue;
    }
    // Split on either `.` (Python/JS) or `::` (Perl/Ruby/Rust/C++) to find
    // the bare tail. We accept both because configs mix conventions across
    // languages (e.g. `MIME::Base64::decode_base64`, `base64.b64decode`).
    const parts = raw.split(/\.|::/);
    const tail = parts[parts.length - 1] ?? raw;
    alts.push(escapeRegex(raw));
    if (parts.length > 1 && tail !== raw && tail.length > 0) {
      if (isUnsafeBareTail(tail) && !options.allowUnsafeBareTails) {
        const suffix = qualifiedSuffix(raw);
        if (suffix && suffix !== raw) alts.push(escapeRegex(suffix));
        alts.push(`(?:\\.|::)${escapeRegex(tail)}`);
      } else {
        alts.push(escapeRegex(tail));
      }
    }
  }
  // Deduplicate while preserving order
  const seen = new Set<string>();
  const unique: string[] = [];
  for (const a of alts) {
    if (!seen.has(a)) {
      seen.add(a);
      unique.push(a);
    }
  }
  return unique.join("|");
}

/**
 * 1-based line number for a 0-based character offset.
 * Used by every detector to report source positions.
 */
export function lineAtOffset(source: string, offset: number): number {
  let line = 1;
  const cap = Math.min(offset, source.length);
  for (let i = 0; i < cap; i++) {
    if (source.charCodeAt(i) === 10 /* \n */) line++;
  }
  return line;
}

/**
 * 1-based end line of a span starting at `start` and consuming `length` chars.
 */
export function lineAtEnd(source: string, start: number, length: number): number {
  return lineAtOffset(source, start + length);
}

/** Cap on how many findings any single detector emits per file. */
export const MAX_FINDINGS_PER_DETECTOR = 50;

/** Cap on file size before detectors short-circuit. */
export const MAX_SOURCE_BYTES = 2_000_000;
