/**
 * In-source suppression directives.
 *
 * Three forms recognized, mirroring eslint's syntax. Comment style is
 * autodetected — anything between `#`, `//`, `/* ... *\/`, `--`, `;`, or `'`
 * is treated as a comment context.
 *
 *   // obfuscan-disable-next-line obf.high-entropy-literal
 *   const k = "...";
 *
 *   const k = "..."; // obfuscan-disable-line obf.high-entropy-literal
 *
 *   /* obfuscan-disable-line obf.foo, obf.bar *\/
 *
 * Multiple rule ids may be comma-separated. Omitting the ids disables ALL
 * detectors for that line — discouraged, but supported.
 *
 * The aggregator calls `extractDisableDirectives(source)` once per file and
 * filters findings whose `(line, ruleId)` matches.
 */

export interface DisableDirective {
  /** 1-based line number that this directive suppresses. */
  line: number;
  /** Empty array means "all rules". */
  ruleIds: readonly string[];
}

const DIRECTIVE_RE =
  /obfuscan-disable-(next-line|line)\b\s*([A-Za-z0-9_.,\- *]*)/g;

export function extractDisableDirectives(source: string): DisableDirective[] {
  const out: DisableDirective[] = [];
  if (!source) return out;
  const lines = source.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    DIRECTIVE_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = DIRECTIVE_RE.exec(line)) !== null) {
      const kind = m[1];
      const idsRaw = (m[2] ?? "").trim();
      const ruleIds = idsRaw
        .split(/[\s,]+/)
        .map(s => s.trim())
        .filter(s => s.length > 0 && /^[A-Za-z0-9_.\-]+$/.test(s));

      const targetLine = kind === "next-line" ? i + 2 : i + 1;
      out.push({ line: targetLine, ruleIds });
    }
  }
  return out;
}

/**
 * True if `(line, ruleId)` is suppressed by any directive in `directives`.
 * A directive with an empty ruleIds array suppresses every rule on its line.
 */
export function isSuppressedByDirectives(
  line: number,
  ruleId: string,
  directives: readonly DisableDirective[],
): boolean {
  for (const d of directives) {
    if (d.line !== line) continue;
    if (d.ruleIds.length === 0) return true;
    if (d.ruleIds.some(id => ruleId === id || ruleId.startsWith(id + "."))) {
      return true;
    }
  }
  return false;
}
