import type { Finding, ScanResult, Severity } from "@obfuscan/core";

export interface ReportOptions {
  maxFindings: number;
  owner?: string;
  repo?: string;
  sha?: string;
  engineVersion?: string;
  rulesVersion?: string;
}

const MARKER = "<!-- obfuscan-report -->";
const SEVERITIES: readonly Severity[] = ["block", "warn", "info"];

export function reportMarker(): string {
  return MARKER;
}

export function countFindings(findings: readonly Finding[]): Record<Severity, number> {
  return {
    block: findings.filter(f => f.severity === "block").length,
    warn: findings.filter(f => f.severity === "warn").length,
    info: findings.filter(f => f.severity === "info").length,
  };
}

export function shouldFail(findings: readonly Finding[], failOn: "block" | "warn" | "never"): boolean {
  if (failOn === "never") return false;
  if (failOn === "block") return findings.some(f => f.severity === "block");
  return findings.some(f => f.severity === "block" || f.severity === "warn");
}

export function formatMarkdown(result: ScanResult, options: ReportOptions): string {
  const counts = countFindings(result.findings);
  const total = result.findings.length;
  const shown = result.findings.slice(0, Math.max(1, options.maxFindings));
  const omitted = Math.max(0, total - shown.length);
  const status = total === 0
    ? "No findings."
    : counts.block > 0
      ? "Blocking findings found."
      : counts.warn > 0
        ? "Warnings found."
        : "Informational findings found.";

  const lines = [
    MARKER,
    "## obfuscan report",
    "",
    `**Status:** ${status}`,
    "",
    "| Metric | Value |",
    "|---|---:|",
    `| Scanned files | ${result.files.length} |`,
    `| Findings | ${total} |`,
    `| Block | ${counts.block} |`,
    `| Warn | ${counts.warn} |`,
    `| Info | ${counts.info} |`,
    `| Duration | ${result.durationMs} ms |`,
    `| Engine | ${escapeTable(options.engineVersion ?? result.engineVersion)} |`,
    `| Rules | ${escapeTable(options.rulesVersion ?? result.rulesVersion)} |`,
  ];

  if (result.failedDetectors.length > 0) {
    lines.push(`| Failed detectors | ${escapeTable(result.failedDetectors.join(", "))} |`);
  }

  if (total === 0) {
    lines.push("", "No suspicious obfuscation or backdoor patterns were found in the scanned diff.");
    return lines.join("\n");
  }

  for (const severity of SEVERITIES) {
    const group = shown.filter(f => f.severity === severity);
    if (group.length === 0) continue;

    lines.push("", `### ${titleCase(severity)} findings`, "");
    lines.push("| Location | Rule | Score | Reason | Snippet |");
    lines.push("|---|---|---:|---|---|");
    for (const finding of group) {
      lines.push(formatFindingRow(finding, options));
    }
  }

  if (omitted > 0) {
    lines.push("", `${omitted} additional finding${omitted === 1 ? "" : "s"} omitted from this comment.`);
  }

  lines.push("", "Suppress a known false positive with an in-source `obfuscan-disable-next-line` directive or `.obfuscan/allowlist.json`.");

  return lines.join("\n");
}

function formatFindingRow(finding: Finding, options: ReportOptions): string {
  const location = formatLocation(finding, options);
  const snippet = inlineCode(finding.snippet.replace(/\s+/g, " ").slice(0, 160));
  return [
    location,
    inlineCode(finding.ruleId),
    String(finding.score),
    escapeTable(finding.reason),
    snippet,
  ].join(" | ").replace(/^/, "|").replace(/$/, "|");
}

function formatLocation(finding: Finding, options: ReportOptions): string {
  const label = `${finding.file}:${finding.line}`;
  if (!options.owner || !options.repo || !options.sha) return escapeTable(label);
  const path = finding.file.split("/").map(encodeURIComponent).join("/");
  return `[${escapeTable(label)}](https://github.com/${options.owner}/${options.repo}/blob/${options.sha}/${path}#L${finding.line})`;
}

function inlineCode(value: string): string {
  const escaped = escapeTable(value).replace(/`/g, "&#96;");
  return `<code>${escaped}</code>`;
}

function escapeTable(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\|/g, "&#124;")
    .replace(/\r?\n/g, "<br>");
}

function titleCase(value: string): string {
  return value.slice(0, 1).toUpperCase() + value.slice(1);
}
