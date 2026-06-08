import { describe, expect, it } from "vitest";
import type { ScanResult } from "@obfuscan/core";
import { countFindings, formatMarkdown, reportMarker, shouldFail } from "../src/report";

const result: ScanResult = {
  findings: [
    {
      ruleId: "obf.decode-then-exec.javascript",
      severity: "block",
      score: 10,
      file: "src/a.js",
      line: 12,
      snippet: "eval(atob(payload))",
      reason: "Decoded data is being executed via a dynamic sink.",
    },
    {
      ruleId: "obf.high-entropy-literal",
      severity: "warn",
      score: 6,
      file: "src/b.js",
      line: 3,
      snippet: "const token = 'abc|def';",
      reason: "High entropy string literal.",
    },
  ],
  files: [{ path: "src/a.js", languageId: "javascript" }],
  durationMs: 42,
  failedDetectors: [],
  rulesVersion: "2026.04.0",
  engineVersion: "0.2.0",
};

describe("report formatting", () => {
  it("renders a marked Markdown report", () => {
    const markdown = formatMarkdown(result, {
      maxFindings: 10,
      owner: "ByteBardOrg",
      repo: "obfuscan",
      sha: "abc123",
    });

    expect(markdown).toContain(reportMarker());
    expect(markdown).toContain("## obfuscan report");
    expect(markdown).toContain("Blocking findings found.");
    expect(markdown).toContain("src/a.js:12");
    expect(markdown).toContain("obf.decode-then-exec.javascript");
    expect(markdown).toContain("abc&#124;def");
  });

  it("counts findings by severity", () => {
    expect(countFindings(result.findings)).toEqual({ block: 1, warn: 1, info: 0 });
  });

  it("applies fail-on thresholds", () => {
    expect(shouldFail(result.findings, "block")).toBe(true);
    expect(shouldFail(result.findings, "warn")).toBe(true);
    expect(shouldFail(result.findings, "never")).toBe(false);
  });
});
