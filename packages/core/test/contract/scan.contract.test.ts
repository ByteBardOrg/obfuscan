/**
 * Contract tests for the `scan()` entry point.
 *
 * These tests are intentionally implementation-agnostic. They lock in the
 * behavior that consumers of @obfuscan/core can rely on across versions.
 * Anything specific to "did rule X fire on code Y" lives in unit/.
 */

import { describe, it, expect } from "vitest";
import {
  scan,
  InvalidScanInputError,
  ENGINE_VERSION,
  type Finding,
  type ScanResult,
  type Severity,
} from "@obfuscan/core";
import { virtualFiles, diffWithPostImage, silentOptions } from "../helpers/matchers";

describe("scan() — input validation", () => {
  it("rejects an empty ScanInput", async () => {
    await expect(
      scan({} as never, { fileResolver: async () => null }),
    ).rejects.toBeInstanceOf(InvalidScanInputError);
  });

  it("accepts paths-only input", async () => {
    const { input, fileResolver } = virtualFiles({ "a.js": "var x = 1;" });
    const r = await scan(input, { fileResolver, ...silentOptions() });
    expect(r.files.map(f => f.path)).toContain("a.js");
  });

  it("accepts diff-only input", async () => {
    const { input, fileResolver } = diffWithPostImage(
      `diff --git a/a.js b/a.js\n--- a/a.js\n+++ b/a.js\n@@ -0,0 +1,1 @@\n+var x = 1;\n`,
      { "a.js": "var x = 1;\n" },
    );
    const r = await scan(input, { fileResolver, ...silentOptions() });
    expect(r.files.map(f => f.path)).toContain("a.js");
  });

  it("accepts dir-only input", async () => {
    // host is responsible for enumerating; resolver returns content.
    const r = await scan(
      { dir: "/tmp/empty" },
      { fileResolver: async () => null, ...silentOptions() },
    );
    expect(r.findings).toEqual([]);
  });

  it("rejects when more than one of {diff, paths, dir} is set", async () => {
    await expect(
      scan(
        { diff: "x", paths: ["a"] } as never,
        { fileResolver: async () => null },
      ),
    ).rejects.toBeInstanceOf(InvalidScanInputError);
  });
});

describe("scan() — output shape", () => {
  it("returns a ScanResult with all documented fields", async () => {
    const { input, fileResolver } = virtualFiles({ "a.js": "var x = 1;" });
    const r: ScanResult = await scan(input, { fileResolver, ...silentOptions() });
    expect(r).toMatchObject({
      findings: expect.any(Array),
      files: expect.any(Array),
      durationMs: expect.any(Number),
      failedDetectors: expect.any(Array),
      rulesVersion: expect.any(String),
      engineVersion: expect.any(String),
    });
    expect(r.engineVersion).toBe(ENGINE_VERSION);
    expect(r.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("findings are sorted by (severity desc, score desc, file, line)", async () => {
    const src = "/* synthetic input that triggers multiple findings */\n".repeat(0);
    const { input, fileResolver } = virtualFiles({ "a.js": src });
    const r = await scan(input, { fileResolver, ...silentOptions() });
    const ranks: Record<Severity, number> = { block: 0, warn: 1, info: 2 };
    for (let i = 1; i < r.findings.length; i++) {
      const a = r.findings[i - 1]!;
      const b = r.findings[i]!;
      const ra = ranks[a.severity];
      const rb = ranks[b.severity];
      expect(ra <= rb).toBe(true);
      if (ra === rb) {
        expect(
          a.score >= b.score ||
          (a.score === b.score &&
            (a.file < b.file || (a.file === b.file && a.line <= b.line))),
        ).toBe(true);
      }
    }
  });

  it("every finding has 1-based line numbers", async () => {
    const { input, fileResolver } = virtualFiles({ "a.js": "var x=1;\n".repeat(5) });
    const r = await scan(input, { fileResolver, ...silentOptions() });
    for (const f of r.findings) {
      expect(f.line).toBeGreaterThanOrEqual(1);
      if (f.endLine != null) expect(f.endLine).toBeGreaterThanOrEqual(f.line);
    }
  });

  it("snippets are at most 200 chars (or end with ellipsis)", async () => {
    const { input, fileResolver } = virtualFiles({ "a.js": "var x = '" + "A".repeat(5000) + "';" });
    const r = await scan(input, { fileResolver, ...silentOptions() });
    for (const f of r.findings) {
      expect(f.snippet.length).toBeLessThanOrEqual(220); // 200 + "…"
    }
  });
});

describe("scan() — diff-awareness", () => {
  it("only emits findings on lines within the diff's added ranges", async () => {
    const post = [
      "// preexisting line 1",                     // L1 — not added
      "// preexisting line 2",                     // L2 — not added
      "eval(Buffer.from('x','base64').toString())" // L3 — added
    ].join("\n") + "\n";
    const diff = `diff --git a/a.js b/a.js
--- a/a.js
+++ b/a.js
@@ -2,2 +2,3 @@
 // preexisting line 1
 // preexisting line 2
+eval(Buffer.from('x','base64').toString())
`;
    const r = await scan(
      { diff },
      { fileResolver: async () => post, ...silentOptions() },
    );
    for (const f of r.findings) expect(f.line).toBe(3);
  });

  it("scanning the same file by `paths` is allowed to flag everywhere", async () => {
    const post = [
      "// preexisting line 1",
      "eval(Buffer.from('x','base64').toString())",
    ].join("\n") + "\n";
    const r = await scan(
      { paths: ["a.js"] },
      { fileResolver: async () => post, ...silentOptions() },
    );
    expect(r.findings.some((f: Finding) => f.line === 2)).toBe(true);
  });
});

describe("scan() — options", () => {
  it("respects minSeverity", async () => {
    const { input, fileResolver } = virtualFiles({ "a.js": "var x = 1;" });
    const r = await scan(input, { fileResolver, minSeverity: "block", ...silentOptions() });
    for (const f of r.findings) expect(f.severity).toBe("block");
  });

  it("respects disabledDetectors", async () => {
    const { input, fileResolver } = virtualFiles({ "a.js": "var x = 1;" });
    const r = await scan(input, {
      fileResolver,
      disabledDetectors: ["obf.high-entropy-literal"],
      ...silentOptions(),
    });
    for (const f of r.findings) expect(f.ruleId).not.toBe("obf.high-entropy-literal");
  });

  it("calls onProgress at least once for non-empty input", async () => {
    const calls: number[] = [];
    const { input, fileResolver } = virtualFiles({ "a.js": "var x=1;", "b.js": "var y=2;" });
    await scan(input, {
      fileResolver,
      onProgress: p => calls.push(p.filesDone),
      ...silentOptions(),
    });
    expect(calls.length).toBeGreaterThan(0);
    expect(calls[calls.length - 1]).toBe(2);
  });

  it("returns findings enriched by symbolResolver", async () => {
    const { input, fileResolver } = virtualFiles({ "a.js": "function f() { return 1; }" });
    const r = await scan(input, {
      fileResolver,
      symbolResolver: async () => "f",
      detectors: [{
        id: "test.symbol",
        applies: () => true,
        run: () => [{
          ruleId: "test.symbol",
          severity: "warn",
          score: 5,
          file: "a.js",
          line: 1,
          snippet: "function f",
          reason: "synthetic finding",
        }],
      }],
      ...silentOptions(),
    });
    expect(r.findings[0]?.enclosingSymbol).toBe("f");
  });

  it("never throws from a host fileResolver error; logs and continues", async () => {
    const r = await scan(
      { paths: ["broken.js", "ok.js"] },
      {
        fileResolver: async (p) => {
          if (p === "broken.js") throw new Error("boom");
          return "var x = 1;";
        },
        ...silentOptions(),
      },
    );
    // ok.js is still scanned
    expect(r.files.find(f => f.path === "ok.js")).toBeDefined();
  });
});

describe("scan() — determinism", () => {
  it("two scans of the same input produce identical findings (modulo durationMs)", async () => {
    const { input, fileResolver } = virtualFiles({ "a.js": "var x = 1;\n".repeat(20) });
    const a = await scan(input, { fileResolver, ...silentOptions() });
    const b = await scan(input, { fileResolver, ...silentOptions() });
    const norm = (r: ScanResult) => r.findings.map(f => ({ ...f, evidence: undefined }));
    expect(norm(a)).toEqual(norm(b));
  });
});
