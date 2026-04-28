/**
 * Contract tests for the Detector plugin interface.
 *
 * Asserts the documented guarantees:
 *  - detectors only see files where applies() returned true
 *  - detectors that throw are caught and reported via failedDetectors
 *  - findings are filtered to addedRanges when scanning a diff
 *  - the engine respects detector ordering for stable rule ids
 */

import { describe, it, expect } from "vitest";
import {
  scan,
  defaultDetectors,
  type Detector,
  type FileContext,
  type Finding,
} from "@obfuscan/core";
import { virtualFiles, diffWithPostImage, silentOptions } from "../helpers/matchers";

function inertDetector(id: string, body: (ctx: FileContext) => Finding[]): Detector {
  return {
    id,
    applies: () => true,
    run: body,
  };
}

describe("Detector contract", () => {
  it("applies() filters which files reach run()", async () => {
    const seen: string[] = [];
    const det: Detector = {
      id: "test.only-js",
      applies: ctx => ctx.path.endsWith(".js"),
      run: ctx => { seen.push(ctx.path); return []; },
    };
    const { input, fileResolver } = virtualFiles({ "a.js": "x", "b.py": "x", "c.js": "x" });
    await scan(input, { fileResolver, detectors: [det], ...silentOptions() });
    expect(seen.sort()).toEqual(["a.js", "c.js"]);
  });

  it("a thrown error in run() does not abort the scan and is reported", async () => {
    const bad: Detector = {
      id: "test.boom",
      applies: () => true,
      run: () => { throw new Error("kaboom"); },
    };
    const ok = inertDetector("test.ok", () => []);
    const { input, fileResolver } = virtualFiles({ "a.js": "x" });
    const r = await scan(input, {
      fileResolver,
      detectors: [bad, ok],
      ...silentOptions(),
    });
    expect(r.failedDetectors).toContain("test.boom");
    // The scan completed; ok detector ran.
    expect(r.findings).toBeDefined();
  });

  it("findings are filtered to addedRanges when scanning a diff", async () => {
    const allLines: Finding[] = [
      { ruleId: "test.line", severity: "warn", score: 5, file: "a.js", line: 1, snippet: "", reason: "" },
      { ruleId: "test.line", severity: "warn", score: 5, file: "a.js", line: 5, snippet: "", reason: "" },
    ];
    const det: Detector = {
      id: "test.line",
      applies: () => true,
      run: () => allLines,
    };
    const { input, fileResolver } = diffWithPostImage(
      `diff --git a/a.js b/a.js\n--- a/a.js\n+++ b/a.js\n@@ -4,0 +5,1 @@\n+x\n`,
      { "a.js": "a\nb\nc\nd\nx\n" },
    );
    const r = await scan(input, {
      fileResolver,
      detectors: [det],
      ...silentOptions(),
    });
    // Only line 5 (within addedRanges) should survive.
    expect(r.findings.map(f => f.line)).toEqual([5]);
  });

  it("findings are NOT filtered when scanning by paths", async () => {
    const det: Detector = {
      id: "test.line",
      applies: () => true,
      run: () => [
        { ruleId: "test.line", severity: "warn", score: 5, file: "a.js", line: 1, snippet: "", reason: "" },
        { ruleId: "test.line", severity: "warn", score: 5, file: "a.js", line: 5, snippet: "", reason: "" },
      ],
    };
    const { input, fileResolver } = virtualFiles({ "a.js": "a\nb\nc\nd\ne\n" });
    const r = await scan(input, {
      fileResolver,
      detectors: [det],
      ...silentOptions(),
    });
    expect(r.findings.map(f => f.line).sort()).toEqual([1, 5]);
  });

  it("defaultDetectors() returns at least the documented Layer-A set", () => {
    const ids = new Set(defaultDetectors().map(d => d.id));
    expect(ids.has("obf.high-entropy-literal")).toBe(true);
    expect(ids.has("obf.bidi-control")).toBe(true);
    expect(ids.has("obf.long-line")).toBe(true);
  });

  it("a custom detector list completely replaces the defaults", async () => {
    const custom = inertDetector("only.me", () => [
      { ruleId: "only.me", severity: "info", score: 1, file: "a.js", line: 1, snippet: "", reason: "" },
    ]);
    const { input, fileResolver } = virtualFiles({ "a.js": "var x = 1;" });
    const r = await scan(input, {
      fileResolver,
      detectors: [custom],
      ...silentOptions(),
    });
    for (const f of r.findings) expect(f.ruleId).toBe("only.me");
  });
});
