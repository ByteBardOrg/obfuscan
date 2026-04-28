/**
 * Contract for parseDiffToFiles() — the helper exposed for hosts that already
 * have a structured diff representation.
 */

import { describe, it, expect } from "vitest";
import { parseDiffToFiles, type DiffFile } from "@obfuscan/core";

const SAMPLE = `diff --git a/a.js b/a.js
--- a/a.js
+++ b/a.js
@@ -1,2 +1,3 @@
 keep
+added
 keep2
diff --git a/removed.js b/removed.js
deleted file mode 100644
--- a/removed.js
+++ /dev/null
@@ -1,1 +0,0 @@
-only line
diff --git a/b.py b/b.py
new file mode 100644
--- /dev/null
+++ b/b.py
@@ -0,0 +1,2 @@
+import os
+os.system("uname")
`;

describe("parseDiffToFiles()", () => {
  it("extracts added files", () => {
    const files = parseDiffToFiles(SAMPLE);
    const b = files.find(f => f.path === "b.py")!;
    expect(b).toBeDefined();
    expect(b.status).toBe("added");
    expect(b.addedRanges).toEqual([[1, 2]]);
  });

  it("extracts modified files with addedRanges scoped to inserted lines", () => {
    const files = parseDiffToFiles(SAMPLE);
    const a = files.find(f => f.path === "a.js")!;
    expect(a.status).toBe("modified");
    expect(a.addedRanges).toEqual([[2, 2]]);
  });

  it("ignores deleted files", () => {
    const files = parseDiffToFiles(SAMPLE);
    expect(files.find(f => f.path === "removed.js")).toBeUndefined();
  });

  it("returns paths normalized to forward slashes", () => {
    const files = parseDiffToFiles(SAMPLE);
    for (const f of files) expect(f.path).not.toMatch(/\\/);
  });

  it("handles empty input", () => {
    const files: DiffFile[] = parseDiffToFiles("");
    expect(files).toEqual([]);
  });
});
