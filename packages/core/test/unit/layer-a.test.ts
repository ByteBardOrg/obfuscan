/**
 * Layer A — universal text/regex detectors.
 *
 * These detectors run on every file regardless of language, so the tests
 * exercise them on multiple languages to make sure no language-specific
 * coupling has crept in.
 *
 * Rule IDs covered:
 *   obf.high-entropy-literal
 *   obf.bidi-control
 *   obf.homoglyph-identifier
 *   obf.long-line
 *   obf.encoded-array-fingerprint
 */

import { describe, expect, it } from "vitest";
import { scan } from "@obfuscan/core";
import { virtualFiles, silentOptions } from "../helpers/matchers";

// ─── Fixtures generated inline (small, self-contained payloads) ────────────

/** A 96-char base64-ish blob; mean Shannon entropy > 4.5. */
const HIGH_ENTROPY = "Zm9vYmFyYmF6cXV4cXV1eHF1dXV4ZG9nY2F0bW91c2VlbGVwaGFudHJoaW5vY2Vyb3NoaXBwb3BvdGFtdXNNTk9QUVJTVA==";

/** A 96-char string with low entropy (just repeating patterns). */
const LOW_ENTROPY = "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh";

/** Cyrillic 'а' (U+0430) hidden inside an otherwise-ASCII identifier. */
const HOMOGLYPH_IDENT = "pаyload"; // looks like "payload"

/** RTL override + content + pop directional formatting. */
const BIDI_TRAP = "name = \"\u202EevilPath/\u202Cbenign.txt\"";

describe("Layer A: high-entropy-literal", () => {
  it("flags a single high-entropy string in JavaScript", async () => {
    const { input, fileResolver } = virtualFiles({
      "src/secret.js": `const k = "${HIGH_ENTROPY}";\n`,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.high-entropy-literal");
  });

  it("flags a single high-entropy string in Python", async () => {
    const { input, fileResolver } = virtualFiles({
      "src/secret.py": `KEY = "${HIGH_ENTROPY}"\n`,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.high-entropy-literal");
  });

  it("flags a single high-entropy string in PowerShell", async () => {
    const { input, fileResolver } = virtualFiles({
      "src/x.ps1": `$k = "${HIGH_ENTROPY}"\n`,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.high-entropy-literal");
  });

  it("does not flag low-entropy strings", async () => {
    const { input, fileResolver } = virtualFiles({
      "src/clean.js": `const k = "${LOW_ENTROPY}";\n`,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.high-entropy-literal");
  });

  it("does not flag short strings even if entropy is high", async () => {
    const { input, fileResolver } = virtualFiles({
      "src/short.js": `const k = "Zm9v";\n`, // 4 chars, well below the 64-char floor
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.high-entropy-literal");
  });

  it("can be disabled via disabledDetectors", async () => {
    const { input, fileResolver } = virtualFiles({
      "src/secret.js": `const k = "${HIGH_ENTROPY}";\n`,
    });
    const result = await scan(input, {
      fileResolver,
      disabledDetectors: ["obf.high-entropy-literal"],
      ...silentOptions(),
    });
    expect(result).toNotFlag("obf.high-entropy-literal");
  });
});

describe("Layer A: bidi-control", () => {
  it("flags U+202E (right-to-left override) in source", async () => {
    const { input, fileResolver } = virtualFiles({
      "src/trap.py": `${BIDI_TRAP}\n`,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.bidi-control");
  });

  it("blocks on bidi (severity is block)", async () => {
    const { input, fileResolver } = virtualFiles({
      "src/trap.go": `${BIDI_TRAP}\n`,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toBlock("obf.bidi-control");
  });

  it("clean ASCII source does not flag", async () => {
    const { input, fileResolver } = virtualFiles({
      "src/clean.go": `package main\nfunc main() {}\n`,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.bidi-control");
  });
});

describe("Layer A: homoglyph-identifier", () => {
  it("flags Cyrillic-in-ASCII identifiers", async () => {
    const { input, fileResolver } = virtualFiles({
      "src/h.js": `function ${HOMOGLYPH_IDENT}() { return 1 }\n`,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.homoglyph-identifier");
  });

  it("does not flag pure ASCII identifiers", async () => {
    const { input, fileResolver } = virtualFiles({
      "src/h.js": `function payload() { return 1 }\n`,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.homoglyph-identifier");
  });

  it("does not flag pure non-ASCII identifiers (e.g. all Cyrillic)", async () => {
    // A function named entirely in Cyrillic is not a homoglyph attack —
    // it's just a non-English identifier.
    const { input, fileResolver } = virtualFiles({
      "src/h.js": `const функция = 1\n`,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.homoglyph-identifier");
  });
});

describe("Layer A: long-line", () => {
  it("flags very long minified lines", async () => {
    const longLine = "var x=" + "a".repeat(5000) + ";";
    const { input, fileResolver } = virtualFiles({
      "src/min.js": longLine,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.long-line");
  });

  it("does not flag normally-formatted source", async () => {
    const normal = Array.from({ length: 200 }, (_, i) => `const x${i} = ${i};`).join("\n");
    const { input, fileResolver } = virtualFiles({
      "src/normal.js": normal,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.long-line");
  });
});

describe("Layer A: encoded-array-fingerprint", () => {
  it("flags a large array of base64-looking strings (string-array decoder pattern)", async () => {
    const arr = Array.from({ length: 64 }, (_, i) =>
      `"${Buffer.from("payload-" + i + "-".repeat(8)).toString("base64")}"`
    ).join(", ");
    const src = `const _0xabc = [${arr}];\n`;
    const { input, fileResolver } = virtualFiles({
      "src/loader.js": src,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.encoded-array-fingerprint");
  });

  it("does not flag a small array of human-readable strings", async () => {
    const arr = ["red", "green", "blue", "yellow", "purple"].map(s => `"${s}"`).join(", ");
    const src = `const colors = [${arr}];\n`;
    const { input, fileResolver } = virtualFiles({
      "src/colors.js": src,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.encoded-array-fingerprint");
  });
});

describe("Layer A: language-agnostic execution", () => {
  it("runs on a Tier-3 language with no AST support (e.g. .erl)", async () => {
    // Erlang isn't in our parameterized AST list, but Layer A must still run.
    const src = `% erlang\n-module(t).\n-export([k/0]).\nk() -> "${HIGH_ENTROPY}".\n`;
    const { input, fileResolver } = virtualFiles({ "src/t.erl": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.high-entropy-literal");
  });

  it("runs on plain text files (e.g. .txt) without crashing", async () => {
    const { input, fileResolver } = virtualFiles({
      "notes/readme.txt": `Just some notes.\n`,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result.findings).toHaveLength(0);
    expect(result.failedDetectors).toHaveLength(0);
  });
});
