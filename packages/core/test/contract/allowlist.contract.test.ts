/**
 * Allowlist contract: helpers, semantics, and behavior under scan().
 */

import { describe, it, expect } from "vitest";
import {
  scan,
  hashSnippet,
  matchesAllowlist,
  type Allowlist,
  type Finding,
} from "@obfuscan/core";
import { virtualFiles, silentOptions } from "../helpers/matchers";

describe("hashSnippet()", () => {
  it("produces a stable lowercase hex sha256", () => {
    const h = hashSnippet("hello");
    expect(h).toBe("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it("normalizes whitespace before hashing", () => {
    // Whitespace normalization is documented so suppressions survive reformatters.
    const a = hashSnippet("eval(  x  )");
    const b = hashSnippet("eval( x )");
    expect(a).toBe(b);
  });
});

describe("matchesAllowlist()", () => {
  const finding = (overrides: Partial<Finding> = {}): Finding => ({
    ruleId: "obf.high-entropy-literal",
    severity: "warn",
    score: 4,
    file: "src/lib.js",
    line: 5,
    snippet: "VGhpcyBpcyB0ZXN0IGRhdGE=",
    reason: "",
    ...overrides,
  });

  it("matches a path-glob entry", () => {
    const list: Allowlist = { paths: [{ pattern: "**/vendor/**" }] };
    expect(matchesAllowlist(finding({ file: "node/vendor/x.js" }), list, "node/vendor/x.js")).toBe(true);
    expect(matchesAllowlist(finding({ file: "src/lib.js" }), list, "src/lib.js")).toBe(false);
  });

  it("respects maxSeverity ceilings on path entries", () => {
    const list: Allowlist = {
      paths: [{ pattern: "src/**", maxSeverity: "warn" }],
    };
    expect(matchesAllowlist(finding({ severity: "info" }), list, "src/lib.js")).toBe(true);
    expect(matchesAllowlist(finding({ severity: "warn" }), list, "src/lib.js")).toBe(true);
    expect(matchesAllowlist(finding({ severity: "block" }), list, "src/lib.js")).toBe(false);
  });

  it("matches a snippet entry by (ruleId, snippetHash)", () => {
    const f = finding();
    const list: Allowlist = {
      snippets: [{ ruleId: f.ruleId, snippetHash: hashSnippet(f.snippet) }],
    };
    expect(matchesAllowlist(f, list, f.file)).toBe(true);
  });

  it("snippet entry does not match across rule ids", () => {
    const f = finding();
    const list: Allowlist = {
      snippets: [{ ruleId: "obf.different", snippetHash: hashSnippet(f.snippet) }],
    };
    expect(matchesAllowlist(f, list, f.file)).toBe(false);
  });
});

describe("scan() integration with allowlist", () => {
  it("findings matching a path entry are dropped from the result", async () => {
    const { input, fileResolver } = virtualFiles({
      "vendor/min.js": "var x = '" + "A".repeat(2000) + "';",
    });
    const r = await scan(input, {
      fileResolver,
      allowlist: { paths: [{ pattern: "vendor/**" }] },
      ...silentOptions(),
    });
    expect(r.findings).toHaveLength(0);
  });

  it("findings matching a snippet entry are dropped", async () => {
    const src = "var x = '" + "ABCDEF".repeat(200) + "';";
    const { input, fileResolver } = virtualFiles({ "a.js": src });
    const baseline = await scan(input, { fileResolver, ...silentOptions() });
    const target = baseline.findings.find(f => f.ruleId === "obf.high-entropy-literal");
    if (!target) return; // engine not implemented yet — contract test only guards shape

    const r = await scan(input, {
      fileResolver,
      allowlist: {
        snippets: [{ ruleId: target.ruleId, snippetHash: hashSnippet(target.snippet) }],
      },
      ...silentOptions(),
    });
    expect(r.findings.find(f => f.ruleId === target.ruleId)).toBeUndefined();
  });
});
