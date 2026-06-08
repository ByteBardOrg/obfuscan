import { describe, expect, it } from "vitest";
import { readInputs } from "../src/inputs";

describe("readInputs", () => {
  it("reads GitHub action input environment variables with hyphenated names", () => {
    const inputs = readInputs({
      "INPUT_GITHUB-TOKEN": "token-1",
      "INPUT_FAIL-ON": "warn",
      "INPUT_MIN-SEVERITY": "block",
      "INPUT_COMMENT": "false",
      "INPUT_MAX-FINDINGS": "7",
      "INPUT_ALLOWLIST-PATH": "custom/allowlist.json",
      "INPUT_DISABLED-DETECTORS": "obf.long-line\nobf.high-entropy-literal",
      "INPUT_FILE-TIMEOUT-MS": "1234",
    });

    expect(inputs).toEqual({
      githubToken: "token-1",
      failOn: "warn",
      minSeverity: "block",
      comment: false,
      maxFindings: 7,
      allowlistPath: "custom/allowlist.json",
      disabledDetectors: ["obf.long-line", "obf.high-entropy-literal"],
      fileTimeoutMs: 1234,
    });
  });

  it("keeps underscore input names as a compatibility fallback", () => {
    const inputs = readInputs({
      "INPUT_GITHUB_TOKEN": "token-2",
      "INPUT_FAIL_ON": "never",
      "INPUT_MIN_SEVERITY": "warn",
      "INPUT_COMMENT": "true",
      "INPUT_MAX_FINDINGS": "12",
      "INPUT_ALLOWLIST_PATH": "fallback.json",
      "INPUT_DISABLED_DETECTORS": "obf.a,obf.b",
      "INPUT_FILE_TIMEOUT_MS": "4321",
    });

    expect(inputs).toEqual({
      githubToken: "token-2",
      failOn: "never",
      minSeverity: "warn",
      comment: true,
      maxFindings: 12,
      allowlistPath: "fallback.json",
      disabledDetectors: ["obf.a", "obf.b"],
      fileTimeoutMs: 4321,
    });
  });

  it("prefers GitHub hyphenated input names over underscore fallbacks", () => {
    const inputs = readInputs({
      "INPUT_GITHUB-TOKEN": "official-token",
      "INPUT_GITHUB_TOKEN": "fallback-token",
    });

    expect(inputs.githubToken).toBe("official-token");
  });
});
