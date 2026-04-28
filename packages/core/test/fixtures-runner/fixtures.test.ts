/**
 * Fixture-driven regression suite.
 *
 * Layout:
 *   test/fixtures/
 *     malicious/<lang>/<case-name>/
 *       input.<ext>            — source file under test
 *       expected.json          — expected findings (see schema below)
 *       SOURCE.md              — provenance + reference URLs (REQUIRED)
 *     benign/<lang>/<case-name>/
 *       input.<ext>
 *       expected.json          — must declare zero blocking findings
 *       SOURCE.md
 *
 * `expected.json` schema:
 *   {
 *     "description": "<one-line summary>",
 *     "mustFlag":   ["obf.decode-then-exec"],          // ruleId prefixes
 *     "mustNotFlag":["obf.high-entropy-literal"],      // optional
 *     "mustBlock":  ["obf.network-then-exec"],         // optional
 *     "expectClean": false,                            // benign cases set true
 *     "as":          "package.json"                    // optional: present the file
 *                                                      // to the scanner under this
 *                                                      // workspace-relative path. Used
 *                                                      // when the detector keys off the
 *                                                      // filename (package.json, setup.py,
 *                                                      // Dockerfile, .github/workflows/*).
 *   }
 *
 * To add a new fixture: drop a directory in. No code changes needed.
 *
 * Provenance rules (enforced by the loader):
 *   - SOURCE.md MUST exist for every fixture
 *   - Live malicious payloads from real incidents MUST be defanged: replace
 *     command-and-control URLs with example.com, replace base64 of real
 *     payloads with structurally-equivalent stubs of the same shape.
 *   - Reference the real-world incident in SOURCE.md by URL.
 */

import { describe, expect, it } from "vitest";
import { scan } from "@obfuscan/core";
import { silentOptions } from "../helpers/matchers";
import * as fs from "node:fs/promises";
import * as path from "node:path";

const FIXTURES_DIR = path.resolve(__dirname, "..", "fixtures");

interface ExpectedSpec {
  description: string;
  mustFlag?: string[];
  mustNotFlag?: string[];
  mustBlock?: string[];
  expectClean?: boolean;
  /** Optional. If set, the file is presented to the scanner under this workspace-relative path. */
  as?: string;
}

interface FixtureCase {
  category: "malicious" | "benign";
  language: string;
  name: string;
  inputPath: string;       // workspace-relative path used by scan()
  inputAbsPath: string;    // absolute path on disk
  expected: ExpectedSpec;
}

async function discoverFixtures(): Promise<FixtureCase[]> {
  const cases: FixtureCase[] = [];
  for (const category of ["malicious", "benign"] as const) {
    const catDir = path.join(FIXTURES_DIR, category);
    let langs: string[];
    try {
      langs = await fs.readdir(catDir);
    } catch {
      continue;
    }
    for (const language of langs) {
      const langDir = path.join(catDir, language);
      const stat = await fs.stat(langDir).catch(() => null);
      if (!stat?.isDirectory()) continue;
      for (const name of await fs.readdir(langDir)) {
        const caseDir = path.join(langDir, name);
        const cstat = await fs.stat(caseDir).catch(() => null);
        if (!cstat?.isDirectory()) continue;

        const entries = await fs.readdir(caseDir);
        const inputName = entries.find(e => e.startsWith("input."));
        if (!inputName) {
          throw new Error(`fixture ${caseDir}: missing input.<ext> file`);
        }
        if (!entries.includes("SOURCE.md")) {
          throw new Error(`fixture ${caseDir}: missing SOURCE.md (required for provenance)`);
        }
        const expectedRaw = await fs.readFile(path.join(caseDir, "expected.json"), "utf8");
        const expected = JSON.parse(expectedRaw) as ExpectedSpec;

        const inputPath = expected.as
          ? expected.as
          : `${category}/${language}/${name}/${inputName}`;
        cases.push({
          category,
          language,
          name,
          inputPath,
          inputAbsPath: path.join(caseDir, inputName),
          expected,
        });
      }
    }
  }
  return cases.sort((a, b) =>
    a.category.localeCompare(b.category) ||
    a.language.localeCompare(b.language) ||
    a.name.localeCompare(b.name),
  );
}

const cases = await discoverFixtures();

describe("fixture corpus", () => {
  // The canonical tier list. Adding a language to either tier here makes
  // the structural guard fail until a fixture lands; that's intentional.
  // Source of truth: docs/coverage.md.
  const TIER1 = [
    "javascript", "typescript", "python", "powershell",
    "bash", "php", "ruby",
  ] as const;
  const TIER2 = [
    "go", "rust", "csharp", "java",
    "kotlin", "lua", "perl", "vbscript",
  ] as const;

  it.each([...TIER1, ...TIER2])(
    "%s has at least one malicious fixture",
    (lang) => {
      const mal = cases.filter(c => c.category === "malicious" && c.language === lang);
      expect(mal.length, `${lang}: needs at least one malicious fixture in test/fixtures/malicious/${lang}/`).toBeGreaterThan(0);
    },
  );

  it.each([...TIER1, ...TIER2])(
    "%s has at least one benign fixture",
    (lang) => {
      const ben = cases.filter(c => c.category === "benign" && c.language === lang);
      expect(ben.length, `${lang}: needs at least one benign fixture in test/fixtures/benign/${lang}/`).toBeGreaterThan(0);
    },
  );
});

describe.each(cases)("$category / $language / $name", (c) => {
  it(c.expected.description, async () => {
    const source = await fs.readFile(c.inputAbsPath, "utf8");
    const result = await scan(
      { paths: [c.inputPath] },
      {
        fileResolver: async (p) => (p === c.inputPath ? source : null),
        ...silentOptions(),
      },
    );

    for (const id of c.expected.mustFlag ?? []) {
      expect(result, `mustFlag: ${id}`).toFlag(id);
    }
    for (const id of c.expected.mustNotFlag ?? []) {
      expect(result, `mustNotFlag: ${id}`).toNotFlag(id);
    }
    for (const id of c.expected.mustBlock ?? []) {
      expect(result, `mustBlock: ${id}`).toBlock(id);
    }
    if (c.expected.expectClean) {
      // benign fixtures: no block-severity findings allowed
      const blocking = result.findings.filter(f => f.severity === "block");
      expect(blocking, "benign fixture must not produce block-severity findings").toEqual([]);
    }
  });
});
