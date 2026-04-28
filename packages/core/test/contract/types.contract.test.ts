/**
 * Compile-time contract tests for the public type surface.
 *
 * These tests don't have runtime expectations — their job is to fail to
 * type-check if the documented type shape regresses. Keep them small and
 * close to what is actually documented in src/index.ts and src/types.ts.
 */

import { describe, it, expectTypeOf } from "vitest";
import type {
  Severity,
  Finding,
  LanguageConfig,
  ScanInput,
  ScanOptions,
  ScanResult,
  Detector,
  FileContext,
  Allowlist,
} from "@obfuscan/core";

describe("public types", () => {
  it("Severity is a union of three strings", () => {
    expectTypeOf<Severity>().toEqualTypeOf<"info" | "warn" | "block">();
  });

  it("Finding has the documented required fields", () => {
    type Required = "ruleId" | "severity" | "score" | "file" | "line" | "snippet" | "reason";
    expectTypeOf<keyof Finding>().toMatchTypeOf<Required | "endLine" | "enclosingSymbol" | "evidence">();
  });

  it("ScanInput is a discriminated-ish union", () => {
    const a: ScanInput = { diff: "x" };
    const b: ScanInput = { paths: ["a"] };
    const c: ScanInput = { dir: "." };
    void a; void b; void c;
  });

  it("Detector.run can be sync or async", () => {
    const sync: Detector = { id: "x", applies: () => true, run: () => [] };
    const async: Detector = { id: "x", applies: () => true, run: async () => [] };
    void sync; void async;
  });

  it("LanguageConfig requires the four core lists; others optional", () => {
    type Required = "id" | "extensions" | "dynamic_exec_sinks" | "decoders";
    expectTypeOf<Required>().toMatchTypeOf<keyof LanguageConfig>();
  });

  it("ScanOptions allows omitting everything except fileResolver", () => {
    const opts: ScanOptions = { fileResolver: async () => null };
    void opts;
  });

  it("Allowlist entries are independently optional", () => {
    const a: Allowlist = {};
    const b: Allowlist = { paths: [{ pattern: "**" }] };
    const c: Allowlist = { snippets: [{ ruleId: "x", snippetHash: "00" }] };
    void a; void b; void c;
  });

  it("ScanResult.findings is read-only", () => {
    expectTypeOf<ScanResult["findings"]>().toEqualTypeOf<readonly Finding[]>();
  });

  it("FileContext exposes a tree() promise (lazy parse)", () => {
    expectTypeOf<FileContext["tree"]>().toMatchTypeOf<() => Promise<unknown | null>>();
  });
});
