/**
 * Custom matchers + helpers used across all suites.
 *
 * Tests import obfuscan only through @obfuscan/core (the public entry); this
 * file is the single place that's allowed to wrap the public API for testing
 * ergonomics.
 */

import { expect } from "vitest";
import type { Finding, Severity, ScanResult } from "@obfuscan/core";

declare module "vitest" {
  interface Assertion<T> {
    /** At least one finding has `ruleId` matching exactly or by prefix (e.g. "obf.decode-then-exec"). */
    toFlag(ruleId: string): T;
    /** No finding's ruleId starts with `ruleId`. */
    toNotFlag(ruleId: string): T;
    /** At least one finding has severity "block". Optionally constrained by ruleId prefix. */
    toBlock(ruleId?: string): T;
    /** Findings list is empty. Pretty-prints findings on failure. */
    toBeClean(): T;
  }
}

const SEVERITY_RANK: Record<Severity, number> = { info: 0, warn: 1, block: 2 };

function findingsOf(received: ScanResult | readonly Finding[]): readonly Finding[] {
  return Array.isArray(received)
    ? (received as readonly Finding[])
    : ((received as ScanResult).findings ?? []);
}

function format(findings: readonly Finding[]): string {
  if (findings.length === 0) return "  (no findings)";
  return findings
    .map(f => `  ${f.severity.toUpperCase()} ${f.file}:${f.line} [${f.ruleId}] ${f.reason}`)
    .join("\n");
}

expect.extend({
  toFlag(received, ruleId: string) {
    const findings = findingsOf(received);
    const matched = findings.some(f => f.ruleId === ruleId || f.ruleId.startsWith(ruleId + "."));
    return {
      pass: matched,
      message: () =>
        matched
          ? `expected NOT to flag ${ruleId}\n${format(findings)}`
          : `expected to flag ${ruleId}, got:\n${format(findings)}`,
    };
  },
  toNotFlag(received, ruleId: string) {
    const findings = findingsOf(received);
    const matched = findings.find(f => f.ruleId === ruleId || f.ruleId.startsWith(ruleId + "."));
    return {
      pass: !matched,
      message: () =>
        matched
          ? `expected NOT to flag ${ruleId}, but found:\n${format([matched])}`
          : `expected to flag ${ruleId} but it was clean (this is the success message)`,
    };
  },
  toBlock(received, ruleId?: string) {
    const findings = findingsOf(received);
    const matched = findings.find(f =>
      f.severity === "block" &&
      (!ruleId || f.ruleId === ruleId || f.ruleId.startsWith(ruleId + "."))
    );
    return {
      pass: !!matched,
      message: () =>
        matched
          ? `expected NOT to block${ruleId ? ` on ${ruleId}` : ""}\n${format([matched])}`
          : `expected to block${ruleId ? ` on ${ruleId}` : ""}, got:\n${format(findings)}`,
    };
  },
  toBeClean(received) {
    const findings = findingsOf(received);
    const blocking = findings.filter(f => SEVERITY_RANK[f.severity] >= SEVERITY_RANK.block);
    return {
      pass: blocking.length === 0,
      message: () =>
        blocking.length === 0
          ? `expected blocking findings, got none`
          : `expected no block-severity findings, got:\n${format(blocking)}`,
    };
  },
});

// ─── Helpers used in tests ─────────────────────────────────────────────────

import type { ScanInput, ScanOptions, FileResolver } from "@obfuscan/core";

/** Build a ScanInput + FileResolver from a virtual filesystem. */
export function virtualFiles(files: Record<string, string>): {
  input: ScanInput;
  fileResolver: FileResolver;
} {
  return {
    input: { paths: Object.keys(files) },
    fileResolver: async (p) => (p in files ? (files[p] ?? null) : null),
  };
}

/** Build a ScanInput + FileResolver from a unified diff and the post-image content. */
export function diffWithPostImage(
  diff: string,
  postImage: Record<string, string>,
): { input: ScanInput; fileResolver: FileResolver } {
  return {
    input: { diff },
    fileResolver: async (p) => (p in postImage ? (postImage[p] ?? null) : null),
  };
}

/** Convenience: a ScanOptions with defaults but a stable, silent logger. */
export function silentOptions(extra: Partial<ScanOptions> = {}): Partial<ScanOptions> {
  return {
    logger: { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} },
    ...extra,
  };
}
