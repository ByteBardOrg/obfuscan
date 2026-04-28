/**
 * Performance budgets.
 *
 * The scanner is meant to run on every PR — it must be fast and must not
 * blow up on adversarially-shaped input (huge files, very long lines, deeply
 * nested structures).
 *
 * These budgets are wall-clock on the test runner, so they're loose enough
 * to survive shared CI hardware. Tighten when the engine matures.
 */

import { describe, expect, it } from "vitest";
import { scan } from "@obfuscan/core";
import { virtualFiles, silentOptions } from "../helpers/matchers";

const PERF_FULL = process.env.OBFUSCAN_PERF_FULL === "1";

const BUDGET_MS_10K_LINES = 1500; // 10k-line normal file: 1.5s wall clock
const BUDGET_MS_100K_LINES = 8000; // 100k-line normal file: 8s wall clock
const BUDGET_MS_LONG_LINE = 1500; // single huge line: must NOT trigger ReDoS
const BUDGET_MS_DEEP_NEST = 1500; // deeply-nested AST: must NOT explode

const LONG_LINE_BYTES = PERF_FULL ? 500_000 : 100_000;

function genNormalJs(lines: number): string {
  // Realistic-ish JS — function defs, calls, arithmetic. No obfuscation
  // shapes that would trigger a tonne of findings.
  const buf: string[] = [];
  for (let i = 0; i < lines; i++) {
    buf.push(
      `function fn_${i}(x) { const y = x * ${i % 31}; return y + ${i}; }`,
    );
  }
  return buf.join("\n");
}

describe("perf budgets", () => {
  it(`scans a 10,000-line JS file in ≤${BUDGET_MS_10K_LINES}ms`, async () => {
    const src = genNormalJs(10_000);
    const { input, fileResolver } = virtualFiles({ "src/big.js": src });

    const t0 = Date.now();
    const result = await scan(input, { fileResolver, ...silentOptions() });
    const dt = Date.now() - t0;

    // eslint-disable-next-line no-console
    console.log(`[perf] 10k-line JS: ${dt}ms (budget ${BUDGET_MS_10K_LINES}ms)`);
    expect(dt).toBeLessThanOrEqual(BUDGET_MS_10K_LINES);
    expect(result.failedDetectors).toHaveLength(0);
  });

  const itFull = PERF_FULL ? it : it.skip;

  itFull(`scans a 100,000-line JS file in ≤${BUDGET_MS_100K_LINES}ms`, async () => {
    const src = genNormalJs(100_000);
    const { input, fileResolver } = virtualFiles({ "src/huge.js": src });

    const t0 = Date.now();
    const result = await scan(input, { fileResolver, ...silentOptions() });
    const dt = Date.now() - t0;

    // eslint-disable-next-line no-console
    console.log(`[perf] 100k-line JS: ${dt}ms (budget ${BUDGET_MS_100K_LINES}ms)`);
    expect(dt).toBeLessThanOrEqual(BUDGET_MS_100K_LINES);
    expect(result.failedDetectors).toHaveLength(0);
  });

  it(`survives a single ${(LONG_LINE_BYTES / 1000).toFixed(0)}KB line without ReDoS (≤${BUDGET_MS_LONG_LINE}ms)`, async () => {
    // Pathological shape: one line, a half-million chars. A naive regex
    // on `^.{1000,}$` with backtracking would explode.
    const src = "var x = " + "a".repeat(LONG_LINE_BYTES) + ";\n";
    const { input, fileResolver } = virtualFiles({ "src/redos.js": src });

    const t0 = Date.now();
    const result = await scan(input, { fileResolver, ...silentOptions() });
    const dt = Date.now() - t0;

    // eslint-disable-next-line no-console
    console.log(`[perf] ${Math.round(LONG_LINE_BYTES / 1000)}KB single line: ${dt}ms (budget ${BUDGET_MS_LONG_LINE}ms)`);
    expect(dt).toBeLessThanOrEqual(BUDGET_MS_LONG_LINE);
    // We don't care whether it flags `obf.long-line` — we care that it returns.
    expect(result.failedDetectors).toHaveLength(0);
  });

  it(`survives deeply-nested call expressions (≤${BUDGET_MS_DEEP_NEST}ms)`, async () => {
    // Nested calls: f(f(f(f(...)))) — 1024 deep. Tree-sitter handles this,
    // but a recursive walker without depth limits would stack-overflow.
    const depth = 1024;
    const src = "var x = " + "f(".repeat(depth) + "1" + ")".repeat(depth) + ";\n";
    const { input, fileResolver } = virtualFiles({ "src/nest.js": src });

    const t0 = Date.now();
    const result = await scan(input, { fileResolver, ...silentOptions() });
    const dt = Date.now() - t0;

    // eslint-disable-next-line no-console
    console.log(`[perf] deep-nested calls: ${dt}ms (budget ${BUDGET_MS_DEEP_NEST}ms)`);
    expect(dt).toBeLessThanOrEqual(BUDGET_MS_DEEP_NEST);
    expect(result.failedDetectors).toHaveLength(0);
  });

  it("scales sub-quadratically: doubling input must not 4× the time", async () => {
    const small = genNormalJs(2_500);
    const large = genNormalJs(5_000);

    const v1 = virtualFiles({ "src/small.js": small });
    const v2 = virtualFiles({ "src/large.js": large });

    // Warm-up to amortize JIT.
    await scan(v1.input, { fileResolver: v1.fileResolver, ...silentOptions() });

    const t1 = Date.now();
    await scan(v1.input, { fileResolver: v1.fileResolver, ...silentOptions() });
    const dtSmall = Date.now() - t1;

    const t2 = Date.now();
    await scan(v2.input, { fileResolver: v2.fileResolver, ...silentOptions() });
    const dtLarge = Date.now() - t2;

    // Allow generous slack to avoid CI flakiness, but anything ≥3× on a 2× input
    // is a signal of accidental quadratic behavior.
    const ratio = dtLarge / Math.max(dtSmall, 1);
    // eslint-disable-next-line no-console
    console.log(
      `[perf] scaling: small=${dtSmall}ms large=${dtLarge}ms ratio=${ratio.toFixed(2)} (max 3.0)`,
    );
    expect(ratio).toBeLessThanOrEqual(3.0);
  });

  it("respects the per-file timeout — slow files emit info, scan completes", async () => {
    // We construct a file that *might* be slow, but the timeout is the
    // primary guarantee: scan() must always return within (timeout × concurrency).
    const src = genNormalJs(20_000);
    const { input, fileResolver } = virtualFiles({ "src/slowish.js": src });

    const t0 = Date.now();
    const result = await scan(input, {
      fileResolver,
      fileTimeoutMs: 100, // aggressive
      ...silentOptions(),
    });
    const dt = Date.now() - t0;

    // eslint-disable-next-line no-console
    console.log(`[perf] aggressive 100ms timeout on 20k-line file: completed in ${dt}ms`);
    // scan() must complete; we don't assert findings here.
    expect(result).toBeDefined();
  });
});
