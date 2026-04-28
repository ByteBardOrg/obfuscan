/// <reference types="vitest" />
import { defineConfig } from "vitest/config";
import * as path from "node:path";

const ROOT = path.resolve(__dirname, "..");

/**
 * Single config; suite selection is via Vitest filters in package.json
 * (`vitest run --dir test/contract`, etc.).
 *
 * Why not vitest workspaces / `projects`: the workspace API has churned
 * across vitest 0.x → 1.x → 2.x. A flat config + script-level filtering
 * is stable across the supported range and keeps "what runs where"
 * obvious from package.json alone.
 */
export default defineConfig({
  resolve: {
    alias: {
      // Tests import the public entry only.
      "@obfuscan/core": path.resolve(ROOT, "src/index.ts"),
    },
  },
  test: {
    setupFiles: [path.resolve(__dirname, "helpers/matchers.ts")],
    include: [
      "test/contract/**/*.test.ts",
      "test/unit/**/*.test.ts",
      "test/fixtures-runner/**/*.test.ts",
      "test/perf/**/*.test.ts",
    ],
    // Fixture *data* directories must never be picked up as test files.
    exclude: [
      "test/fixtures/**",
      "node_modules/**",
      "dist/**",
    ],
    testTimeout: 10 * 60 * 1000,
  },
});
