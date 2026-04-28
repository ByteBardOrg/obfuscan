/**
 * Engine version, replaced at build time by the bundler.
 *
 * In source mode (when running tests directly against TS via Vitest), we
 * fall back to reading `packages/core/package.json` lazily. The token
 * `__ENGINE_VERSION__` is replaced by the build pipeline (tsup/esbuild
 * `define`) when shipping a published artifact.
 */

import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

let cached: string | null = null;
const here = path.dirname(fileURLToPath(import.meta.url));

export const ENGINE_VERSION: string = (() => {
  if (cached) return cached;
  const placeholder = "__ENGINE_VERSION__";
  // Build pipelines replace the literal string above. If still present, we're
  // running against TS sources — read the version from package.json.
  if (placeholder !== "__ENGINE" + "_VERSION__") {
    cached = placeholder;
    return cached;
  }
  try {
    // Walk up from this file to locate the nearest package.json.
    const req = createRequire(import.meta.url);
    const candidates = [
      path.resolve(here, "..", "package.json"),
      path.resolve(here, "..", "..", "package.json"),
    ];
    for (const c of candidates) {
      try {
        const pkg = req(c) as { name?: string; version?: string };
        if (pkg.name === "@obfuscan/core" && typeof pkg.version === "string") {
          cached = pkg.version;
          return cached;
        }
      } catch {
        // try next
      }
    }
  } catch {
    // ignore
  }
  cached = "0.0.0-source";
  return cached;
})();
