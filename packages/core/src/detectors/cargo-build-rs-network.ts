/**
 * obf.cargo-build-rs-network — Manifest detector for Cargo `build.rs`.
 *
 * Flags `build.rs` files that perform network IO. `build.rs` runs at compile
 * time on every machine that builds the crate; network-fetching binaries
 * here is a supply-chain malware delivery shape.
 *
 * Allowed: `println!("cargo:...")` directives and pure-compute build logic.
 */

import type { Detector, FileContext, Finding } from "../types.js";
import { lineAtOffset } from "../internal/patterns.js";
import { truncateSnippet } from "../internal/text.js";

function isBuildRs(p: string): boolean {
  return p === "build.rs" || p.endsWith("/build.rs");
}

// Network markers in Rust build scripts
const NETWORK_RE =
  /\b(?:reqwest::|ureq::|isahc::|hyper::|surf::|attohttpc::|curl::|tokio::net|std::net::TcpStream|std::net::UdpSocket)/g;

// Process-spawn markers (curl|wget shelled out from build.rs)
const PROCESS_NETWORK_RE =
  /Command::new\s*\(\s*"(?:curl|wget|powershell|pwsh)"/g;

export const cargoBuildRsNetwork: Detector = {
  id: "obf.cargo-build-rs-network",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfcargo-build-rs-network",

  applies(ctx: FileContext): boolean {
    return isBuildRs(ctx.path);
  },

  run(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const src = ctx.source;
    const seen = new Set<number>();

    for (const re of [NETWORK_RE, PROCESS_NETWORK_RE]) {
      const local = new RegExp(re.source, re.flags);
      let m: RegExpExecArray | null;
      while ((m = local.exec(src)) !== null) {
        const line = lineAtOffset(src, m.index);
        if (seen.has(line)) continue;
        seen.add(line);
        findings.push({
          ruleId: cargoBuildRsNetwork.id,
          severity: "block",
          score: 9,
          file: ctx.path,
          line,
          snippet: truncateSnippet(m[0]),
          reason:
            `\`build.rs\` performs network IO at compile time. Fetching code or ` +
            `binaries from the network during a build is a supply-chain ` +
            `malware delivery vector.`,
          evidence: { marker: m[0] },
        });
      }
    }
    return findings;
  },
};
