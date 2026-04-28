/**
 * obf.suspicious-io-cluster.<lang> — Layer B.
 *
 * Fires when a single file *both* reads from a known-secrets path
 * (~/.npmrc, ~/.aws/credentials, ~/.ssh/id_*, etc.) *and* makes an
 * outbound network call. The cluster is the signal — either alone is
 * usually benign.
 */

import type { Detector, FileContext, Finding, LanguageConfig } from "../types.js";
import {
  lineAtOffset,
  MAX_FINDINGS_PER_DETECTOR,
  MAX_SOURCE_BYTES,
  namedCallAlternation,
} from "../internal/patterns.js";
import { truncateSnippet } from "../internal/text.js";

// Path fragments that strongly indicate a secrets read.
const SECRET_PATH_RE =
  /(\.npmrc|\.aws[\/\\]credentials|\.aws[\/\\]config|\.ssh[\/\\]id_[a-z0-9_]+|\.docker[\/\\]config|\.gitconfig|\.netrc|GITHUB_TOKEN|NPM_TOKEN|AWS_ACCESS_KEY)/g;

interface Compiled {
  network: RegExp | null;
  secretsIo: RegExp | null;
  shellExec: RegExp | null;
}

const cache = new WeakMap<LanguageConfig, Compiled>();

function compile(config: LanguageConfig): Compiled {
  const cached = cache.get(config);
  if (cached) return cached;
  const net = config.network_io ?? [];
  const sec = config.secrets_io ?? [];
  const shell = config.shell_exec ?? [];
  const compiled: Compiled = {
    network: net.length ? new RegExp(`(?:${namedCallAlternation(net)})\\s*\\(`, "g") : null,
    secretsIo: sec.length ? new RegExp(`(?:${namedCallAlternation(sec)})\\s*\\(`, "g") : null,
    shellExec: shell.length ? new RegExp(`(?:${namedCallAlternation(shell)})\\s*\\(`, "g") : null,
  };
  cache.set(config, compiled);
  return compiled;
}

export const suspiciousIoCluster: Detector = {
  id: "obf.suspicious-io-cluster",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfsuspicious-io-cluster",

  applies(ctx: FileContext): boolean {
    return (
      ctx.config !== null &&
      ctx.source.length > 0 &&
      ctx.source.length < MAX_SOURCE_BYTES
    );
  },

  run(ctx: FileContext): Finding[] {
    if (!ctx.config) return [];
    const cfg = ctx.config;
    const src = ctx.source;
    const { network, shellExec } = compile(cfg);
    if (!network) return [];

    // 1. Find at least one secret-path reference.
    const secretPathMatch = SECRET_PATH_RE.exec(src);
    SECRET_PATH_RE.lastIndex = 0;
    const hasSecretPath = !!secretPathMatch;

    // 2. Find at least one network call.
    const netRe = new RegExp(network.source, network.flags);
    const netMatch = netRe.exec(src);
    if (!netMatch) return [];

    // Secondary cluster: shell + network in the same file. This catches
    // setup.py and similar install-time droppers that fetch and execute.
    const shellMatch = shellExec ? new RegExp(shellExec.source, shellExec.flags).exec(src) : null;
    if (!hasSecretPath && !shellMatch) return [];

    const findings: Finding[] = [];
    if (findings.length >= MAX_FINDINGS_PER_DETECTOR) return findings;

    // Anchor the finding on whichever appears earlier — gives the user a
    // single jump-to location for the cluster.
    const offset = hasSecretPath
      ? Math.min(secretPathMatch!.index, netMatch.index)
      : Math.min(shellMatch!.index, netMatch.index);
    findings.push({
      ruleId: `obf.suspicious-io-cluster.${cfg.id}`,
      severity: "warn",
      score: 8,
      file: ctx.path,
      line: lineAtOffset(src, offset),
      snippet: truncateSnippet(
        src.slice(offset, Math.min(src.length, offset + 200)),
      ),
      reason:
        `File reads from a known secrets location AND makes a network call. ` +
        `This is the data-exfil cluster shape that defines supply-chain malware.`,
      evidence: {
        language: cfg.id,
        secretMarker: secretPathMatch?.[0] ?? null,
        shellCall: shellMatch?.[0] ?? null,
        networkCall: netMatch[0],
      },
    });
    return findings;
  },
};
