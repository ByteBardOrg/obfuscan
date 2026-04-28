/**
 * Built-in detector registry.
 *
 * `defaultDetectors()` returns the canonical, ordered list shipped with
 * `@obfuscan/core`. Order is meaningful for stable output: when two detectors
 * fire on the same line and severity, the earlier-listed one's finding sorts
 * first.
 */

import type { Detector } from "../types.js";

// Layer A — universal source-level detectors
import { highEntropyLiteral } from "./high-entropy-literal.js";
import { bidiControlChar } from "./bidi-control.js";
import { homoglyphIdentifier } from "./homoglyph-identifier.js";
import { longLine } from "./long-line.js";
import { encodedArrayFingerprint } from "./encoded-array-fingerprint.js";

// Layer B — config-driven semantic detectors
import { decodeThenExec } from "./decode-then-exec.js";
import { dynamicExecNonLiteral } from "./dynamic-exec-non-literal.js";
import { networkThenExec } from "./network-then-exec.js";
import { deserializerUntrusted } from "./deserializer-untrusted.js";
import { suspiciousIoCluster } from "./suspicious-io-cluster.js";
import { stringArrayDecoder } from "./string-array-decoder.js";
import { shellUntrustedInput } from "./shell-untrusted-input.js";
import { libraryLoadNonLiteral } from "./library-load-non-literal.js";

// Manifest — ecosystem-specific detectors
import { manifestInstallScript } from "./manifest-install-script.js";
import { pythonSetupSideEffect } from "./python-setup-side-effect.js";
import { perlMakefileSideEffect } from "./perl-makefile-side-effect.js";
import { cargoBuildRsNetwork } from "./cargo-build-rs-network.js";
import { ghaCurlPipeShell } from "./gha-curl-pipe-shell.js";
import { dockerfileCurlPipeShell } from "./dockerfile-curl-pipe-shell.js";

export function defaultDetectors(): readonly Detector[] {
  return DEFAULTS;
}

const DEFAULTS: readonly Detector[] = Object.freeze([
  // Layer A
  highEntropyLiteral,
  bidiControlChar,
  homoglyphIdentifier,
  longLine,
  encodedArrayFingerprint,

  // Layer B
  decodeThenExec,
  networkThenExec,
  dynamicExecNonLiteral,
  deserializerUntrusted,
  suspiciousIoCluster,
  stringArrayDecoder,
  shellUntrustedInput,
  libraryLoadNonLiteral,

  // Manifest
  manifestInstallScript,
  pythonSetupSideEffect,
  perlMakefileSideEffect,
  cargoBuildRsNetwork,
  ghaCurlPipeShell,
  dockerfileCurlPipeShell,
]);

// Named re-exports for tests and advanced consumers.
export {
  highEntropyLiteral,
  bidiControlChar,
  homoglyphIdentifier,
  longLine,
  encodedArrayFingerprint,
  decodeThenExec,
  dynamicExecNonLiteral,
  networkThenExec,
  deserializerUntrusted,
  suspiciousIoCluster,
  stringArrayDecoder,
  shellUntrustedInput,
  libraryLoadNonLiteral,
  manifestInstallScript,
  pythonSetupSideEffect,
  perlMakefileSideEffect,
  cargoBuildRsNetwork,
  ghaCurlPipeShell,
  dockerfileCurlPipeShell,
};
