/**
 * obf.npm-c2-dropper — Layer B/package malware heuristic.
 *
 * Flags the combined shape used by npm C2 droppers: package code polls a C2
 * API, decrypts staged content, writes it to disk, marks it executable, and
 * launches it with Node or a child process. Each individual API is common;
 * the cluster is the signal.
 */

import type { Detector, FileContext, Finding } from "../types.js";
import { lineAtOffset, MAX_SOURCE_BYTES } from "../internal/patterns.js";
import { truncateSnippet } from "../internal/text.js";

const JS_LIKE = new Set(["javascript", "typescript"]);

const C2_RE =
  /(?:slack\.com|conversations\.history|auth\.test|\bAuthorization\s*:\s*["']Bearer\s+|\bxox[abprs]-)/;
const CRYPTO_RE = /(?:AES-GCM|PBKDF2|subtle|\.decrypt\s*\(|deriveKey\s*\(|importKey\s*\()/;
const WRITE_RE = /\bwriteFileSync\s*\(/;
const CHMOD_RE = /\bchmodSync\s*\(/;
const CHILD_PROCESS_RE =
  /(?:\bspawn\s*[:=,}]|\bexecSync\s*[:=,}]|\bchild_process\b|\bprocess\.execPath\b|\b\.unref\s*\()/;
const SELF_DELETE_RE = /\bunlinkSync\s*\(\s*__filename\b/;

export const npmC2Dropper: Detector = {
  id: "obf.npm-c2-dropper",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfnpm-c2-dropper",

  applies(ctx: FileContext): boolean {
    return (
      ctx.source.length > 0 &&
      ctx.source.length < MAX_SOURCE_BYTES &&
      (ctx.languageId === null || JS_LIKE.has(ctx.languageId))
    );
  },

  run(ctx: FileContext): Finding[] {
    const src = ctx.source;
    const c2 = C2_RE.exec(src);
    if (!c2) return [];

    const crypto = CRYPTO_RE.exec(src);
    if (!crypto) return [];

    const write = WRITE_RE.exec(src);
    const chmod = CHMOD_RE.exec(src);
    const child = CHILD_PROCESS_RE.exec(src);
    const selfDelete = SELF_DELETE_RE.exec(src);
    if (!write || !chmod || !child) return [];

    const offset = Math.min(
      c2.index,
      crypto.index,
      write.index,
      chmod.index,
      child.index,
      selfDelete?.index ?? Number.POSITIVE_INFINITY,
    );

    return [{
      ruleId: npmC2Dropper.id,
      severity: "block",
      score: 10,
      file: ctx.path,
      line: lineAtOffset(src, offset),
      snippet: truncateSnippet(src.slice(offset, offset + 200)),
      reason:
        `JavaScript package contains C2 polling, decrypt-stage, write/chmod, ` +
        `and child-process launch signals. This matches npm command-and-control dropper behavior.`,
      evidence: {
        c2: c2[0],
        crypto: crypto[0],
        writesFile: true,
        chmodsFile: true,
        launchesChildProcess: true,
        selfDelete: !!selfDelete,
      },
    }];
  },
};
