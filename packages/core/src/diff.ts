/**
 * Unified-diff parser → DiffFile[].
 *
 * Pure, dependency-free, line-based parser. Handles:
 *   - added / modified / deleted file headers (`new file mode`, `deleted file mode`, `/dev/null`)
 *   - hunk headers `@@ -a,b +c,d @@`
 *   - paths normalized to forward slashes (no Windows backslashes leak through)
 *
 * `addedRanges` is a list of inclusive 1-based [startLine, endLine] tuples
 * pointing into the *post-image* (the file as it exists after the diff is
 * applied), covering only the lines marked with `+` in each hunk.
 */

export interface DiffFile {
  /** Workspace-relative POSIX path. */
  path: string;
  status: "added" | "modified" | "deleted";
  /** 1-based inclusive line ranges of added lines in the post-image. Empty for deleted files. */
  addedRanges: ReadonlyArray<readonly [number, number]>;
}

const FILE_HEADER = /^diff --git a\/(.+?) b\/(.+?)$/;
const HUNK_HEADER = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/;

interface Hunk {
  /** 1-based starting line in the post-image. */
  postStart: number;
}

export function parseDiffToFiles(diff: string): DiffFile[] {
  if (!diff || diff.length === 0) return [];

  const out: DiffFile[] = [];
  const lines = diff.split(/\r?\n/);

  let i = 0;
  while (i < lines.length) {
    const line = lines[i] ?? "";
    const header = FILE_HEADER.exec(line);
    if (!header) {
      i++;
      continue;
    }

    // Default to the b-side path; overridden below if /dev/null appears.
    let path = (header[2] ?? "").replace(/\\/g, "/");
    let status: DiffFile["status"] = "modified";
    const addedRanges: Array<[number, number]> = [];

    i++;

    // Parse meta lines until we hit the first hunk or the next file header.
    while (i < lines.length) {
      const meta = lines[i] ?? "";
      if (FILE_HEADER.test(meta)) break;
      if (meta.startsWith("@@")) break;

      if (meta.startsWith("new file mode")) status = "added";
      else if (meta.startsWith("deleted file mode")) status = "deleted";
      else if (meta.startsWith("--- ")) {
        // No-op; b-side path drives reporting.
      } else if (meta.startsWith("+++ ")) {
        const rhs = meta.slice(4).trim();
        if (rhs === "/dev/null") status = "deleted";
        else if (rhs.startsWith("b/")) path = rhs.slice(2).replace(/\\/g, "/");
        else if (rhs !== "/dev/null") path = rhs.replace(/\\/g, "/");
      }
      i++;
    }

    // Parse hunks.
    while (i < lines.length) {
      const hunkLine = lines[i] ?? "";
      if (FILE_HEADER.test(hunkLine)) break;
      if (!hunkLine.startsWith("@@")) {
        i++;
        continue;
      }

      const m = HUNK_HEADER.exec(hunkLine);
      if (!m) {
        i++;
        continue;
      }
      const hunk: Hunk = {
        postStart: parseInt(m[1] ?? "0", 10) || 0,
      };
      i++;

      // Walk hunk body. Lines starting with "+" advance the post-image cursor
      // and contribute to addedRanges. " " lines advance both. "-" lines do
      // not advance the post cursor. "\ No newline at end of file" is ignored.
      let postCursor = hunk.postStart;
      let runStart: number | null = null;

      while (i < lines.length) {
        const body = lines[i] ?? "";
        if (FILE_HEADER.test(body) || body.startsWith("@@")) break;

        if (body.startsWith("+")) {
          if (runStart === null) runStart = postCursor;
          postCursor++;
          i++;
        } else if (body.startsWith(" ")) {
          if (runStart !== null) {
            addedRanges.push([runStart, postCursor - 1]);
            runStart = null;
          }
          postCursor++;
          i++;
        } else if (body.startsWith("-")) {
          if (runStart !== null) {
            addedRanges.push([runStart, postCursor - 1]);
            runStart = null;
          }
          i++;
        } else if (body.startsWith("\\")) {
          // "\ No newline at end of file" — skip.
          i++;
        } else if (body === "") {
          // Blank line: treat as context unless it's the trailing blank from split.
          if (i + 1 >= lines.length) {
            i++;
            break;
          }
          if (runStart !== null) {
            addedRanges.push([runStart, postCursor - 1]);
            runStart = null;
          }
          postCursor++;
          i++;
        } else {
          break;
        }
      }
      if (runStart !== null) addedRanges.push([runStart, postCursor - 1]);
    }

    if (status !== "deleted") {
      out.push({ path, status, addedRanges });
    }
  }

  return out;
}

/** True if `line` (1-based) falls within any of the given inclusive ranges. */
export function lineInRanges(
  line: number,
  ranges: ReadonlyArray<readonly [number, number]>,
): boolean {
  for (const [start, end] of ranges) {
    if (line >= start && line <= end) return true;
  }
  return false;
}
