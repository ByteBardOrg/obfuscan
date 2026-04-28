/**
 * Internal text helpers shared across detectors.
 *
 * Anything in `src/internal/` is NOT part of the public API and may change
 * without a major version bump. Detectors are allowed to import from here.
 * External consumers must not.
 */

const MAX_SNIPPET_LEN = 200;
const ELLIPSIS = "...";

/**
 * Truncate a snippet to `Finding.snippet`'s documented 200-char ceiling.
 * The engine also enforces this defensively, but doing it in the detector
 * keeps `Finding.evidence` payloads consistent with what the user sees.
 */
export function truncateSnippet(s: string): string {
  if (s.length <= MAX_SNIPPET_LEN) return s;
  return s.slice(0, MAX_SNIPPET_LEN - ELLIPSIS.length) + ELLIPSIS;
}
