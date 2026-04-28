/**
 * Error classes — hoisted to a separate module to avoid circular imports
 * between rules.ts, scan.ts, and index.ts.
 */

export class InvalidScanInputError extends Error {
  override readonly name = "InvalidScanInputError";
}

export class InvalidRuleSetError extends Error {
  override readonly name = "InvalidRuleSetError";
  constructor(
    message: string,
    readonly details: ReadonlyArray<{ file: string; problem: string }>,
  ) {
    super(message);
  }
}
