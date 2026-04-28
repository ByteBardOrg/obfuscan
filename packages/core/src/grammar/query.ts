/**
 * Tree-sitter query runner — internal facade.
 *
 * STATUS: stub. The real implementation will:
 *   1. Resolve the per-grammar query file `queries/per-grammar/<lang>.scm`
 *   2. Concatenate it with the shared template `queries/shared/<name>.scm`
 *   3. Compile via `web-tree-sitter` Query, cached per (grammar, name)
 *   4. Run against the parsed tree and yield captures
 *
 * Detectors depend only on the `QueryMatch` / `QueryNode` shapes below, so
 * the engine implementation can evolve without rewriting detectors.
 */

import type { GrammarHandle } from "../types.js";

/** A captured node from a tree-sitter query. */
export interface QueryNode {
  /** Source text of the node. */
  readonly text: string;
  /** 0-based byte offset of the node start in the source. */
  readonly startIndex: number;
  /** 0-based byte offset of the node end (exclusive). */
  readonly endIndex: number;
  /** 0-based row/column of node start. */
  readonly startPosition: { readonly row: number; readonly column: number };
  /** 0-based row/column of node end. */
  readonly endPosition: { readonly row: number; readonly column: number };
}

/** A single match from a query — a map from capture name to node. */
export interface QueryMatch {
  readonly captures: ReadonlyMap<string, QueryNode>;
}

/**
 * Run a named query against a parsed tree and return all matches.
 *
 * Throws if the query name is unknown for this grammar — detectors should
 * catch and treat as "this language hasn't been ported to this query yet".
 */
export function runQuery(
  _grammar: GrammarHandle,
  _tree: unknown,
  _queryName: string,
): readonly QueryMatch[] {
  // Reference stub: returns no matches. Replace with a real implementation
  // that compiles `.scm` files and walks the tree.
  return [];
}
