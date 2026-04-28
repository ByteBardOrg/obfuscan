# Tree-sitter integration

`@obfuscan/core` ships **without** tree-sitter parser grammars. The bundled
detectors operate on raw source via regex and structural parsing of well-known
manifest formats. `@obfuscan/rules` includes language configs and `.scm` query
assets, but not the parser runtimes or compiled grammars needed to execute
those queries. This keeps the engine small, runnable in restricted sandboxes,
and trivial to test against synthetic source.

That tradeoff is reversible. The engine has two host-override seams that let
you bring your own parser without forking the package:

1. A **`RuleSet`** is a normal interface. Pass your own to `scan()` and you
   own grammar loading end-to-end.
2. A **`GrammarHandle`** has an optional `parse(source)` method. Hosts that
   want to keep the bundled rule loader but add live parsing only need to
   override `loadGrammar`.

This document is the contract for both.

---

## When you need tree-sitter

You **don't** need it for:
- Layer A detectors (entropy, bidi, homoglyph, long-line, encoded-array)
- Manifest detectors (`package.json`, `setup.py`, `build.rs`, `Dockerfile`,
  GitHub Actions, `Makefile.PL`, `composer.json`, `*.gemspec`, `*.rockspec`,
  `*.nuspec`)
- The regex-driven Layer B detectors that ship today
  (`decode-then-exec`, `network-then-exec`, `dynamic-exec-non-literal`,
  `deserializer-untrusted`, `library-load-non-literal`,
  `string-array-decoder`, `shell-untrusted-input`, `suspicious-io-cluster`)

You **do** want it when you ship custom Layer B detectors that need:
- Reliable scope analysis (is this `eval` actually shadowed by a local?)
- Multi-line call expressions where the regex first-arg peek is too coarse
- Comment / string-literal awareness without manual stripping
- Tracking variable assignments across reassignments

The detectors that ship today accept the regex tradeoff because their
malicious-shape signal is loud enough that AST precision is not load-bearing
for the published recall numbers (see `docs/coverage.md`). Your detectors may
not have the same property — wire in tree-sitter when they don't.

---

## Architecture

```
                ┌────────────────────────────────────────────┐
                │              scan()                        │
                │                                            │
ScanOptions────►│  ruleSet.detectLanguage(path) -> "javascript"
                │  ruleSet.configFor("javascript") -> {...}  │
                │                                            │
                │  ctx.tree() ──┐                            │
                └───────────────┼────────────────────────────┘
                                │
                                ▼
                ┌──────────────────────────────────┐
                │  ruleSet.loadGrammar(id)         │
                │  -> GrammarHandle { parse(src) } │
                │                                  │
                │  cachedTree = await              │
                │    grammar.parse(source)         │
                └──────────────────────────────────┘
                                │
                                ▼
                ┌──────────────────────────────────┐
                │  Custom detector reads ctx.tree()│
                │  and walks/queries the AST       │
                └──────────────────────────────────┘
```

The engine never imports a parser. It calls `loadGrammar(id)` to get an opaque
`GrammarHandle`, and if that handle has a `parse` method, it caches one tree
per file. Whatever `parse` returns is what `ctx.tree()` returns. The shape is
a contract between your `RuleSet` and your detectors.

---

## The interfaces (verbatim from `src/types.ts`)

```ts
export interface RuleSet {
  /** Language ids this ruleset supports. */
  languages(): readonly string[];
  /** Look up a config by language id. Returns null if unsupported. */
  configFor(languageId: string): LanguageConfig | null;
  /** Map a file path to a language id, or null if unknown. */
  detectLanguage(path: string): string | null;
  /** Load the parser+queries for a language. Implementations may cache. */
  loadGrammar(languageId: string): Promise<GrammarHandle>;
  /** Calver version of the rule pack (e.g. "2026.04.0"). */
  version(): string;
}

export interface GrammarHandle {
  readonly id: string;            // e.g. "javascript"
  readonly _internal: unknown;    // host's parser handle (Language object)
  parse?: (source: string) => unknown | Promise<unknown>;
}
```

---

## Pattern A — keep the bundled rule loader, add `parse`

The simplest integration. You ship one wrapper that defers everything to the
default `RuleSet` and only overrides `loadGrammar`.

```ts
import { scan, defaultRuleSet, type RuleSet, type GrammarHandle } from "@obfuscan/core";
import { Parser, Language } from "web-tree-sitter";

await Parser.init();

// Map obfuscan language id -> WASM grammar URL/path. You bundle these.
const GRAMMAR_WASM: Record<string, string> = {
  javascript: "/wasm/tree-sitter-javascript.wasm",
  typescript: "/wasm/tree-sitter-typescript.wasm",
  python:     "/wasm/tree-sitter-python.wasm",
  // …add the languages you actually ship grammars for.
};

const grammarCache = new Map<string, Promise<GrammarHandle>>();

async function loadGrammar(id: string): Promise<GrammarHandle> {
  const cached = grammarCache.get(id);
  if (cached) return cached;

  const promise = (async (): Promise<GrammarHandle> => {
    const url = GRAMMAR_WASM[id];
    if (!url) {
      // No grammar for this language — return a stub. The engine will set
      // ctx.tree() to null for files in this language; your detectors should
      // gracefully degrade (e.g. fall back to regex).
      return { id, _internal: null };
    }
    const language = await Language.load(url);
    const parser = new Parser();
    parser.setLanguage(language);
    return {
      id,
      _internal: language,
      parse: (source: string) => parser.parse(source),
    };
  })();

  grammarCache.set(id, promise);
  return promise;
}

const base = await defaultRuleSet();
const rules: RuleSet = {
  languages:      () => base.languages(),
  configFor:      id => base.configFor(id),
  detectLanguage: p  => base.detectLanguage(p),
  version:        () => base.version(),
  loadGrammar,
};

const result = await scan({ dir: "./src" }, { fileResolver, rules });
```

That's the whole integration. Custom detectors can now `await ctx.tree()` and
get back a real `web-tree-sitter` `Tree`.

---

## Pattern B — the parser is shared across files

`Parser` instances aren't free. If you scan many files in one run, build the
parser once per language and reuse it inside `parse`:

```ts
async function loadGrammar(id: string): Promise<GrammarHandle> {
  const url = GRAMMAR_WASM[id];
  if (!url) return { id, _internal: null };

  const language = await Language.load(url);
  const parser = new Parser();
  parser.setLanguage(language);

  return {
    id,
    _internal: language,
    parse: (source: string) => parser.parse(source),
  };
}
```

`scan()` will call your `loadGrammar` at most once per `(language, file)` pair
already (via the in-loop `cachedGrammar`), but in long-running processes you
should also cache `loadGrammar`'s promise across `scan()` invocations. The
example in Pattern A does this with `grammarCache`.

---

## Pattern C — author a detector that actually uses the tree

```ts
import type { Detector, FileContext, Finding } from "@obfuscan/core";
import type { Tree, SyntaxNode } from "web-tree-sitter";

export const noEvalInTests: Detector = {
  id: "myorg.no-eval-in-tests",

  applies: (ctx) => /\.test\.(t|j)sx?$/.test(ctx.path),

  async run(ctx: FileContext): Promise<Finding[]> {
    const tree = (await ctx.tree()) as Tree | null;
    if (!tree) return [];      // language has no grammar bound — skip cleanly

    const findings: Finding[] = [];
    walk(tree.rootNode, (node) => {
      if (node.type !== "call_expression") return;
      const callee = node.firstChild;
      if (callee?.type === "identifier" && callee.text === "eval") {
        findings.push({
          ruleId: "myorg.no-eval-in-tests",
          severity: "warn",
          score: 5,
          file: ctx.path,
          line: node.startPosition.row + 1,
          snippet: node.text.slice(0, 120),
          reason: "eval() in a test file is almost always a debugging artifact left in by accident.",
          evidence: {},
        });
      }
    });
    return findings;
  },
};

function walk(n: SyntaxNode, visit: (n: SyntaxNode) => void): void {
  visit(n);
  for (let i = 0; i < n.namedChildCount; i++) {
    const child = n.namedChild(i);
    if (child) walk(child, visit);
  }
}
```

Pass it via `ScanOptions.detectors`:

```ts
import { defaultDetectors } from "@obfuscan/core";

await scan(input, {
  fileResolver,
  rules,
  detectors: [...defaultDetectors(), noEvalInTests],
});
```

---

## Defensive coding rules for grammar overrides

These are non-obvious failure modes from running tree-sitter at scale:

1. **Always allow `parse` to fail.** WASM loading races, grammars get out of
   sync with parser versions, and very large files can OOM. Catch inside
   `parse` and return `null` rather than throwing — the engine catches
   regardless, but explicit handling lets you log the cause.

2. **Don't share a `Parser` across concurrent `parse` calls.** `scan()` runs
   detectors sequentially within a file but multiple files concurrently.
   Either build one `Parser` per `loadGrammar` invocation (which the engine
   caches per language) or guard with a mutex. `web-tree-sitter`'s parser is
   not reentrant.

3. **Pin grammar versions.** Tree-sitter grammars evolve their node-kind
   names. If you ship pre-compiled WASM and your detectors hard-code node
   types, a grammar bump can silently break recall. Pin the grammar revision
   in your build, and run the obfuscan fixture suite as part of grammar
   upgrades.

4. **Bundle size matters.** A typical tree-sitter grammar is 200KB–2MB of
   WASM. Tier-1 (7 langs) plus Tier-2 (8 langs) = ~15–20MB if you ship them
   all. Lazy-load grammars on first sighting of the language rather than
   loading all upfront.

5. **`ctx.tree()` is `Promise<unknown>` for a reason.** The engine doesn't
   type the tree; you do. Cast on read and document the cast site. If you
   later swap parsers, every detector that consumes `tree()` is now your
   migration surface.

---

## What the bundled detectors won't do

They will **not** call `ctx.tree()` — even with a host-supplied grammar
present. They are regex-only, and the regex paths are the recall budget
documented in `docs/coverage.md`. If you want AST-precise replacements for
them:

- Filter the bundled set: `defaultDetectors().filter(d => d.id !== "obf.decode-then-exec.javascript")`
- Add your own with the same `obf.<rule>.<lang>` ID convention so reports
  stay diffable across hosts.

The unit tests in `packages/core/test/unit/layer-b.test.ts` are the
specification of the expected shapes for each Layer B rule. If you reimplement
a rule on tree-sitter, run those tests against your version.

---

## FAQ

**Why isn't this the default?**
Because the engine's contract tests and a meaningful slice of consumers run
in environments where loading WASM is awkward (sandboxed CI, edge runtimes,
desktop apps that don't ship a Wasm runtime). Making tree-sitter the default
would have made the engine harder to embed without producing better detection
on the rules that ship today.

**Can I use `node-tree-sitter` (native bindings) instead of `web-tree-sitter`?**
Yes. The `parse` contract is parser-agnostic. Native bindings are faster but
constrain where the engine runs (no browser, no Wasm-only runtimes).

**What about queries (`*.scm` files)?**
The `packages/rules/queries/` directory ships `.scm` files that name canonical
captures (`@call`, `@callee`, `@first-arg`, etc.). Today they're informational
— the engine doesn't load them because the bundled detectors don't query the
tree. If you add tree-sitter-driven detectors, load the appropriate `.scm`
files in your `loadGrammar` and use them via `Language.query(...)`.

**Does enabling tree-sitter change the rule output?**
No. The engine ID and severity space are stable. A rule shipped on regex and
a rule reimplemented on tree-sitter both surface as `obf.<rule>.<lang>` with
the same severity contract. Hosts may add their own rule IDs (`myorg.<rule>`)
for AST-only checks they author themselves.
