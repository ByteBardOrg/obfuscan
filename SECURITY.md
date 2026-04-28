# Security policy

## Scope

obfuscan is a **detection** library, not an enforcement boundary. It scans source code and emits findings. It does not block, sandbox, or otherwise prevent code from running. Treat its output as a high-quality reviewer hint, not as a security guarantee.

This document explains:

1. What we treat as a vulnerability vs. a bug.
2. How to report a vulnerability privately.
3. How we handle detection bypasses (malicious code obfuscan failed to flag).
4. The trust model of the library itself.

## What is a vulnerability?

We treat the following as security vulnerabilities and request private disclosure:

- **Code execution from running obfuscan** on attacker-controlled input. obfuscan parses untrusted source code; if a maliciously crafted source file can cause `obfuscan scan` to execute attacker bytes (RCE in the scanner itself), that's a vulnerability.
- **Path traversal or arbitrary file read** through the diff parser, file resolver, or suppression-file loader.
- **Denial of service that is asymmetric**: input that takes the scanner exponentially longer than its size warrants (e.g. a 1 KB file that hangs the scanner for minutes). Linear slowdowns from large files are not vulnerabilities; we'll fix them but they don't merit private disclosure.
- **Secret leakage**: the scanner reading or logging credentials it shouldn't (e.g. logging the contents of `~/.aws/credentials` even though it flagged that path as suspicious).
- **Tampering with suppression state**: ways to cause `.obfuscan/allowlist.json` to suppress findings without the user's intent.

## What is *not* a vulnerability

These are bugs, often important ones, but should be reported as **public issues** so the community benefits from the discussion:

- **Detection bypasses**. A malicious sample obfuscan does not flag is a missed detection, not a vulnerability in obfuscan. Static analysis bypasses are inherent to the discipline (xz is the existence proof). We treat bypasses as severity-1 bugs and fix them quickly, but they are public knowledge by the time you find them and benefit from public discussion.
- **False positives**. Important to fix, but not a vulnerability.
- **Rule omissions** (a sink/decoder we don't list yet). Open a regular PR or issue.
- **Performance issues that scale linearly with input.**

If you're unsure whether something is a vulnerability or a bypass, **report it privately first**; we'll redirect you to the public tracker if appropriate.

## Reporting a vulnerability

**Use GitHub Security Advisories** (preferred): <https://github.com/ByteBardOrg/obfuscan/security/advisories/new>

This creates a private channel between you and the maintainers and gives us a clean path to issue a CVE if warranted.

**Email** (fallback): `security@bytebard.org`.

Please include:

- A description of the issue and its impact.
- A minimal reproducer (source files, command lines, expected vs. actual behavior).
- The version of `@obfuscan/core` and `@obfuscan/rules` you tested against.
- Any suggested mitigation.

### What to expect

| Day | What we do |
|---|---|
| 0 | You report. |
| ≤ 2 | Acknowledgement of receipt. |
| ≤ 7 | Initial triage: confirmed, not-confirmed, or need-more-info. |
| ≤ 30 | Fix landed, advisory drafted, CVE requested if applicable. |
| Day of release | Advisory published, fix shipped to npm, you're credited (unless you'd rather not be). |

We aim to coordinate disclosure timing with you. Standard window is 90 days; we'll go faster for already-exploited issues and slower for complex ones with your agreement.

## Reporting a detection bypass

Bypasses are **public**: open a regular GitHub issue with the `bypass` label.

Include:

- The malicious sample (or a redacted/stub version that preserves the shape — see CONTRIBUTING.md for fixture conventions).
- The detection rules that should have fired but didn't.
- Where you encountered it (advisory URL, package name + version, CVE if assigned).

We label bypasses by severity:

| Severity | Definition | Target fix |
|---|---|---|
| `bypass:critical` | Active in-the-wild attack we don't catch. | < 7 days |
| `bypass:high` | Plausible attack technique demonstrated, no in-the-wild use yet. | < 30 days |
| `bypass:research` | Theoretical bypass, requires attacker effort to apply. | Best effort |

Do not send live attacker payloads. We don't need them to fix the rule. Stubs that preserve syntactic shape are sufficient and keep contributors safe.

## The library's own trust model

When you run obfuscan, you are running:

1. **`@obfuscan/core`** (npm) — the engine. TypeScript code, signed npm provenance.
2. **`@obfuscan/rules`** (npm) — JSON configs and `.scm` query files. Data, no code execution, and no parser grammars.
3. **Optional host-supplied parsers** — hosts can wire in tree-sitter grammars through `RuleSet.loadGrammar()` / `GrammarHandle.parse()`. The default engine does not load parsers or grammars.
4. **The source code being scanned** — never executed, only read as text.

obfuscan **never executes** code from the files it scans. The default scanner reads source text, applies regex/config-driven detectors and manifest/path detectors, and emits findings. Hosts that add parser-backed custom detectors are responsible for their own parser dependency and caching choices.

obfuscan **never makes network calls** in its core scanning path.

### Build/release integrity

- Releases are published from CI with [npm provenance](https://docs.npmjs.com/generating-provenance-statements) attestation.
- The release workflow builds, tests, and smoke-tests the published entry point from a clean checkout.

If a release ever ships without provenance, **do not install it**, and report it to security@bytebard.org.

## Hall of fame

We credit reporters of confirmed vulnerabilities here unless they decline. Your name links wherever you'd like it to.

(Empty until first reporter.)

## Credits and prior art

This policy borrows structure from the [Tidelift](https://tidelift.com/about/lifter-resources/security-policy) and [Datadog open-source](https://www.datadoghq.com/security/) policies. Where it differs, the differences are intentional — most notably the explicit treatment of detection bypasses as public bugs rather than vulnerabilities.
