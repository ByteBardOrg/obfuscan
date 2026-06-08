import * as fs from "node:fs/promises";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const actionDir = path.join(root, "packages", "action");
const sourceDist = path.join(actionDir, "dist");
const target = path.join(root, "marketplace", "obfuscan-action");

await assertExists(path.join(sourceDist, "index.js"), "Run `npm run build` in packages/action before generating marketplace output.");

await fs.rm(target, { recursive: true, force: true });
await fs.mkdir(path.join(target, ".github", "workflows"), { recursive: true });
await fs.cp(sourceDist, path.join(target, "dist"), { recursive: true });
await fs.copyFile(path.join(root, "LICENSE"), path.join(target, "LICENSE"));

await write("action.yml", actionYml());
await write("README.md", readme());
await write("GENERATED.md", generated());
await write("SECURITY.md", security());
await write("CONTRIBUTING.md", contributing());
await write("CODE_OF_CONDUCT.md", codeOfConduct());
await write(".gitignore", gitignore());
await write(path.join(".github", "workflows", "smoke.yml"), smokeWorkflow());

console.log(`Generated ${path.relative(root, target)}`);

async function assertExists(file, message) {
  try {
    await fs.access(file);
  } catch {
    throw new Error(message);
  }
}

async function write(relativePath, content) {
  await fs.writeFile(path.join(target, relativePath), content.trimStart() + "\n", "utf8");
}

function actionYml() {
  return `
name: obfuscan
description: Detect obfuscated code and likely backdoors in pull-request diffs.
author: ByteBardOrg

inputs:
  github-token:
    description: GitHub token used to read diffs and write pull request comments.
    required: false
    default: \${{ github.token }}
  fail-on:
    description: Severity that fails the workflow. One of block, warn, never.
    required: false
    default: block
  min-severity:
    description: Minimum severity to report. One of info, warn, block.
    required: false
    default: info
  comment:
    description: Whether to create or update a pull request comment.
    required: false
    default: "true"
  max-findings:
    description: Maximum number of findings shown in the Markdown report.
    required: false
    default: "50"
  allowlist-path:
    description: Workspace-relative allowlist path.
    required: false
    default: .obfuscan/allowlist.json
  disabled-detectors:
    description: Comma or newline separated detector ids to disable.
    required: false
    default: ""
  file-timeout-ms:
    description: Optional per-file detector timeout in milliseconds.
    required: false
    default: ""

outputs:
  findings-total:
    description: Total number of findings.
  findings-block:
    description: Number of block findings.
  findings-warn:
    description: Number of warn findings.
  findings-info:
    description: Number of info findings.
  conclusion:
    description: pass or fail.

runs:
  using: node20
  main: dist/index.js

branding:
  icon: shield
  color: purple
`;
}

function readme() {
  return `
# obfuscan action

Detect obfuscated code and likely backdoors in pull-request diffs. Multi-language. Diff-aware. Pure offline. Built for GitHub code review.

## Quick start

\`\`\`yaml
name: obfuscan

on:
  pull_request:

permissions:
  contents: read
  pull-requests: read
  issues: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}

      - uses: ByteBardOrg/obfuscan-action@v1
        with:
          fail-on: block
\`\`\`

The action scans the PR diff, annotates findings, writes a job summary, and upserts one Markdown PR comment.

## What it catches

obfuscan looks for the patterns common to supply-chain attacks:

- Decode-then-execute chains like \`eval(Buffer.from(payload, "base64").toString())\`.
- Dynamic execution of non-literal code across JavaScript, Python, PowerShell, Bash, PHP, Ruby, Go, Rust, C#, Java, Kotlin, Lua, Perl, and VBScript.
- Suspicious install-time behavior in \`package.json\`, \`setup.py\`, \`build.rs\`, GitHub Actions workflows, and Dockerfiles.
- Obfuscation signals including high-entropy strings, encoded string arrays, bidi controls, homoglyph identifiers, and very long generated lines.

Static analysis is a reviewer aid, not a proof of safety. Treat findings as high-signal review prompts.

## Distribution model

GitHub runs JavaScript actions directly from the checked-out action repository and does not run \`npm install\`. This repo therefore contains generated runtime artifacts under \`dist/\`, including a bundled copy of the exact \`@obfuscan/rules\` JSON files used by the scanner.

Do not edit \`dist/\` or \`dist/rules\` by hand. They are generated from the main obfuscan repository:

\`\`\`bash
cd packages/action
npm run marketplace
\`\`\`

Source of truth:

- Action source: <https://github.com/ByteBardOrg/obfuscan/tree/main/packages/action>
- Rules source: <https://github.com/ByteBardOrg/obfuscan/tree/main/packages/rules>

## Inputs

| Input | Default | Description |
|---|---|---|
| \`github-token\` | \`\${{ github.token }}\` | Token used to read diffs and write PR comments. |
| \`fail-on\` | \`block\` | Fails the workflow at \`block\`, \`warn\`, or \`never\`. |
| \`min-severity\` | \`info\` | Minimum severity to report: \`info\`, \`warn\`, or \`block\`. |
| \`comment\` | \`true\` | Create or update a PR comment. Set to \`false\` for annotations and summaries only. |
| \`max-findings\` | \`50\` | Maximum findings shown in the Markdown report. |
| \`allowlist-path\` | \`.obfuscan/allowlist.json\` | Workspace-relative allowlist path. |
| \`disabled-detectors\` | empty | Comma or newline separated detector ids to disable. |
| \`file-timeout-ms\` | engine default | Optional per-file detector timeout in milliseconds. |

## Outputs

| Output | Description |
|---|---|
| \`findings-total\` | Total number of findings. |
| \`findings-block\` | Number of block findings. |
| \`findings-warn\` | Number of warn findings. |
| \`findings-info\` | Number of info findings. |
| \`conclusion\` | \`pass\` or \`fail\`. |

## Examples

Fail on warnings too:

\`\`\`yaml
- uses: ByteBardOrg/obfuscan-action@v1
  with:
    fail-on: warn
\`\`\`

Only report blocking findings:

\`\`\`yaml
- uses: ByteBardOrg/obfuscan-action@v1
  with:
    min-severity: block
\`\`\`

Run without PR comments:

\`\`\`yaml
permissions:
  contents: read
  pull-requests: read

steps:
  - uses: actions/checkout@v4
    with:
      ref: \${{ github.event.pull_request.head.sha }}
  - uses: ByteBardOrg/obfuscan-action@v1
    with:
      comment: false
\`\`\`

Disable a detector:

\`\`\`yaml
- uses: ByteBardOrg/obfuscan-action@v1
  with:
    disabled-detectors: |
      obf.high-entropy-literal
      obf.long-line
\`\`\`

## Permissions

Use these permissions when \`comment: true\`:

\`\`\`yaml
permissions:
  contents: read
  pull-requests: read
  issues: write
\`\`\`

Use these permissions when \`comment: false\`:

\`\`\`yaml
permissions:
  contents: read
  pull-requests: read
\`\`\`

GitHub may restrict \`GITHUB_TOKEN\` on pull requests from forks. In that case, obfuscan still emits annotations and a job summary, but PR comment creation can be skipped or fail with a warning.

## Suppressions

Suppress a known false positive inline:

\`\`\`js
// obfuscan-disable-next-line obf.high-entropy-literal
const fixture = "U29tZSBsb25nIGRldGVjdG9yIGZpeHR1cmU=";
\`\`\`

Or use \`.obfuscan/allowlist.json\`:

\`\`\`json
{
  "paths": [
    { "pattern": "vendor/**", "maxSeverity": "warn", "reason": "third-party bundle" }
  ]
}
\`\`\`

## Releases

This repo should maintain a moving major tag:

\`\`\`bash
git tag v1
git push origin v1
\`\`\`

For future \`1.x\` releases, move the major tag after publishing the release tag:

\`\`\`bash
git tag v1.0.1
git push origin v1.0.1
git tag -f v1 v1.0.1
git push -f origin v1
\`\`\`

## License

Apache-2.0. See [LICENSE](./LICENSE).
`;
}

function generated() {
  return `
# Generated distribution

This folder is a generated GitHub Marketplace distribution for the obfuscan action.

Do not maintain copied rules or bundled JavaScript by hand. Regenerate everything from the main obfuscan repository:

\`\`\`bash
cd packages/action
npm run marketplace
\`\`\`

Source of truth:

- \`packages/action/src\` for action behavior.
- \`packages/rules/languages\` for rule JSON.
- \`packages/core/src\` for scanner behavior.

GitHub Actions does not run \`npm install\` for JavaScript actions, so \`dist/\` intentionally contains the bundled runtime files needed by Marketplace users.
`;
}

function security() {
  return `
# Security policy

This repository distributes the GitHub Marketplace action for obfuscan.

Report vulnerabilities in the scanner or action privately through GitHub Security Advisories in the source repository:

<https://github.com/ByteBardOrg/obfuscan/security/advisories/new>

Use \`security@bytebard.org\` as a fallback.

Detection bypasses and false positives are usually public issues, not vulnerabilities. Open them in the source repository so rules and fixtures can be updated:

<https://github.com/ByteBardOrg/obfuscan/issues>
`;
}

function contributing() {
  return `
# Contributing

The source for this action lives in the main obfuscan repository:

<https://github.com/ByteBardOrg/obfuscan/tree/main/packages/action>

Open code changes, rule updates, false positives, and bypass reports there. This Marketplace repository is intended to hold generated distribution files: \`action.yml\`, \`dist/index.js\`, and bundled rule files.

Useful local checks in the source repository:

\`\`\`bash
cd packages/action
npm ci --legacy-peer-deps
npm run marketplace
npm test
\`\`\`
`;
}

function codeOfConduct() {
  return `
# Code of Conduct

This project follows the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

In short: be kind, assume good faith, criticize work and not people, and remember that the security community is small and reputations are forever.

Report violations privately to \`conduct@bytebard.org\`. Reports are read by maintainers only.
`;
}

function gitignore() {
  return `
# Logs and local installs
*.log
node_modules/

# Local editor and OS files
.DS_Store
.idea/
.vscode/

# Keep the generated action distribution committed for GitHub Marketplace.
!dist/
!dist/**
`;
}

function smokeWorkflow() {
  return `
name: Smoke

on:
  pull_request:
  push:
    branches:
      - main
  workflow_dispatch:

permissions:
  contents: read
  pull-requests: read

jobs:
  smoke:
    name: Action smoke test
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 2
          ref: \${{ github.event.pull_request.head.sha || github.sha }}

      - name: Run obfuscan action
        uses: ./
        with:
          github-token: \${{ github.token }}
          comment: false
          fail-on: never
`;
}
