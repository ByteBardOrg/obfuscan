#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p dist
tsc -p .
cp package.json dist/
echo "build ok"
