"""Defanged: exec() of a base64-decoded blob."""
import base64
# Real-world attacks would put the actual payload here.
# This blob decodes to: print("stub")
_BLOB = "cHJpbnQoInN0dWIiKQ=="
exec(base64.b64decode(_BLOB).decode())
