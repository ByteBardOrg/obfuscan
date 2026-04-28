# vbscript inventory

Hand-written. Note: VBScript uses `CreateObject` for ordinary COM access
(filesystem here). The detector targets specific COM ProgIDs that map to
shell / script-control / network — not all `CreateObject` calls.
