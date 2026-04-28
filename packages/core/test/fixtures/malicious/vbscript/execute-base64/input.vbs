' Defanged: VBScript Execute on a string built from Chr() calls.
' VBScript's Execute / ExecuteGlobal are in dynamic_exec_sinks; Chr() is in
' decoders. The decoded payload is: WScript.Echo "stub"
Dim s
s = Chr(87) & Chr(83) & Chr(99) & Chr(114) & Chr(105) & Chr(112) & Chr(116) & Chr(46) & Chr(69) & Chr(99) & Chr(104) & Chr(111) & Chr(32) & Chr(34) & Chr(115) & Chr(116) & Chr(117) & Chr(98) & Chr(34)
Execute s
