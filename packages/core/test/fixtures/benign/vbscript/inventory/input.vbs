' Pure local inventory — no Execute, no network, no decoders.
Dim fso, folder, files, file
Set fso = CreateObject("Scripting.FileSystemObject")
Set folder = fso.GetFolder("C:\Logs")
For Each file In folder.Files
    WScript.Echo file.Name & vbTab & file.Size
Next
