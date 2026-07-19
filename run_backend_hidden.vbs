Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = scriptDir
batchPath = scriptDir & "\start_server_backend_only.bat"
logPath = scriptDir & "\cmd_debug.log"
WshShell.Run "cmd.exe /c """ & batchPath & """ > """ & logPath & """ 2>&1", 0, False
