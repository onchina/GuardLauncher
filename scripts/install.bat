@echo off
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msedge.exe" /v Debugger /t REG_SZ /d "C:\Tools\GuardLauncher.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\chrome.exe" /v Debugger /t REG_SZ /d "C:\Tools\GuardLauncher.exe" /f
echo GuardLauncher IFEO 接管已生效。
pause
