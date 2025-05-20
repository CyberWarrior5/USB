@echo off
setlocal EnableDelayedExpansion
set "USERNAME=hiddenuser"

echo [*] Starting undo script for backdoor setup...
echo [!] WARNING: This script will attempt to:
echo [!]   - Delete the user account "%USERNAME%"
echo [!]   - Delete the user profile folder "C:\Users\%USERNAME%" (ALL DATA WILL BE LOST!)
echo [!]   - Restore the original sethc.exe from sethc.bak
echo [!]   - Restore the original net.exe from ndts.exe
echo [!]   - Remove related Windows Defender exclusions
echo [!]
echo [!] This script MUST be run as Administrator.
echo [!] Make sure the USERNAME variable matches the account created.

:: === CONFIGURATION ===
set "PROFILEFOLDER=C:\Users\%USERNAME%"
set "SETHC_BACKUP=C:\Windows\System32\sethc.bak"
set "SETHC_TARGET=C:\Windows\System32\sethc.exe"
set "REG_KEY=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
set "REG_VALUE=%USERNAME%"
set "SYSTEM32=%SystemRoot%\System32"
set "REAL_NET=%SYSTEM32%\net.exe"
set "RENAMED_NET=%SYSTEM32%\ndts.exe"

:: --- Check for Administrator Privileges ---
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo [!] ERROR: This script requires Administrator privileges. Please right-click and select "Run as administrator".
    goto :end
) else (
    echo [✓] Administrator privileges confirmed.
)

:: === 1. Remove user hiding from Registry ===
echo [*] Attempting to remove user hiding registry key for "%USERNAME%"
reg delete "%REG_KEY%" /v "%REG_VALUE%" /f >nul 2>&1
if %errorlevel% equ 0 (
    echo [✓] Registry key removed (or did not exist)
) else (
    echo [!] WARNING: Could not remove registry key. Key may not exist or permission issue. (%errorlevel%)
)

:: === 2. Delete the hidden user profile folder ===
echo [*] Attempting to remove attributes and delete user profile folder "%PROFILEFOLDER%"

if exist "%PROFILEFOLDER%" (
    attrib -s -h "%PROFILEFOLDER%" >nul 2>&1
    echo [*] Deleting profile folder...
    rd /s /q "%PROFILEFOLDER%"
    if %errorlevel% equ 0 (
        echo [✓] Profile folder "%PROFILEFOLDER%" deleted
    ) else (
        echo [!] WARNING: Failed to delete profile folder "%PROFILEFOLDER%". (%errorlevel%)
    )
) else (
    echo [!] Profile folder not found. Skipping.
)

:: === 3. Delete the user account ===
echo [*] Attempting to delete user account "%USERNAME%"
net user "%USERNAME%" >nul 2>&1
if %errorlevel% equ 0 (
    net user "%USERNAME%" /delete >nul 2>&1
    if %errorlevel% equ 0 (
        echo [✓] User account deleted
    ) else (
        echo [!] WARNING: Failed to delete user account (%errorlevel%)
    )
) else (
    echo [!] User not found. Skipping.
)

:: === 4. Restore original sethc.exe ===
echo [*] Attempting to restore original %SETHC_TARGET% from %SETHC_BACKUP%...
if not exist "%SETHC_BACKUP%" (
    echo [!] CRITICAL: Backup not found: %SETHC_BACKUP%
    goto :restore_net
)

takeown /F "%SETHC_TARGET%" >nul 2>&1
icacls "%SETHC_TARGET%" /grant administrators:F >nul 2>&1
copy /Y "%SETHC_BACKUP%" "%SETHC_TARGET%" >nul
if %errorlevel% equ 0 (
    echo [✓] sethc.exe restored
) else (
    echo [!] CRITICAL: Failed to restore sethc.exe (%errorlevel%)
)

:: === 5. Restore original net.exe ===
:restore_net
echo [*] Restoring original net.exe...

if exist "%RENAMED_NET%" (
    takeown /F "%REAL_NET%" >nul 2>&1
    icacls "%REAL_NET%" /grant administrators:F >nul 2>&1

    echo [*] Deleting fake net.exe (Python wrapper)...
    del /f /q "%REAL_NET%" >nul 2>&1

    echo [*] Renaming ndts.exe back to net.exe...
    ren "%RENAMED_NET%" net.exe >nul 2>&1

    if exist "%REAL_NET%" (
        echo [✓] net.exe successfully restored
    ) else (
        echo [!] WARNING: net.exe was not restored properly.
    )
) else (
    echo [!] ndts.exe not found. Original net.exe may already be restored or never renamed.
)

:: === 6. Remove Defender exclusions ===
echo [*] Removing Defender exclusions...
powershell -Command "Remove-MpPreference -ExclusionPath '%SETHC_TARGET%'" >nul 2>&1
powershell -Command "Remove-MpPreference -ExclusionPath '%SYSTEM32%'" >nul 2>&1

echo.
echo [*] Undo process complete.
echo [!] Review output above for any failed steps or manual actions needed.
echo.

:end
pause
