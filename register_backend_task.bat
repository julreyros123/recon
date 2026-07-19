@echo off
title Recon NDS - Windows Startup Registration
cd /d "%~dp0"

set "startup_file=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\recon_startup.vbs"

echo ===================================================
echo   Recon NDS - Register Startup Task (recon)
echo ===================================================
echo.
echo Select the startup task option:
echo  1) Register FastAPI Server to start silently at login.
echo  2) Unregister / Remove startup task
echo.

set /p choice="Enter choice (1-2): "

if "%choice%"=="1" goto REG_BACKEND
if "%choice%"=="2" goto UNREG
echo Invalid choice. Exiting...
pause
exit /b

:REG_BACKEND
echo.
echo Registering FastAPI Backend Startup Task...
(
echo Set WshShell = CreateObject^("WScript.Shell"^)
echo WshShell.CurrentDirectory = "%CD%"
echo WshShell.Run "cmd.exe /c start_server_backend_only.bat", 0, False
) > "%startup_file%"
if %errorlevel% equ 0 (
    echo [SUCCESS] Startup script registered in:
    echo   %startup_file%
    echo It will run silently next time you log in to Windows.
) else (
    echo [ERROR] Failed to write startup script.
)
goto END

:UNREG
echo.
echo Deleting startup script...
if exist "%startup_file%" (
    del /f /q "%startup_file%"
    echo [SUCCESS] Deleted startup task script.
) else (
    echo No startup task script found.
)
goto END

:END
echo.
pause
