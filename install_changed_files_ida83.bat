@echo off
setlocal EnableExtensions

set "SOURCE_DIR=%~dp0"
set "IDA_PLUGINS=C:\Program Files\IDA Pro 8.3\plugins"
set "TARGET_PACKAGE=%IDA_PLUGINS%\pseudonote"

rem Program Files normally requires elevation. Relaunch this script as admin.
fltmc >nul 2>&1
if errorlevel 1 (
    echo Requesting Administrator permission to update the IDA plugins folder...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
        "Start-Process -FilePath '%~f0' -Verb RunAs -Wait"
    exit /b
)

if not exist "%IDA_PLUGINS%\" (
    echo ERROR: IDA plugins directory was not found:
    echo        %IDA_PLUGINS%
    goto :failed
)

if not exist "%TARGET_PACKAGE%\" (
    mkdir "%TARGET_PACKAGE%" || goto :failed
)

echo Synchronizing new and modified PseudoNote files into:
echo   %TARGET_PACKAGE%
echo.

rem Robocopy automatically copies only files that are new or differ in size/time.
rem /E includes any future subdirectories; Python bytecode caches are excluded.
robocopy "%SOURCE_DIR%pseudonote" "%TARGET_PACKAGE%" /E /R:2 /W:1 /COPY:DAT /DCOPY:DAT /XD __pycache__ /XF *.pyc *.pyo
if errorlevel 8 goto :failed

rem Keep IDA's root plugin entry point synchronized as well.
copy /Y "%SOURCE_DIR%PseudoNote.py" "%IDA_PLUGINS%\PseudoNote.py" >nul
if errorlevel 1 goto :failed

echo.
echo Installation completed successfully.
echo Restart IDA Pro before testing the updated plugin.
pause
exit /b 0

:failed
echo.
echo Installation failed. No additional files will be copied.
pause
exit /b 1
