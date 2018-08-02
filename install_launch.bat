@echo off
REM Defendpoint Deployment Toolkit Launcher V1.2
REM Written by Avecto Professional Services (Adem Murselaj)

cd /d %~dp0
REM xcopy /Y /E ".\*" C:\Avecto\ClientInstall\
START /B /WAIT "Client Deployment" cmd /c "echo Defendpoint Deployment Toolkit V1.2 & echo.& echo.~~Install mode~~& echo.& echo.##########################################################################################& echo.& echo.##########################################################################################&echo("

net file 1>nul 2>nul && goto :run || powershell -ex Bypass -Command "Start-Process -Verb RunAs -FilePath '%comspec%' -ArgumentList '/c ""%~fnx0"""" %*'"
goto :eof
:run
START /B /WAIT "Client Deployment" powershell -ex Bypass -WindowStyle Hidden -Command "& { & '.\Deploy-Application.ps1' -DeploymentType Install -IC3Mode $false -ShowWelcomePromptWithDefer $false -ForceUninstallPreviousVersions $false -ReplaceCurrentClient $false -CustomActions $false; Exit $LastExitCode }
EXIT %errorlevel%
