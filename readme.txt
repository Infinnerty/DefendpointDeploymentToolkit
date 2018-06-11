## Readme: Avecto Deployment Tool ##
## Author: Adem Murselaj (Avecto) ##
## Version: 1.0 ##

Used to install/uninstall Avecto Defendpoint Client and/or Avecto iC3 Adapter.
Can be invoked using 'install_launch.bat' or 'Deploy-Application.ps1' or 'Deploy-Application.exe', depending on the environment.
When configured to install, the script checks whether a specific version of Defendpoint is installed.
The Defendpoint version to check is defined using [string]$appVersion = '5.1.149' on line 296. This should be changed according to the environment.
If the Defendpoint client version, as specified on line 296, is already installed, the script will not initiate an install unless $ReplaceCurrentClient is set to $true.
The parameter $ForceUninstallPreviousVersion, when $true, will remove all known traces of Defendpoint from a system. This is useful in situations where upgrades are failing.
The Defendpoint MSI to install is stored in the 'Files' directory.
Parameters can be defined in "Deploy-Application.ps1" on line 35 onwards, or they can be passed to the PowerShell script using a batch file (i.e. "install_launch.bat" / "uninstall_launch.bat")
PowerShell and verbose MSI logs are located: "C:\Windows\Logs\Software\"
The script requires elevation to operate.