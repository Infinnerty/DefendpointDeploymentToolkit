### Readme: Defendpoint Deployment Tool ###
### Author: Adem Murselaj (adem.murselaj@avecto.com) ###
### Version: 1.2 ###

• Used to install/uninstall Avecto Defendpoint Client and/or Avecto iC3 Adapter.

• Can be invoked using 'install_launch.bat' or 'Deploy-Application.ps1' or 'Deploy-Application.exe', depending on the environment.

• When configured to install, the script checks whether a specific version of Defendpoint is installed.

• The Defendpoint client version check is made dynamically from the MSI file. If a version older (or lack thereof) is installed, the script will install the MSI.

• If the intended Defendpoint client version is already installed, the script will not initiate an install unless the parameter $ReplaceCurrentClient is set to $true.

• The parameter $ForceUninstallPreviousVersion, when $true, will remove all known traces of Defendpoint from a system; this is useful in situations where upgrades are failing.

• The Defendpoint MSI (DefendpointClient_x64.msi OR DefendpointClient_x86.msi) should be stored in the 'Files' directory.

• Parameters values can be defined in 'Deploy-Application.ps1', or passed to 'Deploy-Application.ps1' directly, or using the provided batch files ('install_launch.bat' / 'uninstall_launch.bat')

• Removal/downgrade of administrator accounts can occur at the same time of software installation using $RemoveAllUsersFromLocalAdmin or $RemoveCurrentUserFromLocalAdmin

• Exceptions to administrator account downgrade can be made using $RemoveAllUsersFromLocalAdminExclusions in 'Deploy-Application.ps1'

• Admin account downgrade only occurs if Defendpoint is installed.

• Admin accounts are downgraded to standard users.

• Admin accounts can also be added to the 'Power User' or 'Remote Desktop Users' group if using $AddRemovedUserstoPowerUsers or $AddRemovedUserstoRemoteDesktopUsers.

• Verbose logs are located: 'C:\Windows\Logs\Software\'

• The script requires elevation to operate.