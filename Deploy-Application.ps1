<#
.SYNOPSIS
	This script performs the installation or uninstallation of an application(s).
.DESCRIPTION
	The script is provided as a template to perform an install or uninstall of an application(s).
	The script either performs an "Install" deployment type or an "Uninstall" deployment type.
	The install deployment type is broken down into 3 main sections/phases: Pre-Install, Install, and Post-Install.
	The script dot-sources the AppDeployToolkitMain.ps1 script which contains the logic and functions required to install or uninstall an application.
.PARAMETER DeploymentType
	The type of deployment to perform. Default is: Install.
.PARAMETER DeployMode
	Specifies whether the installation should be run in Interactive, Silent, or NonInteractive mode. Default is: Interactive. Options: Interactive = Shows dialogs, Silent = No dialogs, NonInteractive = Very silent, i.e. no blocking apps. NonInteractive mode is automatically set If it is detected that the process is not user interactive.
.PARAMETER AllowRebootPassThru
	Allows the 3010 return code (requires restart) to be passed back to the parent process (e.g. SCCM) if detected from an installation. If 3010 is passed back to SCCM, a reboot prompt will be triggered.
.PARAMETER TerminalServerMode
	Changes to "user install mode" and back to "user execute mode" for installing/uninstalling applications for Remote Destkop Session Hosts/Citrix servers.
.PARAMETER DisableLogging
	Disables logging to file for the script. Default is: $false.
.EXAMPLE
    powershell.exe -Command "& { & '.\Deploy-Application.ps1' -DeployMode 'Silent'; Exit $LastExitCode }"
.EXAMPLE
    powershell.exe -Command "& { & '.\Deploy-Application.ps1' -AllowRebootPassThru; Exit $LastExitCode }"
.EXAMPLE
    powershell.exe -Command "& { & '.\Deploy-Application.ps1' -DeploymentType 'Uninstall'; Exit $LastExitCode }"
.EXAMPLE
    Deploy-Application.exe -DeploymentType "Install" -DeployMode "Silent"
.NOTES
	Toolkit Exit Code Ranges:
	60000 - 68999: Reserved for built-in exit codes in Deploy-Application.ps1, Deploy-Application.exe, and AppDeployToolkitMain.ps1
	69000 - 69999: Recommended for user customized exit codes in Deploy-Application.ps1
	70000 - 79999: Recommended for user customized exit codes in AppDeployToolkitExtensions.ps1
.LINK 
	http://psappdeploytoolkit.com
#>
[CmdletBinding()]
Param (
	[Parameter(Mandatory=$false)]
	[ValidateSet('Install','Uninstall')]
	[string]$DeploymentType = 'Install',
	[Parameter(Mandatory=$false)]
	[ValidateSet('Interactive','Silent','NonInteractive')]
	[string]$DeployMode = 'Interactive',
	[Parameter(Mandatory=$false)]
	[switch]$AllowRebootPassThru = $false,
	[Parameter(Mandatory=$false)]
	[switch]$TerminalServerMode = $false,
	[Parameter(Mandatory=$false)]
	[switch]$DisableLogging = $false,
	[Parameter(Mandatory=$false)]
	[boolean]$CustomActions = $false,													# Toggle whether to apply the custom actions
	[Parameter(Mandatory=$false)]
	[boolean]$ReplaceCurrentClient = $false,											# Toggle whether to reinstall the existing client version (even if it's the same as what's being deployed)
	[Parameter(Mandatory=$false)]
	[boolean]$ShowWelcomePromptWithDefer = $false,										# Display a welcome prompt with the option to defer (Default: Enabled)
	[Parameter(Mandatory=$false)]
	[int32]$WelcomePromptDeferTimes = 3,												# The number of times the install can be deferred (Default: 3)
	[Parameter(Mandatory=$false)]
	[boolean]$ShowRestartPrompt = $true,												# Display a restart prompt (Default: Enabled)
	[Parameter(Mandatory=$false)]
	[int32]$RestartCountDownSeconds = 28800,											# Automatically restart when complete after x seconds (Default: 600)
	[Parameter(Mandatory=$false)]
	[boolean]$ForceUninstallPreviousVersions = $false, 									# Force uninstall any previous versions (in the event of an upgrade error)
	[Parameter(Mandatory=$false)]
	[boolean]$IC3Mode = $false, 														# Enable IC3 Mode (Default: Disabled)
	[Parameter(Mandatory=$false)]
	[boolean]$EPOMode = $false, 														# Enable EPO Mode (Default: Disabled)
	[Parameter(Mandatory=$false)]	
	[boolean]$WebServerMode = $false, 													# Enable Web Server Mode (Default: Disabled)
	[Parameter(Mandatory=$false)]
	[string]$WebServerPolicyURL = "avectopolicy.avecto.com/PrivilegeGuardConfig.xml",	# Web Server Policy URL
	[Parameter(Mandatory=$false)]
	[int32]$WebServerPolicyInterval = 15,												# Web Server Policy Refresh Interval (Default: 90)
	[Parameter(Mandatory=$false)]
	[boolean]$EnableSandboxing = $false,												# Enable / Disable Sandboxing (Default: Disabled)
	[Parameter(Mandatory=$false)]	
	[boolean]$EnableContentControl = $false,											# Enable / Disable Content Control (Default: Disabled)
	[Parameter(Mandatory=$false)]
	[boolean]$AddCPPGProgramsUtil = $true,												# Add Avecto Programs and Features to Control Panel (Default: Enabled)
	[Parameter(Mandatory=$false)]
	[boolean]$AddCPPGPrinterUtil = $false,												# Add Avecto Printer Management to Control Panel (Default: Disabled)
	[Parameter(Mandatory=$false)]
	[boolean]$AddCPPGNetworkAdapterUtil = $false,										# Add Avecto Network Management to Control Panel (Default: Disabled)
	[Parameter(Mandatory=$false)]
	[boolean]$EnableUAC = $false,														# Enable minimum requirements for User Account Control (UAC) (Default: Disabled)
	[Parameter(Mandatory=$false)]
	[boolean]$EnableWinRM = $false,														# Enable Windows Remote Management (WinRM) (Default: Disabled)
	[Parameter(Mandatory=$false)]
	[boolean]$InstallEventForwardingCertificate = $false,								# Install and configure a certificate for Event Forwarding (Default: Disabled)
	[Parameter(Mandatory=$false)]
	[string]$EventForwardingCertificateFile = "Certificate.cer",						# Event Forwarding certificate file-name (should be located in SupportFiles folder)
	[Parameter(Mandatory=$false)]
	[string]$EventForwardingCertificateSubject = "Avecto Defendpoint Event Forwarding",	# Event Forwarding certificate subject
	[Parameter(Mandatory=$false)]
	[boolean]$ConfigureEventSubscription = $false,										# Configure the Event Collector Subscription (Default: Disabled)
	[Parameter(Mandatory=$false)]
	[string]$EventSubscriptionURL = "avectoeventcollector.avecto.com", 					# Event Collector Subscription URL
	[Parameter(Mandatory=$false)]
	[boolean]$RemoveCurrentUserFromLocalAdmin = $false,									# Remove the current user from the Local Administators group (Default: Disabled)
	[Parameter(Mandatory=$false)]
	[boolean]$RemoveAllUsersFromLocalAdmin = $false,									# Remove all users from the Local Administators group (does not remove groups)
	[Parameter(Mandatory=$false)]
	[string[]]$RemoveAllUsersFromLocalAdminExclusions = @("svc_", "avectotest"), 		# List of accounts to exclude from removing from the Local Administrators group (using a substring match)
	[Parameter(Mandatory=$false)]
	[boolean]$AddRemovedUserstoPowerUsers = $false,										# Add any user removed from the Local Administrators group to the Power Users group (Default: Enabled)
	[Parameter(Mandatory=$false)]
	[boolean]$AddRemovedUserstoRemoteDesktopUsers = $false								# Add any user removed from the Local Administrators group to the Remote Desktop Users group (Default: Disabled)
)

#################################################################################
### START FUNCTION REGION #######################################################
#################################################################################

<#############################
#.SYNOPSIS
# Checks whether a given application is installed on the system.
#
#.EXAMPLE
# Get-InstalledApps | Where-Object {$_.DisplayName -like "Application" -and $_.DisplayVersion -eq "Application version"}
#
#############################>
function Get-InstalledApps
{
	If ([IntPtr]::Size -eq 4) 
	{
        $regpath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    }
	Else 
	{
        $regpath = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
            'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
    }
    Get-ItemProperty $regpath | .{process{If($_.DisplayName -and $_.UninstallString) { $_ } }} | Select-Object DisplayName, Publisher, InstallDate, DisplayVersion, UninstallString | Sort-Object DisplayName
}
<#
End of Function
#>

<#############################
#.SYNOPSIS
# Checks whether iC3 Adapter is already installed. If yes, the installation does not continue. If no, then install .NET Framework 4.6.1 and the iC3 Adapter.
#
#.NOTES
# This function also deletes any GPO delivered Defendpoint policy.
#############################>
function Install-iC3Adapter
{
	If ($Is64Bit) { $installArch = 'x64' } Else { $installArch = 'x86' }

	## Read the iC3 version from the file.
	If (Test-Path -Path $dirFiles\ic3_version.txt) 
	{
		Write-Log -Message "Reading iC3 version from: '$dirFiles\ic3_version.txt'"
		If ((Get-Content -Path "$dirFiles\ic3_version.txt") -eq $null) 
		{
			Write-Log -Message "The iC3 version file ['$dirFiles\ic3_version.txt'] is empty so the iC3 adapter cannot be installed!" -Severity 3
			Return
		}
		Else 
		{
			$iC3Version = Get-Content $dirFiles\ic3_version.txt
			Write-Log -Message "The following iC3 adapter version will be used as the version: $iC3Version" -Severity 2
		}
	}
	Else 
	{
		Write-Log -Message "The iC3 version file does not exist so the iC3 adapter cannot be installed!" -Severity 3
		Write-Log -Message "The file should be stored in the '/Files' directory." -Severity 3
		Return
	}

	## Read the iC3 parameters from the file.
	If (Test-Path -Path $dirFiles\ic3_parameters.txt) 
	{
		Write-Log -Message "Reading iC3 parameters from: '$dirFiles\ic3_parameters.txt'"
		If ((Get-Content -Path "$dirFiles\ic3_parameters.txt") -eq $null) 
		{
			Write-Log -Message "The iC3 parameters file ['$dirFiles\ic3_parameters.txt'] is empty so the iC3 adapter cannot be installed!" -Severity 3
			Return
		}
		Else 
		{
			$iC3Parameters = Get-Content $dirFiles\ic3_parameters.txt
			Write-Log -Message "The following parameters will be passed to the iC3 adapter: $iC3Parameters" -Severity 2
		}
	}
	Else 
	{
		Write-Log -Message "The iC3 parameters file does not exist so the iC3 adapter cannot be installed!" -Severity 3
		Write-Log -Message "The file should be stored in the '/Files' directory." -Severity 3
		Return
	}

	## Check whether the iC3 adapter is already installed.
	$appToMatch = 'Avecto iC3 Adapter'
	$result = Get-InstalledApps | Where-Object {$_.DisplayName -like $appToMatch -and $_.DisplayVersion -eq $iC3Version}
	$resultDisplayVersion = $result | Select-Object -ExpandProperty DisplayVersion

	## If the adapter checks returns nothing (either adapter not installed or old version), install it.
	If ([string]::IsNullOrEmpty($result)) 
	{
		## Remove any existing iC3 adapter install.
		Write-Log -Message "Searching for iC3 adapter..."
		If ((Get-InstalledApps | Where-Object {$_.DisplayName -like $appToMatch}) -or (Test-Path "C:\Windows\Logs\Software\ic3_adapter_removed_for_upgrade.tmp")) 
		{
			Remove-MSIApplications -Name 'Avecto iC3 Adapter'

			## End iC3 host process, if running.
			$ic3HostProcess = Get-Process -Name "Avecto.IC3.Client.Host" -ErrorAction SilentlyContinue
			If ($ic3HostProcess) 
			{
				$ic3HostProcess | Stop-Process -Force
			}

			## Remove the iC3 user folder.
			If (Test-Path "C:\Users\IC3Adapter") 
			{
				Remove-Item "C:\Users\IC3Adapter" -Recurse -Force
			}

			## A machine MUST be rebooted before installing/upgrading the iC3 adapter.
			If (Test-Path "C:\Windows\Logs\Software\ic3_adapter_removed_for_upgrade.tmp") 
			{
				Write-Log -Message "Adapter uninstall file exists in 'C:\Windows\Logs\Software\ic3_adapter_removed_for_upgrade.tmp'"
				Write-Log -Message "Checking whether a reboot has been done..."
				$uninstallTimeStringUtc = Get-Content -Path "C:\Windows\Logs\Software\ic3_adapter_removed_for_upgrade.tmp"
				If (((Get-Date) - ([timespan]::FromMilliseconds([Math]::Abs([Environment]::TickCount)))).ToFileTime() -gt $uninstallTimeStringUtc) 
				{
					Write-Log -Message "The host has been rebooted, install will continue..."
					$hostRebooted = $true
				}
				Else 
				{
					Write-Log -Message "The host has not been rebooted, aborting!"
					Exit-Script -ExitCode 1
				}
			}
			## Create entry to confirm iC3 adapter is removed.
			Else 
			{
				Write-Log -Message "Creating record of uninstall in 'C:\Windows\Logs\Software\ic3_adapter_removed_for_upgrade.tmp'"
				(Get-Date).ToFileTime() | Out-File "C:\Windows\Logs\Software\ic3_adapter_removed_for_upgrade.tmp" -NoNewline
			
				## Display a restart prompt (if required).
				If ($ShowRestartPrompt) 
				{
					If ($RestartCountDownSeconds -ne 0) 
					{
						Show-InstallationRestartPrompt -CountDownSeconds $RestartCountDownSeconds -CountdownNoHideSeconds 1800
					} 
					Else 
					{
					Show-InstallationRestartPrompt -NoCountdown
					}
				}
				Exit-Script -ExitCode 3010
			}
		}
		Else 
		{
			Write-Log -Message "Begin pre-reqs and install of iC3 adapter [$iC3Version]"
		}

		## Installs .NET Framework 4.6.1.
		Write-Log -Message "Checking whether NET Framework 4.6.1 or greater is installed..."
		If (!(Get-ChildItem "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\" | Get-ItemProperty -Name Release | ForEach-Object { $_.Release -ge 394254 }))
		{
			Write-Log "NET Framework 4.6.1 or greater is NOT installed."
			Write-Log "Beginning install of .NET Framework 4.6.1 pre-requisite component..."

			If (Test-Path "$dirFiles\KB3151800.exe") 
			{
				$process = Start-Process -FilePath "$dirFiles\KB3151800.exe" -ArgumentList "/q /norestart /log $envWinDir\Logs\Software\" -PassThru -Wait -Verb RunAs
				If ($process.ExitCode -eq 3010) 
				{
					Write-Log -Message "Finished .NET Framework install - a reboot is required!"
					Show-InstallationRestartPrompt -CountDownSeconds $RestartCountDownSeconds -CountdownNoHideSeconds 1800
					Exit-Script -ExitCode 3010
				}
				Write-Log -Message "Finished .NET Framework 4.6.1 install - no reboot is required."
			}
			Else
			{
				Write-Log -Message "'KB3151800.exe' can't be found in the 'Files' directory! The iC3 adapter will likely fail to install." -Severity 3
			}
		}
		Else 
		{
			Write-Log "NET Framework 4.6.1 or greater IS installed - skipping step."
		}

		## Remove all registry key values which contain 'iC3Adapter' from the ProfileList.
		If ($hostRebooted)
		{
			Write-Log -Message "Removing invalid iC3 entries in ['HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList']..."
			Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {Get-ItemProperty $_.pspath} | Where-Object {$_.ProfileImagePath -match "IC3Adapter"} | Remove-Item -Verbose
			Write-Log -Message "Finished cleaning registry of invalid iC3 entries, continue..."
		}
		
		## Removes any GPO/local delivered Defendpoint policy.
		If (Test-Path "C:\ProgramData\Avecto\Privilege Guard\GPO Cache") 
		{
			Remove-Item "C:\ProgramData\Avecto\Privilege Guard\GPO Cache\*" -Recurse -Force
		}
		If (Test-Path "C:\ProgramData\Avecto\Privilege Guard\PrivilegeGuardConfig.xml") 
		{
			Remove-Item "C:\ProgramData\Avecto\Privilege Guard\PrivilegeGuardConfig.xml" -Force
		}

		## Start the iC3 adapter install.
		If (Test-Path "$dirFiles\AvectoIC3Adapter_$installArch.msi") {
			Write-Log -Message "Starting iC3 adapter install."
			Execute-MSI -Action 'Install' -Path "$dirFiles\AvectoIC3Adapter_$installArch.msi" -AddParameters $iC3Parameters
		}
	}
	Else 
	{
		Write-Log -Message "The iC3 adapter [$resultDisplayVersion] is already installed. Exiting function."
	}
}
<#
End of Function
#>

<#############################
#.SYNOPSIS
# Get product & version-specific information from an MSI file.
#
#.EXAMPLE
# C:\> Get-MsiInformation -Path "$env:Temp\Installer.msi"
#
#############################>

function Get-MsiInformationNew {
	Param (
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [System.IO.FileInfo]$Path,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("ProductCode", "ProductVersion", "ProductName", "Manufacturer", "ProductLanguage", "FullVersion")]
	[string]$Property
	)
	Process 
	{
		Try 
		{
			# Read property from MSI database
			$WindowsInstaller = New-Object -ComObject WindowsInstaller.Installer
			$MSIDatabase = $WindowsInstaller.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $WindowsInstaller, @($Path.FullName, 0))
			$Query = "SELECT Value FROM Property WHERE Property = '$($Property)'"
			$View = $MSIDatabase.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $MSIDatabase, ($Query))
			$View.GetType().InvokeMember("Execute", "InvokeMethod", $null, $View, $null)
			$Record = $View.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $View, $null)
			$Value = $Record.GetType().InvokeMember("StringData", "GetProperty", $null, $Record, 1)

			# Commit database and close view
			$MSIDatabase.GetType().InvokeMember("Commit", "InvokeMethod", $null, $MSIDatabase, $null)
			$View.GetType().InvokeMember("Close", "InvokeMethod", $null, $View, $null)           
			$MSIDatabase = $null
			$View = $null

			# Return the value
			return $Value
		} 
		Catch 
		{
			Write-Warning -Message $_.Exception.Message ; break
		}
	}
	End 
	{
		# Run garbage collection and release ComObject
		[System.Runtime.Interopservices.Marshal]::ReleaseComObject($WindowsInstaller) | Out-Null
		[System.GC]::Collect()
	}
}

function ForceUninstallDefendpoint {
	
	Write-Log -Message "Starting a forced removal of Defendpoint client files and settings..." -Severity 2
	
	New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE

	## Stop the systray icon (if required).
	Stop-Process -ProcessName "PGSystemTray" -Force -ErrorAction SilentlyContinue

	## Stop and remove the service and driver (if found).
	Stop-Service "Avecto Privilege Guard Service" -Force -ErrorAction SilentlyContinue
	Stop-Service "Avecto Defendpoint Service" -Force -ErrorAction SilentlyContinue
	Stop-Service "PGDriver" -Force -ErrorAction SilentlyContinue
	sc.exe delete "PGDriver"
	sc.exe delete "Avecto Defendpoint Service"

	## Remove service registry keys.
	Remove-RegistryKey -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Avecto Privilege Guard Service' -Recurse
	Remove-RegistryKey -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Avecto Defendpoint Service' -Recurse

	## Remove Defendpoint class keys.
	Remove-RegistryKey -Key 'HKLM\SOFTWARE\Classes\Installer\UpgradeCodes\C612437742FA76246B8E6A6DCE096D4A' -Recurse

	## Remove HKCR installer keys.
	Write-Log -Message "Starting the removal of all HKCR installer keys..."
	ForEach ($hkcrInstallerKey in (Get-ChildItem "HKCR:\Installer\Products")) 
	{
		$hkcrInstallerKeyValue = Get-RegistryKey -Key $hkcrInstallerKey
		If ($hkcrInstallerKeyValue.ProductName -match 'Avecto Privilege Guard Client') 
		{
			Remove-RegistryKey -Key $hkcrInstallerKeyValue -Recurse -Verbose
		}
		If ($hkcrInstallerKeyValue.ProductName -match 'Avecto Defendpoint Client') 
		{
			Remove-RegistryKey -Key $hkcrInstallerKeyValue -Recurse -Verbose
		}
	}

	## Remove HKLM installer keys.
	Write-Log -Message "Starting the removal of all HKLM installer keys..."
	ForEach ($hklmInstallerKey in (Get-ChildItem "HKLM:\Software\Classes\Installer\Products")) 
	{
		$hklmInstallerKeyValue = Get-RegistryKey -Key $hklmInstallerKey
		If ($hklmInstallerKeyValue.ProductName -match 'Avecto Privilege Guard Client') 
		{
			Remove-RegistryKey -Key $hklmInstallerKeyValue -Recurse -Verbose
		}
		If ($hklmInstallerKeyValue.ProductName -match 'Avecto Defendpoint Client') 
		{
			Remove-RegistryKey -Key $hklmInstallerKeyValue -Recurse -Verbose
		}
	}

	## Remove all PG DLLs located HKCR keys.
	Write-Log -Message "Starting the removal of all PG Class Root (HKCR) DLLs..."
	
	## PGExtension.
	Remove-RegistryKey -Key 'HKCR\CLSID\{01ED801E-1A37-4434-A7DA-303ABC37B08C}' -Recurse
	Remove-RegistryKey -Key 'HKCR\PrivilegeGuardExtension.PGShellExt.1' -Recurse

	## PGOutlookAddin.
	Remove-RegistryKey -Key 'HKCR\CLSID\{420A649C-3BF0-4CFD-AFA2-8F0445AA56EA}' -Recurse

	## PGDownload.
	Remove-RegistryKey -Key 'HKCR\CLSID\{7A88BF59-BB6B-4184-97FD-A92CC7F0A977}' -Recurse

	## PGBHO.
	Remove-RegistryKey -Key 'HKCR\CLSID\{2633209C-31D6-412F-9B00-2419AFC4B254}' -Recurse

	## PGActivityLogWmiProvider.
	Remove-RegistryKey -Key 'HKCR\CLSID\{3DFD6106-2B0C-4CFE-91BA-3510503DA10C}' -Recurse

	## PGPowerShellScript.
	Remove-RegistryKey -Key 'HKCR\CLSID\{0D1CDFFB-739A-351F-8366-F332E332EC6E}' -Recurse
	Remove-RegistryKey -Key 'HKCR\CLSID\{A6C582D3-976A-4F58-9D2A-4CCC05205136}' -Recurse
	Remove-RegistryKey -Key 'HKCR\CLSID\{AF12877E-9895-39BB-8783-0026D2F7B452}' -Recurse
	Remove-RegistryKey -Key 'HKCR\CLSID\{C50C1A20-9E01-3FD2-827C-5F64B6DF257C}' -Recurse

	Write-Log -Message "Finished the removal of all PG Class Root (HKCR) DLLs."
	
	## Remove 4.1.234 HKCR hive.
	Write-Log -Message "Attemping to remove 4.1.234 HKCR hive..." -Severity 2
	Remove-RegistryKey -Key 'HKCR\Installer\Products\C780254786725A94F9C04BBDA2BD86EC' -Recurse
	Remove-RegistryKey -Key 'HKLM\\SOFTWARE\Classes\Installer\Products\C780254786725A94F9C04BBDA2BD86EC' -Recurse
	Write-Log -Message "Finished removing 4.1.234 HKCR hive."

	## Close explorer so we can attempt deletion of 'Program Files' (x64 & x86).
	Write-Log -Message "Closing Windows Explorer to attempt deletion of 'Program Files' (x64 & x86)..." -Severity 2
	Get-Process -Name "explorer" | Stop-Process -Force
	Start-Sleep -Seconds 6

	## Delete the Defendpoint client 'Program Files' directory (if it still exists).
	If (Test-Path "$env:ProgramFiles\Avecto\Privilege Guard Client") 
	{
		Write-Log -Message "Attempting to remove '$env:ProgramFiles\Avecto\Privilege Guard Client'..." -Severity 2
		Remove-Item "$env:ProgramFiles\Avecto\Privilege Guard Client" -Recurse -Force
	}

	## Delete the Defendpoint client 'Program Files (x86)' directory (if it still exists).
	If (Test-Path "${env:ProgramFiles(x86)}\Avecto\Privilege Guard Client")
	{
		Write-Log -Message "Attempting to remove '${env:ProgramFiles(x86)}\Avecto\Privilege Guard Client'..." -Severity 2
		Remove-Item "${env:ProgramFiles(x86)}\Avecto\Privilege Guard Client" -Recurse -Force
	}

	## Remove orphaned driver entries.
	Write-Log -Message "Attempting to remove PGDriver entries from the DriverStore..." -Severity 2
	ForEach ($driverKey in (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DIFx\DriverStore")) 
	{
		$driverKeyValue = Get-RegistryKey -Key $driverKey
		If ($driverKeyValue.ManufacturerName -match 'Avecto') 
		{
			Remove-RegistryKey -Key $driverKeyValue -Recurse -Verbose
		}
		If ($driverKeyValue.ProductName -match 'Avecto Defendpoint Client') 
		{
			Remove-RegistryKey -Key $driverKeyValue -Recurse -Verbose
		}
	}



	## Start explorer (if it's not already running).
	If (!(Get-Process -Name "explorer")) 
	{
		Write-Log -Message "Starting Windows Explorer as active logged on user: [$($RunAsActiveUser.NTAccount)]."
		Execute-ProcessAsUser -Path "C:\Windows\explorer.exe"
	}
	
	Write-Log -Message "Finished the removal of Defendpoint client files and entries."
	
}

#################################################################################
### END FUNCTION REGION #########################################################
#################################################################################

Try 
{
	## Set the script execution policy for this process.
	Try 
	{ 
		Set-ExecutionPolicy -ExecutionPolicy 'Bypass' -Scope 'Process' -Force -ErrorAction 'Stop' 
	} 
	Catch {}

	##* Do not modify section below!
	#region DoNotModify
	
	## Variables: Exit Code
	[int32]$mainExitCode = 0

	## Variables: Script
	[string]$deployAppScriptFriendlyName = 'Deploy Application'
	[version]$deployAppScriptVersion = [version]'3.6.9'
	[string]$deployAppScriptDate = '13/06/2018'
	[hashtable]$deployAppScriptParameters = $psBoundParameters

	## Variables: Environment
	If (Test-Path -LiteralPath 'variable:HostInvocation') { $InvocationInfo = $HostInvocation } Else { $InvocationInfo = $MyInvocation }
	[string]$scriptDirectory = Split-Path -Path $InvocationInfo.MyCommand.Definition -Parent

	## Dot source the required App Deploy Toolkit functions.
	Try 
	{
		[string]$moduleAppDeployToolkitMain = "$scriptDirectory\AppDeployToolkit\AppDeployToolkitMain.ps1"
		If (-not (Test-Path -LiteralPath $moduleAppDeployToolkitMain -PathType 'Leaf')) { Throw "Module does not exist at the specIfied location [$moduleAppDeployToolkitMain]." }
		If ($DisableLogging) { . $moduleAppDeployToolkitMain -DisableLogging } Else { . $moduleAppDeployToolkitMain }
	}
	Catch 
	{
		If ($mainExitCode -eq 0){ [int32]$mainExitCode = 60008 }
		Write-Error -Message "Module [$moduleAppDeployToolkitMain] failed to load: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
		
		## Exit the script, returning the exit code to SCCM.
		If (Test-Path -LiteralPath 'variable:HostInvocation') { $script:ExitCode = $mainExitCode; Exit } Else { Exit $mainExitCode }
	}

	#endregion
	##* Do not modify section above!
	##*===============================================
	##* END VARIABLE DECLARATION
	##*===============================================

	## Set the context to 64-bit or 32-bit, depending on architecture.
	If ($Is64Bit) { $installArch = 'x64' } Else { $installArch = 'x86' }

	##*===============================================
	##* VARIABLE DECLARATION
	##*===============================================
	## Variables: Application
	[string]$appVendor = 'Avecto'
	[string]$appName = 'Defendpoint Client'

	## Rather than define the version manually, we use Get-MsiInformation and retrieve the product version dynamically.
	If (Test-Path "$dirFiles\DefendpointClient_$installArch.msi")
	{
		#[string]$appVersion = Get-MsiInformation -Path "$dirFiles\DefendpointClient_x64.msi" | Select-Object -ExpandProperty ProductVersion
		[string]$appVersion = Get-MsiInformationNew -Path "$dirFiles\DefendpointClient_x64.msi" -Property ProductVersion
	}
	## Unless we are dealing with a mixed pilot environment (where a subset of users are testing a newever client version), $pilotClientVersion should be the same as $appVersion.
	[string]$pilotClientVersion = $appVersion
	[string]$appArch = ''
	[string]$appLang = 'EN'
	[string]$appRevision = '01'
	[string]$appScriptVersion = '1.2'
	[string]$appScriptDate = '13/06/2018'
	[string]$appScriptAuthor = 'Dan Cunningham, Adem Murselaj'
	[boolean]$ClientAlreadyInstalled = $false
	##*===============================================

	## Trigger a warning if the execution of the script is x86 and the OS is x64.
	## 4 = x86 // 8 = x64
	If (([System.IntPtr]::Size -eq 4) -and ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq "64-bit"))
	{
		Write-Log -Message "It is not recommended to run this script in 32-bit mode on a 64-bit OS! Cannot continue." -Severity 3
		Exit-Script -ExitCode 60001
	}

	If ($DeploymentType -ine 'Uninstall') 
	{
		##*===============================================
		##* PRE-INSTALLATION
		##*===============================================
		[string]$installPhase = 'Pre-Installation'

		## Check that the Defendpoint MSI is present, if not then notify and exit.
		If (!(Test-Path "$dirFiles\DefendpointClient_$installArch.msi"))
		{
			Write-Log -Message "The Defendpoint MSI file in: '$dirFiles\DefendpointClient_$installArch.msi' is missing. Cannot continue." -Severity 3
			Exit-Script -ExitCode 60001
		}

		##*===============================================
		##* START CUSTOM ACTIONS
		##*===============================================

		## Enable .NET 3.5.
		If ($CustomActions) 
		{
			## Enable .NET Framework 3.5 (Windows 10).
			Write-Log -Message "Attemping to enable .NET Framework 3.5..."
			DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /LogPath:"$envWinDir\Logs\Software\DISM.log"
			Write-Log -Message "Finished enabling .NET Framework 3.5 - check the log ['$envWinDir\Logs\Software\DISM.log'] for any failures."
		}

		##*===============================================
		##* END CUSTOM ACTIONS
		##*===============================================

		## Check whether the Defendpoint client is already installed.
		$installedProductionClient = 'Avecto Defendpoint Client (x64) ' + $appVersion

		## Don't replace the V5 client with an older version.
		$installedPilotClient = 'Avecto Defendpoint Client (x64) ' + $pilotClientVersion
		$isClientInstalled = Get-InstalledApps | Where-Object {$_.DisplayName -like $installedProductionClient -or $_.DisplayName -like $installedPilotClient}
	
		## If the Defendpoint check returns a value, the Defendpoint client is already installed.
		If ($isClientInstalled -ine $null) {
			Write-Log -Message "The Defendpoint client [$appVersion] is already installed."
			Write-Log -Message "Checking if the iC3 adapter needs installing..."
			$ClientAlreadyInstalled = $true

			## If we are in iC3 mode, check whether the adapter needs installing.
			If ($IC3Mode) 
			{
				Write-Log -Message "The iC3 adapter has been configured for install. Checking whether the iC3 adapter is already installed..."
				Install-iC3Adapter

				## Remove the reference to the adapter being removed (if present).
				If (Test-Path "C:\Windows\Logs\Software\ic3_adapter_removed_for_upgrade.tmp") 
				{
					Write-Log -Message "Removed the iC3 adapter removal marker file."
					Remove-Item "C:\Windows\Logs\Software\ic3_adapter_removed_for_upgrade.tmp"
				}
				If (!($ReplaceCurrentClient)) 
				{
					Exit-Script -ExitCode $mainExitCode
				}	
			}
			ElseIf (!($IC3Mode)) 
			{
				Write-Log -Message "The iC3 adapter does not need installing."
			}
			If (!($ReplaceCurrentClient)) 
			{
				Write-Log -Message "The Defendpoint client [$appVersion] does not need reinstalling."
				Exit-Script -ExitCode $mainExitCode
			}
			Write-Log -Message "The Defendpoint client [$appVersion] will be reinstalled."
		}

		## Check for Event Forwarding Certificate (if required).
		If (($InstallEventForwardingCertificate) -and (-not (Test-Path "$dirSupportFiles\$eventForwardingCertificateFile"))) 
		{
			Show-DialogBox -Text "Installation of Event Forwarding Certificate was specified but no certificate was found at $dirSupportFiles\$eventForwardingCertificateFile" -Icon 'Stop'
			Exit-Script 1
		}

		## Show Welcome Prompt (if required).
		If ($ShowWelcomePromptWithDefer) 
		{
			Show-InstallationWelcome -AllowDefer -DeferTimes $WelcomePromptDeferTimes
		}

		## Show Progress Message (with the default message).
		Show-InstallationProgress
		
		If (!($ClientAlreadyInstalled) -or ($ReplaceCurrentClient)) 
		{
			##*===============================================
			##* START CUSTOM ACTIONS
			##*===============================================
			
			If ($CustomActions) 
			{
				## Place the temp policy with service protection disabled in client program data directory:
				Write-Log -Message "Attempt to copy temp policy file..."
				Try 
				{
					Copy-Item "$dirSupportFiles\PrivilegeGuardConfig.xml" -Destination "C:\ProgramData\Avecto\Privilege Guard\DPC Cache\Machine" -Force -ErrorAction Stop
					Write-Log -Message "Temp policy file copied."
				}
				Catch 
				{
					Write-Log -Message "Failed to copy temp file. Does thes source file exist, or is anti-tamper preventing this?" -Severity 2
					Write-Log -Message "[$($_.Exception.Message)]" -Severity 2
				}
			}

			##*===============================================
			##* END CUSTOM ACTIONS
			##*===============================================

			## Remove previous Defendpoint client.
			Remove-MSIApplications -Name 'Avecto Defendpoint Client'
			
			## Remove any custom registry keys.
			Remove-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Avecto\Privilege Guard Client' -Recurse
			Remove-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Avecto\Privilege Guard Client' -Recurse

			## Enumerate Control Panel and remove any Avecto items.
			New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
			ForEach ($cpClassKeys in (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace" -ErrorAction SilentlyContinue)) 
			{
				$cpClassID = $cpClassKeys.PSChildName
				ForEach ($rootClassKeys in (Get-Item "HKCR:\CLSID\$cpClassID" -ErrorAction SilentlyContinue)) 
				{
					$rootDefault = Get-ItemProperty -Path "HKCR:\CLSID\$cpClassID" -Name '(Default)' -ErrorAction SilentlyContinue
					If ($rootDefault -match 'Avecto') 
					{
						Remove-RegistryKey -Key "HKCR:\CLSID\$cpClassID" -Recurse
						Remove-RegistryKey -Key "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\$cpClassID" -Recurse
					}
				}			
			}
		}

		## Forcibly clean up the leftovers from the uninstall of the client.
		If ($ForceUninstallPreviousVersions) 
		{
			ForceUninstallDefendpoint
		}	

		##*===============================================
		##* INSTALLATION 
		##*===============================================
		[string]$installPhase = 'Installation'
		Write-Log -Message "Starting installation phase..."

		## Disable Sandboxing (if required).
		If (!$EnableSandboxing) 
		{
			Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Avecto\Privilege Guard Client' -Name 'EmailAttachmentsFeatureEnabled' -Value 0 -Type DWord
			Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Avecto\Privilege Guard Client' -Name 'EmailAttachmentsFeatureEnabled' -Value 0 -Type DWord
			Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Avecto\Privilege Guard Client' -Name 'BrowserSandboxingEnabled' -Value 0 -Type DWord
			Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Avecto\Privilege Guard Client' -Name 'BrowserSandboxingEnabled' -Value 0 -Type DWord
			Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Avecto\Privilege Guard Client' -Name 'SandboxingEnabled' -Value 0 -Type DWord
			Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Avecto\Privilege Guard Client' -Name 'SandboxingEnabled' -Value 0 -Type DWord
			Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Avecto\Privilege Guard Client' -Name 'MSIEStartMinimized' -Value 0 -Type DWord
			Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Avecto\Privilege Guard Client' -Name 'MSIEStartMinimized' -Value 0 -Type DWord
		}

		## Disable Content Control (if required).
		If (!$EnableContentControl) 
		{
			Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Avecto\Privilege Guard Client' -Name 'ContentFeatureEnabled' -Value 0 -Type DWord
			Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Avecto\Privilege Guard Client' -Name 'ContentFeatureEnabled' -Value 0 -Type DWord
		}

		## Resolve application compatibility issues with Hook Exclusions.
		If (Test-Path "$dirSupportFiles\ManagedHookExclusions.txt") 
		{
			$hookExclusions = Get-Content "$dirSupportFiles\ManagedHookExclusions.txt"
			Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Avecto\Privilege Guard Client' -Name 'ManagedHookExclusions' -Value $hookExclusions -Type MultiString
			Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Avecto\Privilege Guard Client' -Name 'ManagedHookExclusions' -Value $hookExclusions -Type MultiString
		}

		## Resolve performance issues with Content Control.
		If (Test-Path "$dirSupportFiles\ContentRuleExclusions.txt") 
		{
			$contentRuleExclusions = Get-Content "$dirSupportFiles\ContentRuleExclusions.txt"
			Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Avecto\Privilege Guard Client' -Name 'ContentRuleExclusions' -Value $contentRuleExclusions -Type MultiString
			Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Avecto\Privilege Guard Client' -Name 'ContentRuleExclusions' -Value $contentRuleExclusions -Type MultiString
		}

		## Make sure the client does not switch to AppInit.
		Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Avecto\Privilege Guard Client' -Name 'HookLoadDll' -Value "C:\Program Files\Avecto\Privilege Guard Client\PGHook.dll" -Type String
		Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Avecto\Privilege Guard Client' -Name 'HookLoadMethod' -Value 3 -Type Dword
		Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Avecto\Privilege Guard Client' -Name 'InstallationDirectory' -Value "C:\Program Files\Avecto\Privilege Guard Client\" -Type String
		
		Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Avecto\Privilege Guard Client' -Name 'HookLoadDll' -Value "C:\Program Files (x86)\Avecto\Privilege Guard Client\PGHook.dll" -Type String
		Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Avecto\Privilege Guard Client' -Name 'HookLoadMethod' -Value 3 -Type Dword
		Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Avecto\Privilege Guard Client' -Name 'InstallationDirectory' -Value "C:\Program Files (x86)\Avecto\Privilege Guard Client\" -Type String

		## Install Defendpoint Client (x64 / x86 / IC3 Mode / ePO Mode / WebServer Mode).
		If ($Is64Bit) { $installArch = 'x64' } Else { $installArch = 'x86' }
		If ($IC3Mode) 
		{
			Execute-MSI -Action 'Install' -Path "$dirFiles\DefendpointClient_$installArch.msi" -AddParameters "POLICYENABLED=""WEBSERVICE"""
			
			## Install Defendpoint iC3 adapter (if required).
			Install-iC3Adapter
		}
		ElseIf ($EPOMode) 
		{ 
			Execute-MSI -Action 'Install' -Path "$dirFiles\DefendpointClient_$installArch.msi" -AddParameters "EPOMODE=1"
		}
		ElseIf ($WebServerMode) 
		{
			Execute-MSI -Action 'Install' -Path "$dirFiles\DefendpointClient_$installArch.msi" -AddParameters "/qn /norestart WEBSERVERMODE=1 WSP_URL=""$WebServerPolicyURL"" WSP_INTERVAL=$WebServerPolicyInterval POLICYENABLED=""WEBSERVER,GPO,LOCAL"""
		}
		Else 
		{
			Execute-MSI -Action 'Install' -Path "$dirFiles\DefendpointClient_$installArch.msi"
		}

		##*===============================================
		##* POST-INSTALLATION
		##*===============================================
		[string]$installPhase = 'Post-Installation'
		
		## Add Control Panel Entries (if required).
		If ($AddCPPGProgramsUtil -or $AddCPPGPrinterUtil -or $AddCPPGNetworkAdapterUtil)
		 {
			Copy-File "$envProgramFiles\Avecto\Privilege Guard Client\PGCommonUtil.dll" "$envWinDir\System32\PGCommonUtil.dll"

			## Add PGProgramsUtil.
			If ($AddCPPGProgramsUtil) 
			{
				[string] $guid = [guid]::NewGuid()
				Copy-File "$envProgramFiles\Avecto\Privilege Guard Client\PGProgramsUtil.exe" "$envWinDir\System32\PGProgramsUtil.exe"
				Set-RegistryKey -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{$guid}" -Name '(Default)'
				Set-RegistryKey -Key "HKEY_CLASSES_ROOT\CLSID\{$guid}" -Name '(Default)' -Value "Avecto Programs & Features"
				Set-RegistryKey -Key "HKEY_CLASSES_ROOT\CLSID\{$guid}" -Name "InfoTip" -Value "Allow Standard Users to Uninstall Applications"
				Set-RegistryKey -Key "HKEY_CLASSES_ROOT\CLSID\{$guid}" -Name "System.ControlPanel.Category" -Value "8"
				Set-RegistryKey -Key "HKEY_CLASSES_ROOT\CLSID\{$guid}" -Name "DefaultIcon" -Value "PGProgramsUtil.exe,0"
				Set-RegistryKey -Key "HKEY_CLASSES_ROOT\CLSID\{$guid}\Shell\Open\Command" -Name '(Default)' -Value "PGProgramsUtil.exe"
			}

			## Add PGPrinterUtil.
			If ($AddCPPGPrinterUtil) 
			{
				[string] $guid = [guid]::NewGuid()
				Copy-File "$envProgramFiles\Avecto\Privilege Guard Client\PGPrinterUtil.exe" "$envWinDir\System32\PGPrinterUtil.exe"
				Set-RegistryKey -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{$guid}" -Name '(Default)'
				Set-RegistryKey -Key "HKEY_CLASSES_ROOT\CLSID\{$guid}" -Name '(Default)' -Value "Avecto Printer Manager"
				Set-RegistryKey -Key "HKEY_CLASSES_ROOT\CLSID\{$guid}" -Name "InfoTip" -Value "Allow Standard Users Manage Printer Settings"
				Set-RegistryKey -Key "HKEY_CLASSES_ROOT\CLSID\{$guid}" -Name "System.ControlPanel.Category" -Value "2"
				Set-RegistryKey -Key "HKEY_CLASSES_ROOT\CLSID\{$guid}" -Name "DefaultIcon" -Value "PGPrinterUtil.exe,0"
				Set-RegistryKey -Key "HKEY_CLASSES_ROOT\CLSID\{$guid}\Shell\Open\Command" -Name '(Default)' -Value "PGPrinterUtil.exe"
			}

			## Add PGNetworkAdapterUtil.
			If ($AddCPPGNetworkAdapterUtil) 
			{
				[string] $guid = [guid]::NewGuid()
				Copy-File "$envProgramFiles\Avecto\Privilege Guard Client\PGNetworkAdapterUtil.exe" "$envWinDir\System32\PGNetworkAdapterUtil.exe"
				Set-RegistryKey -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{$guid}" -Name '(Default)'
				Set-RegistryKey -Key "HKEY_CLASSES_ROOT\CLSID\{$guid}" -Name '(Default)' -Value "Avecto Network Manager"
				Set-RegistryKey -Key "HKEY_CLASSES_ROOT\CLSID\{$guid}" -Name "InfoTip" -Value "Allow Standard Users Manage Network Settings"
				Set-RegistryKey -Key "HKEY_CLASSES_ROOT\CLSID\{$guid}" -Name "System.ControlPanel.Category" -Value "3"
				Set-RegistryKey -Key "HKEY_CLASSES_ROOT\CLSID\{$guid}" -Name "DefaultIcon" -Value "PGNetworkAdapterUtil.exe,0"
				Set-RegistryKey -Key "HKEY_CLASSES_ROOT\CLSID\{$guid}\Shell\Open\Command" -Name '(Default)' -Value "PGNetworkAdapterUtil.exe"
			}
		}

		## Enable UAC (if required).
		If ($EnableUAC) 
		{
			Write-Log -Message "Enabling UAC"
			Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableInstallerDetection' -Value 1 -Type DWORD
			Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1 -Type DWORD 
		}

		## Enable WinRM (if required).
		If ($EnableWinRM) 
		{
			Write-Log -Message "Enabling WinRM"
			Enable-PSRemoting -Force -ErrorAction SilentlyContinue
		}

		## Install the Event Forwarding Certificate (if required).
		If ($InstallEventForwardingCertificate) 
		{
			Write-Log -Message "Installing Event Forwarding Certificate [$eventForwardingCertificateFile]"
			If (Test-Path "$dirSupportFiles\$eventForwardingCertificateFile") 
			{
				Try
				{
					$certFile = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
					$certFile.Import("$dirSupportFiles\$eventForwardingCertificateFile")
					$storeLocalMachine = New-Object System.Security.Cryptography.X509certificates.X509Store ("LocalMachine", "Root")
					$storeLocalMachine.Open('ReadWrite')
					$storeLocalMachine.Add($certFile)
					$storeLocalMachine.Close()
					$sslCert = Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.Subject -match $eventForwardingCertificateSubject}
					If ($sslCert -ne $null) 
					{
						$sslCertPrivKey = $sslCert.PrivateKey 
						$privKeyCertFile = Get-Item -Path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\*" | Where-Object {$_.Name -eq $sslCertPrivKey.CspKeyContainerInfo.UniqueKeyContainerName} 
						$privKeyAcl = (Get-Item -Path $privKeyCertFile.FullName).GetAccessControl("Access") 
						$permission = "NT AUTHORITY\NETWORK SERVICE","Read","Allow" 
						$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission 
						$privKeyAcl.AddAccessRule($accessRule) 
						Set-ACL $privKeyCertFile.FullName $privKeyAcl
					} 
					Else 
					{
						Write-Log -Message "No certificate can be found with the Subject [$eventForwardingCertificateSubject]." -Severity 2
					}
				}
				Catch 
				{
					Write-Log -Message "Failed to import certificate [$($_.Exception.Message)]." -Severity 2
				}
			} 
			Else 
			{
				Write-Log -Message "Installation of an Event Forwarding Certificate was specified but no certificate was found." -Severity 2
			}
		}

		## Configure the Event Collector Subscription URL (if required).
		If ($ConfigureEventSubscription) 
		{
			Write-Log -Message "Configuring Event Collector Subscription URL [$EventSubscriptionURL]"
			Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' -Name '1' -Value $EventSubscriptionURL -Type String
		}

		## In order to work in non-English cultures, we can't define the built-in groups using English terminology. Instead, we should convert the well-known SIDs to the localised name.
		Write-Log -Message "Retrieving the correct culture name for the Administrator, Power User, and Remote Desktop user group..."
		Try 
		{
			$adminSid = "S-1-5-32-544"
			$adminGroupFromSid = (New-Object System.Security.Principal.SecurityIdentifier($adminSid)).Translate([System.Security.Principal.NTAccount]).Value
			$adminGroupFromSid = $adminGroupFromSid.Split("\\")[1]
			Write-Log -Message "SID: '$adminSid' translates to: '$adminGroupFromSid'" -Severity 2
		}
		Catch 
		{
			Write-Log -Message "SID: '$adminSid' (Administrator Group) could not be translated, does the account exist? `n[$($_.Exception.Message)]" -Severity 3
			Break
		}
		Try 
		{
			$powerSid = "S-1-5-32-547"
			$powerGroupFromSid = (New-Object System.Security.Principal.SecurityIdentifier($powerSid)).Translate([System.Security.Principal.NTAccount]).Value
			$powerGroupFromSid = $powerGroupFromSid.Split("\\")[1]
			Write-Log -Message "SID: '$powerSid' translates to: '$powerGroupFromSid'" -Severity 2
		}
		Catch 
		{
			Write-Log -Message "SID: '$powerSid' (Power User Group) could not be translated, does the account exist? `n[$($_.Exception.Message)]" -Severity 3
			Break
		}
		Try 
		{
			$remoteSid = "S-1-5-32-555"
			$remoteGroupFromSid = (New-Object System.Security.Principal.SecurityIdentifier($remoteSid)).Translate([System.Security.Principal.NTAccount]).Value
			$remoteGroupFromSid = $remoteGroupFromSid.Split("\\")[1]
			Write-Log -Message "SID: '$remoteSid' translates to: '$remoteGroupFromSid'" -Severity 2
		}
		Catch 
		{
			Write-Log -Message "SID: '$remoteSid' (Remote Desktop User Group) could not be translated, does the account exist? `n[$($_.Exception.Message)]" -Severity 3
			Break
		}

		Write-Log -Message "Starting administrator removal actions..."

		## Remove the current user from the Local Administrators group (if required).
		If ($RemoveCurrentUserFromLocalAdmin) 
		{
			Try 
			{
				$computerName = $env:COMPUTERNAME
				$currentUser = Get-WMIObject -Class Win32_ComputerSystem | Select-Object Username
				$domainName = $currentUser.Username.Split("\")[0]
				$currentUserName = $currentUser.Username.Split("\")[1]
				Write-Log -Message "Removing the current user '$currentUserName' from Local Admin group." -Severity 2
				$localAdminGroup = [ADSI]"WinNT://$computerName/$adminGroupFromSid,group"
				$localAdminGroup.Remove("WinNT://$($domainName)/$($currentUserName)")

				## Add the current user to the Power Users group (if required).
				If ($AddRemovedUserstoPowerUsers) 
				{
					Write-Log -Message "Adding the current user '$currentUserName' to the Power Users group." -Severity 2
					$powerUsersGroup = [ADSI]"WinNT://localhost/$powerGroupFromSid,group"
					$powerUsersGroup.Add("WinNT://$($domainName)/$($currentUserName)")
				}

				## Add the current user to the Remote Desktop Users group (if required).
				If ($AddRemovedUserstoRemoteDesktopUsers) 
				{
					Write-Log -Message "Adding the current user '$currentUserName' to the Remote Desktop Users group." -Severity 2
					$remoteDesktopUsersGroup = [ADSI]"WinNT://localhost/$remoteGroupFromSid,group"
					$remoteDesktopUsersGroup.Add("WinNT://$($domainName)/$($currentUserName)")
				}
			}
			Catch
			{
				Write-Log -Message "Failed to remove the current user from the Local Administrators group `n[$($_.Exception.Message)]" -Severity 2
			}
		}
		## Otherwise, remove all ussers from the Local Administrators group.
		ElseIf ($RemoveAllUsersFromLocalAdmin) 
		{
			Try 
			{
				$computerName = $env:COMPUTERNAME
				$localAdminGroup = [ADSI]"WinNT://localhost/$adminGroupFromSid,group"
				$localAdminGroup.Members() | ForEach-Object {
					$memberPath = $_.GetType.Invoke().InvokeMember("Adspath", 'GetProperty', $null, $_, $null)

					## Domain members will have an memberPath like WinNT://DomainName/UserName.  
					## Local accounts will have a value like WinNT://DomainName/ComputerName/UserName.  
					$memberPathArray = $memberPath.split('/',[StringSplitOptions]::RemoveEmptyEntries)
					$memberName = $memberPathArray[-1]  
					$memberDomain = $memberPathArray[-2]  
					$memberClass = $_.GetType.Invoke().InvokeMember("Class", 'GetProperty', $null, $_, $null)  
					If ($memberPath -like "*/$computerName/*"){ $memberType = "Local" } Else {$memberType = "Domain" }

					## Only process users (exclude groups).
					If ($memberClass -eq "User") 
					{
						$exclusionMatch = $false
						ForEach ($exclusion in $RemoveAllUsersFromLocalAdminExclusions) 
						{
							If ($memberName -match $exclusion -or $memberName -eq "Administrator") 
							{ 
								$exclusionMatch = $true 
							}
						}
						If ($exclusionMatch) 
						{
							Write-Log -Message "Excluding the following user from the Local Admin group removal task: [$memberPath]" -Severity 2
						}
						Else 
						{
							Write-Log -Message "Removing the following user from the Local Admin group: [$memberPath]" -Severity 2
							$localAdminGroup.Remove($memberPath)
							If ($AddRemovedUserstoPowerUsers) 
							{
								Write-Log -Message "Adding the following user to the Power Users group: [$memberPath]" -Severity 2
								$powerUsersGroup = [ADSI]"WinNT://localhost/$powerGroupFromSid,group"
								$powerUsersGroup.Add($memberPath)
							}
							If ($AddRemovedUserstoRemoteDesktopUsers) 
							{
								Write-Log -Message "Adding the following user to the Remote Desktop Users group: [$memberPath]" -Severity2
								$remoteDesktopUsersGroup = [ADSI]"WinNT://localhost/$remoteGroupFromSid,group"
								$remoteDesktopUsersGroup.Add($memberPath)
							}
						}
					}
					ElseIf ($memberClass -eq "Group") 
					{
						Write-Log -Message "Excluding the following group from the Local Admin group removal task: [$memberPath]" -Severity 2
					}
				}
			}
			Catch 
			{
				Write-Log -Message "Failed to remove user from the Local Administrators group `n[$($_.Exception.Message)]" -Severity 3
			}
		}
	
		## Do a final restart of explorer, post-install, to help ensure our hooks are injected.
		If ($ForceUninstallPreviousVersions) 
		{
			## Close explorer so the PGHook is injected.
			Write-Log -Message "Restarting Windows Explorer to allow for injection of PGHook." -Severity 2
			Get-Process -Name "explorer" | Stop-Process -Force
			Start-Sleep -Seconds 6

			## Start explorer.
			If (!(Get-Process -Name "explorer")) 
			{
				Write-Log -Message "Starting Windows Explorer as active logged on user: [$($RunAsActiveUser.NTAccount)]."
				Execute-ProcessAsUser -Path "C:\Windows\explorer.exe"
			}
		}

		## Display a restart prompt (if required).
		If ($ShowRestartPrompt) 
		{
			If ($RestartCountDownSeconds -ne 0) 
			{
				Show-InstallationRestartPrompt -CountDownSeconds $RestartCountDownSeconds -CountdownNoHideSeconds 1800
			} 
			Else 
			{
				Show-InstallationRestartPrompt -NoCountdown	
			}
		}
	
	}
	ElseIf ($DeploymentType -ieq 'Uninstall')
	{
		##*===============================================
		##* PRE-UNINSTALLATION
		##*===============================================
		[string]$installPhase = 'Pre-Uninstallation'

		## Show Progress Message (with the default message).
		Show-InstallationProgress

		##*===============================================
		##* UNINSTALLATION
		##*===============================================
		[string]$installPhase = 'Uninstallation'

		## Remove Defendpoint client
		Remove-MSIApplications -Name 'Avecto Defendpoint Client'

		## Remove iC3 Adapter (if $iC3Mode = $true)
		If ($iC3Mode) 
		{
			Remove-MSIApplications -Name 'Avecto iC3 Adapter'

			## End iC3 host process, if running.
			$ic3HostProcess = Get-Process -Name "Avecto.IC3.Client.Host" -ErrorAction SilentlyContinue
			If ($ic3HostProcess) 
			{
				$ic3HostProcess | Stop-Process -Force
			}

			## Remove the iC3 user folder.
			If (Test-Path "C:\Users\IC3Adapter") 
			{
				Remove-Item "C:\Users\IC3Adapter" -Recurse -Force
			}

			## Run DelProf2 to remove the inactive iC3 user profile.
			## Start-Process -FilePath "$dirFiles\DelProf2.exe" -ArgumentList "/u" -Wait -Verb RunAs

			## Create entry to confirm iC3 adapter is removed.
			Write-Log -Message "Creating record of uninstall in 'C:\Windows\Logs\Software\ic3_adapter_removed_for_upgrade.tmp'"
			(Get-Date).ToFileTime() | Out-File "C:\Windows\Logs\Software\ic3_adapter_removed_for_upgrade.tmp" -NoNewline
		}
		
		##*===============================================
		##* POST-UNINSTALLATION
		##*===============================================
		[string]$installPhase = 'Post-Uninstallation'

		## Remove any custom registry keys.
		Remove-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Avecto\Privilege Guard Client' -Recurse
		Remove-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Avecto\Privilege Guard Client' -Recurse

		## Enumerate Control Panel and remove any Avecto items.
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
		ForEach ($cpClassKeys in (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace" -ErrorAction SilentlyContinue)) 
		{
			$cpClassID = $cpClassKeys.PSChildName
			ForEach ($rootClassKeys in (Get-Item "HKCR:\CLSID\$cpClassID" -ErrorAction SilentlyContinue)) 
			{
				$rootDefault = Get-ItemProperty -Path "HKCR:\CLSID\$cpClassID" -Name '(Default)' -ErrorAction SilentlyContinue
				If ($rootDefault -match 'Avecto') 
				{
					Remove-RegistryKey -Key "HKCR:\CLSID\$cpClassID" -Recurse
					Remove-RegistryKey -Key "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\$cpClassID" -Recurse
				}
			}
		}

		If ($ForceUninstallPreviousVersions) 
		{
			ForceUninstallDefendpoint
		}

		## Display a restart prompt (if required).
		If ($ShowRestartPrompt) 
		{
			If ($RestartCountDownSeconds -ne 0) 
			{
				Show-InstallationRestartPrompt -CountDownSeconds $RestartCountDownSeconds -CountdownNoHideSeconds 1800
			} 
			Else 
			{
				Show-InstallationRestartPrompt -NoCountdown
			}
		}
	}

	##*===============================================
	##* END SCRIPT BODY
	##*===============================================
	
	## Call the Exit-Script function to perform final cleanup operations.
	Exit-Script -ExitCode $mainExitCode
}
Catch 
{
	[int32]$mainExitCode = 60001
	[string]$mainErrorMessage = "$(Resolve-Error)"
	Write-Log -Message $mainErrorMessage -Severity 3 -Source $deployAppScriptFriendlyName
	Show-DialogBox -Text $mainErrorMessage -Icon 'Stop'
	Exit-Script -ExitCode $mainExitCode
}