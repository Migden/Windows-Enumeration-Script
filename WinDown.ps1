<#

.SYNOPSIS
    Windows Enumeration Script based on OSCP Study


.NOTES
    Author: Migwe101
    RIP S.H


#>


# Start of Globals

$global:ProgramBanner = @"
  _      ___      ___                    
 | | /| / (_)__  / _ \___ _    _____     
 | |/ |/ / / _ \/ // / _ \ |/|/ / _ \    
 |__/|__/_/_//_/____/\___/__,__/_//_/    
 ____________________________________    
/___/___/___/___/___/___/___/___/___/    

    Author: Migwe101
    Script for use in authorized systems only
    Author is not responsible for any damage caused
    by missue


"@

$global:PathsToSearch = @(
	'C:\Users'
	'C:\inetpub'
	'C:\temp'
	'C:\xampp'
)
# End of Globals

function PrintLineStart {
	param (
		[string]$StringToPrint
	)

	Write-Host ("=" * 20)($StringToPrint)("=" * 20)	 -ForegroundColor Blue
}

function PrintLineFinish {
	param (
		[string]$StringPrinted
	)

	Write-Host ("=" * 20)("=" * $StringPrinted.Length)("=" * 20) -ForegroundColor Blue
	}

function ReturnPath {
    param(
        [string]$Path
    
    )
    if ($Path -match '([A-Za-z]:\\(?:[^\\\r\n]+\\)*[^\\\r\n]+\.exe)') {
        $Path = $matches[1]
        return $Path
    }
    return $false
}


function ServicePathVulnerable {
    param (
        [string]$Path
    
    )
    $Path = ReturnPath($Path)
        if ($Path -ne $false){
            if ($Path -match " ") {
                if (($Path -like "'*") -or ($Path -like '"*')) {
                    return $false
                } else {
                    return $true
                }
            } else {
                return $false
            }
        } else {
            return $false
        }
}


function GetHostname {
	$results = try { hostname } catch {Write-Error "Error Occurred When Executing command"}
	return $results
	}

function GetProcesses {
	$results = try { Get-Process | Select-Object Name } catch {Write-Error "Error Occurred When Executing command"}
	return $results
	}

function CurrentUserInfo {
	$results = try { whoami -all } catch {Write-Error "Error Occurred When Executing command"}
	return $results
	}


function LocalGroup {
	$results = try { Get-LocalGroup | Select-Object -Property Name } catch {Write-Error "Error Occurred When Executing command"}
	return $results
	}

function LocalUser {
	$results = try { Get-Localuser | Select-Object -Property Name } catch {Write-Error "Error Occurred When Executing command"}
	return $results
	}


function InterestingFiles {
	$results = try { Get-ChildItem -Path C:\ -Include *.kdbx, *.txt, *.ini, toml-3.8.3.jar, *.log, local.txt, proof.txt, flag.txt, *.rsa -File -Recurse -ErrorAction SilentlyContinue | Select-string -Pattern 'password','passwd','pwd', 'pass', 'NTLM', 'Ticket' -SimpleMatch | Select-Object Path,Line } catch {Write-Error "Error Occurred When Executing command"}
	return $results
	}


function RootDirectoryDirectories {
	$results = try { dir C:\ } catch {Write-Error "Error Occurred When Executing command"}
	return $results
	}

function GetPorts {
	$results = try { netstat -an | Select-String "LISTEN" } catch {Write-Error "Error Occurred When Executing command"}
	return $results
}

function GetNetworkAdapters {
	$results = try { get-netadapter | Select-Object Name,InterfaceDescription } catch {Write-Error "Error Occurred When Executing command"}
	return $results
}

function InstalledApplications {
	$results = try { Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object displayname,installlocation } catch {Write-Error "Error Occurred When Executing command"}
	return $results 
}

function GetPowershellHistory {
    $results = try { Get-History } catch {Write-Error "Error Occurred When Executing command"}
    return $results
}

function GetPowershellConsoleHistory {
    $HistoryPath = try { (Get-PSReadLineOption).HistorySavePath } catch {Write-Error "Error Occurred When Executing command"}
    $results =  try { Get-Content $HistoryPath } catch {Write-Error "Error Occurred When Executing command"}
    return $results
}


function GetServiceBinaries {
    $results = try { Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'} } catch {Write-Error "Error Occurred When Executing command"}
    # This Functionality Does not work, Need to fix later
	PrintLineStart("Potentially Vulnreable Service Binaries (Path Hijacking)")
    foreach ($i in $results) {
        if (ServicePathVulnerable($i.PathName)) {
            $ToPrint = $i | select-object Name,PathName
            Write-Host $ToPrint -ForegroundColor Green
        }
    }
    PrintLineFinish("Potentially Vulnreable Service Binaries (Path Hijacking)")
    return $results
}

function ScheduledTasks {
    $results = Get-ScheduledTasks
    return $results
}

function WindowsSysInfo {
    $results = systeminfo
    return $results
}

function GetSecurityPatches {
    $results = Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }
    return $results
}

function WinEnumMain {
	$EnumerationItemsHash = @{
		"Current User Information" = { CurrentUserInfo }
		"System Hostname" = { GetHostname }
		"Running Processes" = { GetProcesses } 
		"Local Groups" = { LocalGroup }
		"Local Users" = { LocalUser }
		"Interesting Files" = { InterestingFiles }
		"Root Directory Contents" = { RootDirectoryDirectories }
		"Open Ports" = { GetPorts }
		"Network Adapters" = { GetNetworkAdapters }
		"Installed Applications" = { InstalledApplications }
        "Powershell History" = { GetPowershellHistory }
        "Powershell Console History" = { GetPowershellConsoleHistory }
        "Running Service Binaries" = { GetServiceBinaries }
        "Scheduled Tasks on the System" = { ScheduledTasks }
        "Windows System Version " = { WindowsSysInfo }
        "Installed Security Patches" = { GetSecurityPatches }

	}
    Write-Host $global:ProgramBanner -ForegroundColor DarkBlue
    Write-Host "====================================================================" -ForegroundColor DarkGreen
	# Start of the results
	foreach ($key in $EnumerationItemsHash.Keys) {
		PrintLineStart($key)
        $block = & $EnumerationItemsHash[$key]
        Write-Output $block | Format-Table -AutoSize
		PrintLineFinish($key)
		}
    Write-Host "====================================================================" -ForegroundColor DarkGreen
	}

WinEnumMain
