<#
.SYNOPSIS
    Deploys a WLAN profile from an XML file.

.DESCRIPTION
    Adds a Wi-Fi profile to the local computer using a provided XML file.
    Handles error cases such as missing/malformed XML, profile already existing,
    and unknown failures.

.PARAMETER XmlPath
    Path to the WLAN profile XML file.

.EXAMPLE
    .\Deploy-WlanProfile.ps1 -XmlPath "C:\Temp\MyWiFi.xml"
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$XmlPath
)

function Write-Status {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    Write-Output "[$Level] $Message"
}

# --- Validate the XML file exists ---
if (-not (Test-Path -Path $XmlPath)) {
    Write-Status "The XML profile file '$XmlPath' was not found." "ERROR"
    exit 1
}

# --- Validate the XML is well-formed ---
try {
    [xml]$profileXml = Get-Content -Path $XmlPath -ErrorAction Stop
} catch {
    Write-Status "The XML profile file '$XmlPath' is malformed or unreadable." "ERROR"
    exit 2
}

# --- Extract profile name for validation ---
$profileName = $null
try {
    $profileName = $profileXml.WLANProfile.name
} catch {
    Write-Status "Unable to read WLAN profile name from XML." "ERROR"
    exit 3
}

if (-not $profileName) {
    Write-Status "The XML does not contain a valid WLAN profile name." "ERROR"
    exit 4
}

# --- Check if the profile already exists ---
$existingProfiles = netsh wlan show profiles | Select-String "All User Profile"
if ($existingProfiles -match $profileName) {
    Write-Status "Profile '$profileName' already exists. No action taken." "INFO"
    exit 0
}

# --- Try adding the profile ---
try {
    $process = Start-Process -FilePath "netsh.exe" `
                             -ArgumentList "wlan add profile filename=`"$XmlPath`" user=all" `
                             -NoNewWindow -Wait -PassThru -ErrorAction Stop

    if ($process.ExitCode -eq 0) {
        Write-Status "Successfully added WLAN profile '$profileName'." "SUCCESS"
        exit 0
    } else {
        Write-Status "Failed to add WLAN profile '$profileName'. Exit code: $($process.ExitCode)" "ERROR"
        exit 5
    }
} catch {
    Write-Status "An unknown error occurred while adding WLAN profile '$profileName'. $_" "ERROR"
    exit 6
}
