<#
.SYNOPSIS
    MeshCentral Azure Trusted Signing Automation Script

.DESCRIPTION
    Automates downloading MeshCentral agents for all device groups and signing them with Azure Trusted Signing.
    Tracks agent versions via GitHub API to avoid unnecessary downloads.
    Supports modular execution: download-only, sign-only, or both.

.PARAMETER Download
    Download agents only (skip signing)

.PARAMETER Sign
    Sign existing agents only (skip download)

.PARAMETER SkipAgeCheck
    Force download all agents regardless of version age

.PARAMETER Help
    Display help information

.EXAMPLE
    irm https://raw.githubusercontent.com/Matt-CyberGuy/MeshAzureSign/main/MeshSigning.ps1 | iex

.EXAMPLE
    .\MeshSigning.ps1
    Run full workflow (download + sign)

.EXAMPLE
    .\MeshSigning.ps1 -Download
    Download agents only

.EXAMPLE
    .\MeshSigning.ps1 -Sign
    Sign existing agents only

.EXAMPLE
    .\MeshSigning.ps1 -SkipAgeCheck
    Force re-download all agents

.NOTES
    Author: Matt (CyberGuy)
    Repository: https://github.com/Matt-CyberGuy/MeshAzureSign
    License: MIT
    Version: 1.0.4
#>

[CmdletBinding(DefaultParameterSetName='All')]
param(
    [Parameter(ParameterSetName='DownloadOnly')]
    [switch]$Download,
    
    [Parameter(ParameterSetName='SignOnly')]
    [switch]$Sign,
    
    [Parameter()]
    [switch]$SkipAgeCheck,
    
    [Parameter()]
    [switch]$Help
)

#Requires -Version 5.1

# ================================
# SCRIPT VERSION
# ================================
$SCRIPT_VERSION = "1.0.4"

# ================================
# GLOBAL CONFIGURATION
# ================================

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# Repository Configuration
$REPO_BASE_URL = "https://raw.githubusercontent.com/Matt-CyberGuy/MeshAzureSign/main"
$MESHCENTRAL_REPO_API = "https://api.github.com/repos/Ylianst/MeshCentral/releases/latest"

# Directory Structure
$BASE_DIR = "C:\MeshSigning"
$MESHCTRL_DIR = "$BASE_DIR\meshctrl"
$AGENTS_DIR = "$BASE_DIR\Agents"
$LOGS_DIR = "$BASE_DIR\Logs"
$CONFIG_DIR = "$BASE_DIR\Config"
$TOOLS_DIR = "$BASE_DIR\Tools"

# Tool Paths
$SIGNTOOL_PATH = "$TOOLS_DIR\signtool.exe"
$TOOLS_X64_DIR = "$TOOLS_DIR\x64"
$DLIB_PATH = "$TOOLS_X64_DIR\Azure.CodeSigning.Dlib.dll"
$MESHCTRL_JS_PATH = "$MESHCTRL_DIR\node_modules\meshcentral\meshctrl.js"

# Configuration Files
$CONFIG_FILE = "$CONFIG_DIR\config.json"
$METADATA_FILE = "$CONFIG_DIR\metadata.json"
$CREDENTIALS_FILE = "$CONFIG_DIR\credentials.json"
$AGENT_AGE_FILE = "$CONFIG_DIR\agent-age.txt"

# Timestamp Server
$TIMESTAMP_SERVER = "http://timestamp.acs.microsoft.com"

# Architecture Mapping
$ARCHITECTURES = @{
    'x86'   = @{ Code = '3';  Label = 'x86' }
    'x64'   = @{ Code = '4';  Label = 'x64' }
    'ARM64' = @{ Code = '30'; Label = 'ARM64' }
}

# Logging
$DATE_STAMP = Get-Date -Format "yyyy-MM-dd"
$DETAILED_LOG = "$LOGS_DIR\MeshSigning_Detailed_$DATE_STAMP.txt"
$EXECUTIVE_LOG = "$LOGS_DIR\MeshSigning_Executive_$DATE_STAMP.txt"

# Statistics
$Script:Stats = @{
    GroupsProcessed   = 0
    AgentsDownloaded  = 0
    AgentsSigned      = 0
    AgentsSkipped     = 0
    Errors            = 0
}

# ================================
# HELP FUNCTION
# ================================

function Show-Help {
    $helpText = @"

╔═══════════════════════════════════════════════════════════════════════╗
║                  MESHCENTRAL AZURE SIGNING TOOL                       ║
║                     https://github.com/Matt-CyberGuy/MeshAzureSign    ║
╚═══════════════════════════════════════════════════════════════════════╝

DESCRIPTION:
    Automates downloading MeshCentral agents for all device groups and 
    signing them with Azure Trusted Signing.

USAGE:
    .\MeshSigning.ps1 [PARAMETERS]

PARAMETERS:
    -Download       Download agents only (skip signing)
    -Sign           Sign existing agents only (skip download)
    -SkipAgeCheck   Force re-download all agents regardless of version
    -Help           Display this help information

EXAMPLES:
    # Full workflow (download + sign)
    .\MeshSigning.ps1

    # Download only
    .\MeshSigning.ps1 -Download

    # Sign only
    .\MeshSigning.ps1 -Sign

    # Force re-download
    .\MeshSigning.ps1 -SkipAgeCheck

ONE-LINE INSTALLER:
    irm https://raw.githubusercontent.com/Matt-CyberGuy/MeshAzureSign/main/MeshSigning.ps1 | iex

FIRST-TIME SETUP:
    The script will automatically:
    - Install Node.js if not present (via winget, Chocolatey, or direct download)
    - Create directory structure under C:\MeshSigning\
    - Download required dependencies (SignTool, Azure DLL, npm modules)
    - Prompt for configuration values
    - Store credentials securely

REQUIREMENTS:
    - Windows 10/11 or Windows Server 2016+
    - Internet connection
    - Azure Trusted Signing account
    - Administrator privileges (for Node.js installation if needed)

DIRECTORY STRUCTURE:
    C:\MeshSigning\
    ├── Agents\          Downloaded MeshCentral agents
    ├── Config\          Configuration and credentials
    ├── Logs\            Detailed and executive logs
    ├── meshctrl\        MeshCentral control module
    └── Tools\           SignTool and Azure DLL

"@
    Write-Host $helpText -ForegroundColor Cyan
    exit 0
}

if ($Help) {
    Show-Help
}

# ================================
# LOGGING FUNCTIONS
# ================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR', 'CRITICAL')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colorMap = @{
        'INFO'     = 'White'
        'SUCCESS'  = 'Green'
        'WARNING'  = 'Yellow'
        'ERROR'    = 'Red'
        'CRITICAL' = 'Magenta'
    }
    
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
    
    if (Test-Path $LOGS_DIR) {
        Add-Content -Path $DETAILED_LOG -Value $logEntry -ErrorAction SilentlyContinue
    }
}

function Add-ExecutiveEntry {
    param(
        [string]$FileName,
        [string]$Hash,
        [string]$Status,
        [string]$Action
    )
    
    $abbrevHash = if ($Hash -and $Hash.Length -ge 8) { $Hash.Substring(0, 8) } else { "N/A     " }
    $entry = "{0,-50} | {1,-10} | {2,-15} | {3,-10}" -f $FileName, $abbrevHash, $Status, $Action
    
    if (Test-Path $LOGS_DIR) {
        Add-Content -Path $EXECUTIVE_LOG -Value $entry -ErrorAction SilentlyContinue
    }
}

function Wait-ForUser {
    <#
    .SYNOPSIS
    Pauses script execution to allow user to read output before window closes.
    Works in both interactive and non-interactive PowerShell sessions.
    #>
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  SCRIPT PAUSED - READ OUTPUT ABOVE" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    # Force output buffer flush
    [Console]::Out.Flush()
    
    # Use Read-Host which is the most reliable blocking method
    # It will wait indefinitely until user presses ENTER
    try {
        Write-Host "Press ENTER to exit..." -ForegroundColor Yellow
        $null = Read-Host
    } catch {
        # If Read-Host fails (unlikely), use a very long sleep
        Write-Host "Waiting 300 seconds (5 minutes) for you to read the output..." -ForegroundColor Yellow
        Write-Host "You can close this window manually if needed." -ForegroundColor Gray
        Start-Sleep -Seconds 300
    }
}

# ================================
# INITIALIZATION FUNCTIONS
# ================================

function Initialize-Directories {
    Write-Log "Creating directory structure..." -Level INFO
    
    $directories = @(
        $BASE_DIR,
        $MESHCTRL_DIR,
        $AGENTS_DIR,
        $LOGS_DIR,
        $CONFIG_DIR,
        $TOOLS_DIR,
        $TOOLS_X64_DIR
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Log "Created: $dir" -Level SUCCESS
        }
    }
}

function Initialize-LogFiles {
    $header = @"
========================================
MESHCENTRAL AGENT SIGNING - EXECUTIVE SUMMARY
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
========================================

{0,-50} | {1,-10} | {2,-15} | {3,-10}
"@ -f "EXECUTABLE", "HASH", "STATUS", "ACTION"
    
    $separator = "{0,-50} | {1,-10} | {2,-15} | {3,-10}" -f ("-" * 50), ("-" * 10), ("-" * 15), ("-" * 10)
    
    Set-Content -Path $EXECUTIVE_LOG -Value $header -ErrorAction SilentlyContinue
    Add-Content -Path $EXECUTIVE_LOG -Value $separator -ErrorAction SilentlyContinue
}

function Install-NodeJs {
    <#
    .SYNOPSIS
    Automatically installs Node.js using the best available method.
    #>
    Write-Log "Attempting to install Node.js automatically..." -Level INFO
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INSTALLING NODE.JS" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    # Method 1: Try winget (Windows 11/10 with App Installer)
    Write-Log "Trying winget (Windows Package Manager)..." -Level INFO
    try {
        $wingetPath = Get-Command winget -ErrorAction SilentlyContinue
        if ($wingetPath) {
            Write-Log "Found winget, installing Node.js..." -Level INFO
            Write-Host "Installing Node.js via winget (this may take a few minutes)..." -ForegroundColor Yellow
            
            $process = Start-Process -FilePath "winget" -ArgumentList "install", "OpenJS.NodeJS.LTS", "--silent", "--accept-package-agreements", "--accept-source-agreements" -Wait -PassThru -NoNewWindow
            
            if ($process.ExitCode -eq 0) {
                Write-Log "Node.js installed successfully via winget" -Level SUCCESS
                Write-Host "Node.js installed successfully!" -ForegroundColor Green
                Write-Host ""
                
                # Refresh PATH environment variable
                Write-Log "Refreshing PATH environment variable..." -Level INFO
                $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
                
                # Wait a moment for PATH to propagate
                Start-Sleep -Seconds 2
                
                # Verify installation
                try {
                    $nodeVersion = & node --version 2>&1
                    if ($LASTEXITCODE -eq 0 -and $nodeVersion) {
                        Write-Log "Node.js verified: $nodeVersion" -Level SUCCESS
                        return $true
                    }
                } catch {
                    Write-Log "Node.js installed but not yet available in PATH. Please restart PowerShell." -Level WARNING
                    Write-Host "Node.js has been installed, but you may need to restart PowerShell for it to be available." -ForegroundColor Yellow
                    Write-Host "Please close this window, open a new PowerShell window, and run the script again." -ForegroundColor Yellow
                    return $false
                }
            } else {
                Write-Log "winget installation failed with exit code: $($process.ExitCode)" -Level WARNING
            }
        }
    } catch {
        Write-Log "winget not available: $($_.Exception.Message)" -Level WARNING
    }
    
    # Method 2: Try Chocolatey
    Write-Log "Trying Chocolatey..." -Level INFO
    try {
        $chocoPath = Get-Command choco -ErrorAction SilentlyContinue
        if ($chocoPath) {
            Write-Log "Found Chocolatey, installing Node.js..." -Level INFO
            Write-Host "Installing Node.js via Chocolatey (this may take a few minutes)..." -ForegroundColor Yellow
            
            $process = Start-Process -FilePath "choco" -ArgumentList "install", "nodejs-lts", "-y" -Wait -PassThru -NoNewWindow -Verb RunAs
            
            if ($process.ExitCode -eq 0) {
                Write-Log "Node.js installed successfully via Chocolatey" -Level SUCCESS
                Write-Host "Node.js installed successfully!" -ForegroundColor Green
                Write-Host ""
                
                # Refresh PATH
                $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
                Start-Sleep -Seconds 2
                
                # Verify installation
                try {
                    $nodeVersion = & node --version 2>&1
                    if ($LASTEXITCODE -eq 0 -and $nodeVersion) {
                        Write-Log "Node.js verified: $nodeVersion" -Level SUCCESS
                        return $true
                    }
                } catch {
                    Write-Log "Node.js installed but not yet available in PATH. Please restart PowerShell." -Level WARNING
                    Write-Host "Node.js has been installed, but you may need to restart PowerShell for it to be available." -ForegroundColor Yellow
                    return $false
                }
            }
        }
    } catch {
        Write-Log "Chocolatey not available: $($_.Exception.Message)" -Level WARNING
    }
    
    # Method 3: Direct download and install MSI
    Write-Log "Trying direct download and install..." -Level INFO
    try {
        Write-Host "Downloading Node.js installer..." -ForegroundColor Yellow
        
        # Get latest LTS version download URL
        $nodeUrl = "https://nodejs.org/dist/v20.18.0/node-v20.18.0-x64.msi"
        $installerPath = "$env:TEMP\nodejs-installer.msi"
        
        Invoke-WebRequest -Uri $nodeUrl -OutFile $installerPath -UseBasicParsing
        
        Write-Host "Installing Node.js (this may take a few minutes)..." -ForegroundColor Yellow
        Write-Host "Please wait..." -ForegroundColor Gray
        
        # Install silently
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", "`"$installerPath`"", "/quiet", "/norestart" -Wait -PassThru -NoNewWindow
        
        # Clean up installer
        Remove-Item $installerPath -ErrorAction SilentlyContinue
        
        if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
            Write-Log "Node.js installed successfully via MSI" -Level SUCCESS
            Write-Host "Node.js installed successfully!" -ForegroundColor Green
            Write-Host ""
            
            # Refresh PATH
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
            Start-Sleep -Seconds 3
            
            # Verify installation
            try {
                $nodeVersion = & node --version 2>&1
                if ($LASTEXITCODE -eq 0 -and $nodeVersion) {
                    Write-Log "Node.js verified: $nodeVersion" -Level SUCCESS
                    return $true
                }
            } catch {
                Write-Log "Node.js installed but not yet available in PATH. Please restart PowerShell." -Level WARNING
                Write-Host "Node.js has been installed, but you may need to restart PowerShell for it to be available." -ForegroundColor Yellow
                return $false
            }
        } else {
            Write-Log "MSI installation failed with exit code: $($process.ExitCode)" -Level ERROR
        }
    } catch {
        Write-Log "Direct download/install failed: $($_.Exception.Message)" -Level ERROR
    }
    
    # If all methods failed
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host "  AUTOMATIC INSTALLATION FAILED" -ForegroundColor Red
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host ""
    Write-Host "Could not automatically install Node.js." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please install Node.js manually from:" -ForegroundColor Yellow
    Write-Host "  https://nodejs.org/" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "After installation, restart PowerShell and run this script again." -ForegroundColor Yellow
    Write-Host ""
    
    return $false
}

function Test-NodeJs {
    Write-Log "Checking for Node.js..." -Level INFO
    
    try {
        $nodeVersion = & node --version 2>&1
        if ($LASTEXITCODE -eq 0 -and $nodeVersion) {
            Write-Log "Node.js found: $nodeVersion" -Level SUCCESS
            return $true
        }
    } catch {
        # Node.js not found
    }
    
    Write-Log "Node.js not found!" -Level WARNING
    Write-Host ""
    Write-Host "Node.js is not installed. Attempting automatic installation..." -ForegroundColor Yellow
    Write-Host ""
    
    # Try to install automatically
    $installSuccess = Install-NodeJs
    
    if ($installSuccess) {
        # Verify one more time after installation
        try {
            $nodeVersion = & node --version 2>&1
            if ($LASTEXITCODE -eq 0 -and $nodeVersion) {
                Write-Log "Node.js verified after installation: $nodeVersion" -Level SUCCESS
                return $true
            }
        } catch {
            # Still not available, but installed
        }
    }
    
    # If installation failed or Node.js still not available
    throw "Node.js is required but could not be installed automatically. Please install manually from https://nodejs.org/"
}

function Install-Dependencies {
    Write-Log "Checking dependencies..." -Level INFO
    
    # Download SignTool
    if (-not (Test-Path $SIGNTOOL_PATH)) {
        Write-Log "Downloading SignTool.exe..." -Level INFO
        try {
            Invoke-WebRequest -Uri "$REPO_BASE_URL/dependencies/signtool.exe" -OutFile $SIGNTOOL_PATH -UseBasicParsing
            Write-Log "SignTool downloaded successfully" -Level SUCCESS
        } catch {
            Write-Log "Failed to download SignTool: $($_.Exception.Message)" -Level CRITICAL
            throw "Failed to download SignTool"
        }
    } else {
        Write-Log "SignTool already exists" -Level SUCCESS
    }
    
    # Download Azure CodeSigning DLLs and dependencies
    Write-Log "Checking Azure CodeSigning dependencies..." -Level INFO
    
    # List of all required DLL files in x64 folder
    $azureDlls = @(
        'Azure.CodeSigning.Dlib.Core.dll',
        'Azure.CodeSigning.Dlib.dll',
        'Azure.CodeSigning.Dlib.runtimeconfig.json',
        'Azure.CodeSigning.dll',
        'Azure.Core.dll',
        'Azure.Identity.dll',
        'concrt140.dll',
        'Ijwhost.dll',
        'mfc140.dll',
        'mfc140chs.dll',
        'mfc140cht.dll',
        'mfc140deu.dll',
        'mfc140enu.dll',
        'mfc140esn.dll',
        'mfc140fra.dll',
        'mfc140ita.dll',
        'mfc140jpn.dll',
        'mfc140kor.dll',
        'mfc140rus.dll',
        'mfc140u.dll',
        'mfcm140.dll',
        'mfcm140u.dll',
        'Microsoft.Extensions.DependencyInjection.Abstractions.dll',
        'Microsoft.Extensions.Logging.Abstractions.dll',
        'Microsoft.Identity.Client.dll',
        'Microsoft.Identity.Client.Extensions.Msal.dll',
        'Microsoft.IdentityModel.Abstractions.dll',
        'msvcp140_1.dll',
        'msvcp140_2.dll',
        'msvcp140_atomic_wait.dll',
        'msvcp140_codecvt_ids.dll',
        'msvcp140.dll',
        'System.ClientModel.dll',
        'System.Memory.Data.dll',
        'System.Security.Cryptography.ProtectedData.dll',
        'vcamp140.dll',
        'vccorlib140.dll',
        'vcomp140.dll',
        'vcruntime140_1.dll',
        'vcruntime140_threads.dll',
        'vcruntime140.dll'
    )
    
    $missingDlls = @()
    foreach ($dll in $azureDlls) {
        $dllPath = Join-Path $TOOLS_X64_DIR $dll
        if (-not (Test-Path $dllPath)) {
            $missingDlls += $dll
        }
    }
    
    if ($missingDlls.Count -gt 0) {
        Write-Log "Downloading $($missingDlls.Count) Azure CodeSigning dependency file(s)..." -Level INFO
        $downloadedCount = 0
        $failedCount = 0
        
        foreach ($dll in $missingDlls) {
            try {
                $dllPath = Join-Path $TOOLS_X64_DIR $dll
                $dllUrl = "$REPO_BASE_URL/dependencies/x64/$dll"
                Write-Log "Downloading $dll..." -Level INFO
                Invoke-WebRequest -Uri $dllUrl -OutFile $dllPath -UseBasicParsing -ErrorAction Stop
                $downloadedCount++
            } catch {
                Write-Log "Failed to download $dll : $($_.Exception.Message)" -Level ERROR
                $failedCount++
            }
        }
        
        if ($failedCount -gt 0) {
            Write-Log "Failed to download $failedCount file(s). Some dependencies may be missing." -Level WARNING
        }
        
        if ($downloadedCount -gt 0) {
            Write-Log "Successfully downloaded $downloadedCount Azure CodeSigning dependency file(s)" -Level SUCCESS
        }
        
        # Verify main DLL exists
        if (-not (Test-Path $DLIB_PATH)) {
            Write-Log "Critical: Azure.CodeSigning.Dlib.dll not found after download" -Level CRITICAL
            throw "Failed to download Azure.CodeSigning.Dlib.dll"
        }
    } else {
        Write-Log "All Azure CodeSigning dependencies already exist" -Level SUCCESS
    }
    
    # Install npm dependencies (minimist and ws)
    $nodeModulesPath = "$MESHCTRL_DIR\node_modules"
    if (-not (Test-Path "$nodeModulesPath\minimist") -or -not (Test-Path "$nodeModulesPath\ws")) {
        Write-Log "Installing npm dependencies (minimist, ws)..." -Level INFO
        Push-Location $MESHCTRL_DIR
        try {
            npm install minimist ws 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "npm dependencies installed successfully" -Level SUCCESS
            } else {
                throw "npm install failed"
            }
        } catch {
            Write-Log "Failed to install npm dependencies: $($_.Exception.Message)" -Level ERROR
            throw
        } finally {
            Pop-Location
        }
    } else {
        Write-Log "npm dependencies already installed" -Level SUCCESS
    }
    
    # Install MeshCentral package
    if (-not (Test-Path $MESHCTRL_JS_PATH)) {
        Write-Log "Installing MeshCentral package..." -Level INFO
        Push-Location $MESHCTRL_DIR
        try {
            npm install meshcentral 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "MeshCentral package installed successfully" -Level SUCCESS
            } else {
                throw "MeshCentral installation failed"
            }
        } finally {
            Pop-Location
        }
    } else {
        Write-Log "MeshCentral package already installed" -Level SUCCESS
    }
}

# ================================
# CONFIGURATION FUNCTIONS
# ================================

function Get-SecureInput {
    param(
        [string]$Prompt,
        [switch]$IsSecret
    )
    
    if ($IsSecret) {
        $secureString = Read-Host $Prompt -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
        $plainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        return $plainText
    } else {
        return Read-Host $Prompt
    }
}

function Initialize-Configuration {
    Write-Log "Checking configuration files..." -Level INFO
    
    # Create config.json if missing
    if (-not (Test-Path $CONFIG_FILE)) {
        Write-Log "Creating default config.json..." -Level INFO
        $configData = @{
            settings = @{
                agentSignLock = $true
                agentTimeStampServer = $TIMESTAMP_SERVER
            }
        }
        $configData | ConvertTo-Json -Depth 10 | Set-Content $CONFIG_FILE -Encoding UTF8
        Write-Log "config.json created" -Level SUCCESS
    }
    
    # Check for metadata.json
    if (-not (Test-Path $METADATA_FILE)) {
        Write-Log "metadata.json not found. Configuration required." -Level WARNING
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  AZURE TRUSTED SIGNING CONFIGURATION" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        
        $endpoint = Get-SecureInput -Prompt "Azure Endpoint (e.g., https://eus.codesigning.azure.net/)"
        $accountName = Get-SecureInput -Prompt "Code Signing Account Name"
        $profileName = Get-SecureInput -Prompt "Certificate Profile Name"
        
        $metadataData = @{
            Endpoint = $endpoint
            CodeSigningAccountName = $accountName
            CertificateProfileName = $profileName
        }
        
        # Save metadata.json without BOM (UTF-8 without Byte Order Mark)
        # This is critical - BOM causes JSON parsing errors in Azure DLL
        $jsonContent = $metadataData | ConvertTo-Json -Depth 10
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($METADATA_FILE, $jsonContent, $utf8NoBom)
        Write-Log "metadata.json created (UTF-8 without BOM)" -Level SUCCESS
    } else {
        # Fix existing metadata.json if it has BOM - re-save without BOM
        try {
            $content = Get-Content -Path $METADATA_FILE -Raw
            $utf8NoBom = New-Object System.Text.UTF8Encoding $false
            [System.IO.File]::WriteAllText($METADATA_FILE, $content, $utf8NoBom)
            Write-Log "metadata.json verified/updated (UTF-8 without BOM)" -Level INFO
        } catch {
            Write-Log "Could not update metadata.json encoding: $($_.Exception.Message)" -Level WARNING
        }
    }
    
    # Check for credentials.json
    if (-not (Test-Path $CREDENTIALS_FILE)) {
        Write-Log "credentials.json not found. Configuration required." -Level WARNING
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  CREDENTIALS CONFIGURATION" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        
        Write-Host "MeshCentral Configuration:" -ForegroundColor Yellow
        $meshServer = Get-SecureInput -Prompt "MeshCentral Server URL (e.g., wss://remote.example.com)"
        $meshUser = Get-SecureInput -Prompt "MeshCentral Login Username"
        $meshKey = Get-SecureInput -Prompt "MeshCentral Login Key" -IsSecret
        
        Write-Host ""
        Write-Host "Azure Configuration:" -ForegroundColor Yellow
        $azureClientId = Get-SecureInput -Prompt "Azure Client ID"
        $azureTenantId = Get-SecureInput -Prompt "Azure Tenant ID"
        $azureSecret = Get-SecureInput -Prompt "Azure Client Secret" -IsSecret
        
        $credentialsData = @{
            MeshCentral = @{
                ServerURL = $meshServer
                LoginUser = $meshUser
                LoginKey = $meshKey
            }
            Azure = @{
                ClientID = $azureClientId
                TenantID = $azureTenantId
                ClientSecret = $azureSecret
            }
        }
        
        $credentialsData | ConvertTo-Json -Depth 10 | Set-Content $CREDENTIALS_FILE -Encoding UTF8
        Write-Log "credentials.json created" -Level SUCCESS
        
        Write-Host ""
        Write-Host "Configuration saved successfully!" -ForegroundColor Green
        Write-Host "Credentials stored in: $CREDENTIALS_FILE" -ForegroundColor Yellow
        Write-Host ""
    }
}

function Load-Configuration {
    Write-Log "Loading configuration..." -Level INFO
    
    try {
        $creds = Get-Content $CREDENTIALS_FILE -Raw | ConvertFrom-Json
        
        $Script:MESHCENTRAL_SERVER = $creds.MeshCentral.ServerURL
        $Script:MESHCENTRAL_LOGIN_USER = $creds.MeshCentral.LoginUser
        $Script:MESHCENTRAL_LOGIN_KEY = $creds.MeshCentral.LoginKey
        $Script:AZURE_CLIENT_ID = $creds.Azure.ClientID
        $Script:AZURE_TENANT_ID = $creds.Azure.TenantID
        $Script:AZURE_CLIENT_SECRET = $creds.Azure.ClientSecret
        
        # Validate and fix MeshCentral server URL format - MUST be wss://
        if ($Script:MESHCENTRAL_SERVER -notmatch '^wss://') {
            Write-Log "MeshCentral server URL format issue detected" -Level WARNING
            Write-Host ""
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow
            Write-Host "  URL FORMAT WARNING" -ForegroundColor Yellow
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "MeshCentral server URL should start with 'wss://' not 'https://'" -ForegroundColor Yellow
            Write-Host "Current URL: $Script:MESHCENTRAL_SERVER" -ForegroundColor White
            Write-Host ""
            
            # Try to auto-fix if it's https://
            if ($Script:MESHCENTRAL_SERVER -match '^https://') {
                $fixedUrl = $Script:MESHCENTRAL_SERVER -replace '^https://', 'wss://'
                Write-Host "Auto-fixing to: $fixedUrl" -ForegroundColor Cyan
                $Script:MESHCENTRAL_SERVER = $fixedUrl
                
                # Update the credentials file with the fixed URL
                $creds.MeshCentral.ServerURL = $fixedUrl
                $creds | ConvertTo-Json -Depth 10 | Set-Content $CREDENTIALS_FILE -Encoding UTF8
                Write-Log "Updated credentials.json with corrected URL" -Level SUCCESS
                Write-Host "Credentials file updated. Continuing..." -ForegroundColor Green
                Write-Host ""
            } elseif ($Script:MESHCENTRAL_SERVER -match '^http://') {
                # Also handle http://
                $fixedUrl = $Script:MESHCENTRAL_SERVER -replace '^http://', 'wss://'
                Write-Host "Auto-fixing to: $fixedUrl" -ForegroundColor Cyan
                $Script:MESHCENTRAL_SERVER = $fixedUrl
                
                # Update the credentials file with the fixed URL
                $creds.MeshCentral.ServerURL = $fixedUrl
                $creds | ConvertTo-Json -Depth 10 | Set-Content $CREDENTIALS_FILE -Encoding UTF8
                Write-Log "Updated credentials.json with corrected URL" -Level SUCCESS
                Write-Host "Credentials file updated. Continuing..." -ForegroundColor Green
                Write-Host ""
            } else {
                throw "MeshCentral server URL must start with 'wss://'. Current URL: $Script:MESHCENTRAL_SERVER"
            }
        }
        
        # Double-check the URL is correct after fixing
        if ($Script:MESHCENTRAL_SERVER -notmatch '^wss://') {
            throw "URL validation failed. URL must be wss:// format. Current: $Script:MESHCENTRAL_SERVER"
        }
        
        Write-Log "Configuration loaded successfully" -Level SUCCESS
        return $true
    } catch {
        Write-Log "Failed to load configuration: $($_.Exception.Message)" -Level CRITICAL
        return $false
    }
}

# ================================
# AGENT AGE TRACKING FUNCTIONS
# ================================

function Get-MeshCentralLatestRelease {
    Write-Log "Checking MeshCentral latest release..." -Level INFO
    
    try {
        $response = Invoke-RestMethod -Uri $MESHCENTRAL_REPO_API -UseBasicParsing
        $releaseDate = [DateTime]::Parse($response.published_at)
        $version = $response.tag_name
        
        Write-Log "Latest MeshCentral release: $version (Published: $($releaseDate.ToString('yyyy-MM-dd')))" -Level INFO
        
        return @{
            Version = $version
            PublishedDate = $releaseDate.ToString('yyyy-MM-dd')
        }
    } catch {
        Write-Log "Failed to check GitHub release: $($_.Exception.Message)" -Level WARNING
        return $null
    }
}

function Test-AgentAge {
    if ($SkipAgeCheck) {
        Write-Log "Age check skipped (SkipAgeCheck parameter)" -Level WARNING
        return $false
    }
    
    $latestRelease = Get-MeshCentralLatestRelease
    if (-not $latestRelease) {
        Write-Log "Could not determine latest release. Proceeding with download." -Level WARNING
        return $false
    }
    
    if (Test-Path $AGENT_AGE_FILE) {
        try {
            $storedData = Get-Content $AGENT_AGE_FILE -Raw | ConvertFrom-Json
            
            if ($storedData.Version -eq $latestRelease.Version -and 
                $storedData.PublishedDate -eq $latestRelease.PublishedDate) {
                Write-Log "Agents are up-to-date (Version: $($latestRelease.Version))" -Level SUCCESS
                return $true
            } else {
                Write-Log "New MeshCentral release detected: $($latestRelease.Version)" -Level WARNING
                Write-Log "Stored: $($storedData.Version) | Latest: $($latestRelease.Version)" -Level INFO
                return $false
            }
        } catch {
            Write-Log "Failed to parse agent-age.txt. Will re-download." -Level WARNING
            return $false
        }
    } else {
        Write-Log "No agent age tracking file found. Will download." -Level INFO
        return $false
    }
}

function Update-AgentAge {
    $latestRelease = Get-MeshCentralLatestRelease
    if ($latestRelease) {
        $latestRelease | ConvertTo-Json | Set-Content $AGENT_AGE_FILE -Encoding UTF8
        Write-Log "Agent age tracking updated" -Level SUCCESS
    }
}

# ================================
# MESHCENTRAL FUNCTIONS
# ================================

function Get-MeshCentralGroups {
    Write-Log "Querying MeshCentral device groups..." -Level INFO
    
        # Validate URL format before using it - CRITICAL CHECK
        Write-Log "Validating MeshCentral server URL format..." -Level INFO
        if ($Script:MESHCENTRAL_SERVER -notmatch '^wss://') {
            Write-Log "Invalid MeshCentral URL format detected: $Script:MESHCENTRAL_SERVER" -Level ERROR
            Write-Host ""
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
            Write-Host "  URL FORMAT ERROR" -ForegroundColor Red
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
            Write-Host ""
            Write-Host "MeshCentral server URL must start with 'wss://' not 'https://' or 'http://'" -ForegroundColor Yellow
            Write-Host "Current URL: $Script:MESHCENTRAL_SERVER" -ForegroundColor White
            Write-Host ""
            
            # Try to auto-fix
            $fixedUrl = $null
            if ($Script:MESHCENTRAL_SERVER -match '^https://') {
                $fixedUrl = $Script:MESHCENTRAL_SERVER -replace '^https://', 'wss://'
            } elseif ($Script:MESHCENTRAL_SERVER -match '^http://') {
                $fixedUrl = $Script:MESHCENTRAL_SERVER -replace '^http://', 'wss://'
            }
            
            if ($fixedUrl) {
                Write-Host "Auto-fixing to: $fixedUrl" -ForegroundColor Cyan
                $Script:MESHCENTRAL_SERVER = $fixedUrl
                Write-Log "URL fixed to: $fixedUrl" -Level SUCCESS
                
                # Update credentials file
                try {
                    $creds = Get-Content $CREDENTIALS_FILE -Raw | ConvertFrom-Json
                    $creds.MeshCentral.ServerURL = $fixedUrl
                    $creds | ConvertTo-Json -Depth 10 | Set-Content $CREDENTIALS_FILE -Encoding UTF8
                    Write-Log "Updated credentials.json with corrected URL" -Level SUCCESS
                    Write-Host "Credentials file updated." -ForegroundColor Green
                } catch {
                    Write-Host "Warning: Could not update credentials file automatically." -ForegroundColor Yellow
                    Write-Log "Failed to update credentials file: $($_.Exception.Message)" -Level WARNING
                }
                Write-Host ""
            } else {
                throw "MeshCentral server URL must start with 'wss://'. Current URL: $Script:MESHCENTRAL_SERVER"
            }
        }
        
        # Final validation - ensure URL is correct
        if ($Script:MESHCENTRAL_SERVER -notmatch '^wss://') {
            throw "URL validation failed. URL must be wss:// format. Current: $Script:MESHCENTRAL_SERVER"
        }
        
        Write-Log "URL validated: $Script:MESHCENTRAL_SERVER" -Level SUCCESS
    
    # Initialize output variable so it's available in catch block
    $output = $null
    
    try {
        $meshctrlArgs = @(
            'listdevicegroups',
            '--json',
            '--loginkey', $Script:MESHCENTRAL_LOGIN_KEY,
            '--loginuser', $Script:MESHCENTRAL_LOGIN_USER,
            '--url', $Script:MESHCENTRAL_SERVER
        )
        
        Write-Log "Executing: node $MESHCTRL_JS_PATH listdevicegroups --json --loginkey [REDACTED] --loginuser $($Script:MESHCENTRAL_LOGIN_USER) --url $($Script:MESHCENTRAL_SERVER)" -Level INFO
        
        # Capture output (both stdout and stderr are merged with 2>&1)
        $output = & node $MESHCTRL_JS_PATH @meshctrlArgs 2>&1 | Out-String
        
        # Clean up the output - remove any leading/trailing whitespace
        $output = $output.Trim()
        
        # Always log the raw output for debugging (show full output, not truncated)
        $outputLength = if ($output) { $output.Length } else { 0 }
        Write-Log "MeshCtrl raw output length: $outputLength characters" -Level INFO
        if ($outputLength -gt 0) {
            Write-Host ""
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
            Write-Host "  MESHCENTRAL RESPONSE (for debugging)" -ForegroundColor Cyan
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
            Write-Host $output -ForegroundColor White
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
            Write-Host ""
        }
        
        # Check for common error messages in output
        if ($output -match "Invalid login|Invalid JSON|Error|Failed|Unauthorized|Authentication failed") {
            Write-Log "MeshCtrl returned an error message" -Level ERROR
            Write-Host ""
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
            Write-Host "  MESHCENTRAL CONNECTION ERROR" -ForegroundColor Red
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
            Write-Host ""
            Write-Host "MeshCtrl output:" -ForegroundColor Yellow
            Write-Host $output -ForegroundColor White
            Write-Host ""
            
            if ($output -match "Invalid login") {
                Write-Host "Possible causes:" -ForegroundColor Yellow
                Write-Host "  - Incorrect login key or username" -ForegroundColor White
                Write-Host "  - Login key has expired" -ForegroundColor White
                Write-Host "  - Server time is out of sync" -ForegroundColor White
                Write-Host "  - Login token feature not enabled on MeshCentral server" -ForegroundColor White
                Write-Host ""
            }
            
            throw "MeshCentral authentication failed. Check your credentials in $CREDENTIALS_FILE"
        }
        
        # Check if output is empty
        if ([string]::IsNullOrWhiteSpace($output)) {
            Write-Log "MeshCtrl returned empty output" -Level ERROR
            throw "MeshCentral returned empty response. Check server URL and credentials."
        }
        
        # Check if output looks like JSON (starts with [ or {)
        if (-not ($output.Trim().StartsWith('[') -or $output.Trim().StartsWith('{'))) {
            Write-Log "MeshCtrl output does not appear to be JSON" -Level ERROR
            Write-Host ""
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
            Write-Host "  MESHCENTRAL RESPONSE ERROR" -ForegroundColor Red
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
            Write-Host ""
            Write-Host "MeshCtrl returned non-JSON output:" -ForegroundColor Yellow
            Write-Host $output -ForegroundColor White
            Write-Host ""
            throw "MeshCentral returned invalid response. Output: $($output.Substring(0, [Math]::Min(200, $output.Length)))"
        }
        
        # Try to parse as JSON
        try {
            $groups = $output | ConvertFrom-Json
        } catch {
            Write-Log "Failed to parse MeshCtrl output as JSON: $($_.Exception.Message)" -Level ERROR
            Write-Host ""
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
            Write-Host "  JSON PARSING ERROR" -ForegroundColor Red
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
            Write-Host ""
            Write-Host "MeshCtrl output that failed to parse:" -ForegroundColor Yellow
            Write-Host $output -ForegroundColor White
            Write-Host ""
            throw "Failed to parse MeshCentral response as JSON: $($_.Exception.Message)"
        }
        
        # Validate we got an array
        if ($groups -isnot [Array]) {
            Write-Log "MeshCtrl returned non-array result" -Level ERROR
            throw "MeshCentral returned unexpected data format. Expected array of groups."
        }
        
        Write-Log "Successfully retrieved $($groups.Count) device groups" -Level SUCCESS
        return $groups
        
    } catch {
        Write-Log "Exception during MeshCentral query: $($_.Exception.Message)" -Level CRITICAL
        
        # If we have output captured, show it in the error
        if ($output) {
            Write-Host ""
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
            Write-Host "  MESHCENTRAL QUERY FAILED" -ForegroundColor Red
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
            Write-Host ""
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host ""
            Write-Host "MeshCtrl returned the following output:" -ForegroundColor Yellow
            Write-Host $output -ForegroundColor White
            Write-Host ""
            Write-Host "This output was not valid JSON or contained an error." -ForegroundColor Yellow
            Write-Host ""
            
            # Provide specific guidance based on common errors
            if ($output -match "Invalid login|Invalid JSON|Invalid") {
                Write-Host "Troubleshooting steps:" -ForegroundColor Cyan
                Write-Host "  1. Verify your MeshCentral server URL is correct" -ForegroundColor White
                Write-Host "  2. Check that your login key is valid (160 hex characters)" -ForegroundColor White
                Write-Host "  3. Ensure your username matches exactly" -ForegroundColor White
                Write-Host "  4. Verify login tokens are enabled on your MeshCentral server" -ForegroundColor White
                Write-Host "  5. Check that server time is synchronized" -ForegroundColor White
                Write-Host ""
                Write-Host "You can update credentials by editing:" -ForegroundColor Yellow
                Write-Host "  $CREDENTIALS_FILE" -ForegroundColor White
                Write-Host ""
            }
        }
        
        Write-Log "Full error details: $($_.Exception | Out-String)" -Level ERROR
        throw
    }
}

function Get-MeshAgent {
    param(
        [string]$MeshId,
        [string]$ArchCode,
        [string]$OutputPath
    )
    
    try {
        $downloadServer = $Script:MESHCENTRAL_SERVER -replace '^wss://', 'https://'
        
        Add-Type -AssemblyName System.Web
        $encodedMeshId = [System.Web.HttpUtility]::UrlEncode($MeshId)
        
        $downloadUrl = "$downloadServer/meshagents?id=$ArchCode&meshid=$encodedMeshId&installflags=0"
        
        Write-Log "Downloading from: $downloadUrl" -Level INFO
        
        Invoke-WebRequest -Uri $downloadUrl -OutFile $OutputPath -UseBasicParsing -TimeoutSec 60
        
        if ((Test-Path $OutputPath) -and (Get-Item $OutputPath).Length -gt 0) {
            $fileSize = (Get-Item $OutputPath).Length / 1KB
            Write-Log "Download successful: $OutputPath ($([math]::Round($fileSize, 2)) KB)" -Level SUCCESS
            $Script:Stats.AgentsDownloaded++
            return $true
        } else {
            Write-Log "Download failed or file is empty: $OutputPath" -Level ERROR
            $Script:Stats.Errors++
            return $false
        }
        
    } catch {
        Write-Log "Error downloading agent: $($_.Exception.Message)" -Level ERROR
        $Script:Stats.Errors++
        return $false
    }
}

function ConvertTo-SafeFileName {
    param([string]$GroupName)
    
    $cleaned = $GroupName -replace '^\d+\s*', ''
    $cleaned = $cleaned -replace '[^\w\s-]', ''
    $cleaned = $cleaned -replace '\s+', '-'
    $cleaned = $cleaned.Trim('-')
    
    return $cleaned
}

# ================================
# SIGNING FUNCTIONS
# ================================

function Test-CodeSignature {
    param([string]$FilePath)
    
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status -eq 'Valid') {
            Write-Log "File is already signed with valid signature: $FilePath" -Level SUCCESS
            return $true
        }
        return $false
    } catch {
        return $false
    }
}

function Invoke-AzureCodeSigning {
    param([string]$FilePath)
    
    Write-Log "========== SIGNING: $FilePath ==========" -Level INFO
    
    try {
        # Set Azure environment variables for authentication
        $env:AZURE_CLIENT_ID = $Script:AZURE_CLIENT_ID
        $env:AZURE_TENANT_ID = $Script:AZURE_TENANT_ID
        $env:AZURE_CLIENT_SECRET = $Script:AZURE_CLIENT_SECRET
        
        # Build SignTool command - EXACTLY matches working template
        # Using SHA256 for both file digest and timestamp digest
        # Quote paths to handle spaces
        $signArgs = @(
            'sign',
            '/v',
            '/fd', 'SHA256',
            '/tr', "`"$TIMESTAMP_SERVER`"",
            '/td', 'SHA256',
            '/dlib', "`"$DLIB_PATH`"",
            '/dmdf', "`"$METADATA_FILE`"",
            "`"$FilePath`""
        )
        
        Write-Log "Executing SignTool with Azure Trusted Signing..." -Level INFO
        Write-Log "Command: $SIGNTOOL_PATH sign /v /fd SHA256 /tr `"$TIMESTAMP_SERVER`" /td SHA256 /dlib `"$DLIB_PATH`" /dmdf `"$METADATA_FILE`" `"$FilePath`"" -Level INFO
        
        # Execute SignTool - capture both stdout and stderr
        $signOutput = & $SIGNTOOL_PATH $signArgs 2>&1
        $signExitCode = $LASTEXITCODE
        
        # Display output with proper formatting
        Write-Log "SignTool Output:" -Level INFO
        Write-Log "Note: 'SHA1 hash' shown below is the certificate's hash (all certificates have both SHA1 and SHA256 hashes)." -Level INFO
        Write-Log "The actual signing algorithm is SHA256 as specified by /fd SHA256 and /td SHA256." -Level INFO
        
        $signOutput | ForEach-Object {
            $line = $_.ToString()
            # Suppress or clarify SHA1 hash line to avoid confusion
            if ($line -match "SHA1 hash:") {
                Write-Log "Certificate SHA1 hash (informational only): $($line -replace '.*SHA1 hash:\s*', '')" -Level INFO
                # Don't display this confusing line to console
            } elseif ($line -match "Successfully signed") {
                Write-Host $line -ForegroundColor Green
                Write-Log $line -Level SUCCESS
            } elseif ($line -match "Error|Failed|SignerSign\(\) failed") {
                Write-Host $line -ForegroundColor Red
                Write-Log $line -Level ERROR
            } elseif ($line -match "WARNING") {
                Write-Host $line -ForegroundColor Yellow
                Write-Log $line -Level WARNING
            } elseif ($line -match "certificate was selected") {
                # Warn if local certificate is being selected instead of Azure
                Write-Host $line -ForegroundColor Yellow
                Write-Log $line -Level WARNING
                Write-Log "WARNING: A local certificate appears to be selected. Azure Trusted Signing should be used instead." -Level WARNING
            } else {
                Write-Host $line
                Write-Log $line -Level INFO
            }
        }
        
        if ($signExitCode -eq 0) {
            Write-Log "Signing completed successfully for: $FilePath" -Level SUCCESS
            
            # Verify signature was applied using SignTool verify
            Write-Log "Verifying signature..." -Level INFO
            try {
                $verifyArgs = @('verify', '/pa', '/v', $FilePath)
                $verifyOutput = & $SIGNTOOL_PATH $verifyArgs 2>&1
                $verifyExitCode = $LASTEXITCODE
                
                $verifyOutput | ForEach-Object {
                    $line = $_.ToString()
                    if ($line -match "Successfully verified") {
                        Write-Host $line -ForegroundColor Green
                        Write-Log $line -Level SUCCESS
                    } elseif ($line -match "Error|Failed") {
                        Write-Host $line -ForegroundColor Red
                        Write-Log $line -Level WARNING
                    } else {
                        Write-Log $line -Level INFO
                    }
                }
                
                # Also check with PowerShell
                $signature = Get-AuthenticodeSignature -FilePath $FilePath
                Write-Log "Signature Status: $($signature.Status)" -Level INFO
                if ($signature.SignerCertificate) {
                    Write-Log "Signer: $($signature.SignerCertificate.Subject)" -Level INFO
                }
                
                if ($signature.Status -eq 'Valid') {
                    $Script:Stats.AgentsSigned++
                    return $true
                } else {
                    Write-Log "Warning: Signature status is $($signature.Status), not Valid" -Level WARNING
                    return $false
                }
            } catch {
                Write-Log "Warning: Could not verify signature details: $($_.Exception.Message)" -Level WARNING
                # Still return true if SignTool said it succeeded
                if ($signExitCode -eq 0) {
                    $Script:Stats.AgentsSigned++
                    return $true
                }
                return $false
            }
        } else {
            Write-Log "Signing failed with exit code: $signExitCode" -Level ERROR
            Write-Host "Signing failed. Check the output above for details." -ForegroundColor Red
            $Script:Stats.Errors++
            return $false
        }
        
    } catch {
        Write-Log "Exception during signing: $($_.Exception.Message)" -Level ERROR
        Write-Host "Exception: $($_.Exception.Message)" -ForegroundColor Red
        $Script:Stats.Errors++
        return $false
    } finally {
        # Clean up environment variables
        Remove-Item Env:\AZURE_CLIENT_ID -ErrorAction SilentlyContinue
        Remove-Item Env:\AZURE_TENANT_ID -ErrorAction SilentlyContinue
        Remove-Item Env:\AZURE_CLIENT_SECRET -ErrorAction SilentlyContinue
    }
}

# ================================
# MAIN WORKFLOW FUNCTIONS
# ================================

function Start-DownloadPhase {
    Write-Log ([Environment]::NewLine + "========================================") -Level INFO
    Write-Log "PHASE 1: DOWNLOADING AGENTS" -Level INFO
    Write-Log ("========================================" + [Environment]::NewLine) -Level INFO
    
    # Check if agents need updating
    $needsDownload = -not (Test-AgentAge)
    
    if (-not $needsDownload) {
        Write-Log "Agents are up-to-date. Skipping download phase." -Level SUCCESS
        Write-Log "Use -SkipAgeCheck to force re-download." -Level INFO
        return @()
    }
    
    $groups = Get-MeshCentralGroups
    
    if (-not $groups -or $groups.Count -eq 0) {
        throw "No device groups found in MeshCentral"
    }
    
    Write-Log "Found $($groups.Count) device groups" -Level SUCCESS
    
    $downloadedAgents = @()
    
    foreach ($group in $groups) {
        $Script:Stats.GroupsProcessed++
        
        $groupName = $group.name
        $meshId = $group._id -replace '^mesh//', ''
        
        Write-Log ([Environment]::NewLine + "--- Processing Group: $groupName ---") -Level INFO
        Write-Log "Mesh ID: $meshId" -Level INFO
        
        $safeGroupName = ConvertTo-SafeFileName -GroupName $groupName
        
        foreach ($archKey in $ARCHITECTURES.Keys) {
            $arch = $ARCHITECTURES[$archKey]
            $fileName = "$safeGroupName`_$($arch.Label).exe"
            $filePath = Join-Path $AGENTS_DIR $fileName
            
            Write-Log "Downloading $($arch.Label) agent for $groupName..." -Level INFO
            
            $downloadSuccess = Get-MeshAgent -MeshId $meshId -ArchCode $arch.Code -OutputPath $filePath
            
            if ($downloadSuccess) {
                $hash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
                Write-Log "SHA256: $hash" -Level INFO
                
                $downloadedAgents += @{
                    FilePath = $filePath
                    FileName = $fileName
                    Hash = $hash
                }
            } else {
                Write-Log "Download failed for $fileName" -Level WARNING
                Add-ExecutiveEntry -FileName $fileName -Hash "N/A" -Status "Download Failed" -Action "ERROR"
            }
        }
    }
    
    # Update agent age tracking after successful downloads
    if ($downloadedAgents.Count -gt 0) {
        Update-AgentAge
    }
    
    return $downloadedAgents
}

function Start-SignPhase {
    param([array]$AgentsToSign)
    
    Write-Log ([Environment]::NewLine + "========================================") -Level INFO
    Write-Log "PHASE 2: SIGNING AGENTS" -Level INFO
    Write-Log ("========================================" + [Environment]::NewLine) -Level INFO
    
    # If no agents provided, scan the Agents directory
    if ($AgentsToSign.Count -eq 0) {
        Write-Log "Scanning for existing agents to sign..." -Level INFO
        $existingAgents = Get-ChildItem -Path $AGENTS_DIR -Filter "*.exe" -ErrorAction SilentlyContinue
        
        if ($existingAgents.Count -eq 0) {
            Write-Log "No agents found in $AGENTS_DIR" -Level WARNING
            return
        }
        
        # Filter out ARM64 files (cannot be signed by SignTool)
        $signableAgents = $existingAgents | Where-Object { $_.Name -notmatch '_ARM64\.exe$' }
        $arm64Count = ($existingAgents | Where-Object { $_.Name -match '_ARM64\.exe$' }).Count
        
        if ($arm64Count -gt 0) {
            Write-Log "Skipping $arm64Count ARM64 file(s) (SignTool does not support ARM64 PE files)" -Level INFO
        }
        
        foreach ($agent in $signableAgents) {
            $hash = (Get-FileHash -Path $agent.FullName -Algorithm SHA256).Hash
            $AgentsToSign += @{
                FilePath = $agent.FullName
                FileName = $agent.Name
                Hash = $hash
            }
        }
        
        Write-Log "Found $($AgentsToSign.Count) signable agent(s) to process" -Level SUCCESS
    }
    
    foreach ($agent in $AgentsToSign) {
        $filePath = $agent.FilePath
        $fileName = $agent.FileName
        $hashBefore = $agent.Hash
        
        Write-Log ([Environment]::NewLine + "--- Checking signature: $fileName ---") -Level INFO
        
        # Skip ARM64 files - SignTool cannot sign ARM64 PE files
        if ($fileName -match '_ARM64\.exe$') {
            Write-Log "ARM64 files cannot be signed by SignTool. Skipping." -Level WARNING
            Add-ExecutiveEntry -FileName $fileName -Hash $hashBefore -Status "ARM64 (Not Supported)" -Action "SKIPPED"
            $Script:Stats.AgentsSkipped++
            continue
        }
        
        if (Test-CodeSignature -FilePath $filePath) {
            Write-Log "Agent already has valid signature. Skipping." -Level SUCCESS
            Add-ExecutiveEntry -FileName $fileName -Hash $hashBefore -Status "Already Signed" -Action "SKIPPED"
            $Script:Stats.AgentsSkipped++
        } else {
            Write-Log "Agent is NOT signed. Proceeding with Azure signing..." -Level WARNING
            
            $signSuccess = Invoke-AzureCodeSigning -FilePath $filePath
            
            if ($signSuccess) {
                $hashAfter = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
                Write-Log "Post-signing SHA256: $hashAfter" -Level SUCCESS
                Add-ExecutiveEntry -FileName $fileName -Hash $hashAfter -Status "Newly Signed" -Action "SIGNED"
            } else {
                Write-Log "Signing failed for $fileName" -Level ERROR
                Add-ExecutiveEntry -FileName $fileName -Hash $hashBefore -Status "Signing Failed" -Action "ERROR"
            }
        }
    }
}

# ================================
# MAIN EXECUTION
# ================================

try {
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                  MESHCENTRAL AZURE SIGNING TOOL                       ║" -ForegroundColor Cyan
    Write-Host "║                     https://github.com/Matt-CyberGuy/MeshAzureSign    ║" -ForegroundColor Cyan
    Write-Host "║                              Version $SCRIPT_VERSION                              ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Log "Script Version: $SCRIPT_VERSION" -Level INFO
    Write-Log "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level INFO
    
    # Initialize directories first (needed for script copy)
    Initialize-Directories
    
    # Copy script to C:\MeshSigning\MeshSigning.ps1 (works for both local and irm | iex)
    $targetPath = "$BASE_DIR\MeshSigning.ps1"
    
    # Try to get script content from various sources
    $scriptContent = $null
    
    # Method 1: If running locally, get from PSCommandPath
    $scriptPath = $MyInvocation.PSCommandPath
    if ($scriptPath -and (Test-Path $scriptPath)) {
        try {
            $scriptContent = Get-Content -Path $scriptPath -Raw -ErrorAction Stop
            Write-Log "Found script at: $scriptPath" -Level INFO
        } catch {
            Write-Log "Could not read script from PSCommandPath: $($_.Exception.Message)" -Level WARNING
        }
    }
    
    # Method 2: If running via irm | iex, download from GitHub
    if (-not $scriptContent) {
        Write-Log "Script not found locally, downloading from GitHub..." -Level INFO
        try {
            $scriptContent = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/Matt-CyberGuy/MeshAzureSign/main/MeshSigning.ps1" -UseBasicParsing -ErrorAction Stop
            Write-Log "Downloaded script from GitHub" -Level SUCCESS
        } catch {
            Write-Log "Could not download script from GitHub: $($_.Exception.Message)" -Level WARNING
        }
    }
    
    # Save script to C:\MeshSigning\MeshSigning.ps1
    if ($scriptContent) {
        try {
            Set-Content -Path $targetPath -Value $scriptContent -Encoding UTF8 -Force -ErrorAction Stop
            Write-Log "Script saved to: $targetPath" -Level SUCCESS
            Write-Host "Script location: $targetPath" -ForegroundColor Cyan
            Write-Host "You can run this script directly from: $targetPath" -ForegroundColor Cyan
            Write-Host ""
        } catch {
            Write-Log "Could not save script to $targetPath : $($_.Exception.Message)" -Level WARNING
        }
    }
    
    # Initialize rest of environment
    Initialize-LogFiles
    Test-NodeJs
    Install-Dependencies
    Initialize-Configuration
    
    if (-not (Load-Configuration)) {
        throw "Failed to load configuration"
    }
    
    # Determine execution mode
    $mode = if ($Download) { "Download Only" } elseif ($Sign) { "Sign Only" } else { "Full Workflow (Download + Sign)" }
    Write-Log "Execution Mode: $mode" -Level INFO
    
    $downloadedAgents = @()
    
    # Execute based on mode
    if ($Download -or (-not $Sign -and -not $Download)) {
        $downloadedAgents = Start-DownloadPhase
    }
    
    if ($Sign -or (-not $Sign -and -not $Download)) {
        Start-SignPhase -AgentsToSign $downloadedAgents
    }
    
    # Display summary
    Write-Log ([Environment]::NewLine + "========================================") -Level INFO
    Write-Log "EXECUTION SUMMARY" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Groups Processed:     $($Script:Stats.GroupsProcessed)" -Level INFO
    Write-Log "Agents Downloaded:    $($Script:Stats.AgentsDownloaded)" -Level SUCCESS
    Write-Log "Agents Signed:        $($Script:Stats.AgentsSigned)" -Level SUCCESS
    Write-Log "Agents Skipped:       $($Script:Stats.AgentsSkipped)" -Level INFO
    Write-Log "Errors:               $($Script:Stats.Errors)" -Level $(if ($Script:Stats.Errors -gt 0) { 'ERROR' } else { 'INFO' })
    Write-Log "========================================" -Level INFO
    
    # Append summary to executive log
    $summaryText = @"

========================================
EXECUTION SUMMARY
========================================
Mode:                 $mode
Groups Processed:     $($Script:Stats.GroupsProcessed)
Agents Downloaded:    $($Script:Stats.AgentsDownloaded)
Agents Signed:        $($Script:Stats.AgentsSigned)
Agents Skipped:       $($Script:Stats.AgentsSkipped)
Errors:               $($Script:Stats.Errors)
========================================
"@
    
    Add-Content -Path $EXECUTIVE_LOG -Value $summaryText -ErrorAction SilentlyContinue
    
    Write-Log ([Environment]::NewLine + "Detailed log: $DETAILED_LOG") -Level INFO
    Write-Log "Executive summary: $EXECUTIVE_LOG" -Level INFO
    Write-Host ""
    
    # Determine if script actually succeeded based on errors and intended operations
    $hasErrors = $Script:Stats.Errors -gt 0
    $intendedWork = if ($Download -or (-not $Sign -and -not $Download)) {
        # Download mode: check if downloads succeeded
        $Script:Stats.AgentsDownloaded -gt 0 -or $Script:Stats.GroupsProcessed -gt 0
    } elseif ($Sign) {
        # Sign mode: check if signings succeeded
        $Script:Stats.AgentsSigned -gt 0
    } else {
        # Full mode: check if both succeeded
        ($Script:Stats.AgentsDownloaded -gt 0 -or $Script:Stats.AgentsSigned -gt 0)
    }
    
    if ($hasErrors -and -not $intendedWork) {
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
        Write-Host "  SCRIPT COMPLETED WITH ERRORS" -ForegroundColor Red
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
        Write-Host ""
        Write-Host "The script encountered $($Script:Stats.Errors) error(s)." -ForegroundColor Yellow
        Write-Host "Please review the error messages above and check the logs:" -ForegroundColor Yellow
        Write-Host "  $DETAILED_LOG" -ForegroundColor White
        Write-Host ""
    } elseif ($hasErrors) {
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow
        Write-Host "  SCRIPT COMPLETED WITH WARNINGS" -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Some operations completed, but $($Script:Stats.Errors) error(s) occurred." -ForegroundColor Yellow
        Write-Host "Please review the output above for details." -ForegroundColor Yellow
        Write-Host ""
    } else {
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host "  SCRIPT COMPLETED SUCCESSFULLY" -ForegroundColor Green
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""
    }
    
    # Wait for user to read the message before closing
    Wait-ForUser
    
} catch {
    # Ensure error is always visible, even if logging hasn't been initialized
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host "  FATAL ERROR" -ForegroundColor Red
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    
    # Try to log if logging is available
    if (Test-Path $LOGS_DIR -ErrorAction SilentlyContinue) {
        try {
            Write-Log ([Environment]::NewLine + "[FATAL ERROR] $($_.Exception.Message)") -Level CRITICAL
            Write-Log "Script execution failed. Check logs for details." -Level CRITICAL
            Write-Host "Detailed log: $DETAILED_LOG" -ForegroundColor Yellow
        } catch {
            # If logging fails, at least we showed the error above
        }
    }
    
    Write-Host ""
    Write-Host "Script execution failed. See error message above." -ForegroundColor Red
    Write-Host ""
    
    # Wait for user to read the error before closing
    Wait-ForUser
    
    # Exit with error code
    exit 1
}