# MeshAzureSign

Automate the download and Azure Trusted Signing of MeshCentral agents for all device groups.

## Overview

MeshCentral agents have unique hashes per group and architecture (x86, x64, ARM64), causing them to be flagged as malware. This tool automates:
1. Downloading agents from MeshCentral server for all device groups
2. Signing them with Azure Trusted Signing certificates
3. Tracking agent versions to avoid unnecessary downloads
4. Running on a schedule (e.g., via NinjaRMM)

## Quick Start

### One-Line Installer

```powershell
irm https://raw.githubusercontent.com/Matt-CyberGuy/MeshAzureSign/main/MeshSigning.ps1 | iex
```

### Manual Installation

1. Clone this repository
2. Run `MeshSigning.ps1` - it will prompt for configuration on first run

## Usage

```powershell
.\MeshSigning.ps1 [-Download] [-Sign] [-SkipAgeCheck] [-Help]
```

- **No parameters:** Full workflow (download + sign)
- **-Download:** Download agents only (skip signing)
- **-Sign:** Sign existing agents only (skip download)
- **-SkipAgeCheck:** Force re-download regardless of version
- **-Help:** Display help information

## Requirements

- Windows 10/11 or Windows Server 2016+
- Node.js (script checks and prompts if missing)
- PowerShell 5.1+
- Azure Trusted Signing account
- MeshCentral server with login token enabled

## Configuration

On first run, the script will prompt for:
- MeshCentral server URL, username, and login key
- Azure Client ID, Tenant ID, and Client Secret
- Azure Trusted Signing account details

Configuration files are stored in `Config\`:
- `credentials.json` - MeshCentral and Azure credentials
- `metadata.json` - Azure Trusted Signing metadata
- `config.json` - Auto-generated settings
- `agent-age.txt` - Version tracking

## Directory Structure

```
C:\MeshSigning\
├── Agents\              # Downloaded MeshCentral agent executables
├── Config\              # Configuration and credential files
├── Logs\                # Detailed and executive summary logs
├── meshctrl\            # MeshCentral control module
│   └── node_modules\    # npm dependencies
└── Tools\               # Signing tools
    ├── signtool.exe     # Windows SDK SignTool
    └── Azure.CodeSigning.Dlib.dll  # Azure Trusted Signing DLL
```

## License

MIT License - see LICENSE file for details

## Author

Matt (CyberGuy)

## Repository

https://github.com/Matt-CyberGuy/MeshAzureSign

