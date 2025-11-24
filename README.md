# VCF HCL Cooker

A Python tool to dynamically generate custom vSAN ESA HCL JSON files by connecting to ESXi hosts and optionally deploying them to SDDC Manager.

## Features

- **Multi-Host Support**: Connect to one or more ESXi servers to collect disk and controller information
- **Automated HCL Generation**: Creates a single vSAN HCL file with all disks and controllers from ESXi hosts
- **Configurable ESXi Releases**: Supports custom ESXi release versions (default: ESXi 9.0)
- **SDDC Manager Integration**: Automatically deploy generated HCL files to SDDC Manager
- **Secure Deployment**: Uses SSH with sudo elevation to update protected files on SDDC Manager
- **Backup Protection**: Automatically backs up existing HCL files before replacement

## Installation

### Prerequisites

- Python 3.8 or higher
- Network access to ESXi hosts and SDDC Manager (if deploying)
- Valid credentials for ESXi hosts and SDDC Manager

### Install Dependencies

```bash
pip install -r requirements.txt
```

Or using Pipenv:

```bash
pipenv install pyvmomi paramiko requests urllib3
```

## Usage

### Basic Usage - Single ESXi Host

```bash
python generate_hcl.py --esxi-host 192.168.1.10 --esxi-user root
```

### Multiple ESXi Hosts

```bash
python generate_hcl.py \
  --esxi-host 192.168.1.10 \
  --esxi-host 192.168.1.11 \
  --esxi-host 192.168.1.12 \
  --esxi-user root
```

### Custom ESXi Release

```bash
python generate_hcl.py \
  --esxi-host 192.168.1.10 \
  --esxi-user root \
  --release "ESXi 8.0"
```

### Multiple ESXi Releases

```bash
python generate_hcl.py \
  --esxi-host 192.168.1.10 \
  --esxi-user root \
  --release "ESXi 8.0" \
  --release "ESXi 9.0"
```

### With SDDC Manager Deployment

```bash
python generate_hcl.py \
  --esxi-host 192.168.1.10 \
  --esxi-user root \
  --sddc-host sddc-manager.example.com \
  --sddc-user vcf
# Will prompt for SDDC user password and root password
```

### Custom Output Filename

```bash
python generate_hcl.py \
  --esxi-host 192.168.1.10 \
  --esxi-user root \
  --output my_custom_hcl.json
```

### Non-Interactive Mode (Passwords in Command)

```bash
python generate_hcl.py \
  --esxi-host 192.168.1.10 \
  --esxi-user root \
  --esxi-password 'MyESXiPassword' \
  --sddc-host sddc-manager.example.com \
  --sddc-user vcf \
  --sddc-password 'MySDDCPassword' \
  --sddc-root-password 'MyRootPassword'
```

**Note**: Providing passwords on the command line is less secure. If passwords are not provided, the script will prompt for them securely.

## Command-Line Arguments

### ESXi Connection Options

- `--esxi-host`: ESXi host(s) to connect to (required, can be specified multiple times)
- `--esxi-user`: ESXi username (default: root)
- `--esxi-password`: ESXi password (will prompt if not provided)
- `--esxi-port`: ESXi port (default: 443)

### HCL Generation Options

- `--release`: Supported ESXi release (default: ESXi 9.0, can be specified multiple times)
- `--output`: Output filename (default: custom_vsan_esa_hcl_<timestamp>.json)

### SDDC Manager Options

- `--sddc-host`: SDDC Manager hostname or IP
- `--sddc-user`: SDDC Manager username
- `--sddc-password`: SDDC Manager password (will prompt if not provided)
- `--sddc-root-password`: SDDC Manager root password for su elevation (will prompt if not provided)

## How It Works

### 1. ESXi Data Collection

The script connects to each specified ESXi host and collects:
- Storage device information (SCSI topology)
- Storage adapter details (controllers)
- PCI device information
- Installed VIB packages and versions
- Disk firmware, capacity, and specifications

### 2. HCL File Generation

The collected data is transformed into VMware's vSAN HCL JSON format:
- Controller entries with driver versions and firmware
- SSD/NVMe device entries with specifications
- Support information for vSAN and vSAN ESA modes
- Compatibility information for specified ESXi releases

### 3. SDDC Manager Deployment (Optional)

If SDDC Manager details are provided:
1. Connects via SSH to SDDC Manager using the regular user account
2. Creates a temporary file with the HCL content
3. Uses `su` to elevate to root with the provided root password
4. Backs up the existing `/nfs/vmware/vcf/nfs-mount/vsan-hcl/all.json` file
5. Replaces the file with the new HCL content
6. Sets proper file permissions (644)
7. Cleans up temporary files

## File Structure

```
VcfHclCooker/
├── generate_hcl.py          # Main Python script
├── generate-hcl.ps1          # Original PowerShell script
├── requirements.txt          # Python dependencies
├── Pipfile                   # Pipenv configuration
└── README.md                 # This file
```

## Output Format

The generated JSON file follows VMware's vSAN HCL format:

```json
{
  "timestamp": 1700000000000,
  "jsonUpdatedTime": "2024-11-24 12:00:00",
  "totalCount": 10,
  "supportedReleases": ["ESXi 9.0"],
  "eula": {},
  "data": {
    "controller": [...],
    "ssd": [...],
    "hdd": []
  }
}
```

## Security Considerations

1. **Password Security**: The script prompts for passwords securely using `getpass` when not provided on the command line
2. **SSH Authentication**: Uses paramiko for secure SSH connections
3. **Privilege Elevation**: Uses `su` on SDDC Manager with root password to handle file operations requiring root access
4. **Separate Credentials**: Requires both the regular user password and root password for SDDC Manager
5. **Backup Protection**: Always backs up existing HCL files before replacement
6. **SSL Verification**: Disables SSL verification for ESXi connections (common in lab environments)

## Troubleshooting

### Connection Issues

- Verify network connectivity to ESXi hosts and SDDC Manager
- Check firewall rules allow connections on port 443 (ESXi) and 22 (SSH)
- Ensure credentials are correct

### Permission Issues on SDDC Manager

- Verify you have the correct root password for su elevation
- Check that the target path `/nfs/vmware/vcf/nfs-mount/vsan-hcl/` exists
- Ensure the NFS mount is accessible
- Verify SSH access is enabled for the user account

### Missing Storage Devices

- Verify storage controllers are supported (nvme_pcie or pvscsi)
- Check that devices are properly recognized by ESXi
- Review ESXi storage configuration

## Credits

- Original PowerShell script by William Lam
- Python conversion and SDDC Manager integration added

## License

This tool is provided as-is for use in VMware environments.

