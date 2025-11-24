# VCF HCL Cooker

A Python tool to dynamically generate custom vSAN ESA HCL JSON files by connecting to ESXi hosts and optionally deploying them to SDDC Manager or VCF Installer.

## Features

- **Multi-Host Support**: Connect to one or more ESXi servers to collect disk and controller information
- **Automated HCL Generation**: Creates a single vSAN HCL file with all disks and controllers from ESXi hosts
- **Configurable ESXi Releases**: Supports custom ESXi release versions (default: ESXi 9.0)
- **SDDC Manager/VCF Installer Integration**: Automatically deploy generated HCL files to SDDC Manager or VCF Installer
- **Secure Deployment**: Uses SSH with su elevation to update protected files
- **Timestamped Backups**: Automatically creates timestamped backups of existing HCL files before replacement
- **Detailed Logging**: Comprehensive logging with timestamped log files for each run
- **Default Usernames**: Sensible defaults (root for ESXi, vcf for SDDC Manager/VCF Installer)

## Installation

### Prerequisites

- Python 3.8 or higher
- Network access to ESXi hosts and SDDC Manager/VCF Installer (if deploying)
- Valid credentials for ESXi hosts and SDDC Manager/VCF Installer

### Install Dependencies

```bash
pip install -r requirements.txt
```

Or using Pipenv:

```bash
pipenv install
```

## Usage

### Basic Usage - Single ESXi Host

```bash
python generate_hcl.py --esxi-host 192.168.1.10
```

This will prompt for the ESXi root password.

### Multiple ESXi Hosts

```bash
python generate_hcl.py \
  --esxi-host 192.168.1.10 \
  --esxi-host 192.168.1.11 \
  --esxi-host 192.168.1.12
```

### Custom ESXi Release

```bash
python generate_hcl.py \
  --esxi-host 192.168.1.10 \
  --release "ESXi 8.0"
```

### Multiple ESXi Releases

```bash
python generate_hcl.py \
  --esxi-host 192.168.1.10 \
  --release "ESXi 8.0" \
  --release "ESXi 9.0"
```

### With SDDC Manager Deployment

```bash
python generate_hcl.py \
  --esxi-host 192.168.1.10 \
  --sddc-host sddc-manager.example.com
# Will prompt for ESXi password, SDDC user (vcf) password, and root password
```

### With VCF Installer Deployment

```bash
python generate_hcl.py \
  --esxi-host 192.168.1.10 \
  --sddc-host vcf-installer.example.com
# Will prompt for passwords
```

**Note for VCF Installer**: When deploying to a VCF Installer, the password for the `vcf` user and the root password are typically the same. You can provide the same password for both `--sddc-password` and `--sddc-root-password`.

### VCF Installer - Non-Interactive Mode (Same Password)

```bash
python generate_hcl.py \
  --esxi-host 192.168.1.10 \
  --esxi-password 'ESXiPass' \
  --sddc-host vcf-installer.example.com \
  --sddc-password 'VcfPassword' \
  --sddc-root-password 'VcfPassword'
```

### Custom Output Filename

```bash
python generate_hcl.py \
  --esxi-host 192.168.1.10 \
  --output my_custom_hcl.json
```

### Custom Log Directory

```bash
python generate_hcl.py \
  --esxi-host 192.168.1.10 \
  --log-dir /var/log/vsan-hcl
```

### Custom Usernames

```bash
python generate_hcl.py \
  --esxi-host 192.168.1.10 \
  --esxi-user administrator \
  --sddc-host sddc-manager.example.com \
  --sddc-user admin
```

### Complete Non-Interactive Example

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
- `--esxi-user`: ESXi username (default: **root**)
- `--esxi-password`: ESXi password (will prompt if not provided)
- `--esxi-port`: ESXi port (default: 443)

### HCL Generation Options

- `--release`: Supported ESXi release (default: ESXi 9.0, can be specified multiple times)
- `--output`: Output filename (default: custom_vsan_esa_hcl_<timestamp>.json)
- `--log-dir`: Directory for log files (default: logs)

### SDDC Manager/VCF Installer Options

- `--sddc-host`: SDDC Manager or VCF Installer hostname or IP
- `--sddc-user`: SDDC Manager/VCF Installer username (default: **vcf**)
- `--sddc-password`: SDDC Manager/VCF Installer password (will prompt if not provided)
- `--sddc-root-password`: SDDC Manager/VCF Installer root password for su elevation (will prompt if not provided)

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

### 3. SDDC Manager/VCF Installer Deployment (Optional)

If SDDC Manager or VCF Installer details are provided:
1. Connects via SSH to SDDC Manager/VCF Installer using the regular user account (default: vcf)
2. Creates a temporary file with the HCL content
3. Uses `su` to elevate to root with the provided root password
4. Creates a timestamped backup of the existing `/nfs/vmware/vcf/nfs-mount/vsan-hcl/all.json` file
   - Backup format: `all.json.YYYYMMDD_HHMMSS` (e.g., `all.json.20241124_143022`)
5. Replaces the file with the new HCL content
6. Sets proper file permissions (644)
7. Cleans up temporary files

### 4. Detailed Logging

Every run generates a timestamped log file in the `logs` directory:
- Log filename format: `vsan_hcl_generator_YYYYMMDD_HHMMSS.log`
- Contains detailed debug information about:
  - Connection attempts and status
  - Storage device discovery
  - Data collection progress
  - File operations
  - Errors and warnings with stack traces
- Console output shows INFO level messages
- Log file contains DEBUG level details for troubleshooting

## SDDC Manager vs VCF Installer

This tool works with both **SDDC Manager** and **VCF Installer** appliances:

### SDDC Manager
- Production VMware Cloud Foundation management appliance
- Typically has separate passwords for the `vcf` user and root account
- Use different values for `--sddc-password` and `--sddc-root-password`

### VCF Installer
- Temporary appliance used during VCF deployment
- **Important**: The `vcf` user password and root password are typically **the same**
- You can provide the same password for both `--sddc-password` and `--sddc-root-password`
- Example:
  ```bash
  python generate_hcl.py \
    --esxi-host 192.168.1.10 \
    --sddc-host vcf-installer.local \
    --sddc-password 'MyPassword' \
    --sddc-root-password 'MyPassword'
  ```

## File Structure

```
VcfHclCooker/
├── generate_hcl.py                           # Main Python script
├── generate-hcl.ps1                          # Original PowerShell script
├── requirements.txt                          # Python dependencies
├── Pipfile                                   # Pipenv configuration
├── README.md                                 # This file
├── logs/                                     # Log files directory (auto-created)
│   └── vsan_hcl_generator_YYYYMMDD_HHMMSS.log
└── custom_vsan_esa_hcl_YYYYMMDD_HHMMSS.json  # Generated HCL files
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
3. **Privilege Elevation**: Uses `su` on SDDC Manager/VCF Installer with root password to handle file operations requiring root access
4. **Separate Credentials**: Requires both the regular user password and root password for SDDC Manager/VCF Installer
5. **VCF Installer Note**: For VCF Installer, the user and root passwords are typically the same
6. **Timestamped Backups**: Always creates timestamped backups of existing HCL files before replacement (e.g., `all.json.20241124_143022`)
7. **SSL Verification**: Disables SSL verification for ESXi connections (common in lab environments)
8. **Audit Trail**: Detailed logging provides a complete audit trail of all operations

## Troubleshooting

### Connection Issues

- Verify network connectivity to ESXi hosts and SDDC Manager/VCF Installer
- Check firewall rules allow connections on port 443 (ESXi) and 22 (SSH)
- Ensure credentials are correct
- For ESXi, default username is `root`
- For SDDC Manager/VCF Installer, default username is `vcf`

### Permission Issues on SDDC Manager/VCF Installer

- Verify you have the correct root password for su elevation
- For VCF Installer, try using the same password for both user and root
- Check that the target path `/nfs/vmware/vcf/nfs-mount/vsan-hcl/` exists
- Ensure the NFS mount is accessible
- Verify SSH access is enabled for the user account

### Missing Storage Devices

- Verify storage controllers are supported (nvme_pcie or pvscsi)
- Check that devices are properly recognized by ESXi
- Review ESXi storage configuration

### Authentication Failures

- Double-check passwords are correct
- For VCF Installer, ensure you're using the correct password (often the same for user and root)
- Verify the user account has SSH access enabled
- Check if the account is locked or expired

### Reviewing Logs

- Check the `logs/` directory for detailed log files
- Log files are named with timestamps: `vsan_hcl_generator_YYYYMMDD_HHMMSS.log`
- Look for ERROR or WARNING messages for troubleshooting
- DEBUG level information shows detailed connection and data collection steps
- The script displays the log file location at the start and end of each run

## Credits

- Original PowerShell script by William Lam
- Python conversion and SDDC Manager/VCF Installer integration added

## License

This tool is provided as-is for use in VMware environments.
