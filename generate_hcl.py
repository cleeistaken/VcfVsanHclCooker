#!/usr/bin/env python3
"""
Author: Converted from William Lam's PowerShell script
Description: Dynamically generate custom vSAN ESA HCL JSON file by connecting to ESXi hosts
             and optionally deploy to SDDC Manager or VCF Installer
"""

import argparse
import json
import random
import requests
import re
import sys
import logging
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from getpass import getpass
from pathlib import Path
import warnings

try:
    from pyVim.connect import SmartConnect, Disconnect
    from pyVmomi import vim
    import paramiko
    import urllib3
except ImportError as e:
    print(f"Error: Missing required package. Please install dependencies:")
    print("  pip install pyvmomi paramiko requests urllib3")
    sys.exit(1)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

# Global logger
logger = None


def setup_logging(log_dir: str = "logs") -> str:
    """Setup logging configuration with timestamped log file"""
    global logger
    
    # Create logs directory if it doesn't exist
    Path(log_dir).mkdir(exist_ok=True)
    
    # Generate timestamped log filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = os.path.join(log_dir, f"vsan_hcl_generator_{timestamp}.log")
    
    # Configure logging
    logger = logging.getLogger('vsan_hcl_generator')
    logger.setLevel(logging.DEBUG)
    
    # File handler - detailed logging
    file_handler = logging.FileHandler(log_filename)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    
    # Console handler - info and above
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)
    
    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    logger.info("=" * 80)
    logger.info("vSAN HCL Generator Started")
    logger.info(f"Log file: {log_filename}")
    logger.info("=" * 80)
    
    return log_filename


class ESXiHCLCollector:
    """Collects disk and controller information from ESXi hosts"""
    
    def __init__(self, host: str, username: str, password: str, port: int = 443):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.si = None
        logger.debug(f"Initialized ESXiHCLCollector for host: {host}, user: {username}, port: {port}")
        
    def connect(self):
        """Connect to ESXi host"""
        try:
            logger.info(f"Connecting to ESXi host {self.host}...")
            logger.debug(f"Connection details - Host: {self.host}, Port: {self.port}, User: {self.username}")
            self.si = SmartConnect(
                host=self.host,
                user=self.username,
                pwd=self.password,
                port=self.port,
                disableSslCertValidation=True
            )
            logger.info(f"Successfully connected to ESXi host {self.host}")
            return True
        except Exception as e:
            logger.error(f"Error connecting to {self.host}: {str(e)}", exc_info=True)
            return False
    
    def disconnect(self):
        """Disconnect from ESXi host"""
        if self.si:
            logger.debug(f"Disconnecting from ESXi host {self.host}")
            Disconnect(self.si)
            logger.info(f"Disconnected from ESXi host {self.host}")
    
    def get_vibs(self, vmhost) -> Dict[str, str]:
        """Get installed VIB packages and their versions"""
        vibs = {}
        try:
            logger.debug(f"Fetching VIB packages from {vmhost.name}")
            image_manager = vmhost.configManager.imageConfigManager
            if image_manager:
                packages = image_manager.FetchSoftwarePackages()
                for package in packages:
                    vibs[package.name] = package.version
                logger.debug(f"Retrieved {len(vibs)} VIB packages")
        except Exception as e:
            logger.warning(f"Could not fetch VIB packages: {str(e)}")
        return vibs
    
    def collect_storage_info(self, supported_releases: List[str]) -> tuple:
        """Collect storage controller and disk information from ESXi host"""
        logger.info(f"Starting storage information collection from {self.host}")
        logger.debug(f"Supported releases: {supported_releases}")
        
        content = self.si.RetrieveContent()
        
        # Get the first host (for standalone ESXi) or iterate through hosts
        host_view = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.HostSystem], True
        )
        hosts = host_view.view
        host_view.Destroy()
        
        logger.debug(f"Found {len(hosts)} host(s) to process")
        
        all_controllers = []
        all_ssds = []
        
        for vmhost in hosts:
            logger.info(f"\nCollecting SSD information from ESXi host {vmhost.name}...")
            
            vibs = self.get_vibs(vmhost)
            
            storage_system = vmhost.configManager.storageSystem
            if not storage_system:
                logger.warning(f"Could not access storage system on {vmhost.name}")
                continue
            
            storage_devices = storage_system.storageDeviceInfo.scsiTopology.adapter
            storage_adapters = storage_system.storageDeviceInfo.hostBusAdapter
            devices = storage_system.storageDeviceInfo.scsiLun
            pci_devices = vmhost.hardware.pciDevice
            
            logger.debug(f"Found {len(storage_devices)} storage devices")
            logger.debug(f"Found {len(storage_adapters)} storage adapters")
            logger.debug(f"Found {len(devices)} SCSI LUNs")
            logger.debug(f"Found {len(pci_devices)} PCI devices")
            
            seen = {}
            
            for storage_device in storage_devices:
                if not storage_device.target:
                    continue
                
                for target in storage_device.target:
                    for scsi_lun in target.lun:
                        # Find matching device
                        device = None
                        for dev in devices:
                            if dev.key == scsi_lun.scsiLun:
                                device = dev
                                break
                        
                        if not device:
                            continue
                        
                        # Find matching storage adapter
                        storage_adapter = None
                        for adapter in storage_adapters:
                            if adapter.key == storage_device.adapter:
                                storage_adapter = adapter
                                break
                        
                        if not storage_adapter:
                            continue
                        
                        # Find matching PCI device
                        pci_device = None
                        for pci in pci_devices:
                            if pci.id == storage_adapter.pci:
                                pci_device = pci
                                break
                        
                        if not pci_device:
                            continue
                        
                        # Convert from decimal to hex
                        vid = format(pci_device.vendorId, 'x').lower()
                        did = format(pci_device.deviceId, 'x').lower()
                        svid = format(pci_device.subVendorId, 'x').lower()
                        ssid = format(pci_device.subDeviceId, 'x').lower()
                        combined = f"{vid}:{did}:{svid}:{ssid}"
                        
                        # Process nvme_pcie or pvscsi controllers
                        if storage_adapter.driver in ["nvme_pcie", "pvscsi"]:
                            controller_type = storage_adapter.driver
                            logger.debug(f"Processing {controller_type} controller: {combined}")
                            
                            # Get controller driver version
                            if controller_type == "nvme_pcie":
                                controller_driver = vibs.get("nvme-pcie", "unknown")
                            elif controller_type == "pvscsi":
                                controller_driver = vibs.get("pvscsi", "unknown")
                            else:
                                controller_driver = "unknown"
                            
                            logger.debug(f"Controller driver version: {controller_driver}")
                            
                            # Get device revision/firmware
                            firmware = getattr(device, 'revision', 'unknown')
                            logger.debug(f"Device firmware: {firmware}")
                            
                            # Build SSD releases structure
                            ssd_releases = {}
                            for release in supported_releases:
                                ssd_releases[release] = {
                                    "vsanSupport": ["All Flash:", "vSANESA-SingleTier"],
                                    controller_type: {
                                        controller_driver: {
                                            "firmwares": [
                                                {
                                                    "firmware": firmware,
                                                    "vsanSupport": {
                                                        "tier": ["AF-Cache", "vSANESA-Singletier"],
                                                        "mode": ["vSAN", "vSAN ESA"]
                                                    }
                                                }
                                            ],
                                            "type": "inbox"
                                        }
                                    }
                                }
                            
                            # Check if this is a disk device and not already seen
                            if hasattr(device, 'deviceType') and device.deviceType == "disk" and combined not in seen:
                                logger.debug(f"Processing disk device: {combined}")
                                
                                # Get capacity
                                capacity = 0
                                if hasattr(device, 'capacity'):
                                    capacity = int((device.capacity.blockSize * device.capacity.block) / 1048576)
                                logger.debug(f"Device capacity: {capacity} MB")
                                
                                # Get device protocol
                                device_protocol = getattr(device, 'applicationProtocol', 'unknown')
                                
                                # Get vendor and model
                                vendor = getattr(device, 'vendor', 'unknown').strip()
                                model = getattr(device, 'model', 'unknown').strip()
                                serial = getattr(device, 'serialNumber', 'unknown')
                                
                                logger.info(f"Found device: {vendor} {model} ({capacity} MB) - {device_protocol}")
                                
                                # Create SSD entry
                                ssd_entry = {
                                    "id": str(random.randint(1000, 50000)),
                                    "did": did,
                                    "vid": vid,
                                    "ssid": ssid,
                                    "svid": svid,
                                    "vendor": vendor,
                                    "model": model,
                                    "devicetype": device_protocol,
                                    "partnername": vendor,
                                    "productid": model,
                                    "partnumber": serial,
                                    "capacity": capacity,
                                    "vcglink": "https://williamlam.com/homelab",
                                    "releases": ssd_releases,
                                    "vsanSupport": {
                                        "mode": ["vSAN", "vSAN ESA"],
                                        "tier": ["vSANESA-Singletier", "AF-Cache"]
                                    }
                                }
                                
                                # Build controller releases structure
                                controller_releases = {}
                                queue_depth = getattr(device, 'queueDepth', 32)
                                
                                for release in supported_releases:
                                    controller_releases[release] = {
                                        controller_type: {
                                            controller_driver: {
                                                "type": "inbox",
                                                "queueDepth": queue_depth,
                                                "firmwares": [
                                                    {
                                                        "firmware": firmware,
                                                        "vsanSupport": [
                                                            "Hybrid:Pass-Through",
                                                            "All Flash:Pass-Through",
                                                            "vSAN ESA"
                                                        ]
                                                    }
                                                ]
                                            }
                                        },
                                        "vsanSupport": [
                                            "Hybrid:Pass-Through",
                                            "All Flash:Pass-Through"
                                        ]
                                    }
                                
                                # Create controller entry
                                controller_entry = {
                                    "id": str(random.randint(1000, 50000)),
                                    "releases": controller_releases
                                }
                                
                                all_controllers.append(controller_entry)
                                all_ssds.append(ssd_entry)
                                seen[combined] = True
                                logger.debug(f"Added controller and SSD entry for device {combined}")
        
        logger.info(f"Collection complete: {len(all_controllers)} controllers, {len(all_ssds)} SSDs")
        return all_controllers, all_ssds


class SDDCManagerDeployer:
    """Handles deployment of HCL file to SDDC Manager or VCF Installer"""
    
    def __init__(self, sddc_host: str, sddc_user: str, sddc_password: str, root_password: str):
        self.sddc_host = sddc_host
        self.sddc_user = sddc_user
        self.sddc_password = sddc_password
        self.root_password = root_password
        self.target_path = "/nfs/vmware/vcf/nfs-mount/vsan-hcl/all.json"
        logger.debug(f"Initialized SDDCManagerDeployer for host: {sddc_host}, user: {sddc_user}")
    
    def deploy_via_ssh(self, hcl_content: str) -> bool:
        """Deploy HCL file to SDDC Manager/VCF Installer via SSH with su elevation"""
        logger.info(f"\nStarting deployment to SDDC Manager/VCF Installer")
        logger.debug(f"Target host: {self.sddc_host}, User: {self.sddc_user}")
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            logger.info(f"Connecting to SDDC Manager/VCF Installer {self.sddc_host} via SSH...")
            ssh.connect(
                self.sddc_host,
                username=self.sddc_user,
                password=self.sddc_password,
                look_for_keys=False,
                allow_agent=False
            )
            logger.info(f"Successfully connected to {self.sddc_host}")
            
            # Create a temporary file with the HCL content
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            temp_file = f"/tmp/vsan_hcl_{timestamp}.json"
            
            logger.info(f"Creating temporary file {temp_file}...")
            logger.debug(f"HCL content size: {len(hcl_content)} bytes")
            sftp = ssh.open_sftp()
            with sftp.file(temp_file, 'w') as f:
                f.write(hcl_content)
            sftp.close()
            logger.info(f"Temporary file created successfully")
            
            logger.info(f"Deploying HCL file to {self.target_path}...")
            
            # Use su to execute commands as root
            # Create backup of existing file with timestamp
            backup_path = f"{self.target_path}.{timestamp}"
            backup_cmd = f"su - root -c 'cp {self.target_path} {backup_path} 2>/dev/null || true'"
            logger.info(f"Creating backup of existing HCL file as {backup_path}...")
            logger.debug(f"Backup command: {backup_cmd}")
            stdin, stdout, stderr = ssh.exec_command(backup_cmd, get_pty=True)
            stdin.write(f"{self.root_password}\n")
            stdin.flush()
            exit_status = stdout.channel.recv_exit_status()
            logger.debug(f"Backup command exit status: {exit_status}")
            
            if exit_status == 0:
                logger.info(f"Backup created successfully: {backup_path}")
            else:
                logger.warning(f"Backup may have failed (exit status: {exit_status})")
            
            # Copy new file to target location using su
            copy_cmd = f"su - root -c 'cp {temp_file} {self.target_path}'"
            logger.info("Copying new HCL file to target location...")
            logger.debug(f"Copy command: {copy_cmd}")
            stdin, stdout, stderr = ssh.exec_command(copy_cmd, get_pty=True)
            stdin.write(f"{self.root_password}\n")
            stdin.flush()
            exit_status = stdout.channel.recv_exit_status()
            logger.debug(f"Copy command exit status: {exit_status}")
            
            if exit_status != 0:
                error = stderr.read().decode()
                logger.error(f"Error copying file: {error}")
                return False
            
            logger.info("File copied successfully")
            
            # Set proper permissions using su
            chmod_cmd = f"su - root -c 'chmod 644 {self.target_path}'"
            logger.info("Setting file permissions...")
            logger.debug(f"Chmod command: {chmod_cmd}")
            stdin, stdout, stderr = ssh.exec_command(chmod_cmd, get_pty=True)
            stdin.write(f"{self.root_password}\n")
            stdin.flush()
            exit_status = stdout.channel.recv_exit_status()
            logger.debug(f"Chmod command exit status: {exit_status}")
            logger.info("File permissions set successfully")
            
            # Clean up temporary file
            cleanup_cmd = f"rm -f {temp_file}"
            logger.debug(f"Cleaning up temporary file: {temp_file}")
            stdin, stdout, stderr = ssh.exec_command(cleanup_cmd)
            stdout.channel.recv_exit_status()
            logger.info("Temporary file cleaned up")
            
            logger.info(f"Successfully deployed HCL file to SDDC Manager/VCF Installer")
            logger.info(f"Backup saved as {backup_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error deploying to SDDC Manager/VCF Installer: {str(e)}", exc_info=True)
            return False
        finally:
            ssh.close()
            logger.debug("SSH connection closed")


def get_vsan_hcl_timestamp() -> Dict[str, Any]:
    """Retrieve the latest vSAN HCL timestamp information"""
    try:
        logger.info("\nRetrieving vSAN HCL timestamp...")
        url = 'https://partnerweb.vmware.com/service/vsan/all.json?lastupdatedtime'
        headers = {'x-vmw-esp-clientid': 'vsan-hcl-vcf-2023'}
        logger.debug(f"Fetching from URL: {url}")
        
        response = requests.get(url, headers=headers, verify=False, timeout=30)
        response.raise_for_status()
        logger.debug(f"Response status code: {response.status_code}")
        
        # Parse out content between '{...}'
        pattern = r'\{(.+?)\}'
        matched = re.search(pattern, response.text)
        
        if matched:
            timestamp_data = json.loads(matched.group(0))
            logger.info(f"Retrieved vSAN HCL timestamp: {timestamp_data.get('jsonUpdatedTime')}")
            logger.debug(f"Timestamp data: {timestamp_data}")
            return timestamp_data
        else:
            logger.warning("Could not parse vSAN HCL timestamp, using defaults")
            return {
                "timestamp": int(datetime.now().timestamp() * 1000),
                "jsonUpdatedTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
    except Exception as e:
        logger.warning(f"Could not retrieve vSAN HCL timestamp: {str(e)}")
        return {
            "timestamp": int(datetime.now().timestamp() * 1000),
            "jsonUpdatedTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }


def generate_hcl_file(controllers: List[Dict], ssds: List[Dict], 
                     supported_releases: List[str]) -> Dict[str, Any]:
    """Generate the complete HCL JSON structure"""
    logger.info("Generating HCL file structure...")
    logger.debug(f"Controllers: {len(controllers)}, SSDs: {len(ssds)}, Releases: {supported_releases}")
    
    vsan_hcl_time = get_vsan_hcl_timestamp()
    
    hcl_object = {
        "timestamp": vsan_hcl_time.get("timestamp"),
        "jsonUpdatedTime": vsan_hcl_time.get("jsonUpdatedTime"),
        "totalCount": len(ssds) + len(controllers),
        "supportedReleases": supported_releases,
        "eula": {},
        "data": {
            "controller": controllers,
            "ssd": ssds,
            "hdd": []
        }
    }
    
    logger.info(f"HCL file generated with {hcl_object['totalCount']} total entries")
    return hcl_object


def main():
    parser = argparse.ArgumentParser(
        description='Generate custom vSAN ESA HCL JSON file from ESXi hosts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single ESXi host
  %(prog)s --esxi-host 192.168.1.10
  
  # Multiple ESXi hosts
  %(prog)s --esxi-host 192.168.1.10 --esxi-host 192.168.1.11
  
  # With SDDC Manager deployment
  %(prog)s --esxi-host 192.168.1.10 \\
           --sddc-host sddc.example.com
  
  # With VCF Installer deployment (user and root password often the same)
  %(prog)s --esxi-host 192.168.1.10 \\
           --sddc-host vcf-installer.example.com \\
           --sddc-password 'MyPassword' --sddc-root-password 'MyPassword'
  
  # Custom ESXi release
  %(prog)s --esxi-host 192.168.1.10 --release "ESXi 8.0"
        """
    )
    
    # ESXi connection arguments
    parser.add_argument('--esxi-host', action='append', required=True,
                       help='ESXi host(s) to connect to (can be specified multiple times)')
    parser.add_argument('--esxi-user', default='root',
                       help='ESXi username (default: root)')
    parser.add_argument('--esxi-password',
                       help='ESXi password (will prompt if not provided)')
    parser.add_argument('--esxi-port', type=int, default=443,
                       help='ESXi port (default: 443)')
    
    # HCL generation arguments
    parser.add_argument('--release', action='append', default=None,
                       help='Supported ESXi release (default: ESXi 9.0, can be specified multiple times)')
    parser.add_argument('--output', default=None,
                       help='Output filename (default: custom_vsan_esa_hcl_<timestamp>.json)')
    
    # SDDC Manager/VCF Installer arguments
    parser.add_argument('--sddc-host',
                       help='SDDC Manager or VCF Installer hostname or IP')
    parser.add_argument('--sddc-user', default='vcf',
                       help='SDDC Manager/VCF Installer username (default: vcf)')
    parser.add_argument('--sddc-password',
                       help='SDDC Manager/VCF Installer password (will prompt if not provided)')
    parser.add_argument('--sddc-root-password',
                       help='SDDC Manager/VCF Installer root password for su elevation (will prompt if not provided)')
    
    # Logging arguments
    parser.add_argument('--log-dir', default='logs',
                       help='Directory for log files (default: logs)')
    
    args = parser.parse_args()
    
    # Setup logging first
    log_file = setup_logging(args.log_dir)
    logger.info(f"Command line arguments: {' '.join(sys.argv[1:])}")
    
    # Set default release if not specified
    if args.release is None:
        supported_releases = ["ESXi 9.0"]
    else:
        supported_releases = args.release
    
    logger.info(f"Supported ESXi releases: {supported_releases}")
    logger.info(f"Target ESXi hosts: {args.esxi_host}")
    
    # Prompt for ESXi password if not provided
    if not args.esxi_password:
        args.esxi_password = getpass("Enter ESXi password: ")
        logger.debug("ESXi password provided via prompt")
    else:
        logger.debug("ESXi password provided via command line")
    
    # Collect storage information from all ESXi hosts
    all_controllers = []
    all_ssds = []
    
    logger.info(f"\n{'='*60}")
    logger.info("Starting ESXi host data collection")
    logger.info(f"{'='*60}")
    
    for esxi_host in args.esxi_host:
        logger.info(f"\nProcessing ESXi host: {esxi_host}")
        collector = ESXiHCLCollector(
            esxi_host,
            args.esxi_user,
            args.esxi_password,
            args.esxi_port
        )
        
        if collector.connect():
            try:
                controllers, ssds = collector.collect_storage_info(supported_releases)
                all_controllers.extend(controllers)
                all_ssds.extend(ssds)
                logger.info(f"Collected {len(controllers)} controllers and {len(ssds)} SSDs from {esxi_host}")
            except Exception as e:
                logger.error(f"Error collecting data from {esxi_host}: {str(e)}", exc_info=True)
            finally:
                collector.disconnect()
        else:
            logger.warning(f"Skipping {esxi_host} due to connection failure")
    
    if not all_controllers and not all_ssds:
        logger.error("No storage devices collected from any ESXi host")
        sys.exit(1)
    
    logger.info(f"\n{'='*60}")
    logger.info(f"Total collected: {len(all_controllers)} controllers and {len(all_ssds)} SSDs")
    logger.info(f"{'='*60}")
    
    # Generate HCL file
    logger.info("\n" + "="*60)
    logger.info("Generating HCL file")
    logger.info("="*60)
    
    hcl_object = generate_hcl_file(all_controllers, all_ssds, supported_releases)
    hcl_json = json.dumps(hcl_object, indent=2)
    
    logger.debug(f"Generated HCL JSON size: {len(hcl_json)} bytes")
    
    # Save to local file
    if args.output:
        output_filename = args.output
        logger.debug(f"Using custom output filename: {output_filename}")
    else:
        date_time_generated = datetime.now().strftime("%m_%d_%Y_%H_%M_%S")
        output_filename = f"custom_vsan_esa_hcl_{date_time_generated}.json"
        logger.debug(f"Using auto-generated filename: {output_filename}")
    
    logger.info(f"\nSaving Custom vSAN ESA HCL to {output_filename}")
    try:
        with open(output_filename, 'w') as f:
            f.write(hcl_json)
        logger.info(f"Successfully saved HCL file with {hcl_object['totalCount']} total entries")
        logger.debug(f"File written to: {os.path.abspath(output_filename)}")
    except Exception as e:
        logger.error(f"Error writing HCL file: {str(e)}", exc_info=True)
        sys.exit(1)
    
    # Deploy to SDDC Manager/VCF Installer if requested
    if args.sddc_host:
        logger.info("\n" + "="*60)
        logger.info("Starting SDDC Manager/VCF Installer deployment")
        logger.info("="*60)
        
        if not args.sddc_password:
            args.sddc_password = getpass(f"Enter SDDC Manager/VCF Installer password for user '{args.sddc_user}': ")
            logger.debug("SDDC password provided via prompt")
        else:
            logger.debug("SDDC password provided via command line")
        
        if not args.sddc_root_password:
            args.sddc_root_password = getpass("Enter SDDC Manager/VCF Installer root password (for su): ")
            logger.debug("SDDC root password provided via prompt")
        else:
            logger.debug("SDDC root password provided via command line")
        
        deployer = SDDCManagerDeployer(
            args.sddc_host,
            args.sddc_user,
            args.sddc_password,
            args.sddc_root_password
        )
        
        if deployer.deploy_via_ssh(hcl_json):
            logger.info("\n✓ HCL file successfully deployed to SDDC Manager/VCF Installer")
        else:
            logger.error("\n✗ Failed to deploy HCL file to SDDC Manager/VCF Installer")
            sys.exit(1)
    
    logger.info("\n" + "="*60)
    logger.info("vSAN HCL Generator Completed Successfully")
    logger.info(f"Log file: {log_file}")
    logger.info("="*60)


if __name__ == "__main__":
    main()
