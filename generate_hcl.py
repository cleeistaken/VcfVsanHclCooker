#!/usr/bin/env python3
"""
Author: Converted from William Lam's PowerShell script
Description: Dynamically generate custom vSAN ESA HCL JSON file by connecting to ESXi hosts
             and optionally deploy to SDDC Manager
"""

import argparse
import json
import random
import requests
import re
import sys
from datetime import datetime
from typing import List, Dict, Any, Optional
from getpass import getpass
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


class ESXiHCLCollector:
    """Collects disk and controller information from ESXi hosts"""
    
    def __init__(self, host: str, username: str, password: str, port: int = 443):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.si = None
        
    def connect(self):
        """Connect to ESXi host"""
        try:
            print(f"Connecting to ESXi host {self.host}...")
            self.si = SmartConnect(
                host=self.host,
                user=self.username,
                pwd=self.password,
                port=self.port,
                disableSslCertValidation=True
            )
            return True
        except Exception as e:
            print(f"Error connecting to {self.host}: {str(e)}")
            return False
    
    def disconnect(self):
        """Disconnect from ESXi host"""
        if self.si:
            Disconnect(self.si)
    
    def get_vibs(self, vmhost) -> Dict[str, str]:
        """Get installed VIB packages and their versions"""
        vibs = {}
        try:
            image_manager = vmhost.configManager.imageConfigManager
            if image_manager:
                packages = image_manager.FetchSoftwarePackages()
                for package in packages:
                    vibs[package.name] = package.version
        except Exception as e:
            print(f"Warning: Could not fetch VIB packages: {str(e)}")
        return vibs
    
    def collect_storage_info(self, supported_releases: List[str]) -> tuple:
        """Collect storage controller and disk information from ESXi host"""
        content = self.si.RetrieveContent()
        
        # Get the first host (for standalone ESXi) or iterate through hosts
        host_view = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.HostSystem], True
        )
        hosts = host_view.view
        host_view.Destroy()
        
        all_controllers = []
        all_ssds = []
        
        for vmhost in hosts:
            print(f"\nCollecting SSD information from ESXi host {vmhost.name}...")
            
            vibs = self.get_vibs(vmhost)
            
            storage_system = vmhost.configManager.storageSystem
            if not storage_system:
                print(f"Warning: Could not access storage system on {vmhost.name}")
                continue
            
            storage_devices = storage_system.storageDeviceInfo.scsiTopology.adapter
            storage_adapters = storage_system.storageDeviceInfo.hostBusAdapter
            devices = storage_system.storageDeviceInfo.scsiLun
            pci_devices = vmhost.hardware.pciDevice
            
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
                            
                            # Get controller driver version
                            if controller_type == "nvme_pcie":
                                controller_driver = vibs.get("nvme-pcie", "unknown")
                            elif controller_type == "pvscsi":
                                controller_driver = vibs.get("pvscsi", "unknown")
                            else:
                                controller_driver = "unknown"
                            
                            # Get device revision/firmware
                            firmware = getattr(device, 'revision', 'unknown')
                            
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
                                # Get capacity
                                capacity = 0
                                if hasattr(device, 'capacity'):
                                    capacity = int((device.capacity.blockSize * device.capacity.block) / 1048576)
                                
                                # Get device protocol
                                device_protocol = getattr(device, 'applicationProtocol', 'unknown')
                                
                                # Get vendor and model
                                vendor = getattr(device, 'vendor', 'unknown').strip()
                                model = getattr(device, 'model', 'unknown').strip()
                                serial = getattr(device, 'serialNumber', 'unknown')
                                
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
        
        return all_controllers, all_ssds


class SDDCManagerDeployer:
    """Handles deployment of HCL file to SDDC Manager"""
    
    def __init__(self, sddc_host: str, sddc_user: str, sddc_password: str, root_password: str):
        self.sddc_host = sddc_host
        self.sddc_user = sddc_user
        self.sddc_password = sddc_password
        self.root_password = root_password
        self.target_path = "/nfs/vmware/vcf/nfs-mount/vsan-hcl/all.json"
    
    def deploy_via_ssh(self, hcl_content: str) -> bool:
        """Deploy HCL file to SDDC Manager via SSH with su elevation"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            print(f"\nConnecting to SDDC Manager {self.sddc_host} via SSH...")
            ssh.connect(
                self.sddc_host,
                username=self.sddc_user,
                password=self.sddc_password,
                look_for_keys=False,
                allow_agent=False
            )
            
            # Create a temporary file with the HCL content
            temp_file = f"/tmp/vsan_hcl_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            print(f"Creating temporary file {temp_file}...")
            sftp = ssh.open_sftp()
            with sftp.file(temp_file, 'w') as f:
                f.write(hcl_content)
            sftp.close()
            
            print(f"Deploying HCL file to {self.target_path}...")
            
            # Use su to execute commands as root
            # Create backup of existing file
            backup_cmd = f"su - root -c 'cp {self.target_path} {self.target_path}.backup 2>/dev/null || true'"
            print("Creating backup of existing HCL file...")
            stdin, stdout, stderr = ssh.exec_command(backup_cmd, get_pty=True)
            stdin.write(f"{self.root_password}\n")
            stdin.flush()
            exit_status = stdout.channel.recv_exit_status()
            
            # Copy new file to target location using su
            copy_cmd = f"su - root -c 'cp {temp_file} {self.target_path}'"
            print("Copying new HCL file to target location...")
            stdin, stdout, stderr = ssh.exec_command(copy_cmd, get_pty=True)
            stdin.write(f"{self.root_password}\n")
            stdin.flush()
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status != 0:
                error = stderr.read().decode()
                print(f"Error copying file: {error}")
                return False
            
            # Set proper permissions using su
            chmod_cmd = f"su - root -c 'chmod 644 {self.target_path}'"
            print("Setting file permissions...")
            stdin, stdout, stderr = ssh.exec_command(chmod_cmd, get_pty=True)
            stdin.write(f"{self.root_password}\n")
            stdin.flush()
            stdout.channel.recv_exit_status()
            
            # Clean up temporary file
            cleanup_cmd = f"rm -f {temp_file}"
            stdin, stdout, stderr = ssh.exec_command(cleanup_cmd)
            stdout.channel.recv_exit_status()
            
            print(f"Successfully deployed HCL file to SDDC Manager")
            print(f"Backup saved as {self.target_path}.backup")
            return True
            
        except Exception as e:
            print(f"Error deploying to SDDC Manager: {str(e)}")
            return False
        finally:
            ssh.close()


def get_vsan_hcl_timestamp() -> Dict[str, Any]:
    """Retrieve the latest vSAN HCL timestamp information"""
    try:
        print("\nRetrieving vSAN HCL timestamp...")
        url = 'https://partnerweb.vmware.com/service/vsan/all.json?lastupdatedtime'
        headers = {'x-vmw-esp-clientid': 'vsan-hcl-vcf-2023'}
        
        response = requests.get(url, headers=headers, verify=False, timeout=30)
        response.raise_for_status()
        
        # Parse out content between '{...}'
        pattern = r'\{(.+?)\}'
        matched = re.search(pattern, response.text)
        
        if matched:
            return json.loads(matched.group(0))
        else:
            print("Warning: Could not parse vSAN HCL timestamp, using defaults")
            return {
                "timestamp": int(datetime.now().timestamp() * 1000),
                "jsonUpdatedTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
    except Exception as e:
        print(f"Warning: Could not retrieve vSAN HCL timestamp: {str(e)}")
        return {
            "timestamp": int(datetime.now().timestamp() * 1000),
            "jsonUpdatedTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }


def generate_hcl_file(controllers: List[Dict], ssds: List[Dict], 
                     supported_releases: List[str]) -> Dict[str, Any]:
    """Generate the complete HCL JSON structure"""
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
    
    return hcl_object


def main():
    parser = argparse.ArgumentParser(
        description='Generate custom vSAN ESA HCL JSON file from ESXi hosts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single ESXi host
  %(prog)s --esxi-host 192.168.1.10 --esxi-user root
  
  # Multiple ESXi hosts
  %(prog)s --esxi-host 192.168.1.10 --esxi-host 192.168.1.11 --esxi-user root
  
  # With SDDC Manager deployment
  %(prog)s --esxi-host 192.168.1.10 --esxi-user root \\
           --sddc-host sddc.example.com --sddc-user vcf --sddc-root-password 'RootPass123'
  
  # Custom ESXi release
  %(prog)s --esxi-host 192.168.1.10 --esxi-user root --release "ESXi 8.0"
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
    
    # SDDC Manager arguments
    parser.add_argument('--sddc-host',
                       help='SDDC Manager hostname or IP')
    parser.add_argument('--sddc-user',
                       help='SDDC Manager username')
    parser.add_argument('--sddc-password',
                       help='SDDC Manager password (will prompt if not provided)')
    parser.add_argument('--sddc-root-password',
                       help='SDDC Manager root password for su elevation (will prompt if not provided)')
    
    args = parser.parse_args()
    
    # Set default release if not specified
    if args.release is None:
        supported_releases = ["ESXi 9.0"]
    else:
        supported_releases = args.release
    
    # Prompt for ESXi password if not provided
    if not args.esxi_password:
        args.esxi_password = getpass("Enter ESXi password: ")
    
    # Collect storage information from all ESXi hosts
    all_controllers = []
    all_ssds = []
    
    for esxi_host in args.esxi_host:
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
                print(f"Collected {len(controllers)} controllers and {len(ssds)} SSDs from {esxi_host}")
            except Exception as e:
                print(f"Error collecting data from {esxi_host}: {str(e)}")
            finally:
                collector.disconnect()
        else:
            print(f"Skipping {esxi_host} due to connection failure")
    
    if not all_controllers and not all_ssds:
        print("\nError: No storage devices collected from any ESXi host")
        sys.exit(1)
    
    print(f"\nTotal collected: {len(all_controllers)} controllers and {len(all_ssds)} SSDs")
    
    # Generate HCL file
    hcl_object = generate_hcl_file(all_controllers, all_ssds, supported_releases)
    hcl_json = json.dumps(hcl_object, indent=2)
    
    # Save to local file
    if args.output:
        output_filename = args.output
    else:
        date_time_generated = datetime.now().strftime("%m_%d_%Y_%H_%M_%S")
        output_filename = f"custom_vsan_esa_hcl_{date_time_generated}.json"
    
    print(f"\nSaving Custom vSAN ESA HCL to {output_filename}")
    with open(output_filename, 'w') as f:
        f.write(hcl_json)
    
    print(f"Successfully saved HCL file with {hcl_object['totalCount']} total entries")
    
    # Deploy to SDDC Manager if requested
    if args.sddc_host:
        if not args.sddc_user:
            args.sddc_user = input("Enter SDDC Manager username: ")
        
        if not args.sddc_password:
            args.sddc_password = getpass("Enter SDDC Manager password: ")
        
        if not args.sddc_root_password:
            args.sddc_root_password = getpass("Enter SDDC Manager root password (for su): ")
        
        deployer = SDDCManagerDeployer(
            args.sddc_host,
            args.sddc_user,
            args.sddc_password,
            args.sddc_root_password
        )
        
        if deployer.deploy_via_ssh(hcl_json):
            print("\n✓ HCL file successfully deployed to SDDC Manager")
        else:
            print("\n✗ Failed to deploy HCL file to SDDC Manager")
            sys.exit(1)
    
    print("\nDone!")


if __name__ == "__main__":
    main()

