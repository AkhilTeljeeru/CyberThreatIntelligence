#!/usr/bin/env python3
"""
USB Monitor Module
Monitors USB devices and scans for threats
"""

import psutil
import threading
import time
import os
import json
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class USBEventHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback
        
    def on_created(self, event):
        if not event.is_directory:
            self.callback({
                'type': 'file_created',
                'path': event.src_path,
                'timestamp': datetime.now().isoformat()
            })
    
    def on_deleted(self, event):
        if not event.is_directory:
            self.callback({
                'type': 'file_deleted',
                'path': event.src_path,
                'timestamp': datetime.now().isoformat()
            })

class USBMonitor:
    def __init__(self):
        self.monitoring = False
        self.observer = None
        self.callback = None
        self.connected_devices = {}
        self.activity_log = []
        self.scan_results = {}
        
    def is_monitoring(self):
        """Check if USB monitoring is active"""
        return self.monitoring
    
    def start_monitoring(self, callback=None):
        """Start USB device monitoring"""
        if self.monitoring:
            return False
            
        self.callback = callback
        self.monitoring = True
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self._monitor_loop)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        return True
    
    def stop_monitoring(self):
        """Stop USB monitoring"""
        self.monitoring = False
        if self.observer:
            self.observer.stop()
            self.observer.join()
    
    def get_connected_devices(self):
        """Get list of connected USB devices"""
        devices = []
        
        try:
            # Get disk partitions
            partitions = psutil.disk_partitions()
            
            for partition in partitions:
                # Check if it's a removable drive (likely USB)
                if 'removable' in partition.opts or partition.fstype in ['FAT32', 'exFAT', 'NTFS']:
                    try:
                        usage = psutil.disk_usage(partition.mountpoint)
                        
                        device_info = {
                            'id': partition.device,
                            'mountpoint': partition.mountpoint,
                            'fstype': partition.fstype,
                            'total_size': usage.total,
                            'used_size': usage.used,
                            'free_size': usage.free,
                            'device_name': self._get_device_name(partition.device),
                            'last_seen': datetime.now().isoformat()
                        }
                        
                        devices.append(device_info)
                        self.connected_devices[partition.device] = device_info
                        
                    except (PermissionError, FileNotFoundError):
                        continue
                        
        except Exception as e:
            print(f"Error getting USB devices: {e}")
        
        return devices
    
    def get_recent_activity(self):
        """Get recent USB activity log"""
        return self.activity_log[-10:]  # Return last 10 activities
    
    def scan_device(self, device_id):
        """Scan specific USB device for threats"""
        result = {
            'device_id': device_id,
            'timestamp': datetime.now().isoformat(),
            'status': 'clean',
            'threats': [],
            'files_scanned': 0,
            'infected_files': [],
            'suspicious_files': [],
            'scan_summary': {}
        }
        
        try:
            if device_id not in self.connected_devices:
                result['status'] = 'error'
                result['threats'].append('Device not found or disconnected')
                return result
            
            device = self.connected_devices[device_id]
            mountpoint = device['mountpoint']
            
            # Scan files on the device
            scan_summary = self._scan_device_files(mountpoint)
            result.update(scan_summary)
            
            # Check for autorun.inf
            autorun_threats = self._check_autorun(mountpoint)
            result['threats'].extend(autorun_threats)
            
            # Check for suspicious file patterns
            pattern_threats = self._check_suspicious_patterns(mountpoint)
            result['threats'].extend(pattern_threats)
            
            # Determine overall status
            if result['threats'] or result['infected_files']:
                result['status'] = 'infected'
            elif result['suspicious_files']:
                result['status'] = 'suspicious'
            else:
                result['status'] = 'clean'
            
            # Store scan result
            self.scan_results[device_id] = result
            
        except Exception as e:
            result['status'] = 'error'
            result['threats'].append(f'Scan error: {str(e)}')
        
        return result
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        previous_devices = set()
        
        while self.monitoring:
            try:
                current_devices = set(device['id'] for device in self.get_connected_devices())
                
                # Check for new devices
                new_devices = current_devices - previous_devices
                for device_id in new_devices:
                    self._log_activity('device_connected', device_id)
                    if self.callback:
                        self.callback({
                            'type': 'device_connected',
                            'device_id': device_id,
                            'timestamp': datetime.now().isoformat()
                        })
                
                # Check for removed devices
                removed_devices = previous_devices - current_devices
                for device_id in removed_devices:
                    self._log_activity('device_disconnected', device_id)
                    if self.callback:
                        self.callback({
                            'type': 'device_disconnected',
                            'device_id': device_id,
                            'timestamp': datetime.now().isoformat()
                        })
                
                previous_devices = current_devices
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                print(f"USB monitoring error: {e}")
                time.sleep(5)
    
    def _scan_device_files(self, mountpoint):
        """Scan all files on USB device"""
        result = {
            'files_scanned': 0,
            'infected_files': [],
            'suspicious_files': [],
            'scan_summary': {
                'total_files': 0,
                'executables': 0,
                'scripts': 0,
                'documents': 0,
                'hidden_files': 0
            }
        }
        
        try:
            for root, dirs, files in os.walk(mountpoint):
                for file in files:
                    filepath = os.path.join(root, file)
                    
                    try:
                        result['files_scanned'] += 1
                        result['scan_summary']['total_files'] += 1
                        
                        # Check if file is hidden
                        if file.startswith('.') or self._is_hidden_file(filepath):
                            result['scan_summary']['hidden_files'] += 1
                        
                        # Categorize file
                        ext = os.path.splitext(file)[1].lower()
                        if ext in ['.exe', '.dll', '.scr', '.bat', '.cmd']:
                            result['scan_summary']['executables'] += 1
                            # Executables are suspicious on USB drives
                            result['suspicious_files'].append({
                                'path': filepath,
                                'reason': 'Executable file on removable media'
                            })
                        elif ext in ['.js', '.vbs', '.ps1', '.py', '.sh']:
                            result['scan_summary']['scripts'] += 1
                            result['suspicious_files'].append({
                                'path': filepath,
                                'reason': 'Script file on removable media'
                            })
                        elif ext in ['.doc', '.docx', '.pdf', '.xls', '.xlsx']:
                            result['scan_summary']['documents'] += 1
                        
                        # Check for malware signatures
                        if self._quick_malware_check(filepath):
                            result['infected_files'].append({
                                'path': filepath,
                                'threat': 'Malware signature detected'
                            })
                    
                    except (PermissionError, FileNotFoundError):
                        continue
                    
        except Exception as e:
            print(f"Error scanning device files: {e}")
        
        return result
    
    def _check_autorun(self, mountpoint):
        """Check for autorun.inf and similar files"""
        threats = []
        
        autorun_files = ['autorun.inf', 'autorun.exe', 'setup.exe', 'run.exe']
        
        for filename in autorun_files:
            filepath = os.path.join(mountpoint, filename)
            if os.path.exists(filepath):
                threats.append(f'Suspicious autorun file found: {filename}')
                
                # If it's autorun.inf, check its contents
                if filename == 'autorun.inf':
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read().lower()
                            if 'shellexecute' in content or 'shell\\open\\command' in content:
                                threats.append('Autorun.inf contains suspicious execution commands')
                    except:
                        pass
        
        return threats
    
    def _check_suspicious_patterns(self, mountpoint):
        """Check for suspicious file patterns"""
        threats = []
        
        try:
            # Check for files with double extensions
            for root, dirs, files in os.walk(mountpoint):
                for file in files:
                    if file.count('.') > 1:
                        # Check for dangerous double extensions
                        if any(ext in file.lower() for ext in ['.exe', '.scr', '.bat', '.cmd']):
                            threats.append(f'File with suspicious double extension: {file}')
                    
                    # Check for very long filenames (potential buffer overflow)
                    if len(file) > 255:
                        threats.append(f'Suspicious long filename: {file[:50]}...')
                    
                    # Check for files with spaces at the end (potential social engineering)
                    if file.endswith(' ') or file.endswith('\t'):
                        threats.append(f'File with trailing spaces: {file}')
        
        except Exception as e:
            print(f"Error checking suspicious patterns: {e}")
        
        return threats
    
    def _quick_malware_check(self, filepath):
        """Quick malware signature check"""
        try:
            # Only check small files to avoid performance issues
            if os.path.getsize(filepath) > 1024 * 1024:  # 1MB limit
                return False
            
            with open(filepath, 'rb') as f:
                content = f.read(1024)  # Read first 1KB
                
                # Check for common malware signatures
                malware_signatures = [
                    b'CreateRemoteThread',
                    b'VirtualAllocEx',
                    b'WriteProcessMemory',
                    b'This program cannot be run in DOS mode'
                ]
                
                return any(sig in content for sig in malware_signatures)
                
        except:
            return False
    
    def _is_hidden_file(self, filepath):
        """Check if file is hidden (Windows)"""
        try:
            import stat
            return bool(os.stat(filepath).st_file_attributes & stat.FILE_ATTRIBUTE_HIDDEN)
        except:
            return False
    
    def _get_device_name(self, device_id):
        """Get friendly name for USB device"""
        # Simplified device name extraction
        if 'USB' in device_id.upper():
            return 'USB Drive'
        elif 'SD' in device_id.upper():
            return 'SD Card'
        else:
            return 'Removable Drive'
    
    def _log_activity(self, activity_type, device_id):
        """Log USB activity"""
        activity = {
            'type': activity_type,
            'device_id': device_id,
            'timestamp': datetime.now().isoformat()
        }
        
        self.activity_log.append(activity)
        
        # Keep only last 100 activities
        if len(self.activity_log) > 100:
            self.activity_log = self.activity_log[-100:]