#!/usr/bin/env python3
"""
Threat Database Module
Simple in-memory database for storing scan results and statistics
"""

import json
import os
from datetime import datetime, timedelta

class ThreatDatabase:
    def __init__(self):
        self.data_file = 'threat_database.json'
        self.data = {
            'url_scans': [],
            'file_scans': [],
            'usb_scans': [],
            'statistics': {
                'total_scans': 0,
                'threats_detected': 0,
                'clean_files': 0,
                'open_ports_found': 0
            }
        }
        self.load_data()
    
    def load_data(self):
        """Load data from JSON file"""
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r') as f:
                    self.data = json.load(f)
        except Exception as e:
            print(f"Error loading threat database: {e}")
    
    def save_data(self):
        """Save data to JSON file"""
        try:
            with open(self.data_file, 'w') as f:
                json.dump(self.data, f, indent=2)
        except Exception as e:
            print(f"Error saving threat database: {e}")
    
    def store_url_scan(self, url, result):
        """Store URL scan result"""
        scan_entry = {
            'id': self._generate_scan_id(),
            'url': url,
            'result': result,
            'timestamp': datetime.now().isoformat()
        }
        
        self.data['url_scans'].append(scan_entry)
        self._update_statistics('url', result)
        self.save_data()
        
        return scan_entry['id']
    
    def store_file_scan(self, filename, result):
        """Store file scan result"""
        scan_entry = {
            'id': self._generate_scan_id(),
            'filename': filename,
            'result': result,
            'timestamp': datetime.now().isoformat()
        }
        
        self.data['file_scans'].append(scan_entry)
        self._update_statistics('file', result)
        self.save_data()
        
        return scan_entry['id']
    
    def store_usb_scan(self, device_id, result):
        """Store USB scan result"""
        scan_entry = {
            'id': self._generate_scan_id(),
            'device_id': device_id,
            'result': result,
            'timestamp': datetime.now().isoformat()
        }
        
        self.data['usb_scans'].append(scan_entry)
        self._update_statistics('usb', result)
        self.save_data()
        
        return scan_entry['id']
    
    def get_scan_data(self, scan_type, scan_id):
        """Get scan data by type and ID"""
        scan_list = self.data.get(f'{scan_type}_scans', [])
        
        for scan in scan_list:
            if scan['id'] == scan_id:
                return scan['result']
        
        return None
    
    def get_total_scans(self):
        """Get total number of scans"""
        return self.data['statistics']['total_scans']
    
    def get_threats_count(self):
        """Get total threats detected"""
        return self.data['statistics']['threats_detected']
    
    def get_clean_files_count(self):
        """Get total clean files"""
        return self.data['statistics']['clean_files']
    
    def get_open_ports_count(self):
        """Get total open ports found"""
        return self.data['statistics']['open_ports_found']
    
    def get_recent_threats(self, limit=5):
        """Get recent threat detections"""
        threats = []
        
        # Collect threats from all scan types
        for scan_type in ['url_scans', 'file_scans', 'usb_scans']:
            for scan in self.data.get(scan_type, []):
                result = scan['result']
                if result.get('threats'):
                    for threat in result['threats']:
                        threats.append({
                            'id': len(threats) + 1,
                            'name': threat,
                            'source': self._get_scan_source(scan_type, scan),
                            'time': self._format_time_ago(scan['timestamp']),
                            'severity': self._get_threat_severity(threat),
                            'status': 'detected'
                        })
        
        # Sort by timestamp and return recent ones
        threats.sort(key=lambda x: x['time'], reverse=True)
        return threats[:limit]
    
    def get_all_reports(self):
        """Get list of all available reports"""
        reports = []
        
        # URL scan reports
        for scan in self.data.get('url_scans', []):
            reports.append({
                'id': scan['id'],
                'type': 'URL Scan',
                'target': scan['url'],
                'timestamp': scan['timestamp'],
                'status': scan['result'].get('status', 'unknown'),
                'threats': len(scan['result'].get('threats', []))
            })
        
        # File scan reports
        for scan in self.data.get('file_scans', []):
            reports.append({
                'id': scan['id'],
                'type': 'File Scan',
                'target': scan['filename'],
                'timestamp': scan['timestamp'],
                'status': scan['result'].get('status', 'unknown'),
                'threats': len(scan['result'].get('threats', []))
            })
        
        # USB scan reports
        for scan in self.data.get('usb_scans', []):
            reports.append({
                'id': scan['id'],
                'type': 'USB Scan',
                'target': scan['device_id'],
                'timestamp': scan['timestamp'],
                'status': scan['result'].get('status', 'unknown'),
                'threats': len(scan['result'].get('threats', []))
            })
        
        # Sort by timestamp (newest first)
        reports.sort(key=lambda x: x['timestamp'], reverse=True)
        return reports
    
    def _generate_scan_id(self):
        """Generate unique scan ID"""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def _update_statistics(self, scan_type, result):
        """Update scan statistics"""
        self.data['statistics']['total_scans'] += 1
        
        threats = result.get('threats', [])
        if threats:
            self.data['statistics']['threats_detected'] += len(threats)
        else:
            self.data['statistics']['clean_files'] += 1
        
        # Count open ports for URL scans
        if scan_type == 'url':
            open_ports = result.get('open_ports', [])
            self.data['statistics']['open_ports_found'] += len(open_ports)
    
    def _get_scan_source(self, scan_type, scan):
        """Get scan source description"""
        if scan_type == 'url_scans':
            return scan['url']
        elif scan_type == 'file_scans':
            return scan['filename']
        elif scan_type == 'usb_scans':
            return scan['device_id']
        else:
            return 'Unknown'
    
    def _format_time_ago(self, timestamp_str):
        """Format timestamp as time ago"""
        try:
            timestamp = datetime.fromisoformat(timestamp_str)
            now = datetime.now()
            diff = now - timestamp
            
            if diff.days > 0:
                return f'{diff.days} days ago'
            elif diff.seconds > 3600:
                hours = diff.seconds // 3600
                return f'{hours} hours ago'
            elif diff.seconds > 60:
                minutes = diff.seconds // 60
                return f'{minutes} minutes ago'
            else:
                return 'Just now'
        except:
            return 'Unknown'
    
    def _get_threat_severity(self, threat):
        """Determine threat severity"""
        high_severity_keywords = ['malware', 'virus', 'trojan', 'ransomware', 'exploit']
        medium_severity_keywords = ['suspicious', 'phishing', 'adware', 'potentially']
        
        threat_lower = threat.lower()
        
        if any(keyword in threat_lower for keyword in high_severity_keywords):
            return 'High'
        elif any(keyword in threat_lower for keyword in medium_severity_keywords):
            return 'Medium'
        else:
            return 'Low'