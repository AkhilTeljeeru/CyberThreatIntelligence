#!/usr/bin/env python3
"""
File Scanner Module
Scans files for malware and threats
"""

import os
import hashlib
import magic
import re
import json
from datetime import datetime
import subprocess

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

class FileScanner:
    def __init__(self):
        self.threat_signatures = {
            'malware_strings': [
                b'CreateRemoteThread',
                b'VirtualAllocEx',
                b'WriteProcessMemory',
                b'LoadLibraryA',
                b'GetProcAddress',
                b'RegCreateKeyEx',
                b'RegSetValueEx',
                b'ShellExecuteA'
            ],
            'suspicious_patterns': [
                rb'eval\s*\(',
                rb'exec\s*\(',
                rb'system\s*\(',
                rb'shell_exec\s*\(',
                rb'passthru\s*\(',
                rb'base64_decode\s*\(',
            ]
        }
        
        self.file_extensions = {
            'executable': ['.exe', '.dll', '.bat', '.cmd', '.scr', '.pif'],
            'script': ['.js', '.vbs', '.ps1', '.py', '.php', '.pl', '.sh'],
            'document': ['.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx'],
            'archive': ['.zip', '.rar', '.7z', '.tar', '.gz'],
            'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg']
        }
        
        # Load YARA rules if available
        self.yara_rules = None
        if YARA_AVAILABLE:
            self._load_yara_rules()
    
    def scan_file(self, filepath):
        """Comprehensive file scanning"""
        result = {
            'filepath': filepath,
            'filename': os.path.basename(filepath),
            'timestamp': datetime.now().isoformat(),
            'status': 'clean',
            'threats': [],
            'file_info': {},
            'hash_analysis': {},
            'signature_analysis': {},
            'yara_matches': [],
            'risk_score': 0
        }
        
        try:
            # Basic file information
            result['file_info'] = self._get_file_info(filepath)
            
            # Hash analysis
            result['hash_analysis'] = self._calculate_hashes(filepath)
            
            # File type detection
            file_type = self._detect_file_type(filepath)
            result['file_info']['detected_type'] = file_type
            
            # Signature-based detection
            result['signature_analysis'] = self._signature_scan(filepath)
            
            # YARA scanning if available
            if self.yara_rules:
                result['yara_matches'] = self._yara_scan(filepath)
            
            # Behavioral analysis
            behavioral_threats = self._behavioral_analysis(filepath, file_type)
            result['threats'].extend(behavioral_threats)
            
            # Hash reputation check (simulated)
            hash_threats = self._hash_reputation_check(result['hash_analysis'])
            result['threats'].extend(hash_threats)
            
            # Calculate risk score
            result['risk_score'] = self._calculate_risk_score(result)
            
            # Determine final status
            if result['threats'] or result['yara_matches']:
                result['status'] = 'infected'
            elif result['risk_score'] > 50:
                result['status'] = 'suspicious'
            else:
                result['status'] = 'clean'
                
        except Exception as e:
            result['status'] = 'error'
            result['threats'].append(f'Scan error: {str(e)}')
        
        return result
    
    def _get_file_info(self, filepath):
        """Get basic file information"""
        stat = os.stat(filepath)
        
        info = {
            'size': stat.st_size,
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'extension': os.path.splitext(filepath)[1].lower(),
            'permissions': oct(stat.st_mode)[-3:]
        }
        
        # Determine file category
        ext = info['extension']
        info['category'] = 'unknown'
        
        for category, extensions in self.file_extensions.items():
            if ext in extensions:
                info['category'] = category
                break
        
        return info
    
    def _calculate_hashes(self, filepath):
        """Calculate file hashes"""
        hashes = {}
        
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
                
                # MD5
                hashes['md5'] = hashlib.md5(content).hexdigest()
                
                # SHA1
                hashes['sha1'] = hashlib.sha1(content).hexdigest()
                
                # SHA256
                hashes['sha256'] = hashlib.sha256(content).hexdigest()
                
        except Exception as e:
            hashes['error'] = str(e)
        
        return hashes
    
    def _detect_file_type(self, filepath):
        """Detect actual file type using python-magic"""
        try:
            file_type = magic.from_file(filepath)
            return file_type
        except:
            # Fallback to extension-based detection
            ext = os.path.splitext(filepath)[1].lower()
            type_map = {
                '.exe': 'Windows executable',
                '.dll': 'Windows library',
                '.pdf': 'PDF document',
                '.zip': 'ZIP archive',
                '.jpg': 'JPEG image',
                '.png': 'PNG image'
            }
            return type_map.get(ext, 'Unknown file type')
    
    def _signature_scan(self, filepath):
        """Scan for malware signatures"""
        analysis = {
            'malware_strings_found': [],
            'suspicious_patterns_found': [],
            'total_matches': 0
        }
        
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
                
                # Check for malware strings
                for signature in self.threat_signatures['malware_strings']:
                    if signature in content:
                        analysis['malware_strings_found'].append(signature.decode('utf-8', errors='ignore'))
                
                # Check for suspicious patterns
                for pattern in self.threat_signatures['suspicious_patterns']:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        analysis['suspicious_patterns_found'].extend([m.decode('utf-8', errors='ignore') for m in matches])
                
                analysis['total_matches'] = len(analysis['malware_strings_found']) + len(analysis['suspicious_patterns_found'])
                
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _load_yara_rules(self):
        """Load YARA rules for malware detection"""
        try:
            # Create simple YARA rules
            rules_content = '''
            rule SuspiciousStrings
            {
                strings:
                    $s1 = "CreateRemoteThread"
                    $s2 = "VirtualAllocEx"
                    $s3 = "WriteProcessMemory"
                    $s4 = "LoadLibraryA"
                    $s5 = "GetProcAddress"
                    $s6 = "RegCreateKeyEx"
                    
                condition:
                    any of them
            }
            
            rule SuspiciousJavaScript
            {
                strings:
                    $js1 = "eval("
                    $js2 = "document.write"
                    $js3 = "unescape("
                    $js4 = "fromCharCode"
                    
                condition:
                    2 of them
            }
            
            rule PackedExecutable
            {
                strings:
                    $upx = "UPX!"
                    $packed1 = "This program cannot be run in DOS mode"
                    $packed2 = { 4D 5A }
                    
                condition:
                    $upx or ($packed1 and $packed2)
            }
            '''
            
            self.yara_rules = yara.compile(source=rules_content)
            
        except Exception as e:
            print(f"Failed to load YARA rules: {e}")
            self.yara_rules = None
    
    def _yara_scan(self, filepath):
        """Perform YARA scan on file"""
        matches = []
        
        try:
            yara_matches = self.yara_rules.match(filepath)
            
            for match in yara_matches:
                match_info = {
                    'rule': match.rule,
                    'tags': match.tags,
                    'strings': []
                }
                
                for string_match in match.strings:
                    match_info['strings'].append({
                        'identifier': string_match.identifier,
                        'instances': len(string_match.instances)
                    })
                
                matches.append(match_info)
                
        except Exception as e:
            matches.append({'error': str(e)})
        
        return matches
    
    def _behavioral_analysis(self, filepath, file_type):
        """Analyze file for behavioral indicators"""
        threats = []
        
        try:
            file_size = os.path.getsize(filepath)
            filename = os.path.basename(filepath)
            
            # Check for suspicious file names
            suspicious_names = [
                'setup.exe', 'install.exe', 'update.exe', 'crack.exe',
                'keygen.exe', 'patch.exe', 'loader.exe', 'backdoor'
            ]
            
            if any(name in filename.lower() for name in suspicious_names):
                threats.append(f'Suspicious filename: {filename}')
            
            # Check for unusual file sizes
            if file_size == 0:
                threats.append('Zero-byte file (potentially corrupted or malicious)')
            elif file_size < 100 and filepath.endswith('.exe'):
                threats.append('Unusually small executable file')
            
            # Check for double extensions
            if filename.count('.') > 1:
                threats.append('File with double extension (potential social engineering)')
            
            # Check for executable disguised as document
            doc_extensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx']
            if any(ext in filename.lower() for ext in doc_extensions) and 'executable' in file_type.lower():
                threats.append('Executable file disguised as document')
                
        except Exception as e:
            threats.append(f'Behavioral analysis error: {str(e)}')
        
        return threats
    
    def _hash_reputation_check(self, hash_analysis):
        """Check file hashes against threat database (simulated)"""
        threats = []
        
        # Simulated known malicious hashes
        known_malicious = {
            'md5': [
                '5d41402abc4b2a76b9719d911017c592',  # Example hash
                '098f6bcd4621d373cade4e832627b4f6'   # Example hash
            ],
            'sha1': [
                'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d',  # Example hash
            ],
            'sha256': [
                'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'  # Example hash
            ]
        }
        
        for hash_type, hash_value in hash_analysis.items():
            if hash_type in known_malicious and hash_value in known_malicious[hash_type]:
                threats.append(f'File matches known malicious {hash_type.upper()} hash')
        
        return threats
    
    def _calculate_risk_score(self, result):
        """Calculate overall risk score"""
        score = 0
        
        # Base score on threats found
        score += len(result['threats']) * 25
        
        # Add score for signature matches
        signature_matches = result['signature_analysis'].get('total_matches', 0)
        score += signature_matches * 15
        
        # Add score for YARA matches
        score += len(result['yara_matches']) * 30
        
        # Add score based on file category
        category = result['file_info'].get('category', 'unknown')
        if category == 'executable':
            score += 10
        elif category == 'script':
            score += 5
        
        # Cap the score at 100
        return min(100, score)