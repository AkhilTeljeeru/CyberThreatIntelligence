#!/usr/bin/env python3
"""
URL Scanner Module
Scans URLs for threats, malware, and open ports
"""

import requests
import socket
import threading
import re
import hashlib
import json
from urllib.parse import urlparse
from datetime import datetime
import dns.resolver
import whois

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

class URLScanner:
    def __init__(self):
        self.threat_signatures = [
            'eval(', 'document.write', '<script', 'javascript:',
            'onclick=', 'onload=', 'onerror=', 'prompt(',
            'alert(', 'confirm(', 'location.href', 'window.open'
        ]
        
        self.malicious_domains = [
            'malware-site.com', 'phishing-example.com',
            'suspicious-domain.org', 'threat-site.net'
        ]
    
    def scan_url(self, url):
        """Comprehensive URL scanning"""
        result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'status': 'safe',
            'threats': [],
            'details': {},
            'reputation': 85,
            'ssl_valid': False,
            'redirects': 0,
            'response_time': 0,
            'content_analysis': {},
            'dns_info': {},
            'whois_info': {}
        }
        
        try:
            # Basic URL validation
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                result['status'] = 'invalid'
                result['threats'].append('Invalid URL format')
                return result
            
            # DNS resolution
            result['dns_info'] = self._get_dns_info(parsed_url.netloc)
            
            # WHOIS information
            try:
                whois_data = whois.whois(parsed_url.netloc)
                result['whois_info'] = {
                    'registrar': str(whois_data.registrar) if whois_data.registrar else 'Unknown',
                    'creation_date': str(whois_data.creation_date) if whois_data.creation_date else 'Unknown',
                    'country': str(whois_data.country) if whois_data.country else 'Unknown'
                }
            except:
                result['whois_info'] = {'error': 'WHOIS lookup failed'}
            
            # HTTP request analysis
            start_time = datetime.now()
            
            headers = {
                'User-Agent': 'CTI-Platform-Scanner/1.0'
            }
            
            response = requests.get(url, headers=headers, timeout=30, 
                                  allow_redirects=True, verify=False)
            
            end_time = datetime.now()
            result['response_time'] = int((end_time - start_time).total_seconds() * 1000)
            
            # SSL/TLS check
            if parsed_url.scheme == 'https':
                result['ssl_valid'] = self._check_ssl(parsed_url.netloc)
            
            # Redirect analysis
            if response.history:
                result['redirects'] = len(response.history)
                if result['redirects'] > 3:
                    result['threats'].append(f'Excessive redirects ({result["redirects"]})')
            
            # Content analysis
            content = response.text.lower()
            result['content_analysis'] = self._analyze_content(content)
            
            # Threat detection
            threats = self._detect_threats(content, parsed_url.netloc)
            result['threats'].extend(threats)
            
            # Reputation calculation
            result['reputation'] = self._calculate_reputation(result)
            
            # Overall status
            if result['threats']:
                result['status'] = 'threat'
            elif result['reputation'] < 50:
                result['status'] = 'suspicious'
            else:
                result['status'] = 'safe'
            
            # Additional details
            result['details'] = {
                'status_code': response.status_code,
                'content_type': response.headers.get('content-type', 'unknown'),
                'server': response.headers.get('server', 'unknown'),
                'content_length': len(response.content),
                'ip_address': socket.gethostbyname(parsed_url.netloc)
            }
            
        except requests.exceptions.RequestException as e:
            result['status'] = 'error'
            result['threats'].append(f'Network error: {str(e)}')
        except Exception as e:
            result['status'] = 'error'
            result['threats'].append(f'Scan error: {str(e)}')
        
        return result
    
    def scan_ports(self, url):
        """Scan common ports on the target host"""
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc.split(':')[0]  # Remove port if present
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443, 3389]
        open_ports = []
        
        if NMAP_AVAILABLE:
            try:
                nm = nmap.PortScanner()
                nm.scan(hostname, '21-8443')
                
                for host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        for port in ports:
                            state = nm[host][proto][port]['state']
                            if state == 'open':
                                service = nm[host][proto][port]['name']
                                open_ports.append({
                                    'port': port,
                                    'service': service,
                                    'state': state
                                })
            except Exception as e:
                # Fallback to manual scanning
                return self._manual_port_scan(hostname, common_ports)
        else:
            return self._manual_port_scan(hostname, common_ports)
        
        return open_ports
    
    def _manual_port_scan(self, hostname, ports):
        """Manual port scanning when nmap is not available"""
        open_ports = []
        
        def scan_port(host, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((host, port))
                if result == 0:
                    service = socket.getservbyport(port) if port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995] else 'unknown'
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'state': 'open'
                    })
                sock.close()
            except:
                pass
        
        threads = []
        for port in ports:
            thread = threading.Thread(target=scan_port, args=(hostname, port))
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join()
        
        return sorted(open_ports, key=lambda x: x['port'])
    
    def _get_dns_info(self, hostname):
        """Get DNS information for hostname"""
        dns_info = {}
        
        try:
            # A record
            a_records = dns.resolver.resolve(hostname, 'A')
            dns_info['A'] = [str(r) for r in a_records]
        except:
            dns_info['A'] = []
        
        try:
            # MX record
            mx_records = dns.resolver.resolve(hostname, 'MX')
            dns_info['MX'] = [str(r) for r in mx_records]
        except:
            dns_info['MX'] = []
        
        try:
            # NS record
            ns_records = dns.resolver.resolve(hostname, 'NS')
            dns_info['NS'] = [str(r) for r in ns_records]
        except:
            dns_info['NS'] = []
        
        return dns_info
    
    def _check_ssl(self, hostname):
        """Check SSL certificate validity"""
        try:
            import ssl
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return cert is not None
        except:
            return False
    
    def _analyze_content(self, content):
        """Analyze webpage content for suspicious patterns"""
        analysis = {
            'scripts': len(re.findall(r'<script', content)),
            'forms': len(re.findall(r'<form', content)),
            'iframes': len(re.findall(r'<iframe', content)),
            'external_links': len(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content)),
            'suspicious_functions': 0
        }
        
        for signature in self.threat_signatures:
            if signature.lower() in content:
                analysis['suspicious_functions'] += content.count(signature.lower())
        
        return analysis
    
    def _detect_threats(self, content, hostname):
        """Detect various types of threats"""
        threats = []
        
        # Check against known malicious domains
        if any(domain in hostname for domain in self.malicious_domains):
            threats.append('Known malicious domain')
        
        # Check for suspicious content
        for signature in self.threat_signatures:
            if signature.lower() in content:
                threats.append(f'Suspicious JavaScript detected: {signature}')
        
        # Check for phishing indicators
        phishing_keywords = ['login', 'password', 'verify', 'account', 'suspended', 'click here', 'urgent']
        phishing_count = sum(1 for keyword in phishing_keywords if keyword in content)
        
        if phishing_count >= 3:
            threats.append('Potential phishing site detected')
        
        # Check for malware indicators
        malware_patterns = [
            r'eval\s*\(',
            r'document\.write\s*\(',
            r'fromCharCode',
            r'unescape\s*\(',
            r'String\.fromCharCode'
        ]
        
        for pattern in malware_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                threats.append(f'Potential malware pattern: {pattern}')
        
        return threats
    
    def _calculate_reputation(self, result):
        """Calculate URL reputation score"""
        score = 100
        
        # Deduct for threats
        score -= len(result['threats']) * 20
        
        # Deduct for excessive redirects
        if result['redirects'] > 2:
            score -= result['redirects'] * 5
        
        # Deduct for no SSL on HTTPS
        if result['url'].startswith('https://') and not result['ssl_valid']:
            score -= 15
        
        # Deduct for suspicious content
        content_analysis = result.get('content_analysis', {})
        if content_analysis.get('suspicious_functions', 0) > 0:
            score -= content_analysis['suspicious_functions'] * 10
        
        # Deduct for too many external links
        if content_analysis.get('external_links', 0) > 20:
            score -= 10
        
        return max(0, min(100, score))