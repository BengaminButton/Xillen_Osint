#!/usr/bin/env python3
"""
XILLEN OSINT - Advanced Open Source Intelligence Tool
Professional OSINT framework for comprehensive intelligence gathering
"""

import requests
import json
import time
import argparse
import sys
from datetime import datetime
from urllib.parse import urljoin, urlparse
import dns.resolver
import socket
import whois
import shodan
import censys
from colorama import init, Fore, Style
import concurrent.futures
import re
import hashlib
import base64

init(autoreset=True)

class XillenOSINT:
    def __init__(self, target, api_keys=None):
        self.target = target
        self.api_keys = api_keys or {}
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'domain_info': {},
            'ip_info': {},
            'subdomains': [],
            'ports': [],
            'emails': [],
            'social_media': {},
            'breaches': [],
            'metadata': {},
            'threat_intel': {}
        }
        
    def banner(self):
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    XILLEN OSINT FRAMEWORK                    ║
║              Advanced Intelligence Gathering Tool            ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}Target: {self.target}
{Fore.YELLOW}Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{Style.RESET_ALL}
"""
        print(banner)
    
    def domain_analysis(self):
        print(f"{Fore.BLUE}[*] Starting domain analysis...{Style.RESET_ALL}")
        
        try:
            domain_info = whois.whois(self.target)
            self.results['domain_info'] = {
                'registrar': str(domain_info.registrar) if domain_info.registrar else 'Unknown',
                'creation_date': str(domain_info.creation_date) if domain_info.creation_date else 'Unknown',
                'expiration_date': str(domain_info.expiration_date) if domain_info.expiration_date else 'Unknown',
                'name_servers': list(domain_info.name_servers) if domain_info.name_servers else [],
                'emails': list(domain_info.emails) if domain_info.emails else [],
                'status': list(domain_info.status) if domain_info.status else []
            }
            print(f"{Fore.GREEN}[+] Domain information collected{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Domain analysis failed: {e}{Style.RESET_ALL}")
    
    def dns_enumeration(self):
        print(f"{Fore.BLUE}[*] Starting DNS enumeration...{Style.RESET_ALL}")
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                records = []
                for rdata in answers:
                    records.append(str(rdata))
                
                if records:
                    self.results['domain_info'][f'dns_{record_type.lower()}'] = records
                    print(f"{Fore.GREEN}[+] {record_type} records found: {len(records)}{Style.RESET_ALL}")
            except Exception as e:
                continue
    
    def subdomain_discovery(self):
        print(f"{Fore.BLUE}[*] Starting subdomain discovery...{Style.RESET_ALL}")
        
        subdomains = []
        wordlist = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'app', 'cdn', 'static', 'assets', 'img', 'images',
            'docs', 'help', 'support', 'portal', 'login', 'secure', 'vpn',
            'remote', 'backup', 'db', 'database', 'sql', 'mysql', 'postgres',
            'redis', 'cache', 'monitor', 'stats', 'analytics', 'tracking'
        ]
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{self.target}"
                socket.gethostbyname(full_domain)
                return full_domain
            except:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in wordlist]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    subdomains.append(result)
                    print(f"{Fore.GREEN}[+] Subdomain found: {result}{Style.RESET_ALL}")
        
        self.results['subdomains'] = subdomains
    
    def port_scanning(self):
        print(f"{Fore.BLUE}[*] Starting port scanning...{Style.RESET_ALL}")
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                sock.close()
                if result == 0:
                    return port
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(scan_port, port) for port in common_ports]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.results['ports'].append(result)
                    print(f"{Fore.GREEN}[+] Open port found: {result}{Style.RESET_ALL}")
    
    def shodan_lookup(self):
        if not self.api_keys.get('shodan'):
            print(f"{Fore.YELLOW}[!] Shodan API key not provided, skipping...{Style.RESET_ALL}")
            return
        
        print(f"{Fore.BLUE}[*] Starting Shodan lookup...{Style.RESET_ALL}")
        
        try:
            api = shodan.Shodan(self.api_keys['shodan'])
            results = api.search(self.target)
            
            self.results['shodan_data'] = {
                'total_results': results['total'],
                'hosts': []
            }
            
            for result in results['matches'][:10]:
                host_info = {
                    'ip': result.get('ip_str'),
                    'port': result.get('port'),
                    'product': result.get('product'),
                    'version': result.get('version'),
                    'banner': result.get('data', '').strip()[:200]
                }
                self.results['shodan_data']['hosts'].append(host_info)
                print(f"{Fore.GREEN}[+] Shodan result: {host_info['ip']}:{host_info['port']} - {host_info['product']}{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Shodan lookup failed: {e}{Style.RESET_ALL}")
    
    def email_harvesting(self):
        print(f"{Fore.BLUE}[*] Starting email harvesting...{Style.RESET_ALL}")
        
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = set()
        
        try:
            response = requests.get(f"https://{self.target}", timeout=10)
            found_emails = re.findall(email_pattern, response.text)
            emails.update(found_emails)
            
            for subdomain in self.results['subdomains'][:5]:
                try:
                    response = requests.get(f"https://{subdomain}", timeout=5)
                    found_emails = re.findall(email_pattern, response.text)
                    emails.update(found_emails)
                except:
                    continue
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Email harvesting failed: {e}{Style.RESET_ALL}")
        
        self.results['emails'] = list(emails)
        for email in emails:
            print(f"{Fore.GREEN}[+] Email found: {email}{Style.RESET_ALL}")
    
    def social_media_osint(self):
        print(f"{Fore.BLUE}[*] Starting social media OSINT...{Style.RESET_ALL}")
        
        social_platforms = {
            'twitter': f"https://twitter.com/{self.target}",
            'linkedin': f"https://linkedin.com/company/{self.target}",
            'facebook': f"https://facebook.com/{self.target}",
            'instagram': f"https://instagram.com/{self.target}",
            'github': f"https://github.com/{self.target}"
        }
        
        for platform, url in social_platforms.items():
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    self.results['social_media'][platform] = {
                        'url': url,
                        'status': 'active',
                        'title': self.extract_title(response.text)
                    }
                    print(f"{Fore.GREEN}[+] {platform.title()} profile found{Style.RESET_ALL}")
                else:
                    self.results['social_media'][platform] = {
                        'url': url,
                        'status': 'not_found'
                    }
            except:
                self.results['social_media'][platform] = {
                    'url': url,
                    'status': 'error'
                }
    
    def extract_title(self, html):
        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        return title_match.group(1) if title_match else 'No title'
    
    def breach_check(self):
        print(f"{Fore.BLUE}[*] Starting breach check...{Style.RESET_ALL}")
        
        for email in self.results['emails']:
            try:
                email_hash = hashlib.sha1(email.encode()).hexdigest().upper()
                url = f"https://api.pwnedpasswords.com/range/{email_hash[:5]}"
                response = requests.get(url, timeout=10)
                
                if response.status_code == 200:
                    hashes = response.text.split('\n')
                    for hash_line in hashes:
                        if email_hash[5:] in hash_line:
                            count = hash_line.split(':')[1]
                            self.results['breaches'].append({
                                'email': email,
                                'breach_count': int(count)
                            })
                            print(f"{Fore.RED}[!] Breach found for {email}: {count} occurrences{Style.RESET_ALL}")
                            break
            except Exception as e:
                continue
    
    def threat_intelligence(self):
        print(f"{Fore.BLUE}[*] Starting threat intelligence gathering...{Style.RESET_ALL}")
        
        threat_apis = {
            'virustotal': f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={self.api_keys.get('virustotal', '')}&domain={self.target}",
            'abuseipdb': f"https://api.abuseipdb.com/api/v2/check?ipAddress={self.target}&maxAgeInDays=90&verbose"
        }
        
        for source, url in threat_apis.items():
            if self.api_keys.get(source.replace('ipdb', 'ipdb_api')):
                try:
                    headers = {'Key': self.api_keys[f'{source}_api']} if 'abuseipdb' in source else {}
                    response = requests.get(url, headers=headers, timeout=10)
                    
                    if response.status_code == 200:
                        data = response.json()
                        self.results['threat_intel'][source] = data
                        print(f"{Fore.GREEN}[+] Threat intelligence from {source}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[-] {source} lookup failed: {e}{Style.RESET_ALL}")
    
    def generate_report(self):
        print(f"{Fore.BLUE}[*] Generating comprehensive report...{Style.RESET_ALL}")
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"xillen_osint_report_{self.target}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"{Fore.GREEN}[+] Report saved to: {filename}{Style.RESET_ALL}")
        
        summary = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                        OSINT SUMMARY                        ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}Target: {self.target}
{Fore.YELLOW}Subdomains Found: {len(self.results['subdomains'])}
{Fore.YELLOW}Open Ports: {len(self.results['ports'])}
{Fore.YELLOW}Emails Found: {len(self.results['emails'])}
{Fore.YELLOW}Social Media Profiles: {len([k for k, v in self.results['social_media'].items() if v.get('status') == 'active'])}
{Fore.YELLOW}Breaches Found: {len(self.results['breaches'])}
{Fore.YELLOW}Report File: {filename}

{Fore.GREEN}OSINT scan completed successfully!{Style.RESET_ALL}
"""
        print(summary)
    
    def run_full_scan(self):
        self.banner()
        
        scan_methods = [
            self.domain_analysis,
            self.dns_enumeration,
            self.subdomain_discovery,
            self.port_scanning,
            self.shodan_lookup,
            self.email_harvesting,
            self.social_media_osint,
            self.breach_check,
            self.threat_intelligence
        ]
        
        for method in scan_methods:
            try:
                method()
                time.sleep(1)
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
                break
            except Exception as e:
                print(f"{Fore.RED}[-] Error in {method.__name__}: {e}{Style.RESET_ALL}")
                continue
        
        self.generate_report()

def main():
    parser = argparse.ArgumentParser(description='XILLEN OSINT - Advanced Intelligence Gathering Tool')
    parser.add_argument('target', help='Target domain or IP address')
    parser.add_argument('--shodan-key', help='Shodan API key')
    parser.add_argument('--virustotal-key', help='VirusTotal API key')
    parser.add_argument('--abuseipdb-key', help='AbuseIPDB API key')
    parser.add_argument('--quick', action='store_true', help='Quick scan (skip time-consuming checks)')
    
    args = parser.parse_args()
    
    api_keys = {
        'shodan': args.shodan_key,
        'virustotal': args.virustotal_key,
        'abuseipdb_api': args.abuseipdb_key
    }
    
    osint = XillenOSINT(args.target, api_keys)
    osint.run_full_scan()

if __name__ == "__main__":
    main()
