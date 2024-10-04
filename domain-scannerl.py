import requests
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import shodan
import os
import sys
import socket
from urllib.parse import urlparse
import json
from datetime import datetime

# Define headers and files to check
HEADERS_TO_CHECK = ['Content-Security-Policy', 'X-Frame-Options', 'X-XSS-Protection', 'Strict-Transport-Security']
SENSITIVE_FILES = ['robots.txt', '.git', 'config.php']
SENSITIVE_DIRECTORIES = ['admin', 'backup', 'uploads']

SHODAN_API_KEY_FILE = "shodan_api_key.txt"

# Function to get the Shodan API key from a file if saved
def get_saved_shodan_api_key():
    if os.path.exists(SHODAN_API_KEY_FILE):
        with open(SHODAN_API_KEY_FILE, 'r') as f:
            return f.read().strip()
    return None

# Function to save the Shodan API key
def save_shodan_api_key(api_key):
    with open(SHODAN_API_KEY_FILE, 'w') as f:
        f.write(api_key)

# Class for the scan report
class ScanReport:
    def __init__(self, domain):
        self.domain = domain
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.ip = None
        self.shodan_results = None
        self.security_headers = {
            'missing': [],
            'present': []
        }
        self.sensitive_files = {
            'found': [],
            'forbidden': []
        }
        self.scan_duration = None
        
    def to_dict(self):
        return {
            'domain': self.domain,
            'scan_timestamp': self.timestamp,
            'ip_address': self.ip,
            'scan_duration': self.scan_duration,
            'security_headers': self.security_headers,
            'sensitive_files': self.sensitive_files,
            'shodan_results': self.shodan_results
        }
    
    def save_to_file(self):
        filename = f"scan_report_{self.domain.replace('https://', '').replace('http://', '').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(self.to_dict(), f, indent=4)
        return filename

def get_ip_from_domain(domain):
    try:
        return socket.gethostbyname(urlparse(domain).hostname)
    except socket.gaierror:
        return None

def check_security_headers(domain, report):
    try:
        response = requests.get(domain, timeout=5)
        headers = response.headers
        
        for header in HEADERS_TO_CHECK:
            if header in headers:
                report.security_headers['present'].append({
                    'header': header,
                    'value': headers[header]
                })
            else:
                report.security_headers['missing'].append(header)
        
    except requests.RequestException as e:
        print(f"Error checking headers: {e}")

def scan_file_or_directory(domain, item):
    url = f"{domain}/{item}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return {'status': 'found', 'url': url}
        elif response.status_code == 403:
            return {'status': 'forbidden', 'url': url}
        return None
    except requests.RequestException:
        return None

def scan_domain(domain, threads, report):
    print(f"\n[+] Starting domain scan for {domain}")
    
    start_time = datetime.now()
    
    # Check security headers
    check_security_headers(domain, report)
    
    # Scan for sensitive files and directories
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for item in SENSITIVE_FILES + SENSITIVE_DIRECTORIES:
            futures.append(executor.submit(scan_file_or_directory, domain, item))
        
        for future in tqdm(as_completed(futures), total=len(futures), desc="Scanning"):
            result = future.result()
            if result:
                if result['status'] == 'found':
                    report.sensitive_files['found'].append(result['url'])
                elif result['status'] == 'forbidden':
                    report.sensitive_files['forbidden'].append(result['url'])
    
    end_time = datetime.now()
    report.scan_duration = str(end_time - start_time)

def shodan_scan(ip, api_key):
    try:
        api = shodan.Shodan(api_key)
        print(f"Performing Shodan scan for IP: {ip}")
        return api.host(ip)
    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")
        return None

def perform_shodan_scan(ip, report, api_key):
    shodan_results = shodan_scan(ip, api_key)
    if shodan_results:
        report.shodan_results = {
            'ip': shodan_results['ip_str'],
            'ports': shodan_results.get('ports', []),
            'organization': shodan_results.get('org', 'N/A'),
            'operating_system': shodan_results.get('os', 'Unknown'),
            'hostnames': shodan_results.get('hostnames', []),
            'vulnerabilities': shodan_results.get('vulns', []),
            'services': [{
                'port': item['port'],
                'service': item.get('product', 'Unknown'),
                'version': item.get('version', 'Unknown'),
                'cpe': item.get('cpe', [])
            } for item in shodan_results.get('data', [])]
        }
    return shodan_results

def display_report(report, verbose=False):
    print("\n" + "="*50)
    print(f"Scan Report for {report.domain}")
    print("="*50)
    print(f"Scan completed at: {report.timestamp}")
    print(f"Scan duration: {report.scan_duration}")
    
    if report.ip:
        print(f"\nIP Address: {report.ip}")
    
    print("\nSecurity Headers:")
    if report.security_headers['missing']:
        print("Missing headers:")
        for header in report.security_headers['missing']:
            print(f"  - {header}")
    if report.security_headers['present']:
        if verbose:
            print("Present headers:")
            for header in report.security_headers['present']:
                print(f"  - {header['header']}: {header['value']}")
        else:
            print(f"Present headers: {len(report.security_headers['present'])}")
    
    print("\nSensitive Files and Directories:")
    if report.sensitive_files['found']:
        print("Found:")
        for url in report.sensitive_files['found']:
            print(f"  - {url}")
    if report.sensitive_files['forbidden']:
        print("Forbidden (might be interesting):")
        for url in report.sensitive_files['forbidden']:
            print(f"  - {url}")
    
    if report.shodan_results:
        print("\nShodan Results:")
        print(f"  Organization: {report.shodan_results['organization']}")
        print(f"  Open Ports: {', '.join(map(str, report.shodan_results['ports']))}")
        if report.shodan_results['vulnerabilities']:
            print(f"  Vulnerabilities: {', '.join(report.shodan_results['vulnerabilities'])}")
        
        if verbose and report.shodan_results['services']:
            print("\n  Detailed Service Information:")
            for service in report.shodan_results['services']:
                print(f"    Port {service['port']}:")
                print(f"      - Service: {service['service']}")
                print(f"      - Version: {service['version']}")
                if service['cpe']:
                    print(f"      - CPE: {', '.join(service['cpe'])}")

# Main execution
if __name__ == "__main__":
    if "--help" in sys.argv:
        show_help()
        sys.exit()

    domain = input("Enter the domain to scan (e.g., https://example.com): ")
    report = ScanReport(domain)
    
    threads = int(input("Enter the number of threads (default is 5): ") or 5)
    verbose = "--verbose" in sys.argv
    
    # Ask user if they want to perform a Shodan scan
    do_shodan_scan = input("\nWould you like to perform a Shodan scan? (y/n): ").lower() == 'y'
    
    if do_shodan_scan:
        saved_api_key = get_saved_shodan_api_key()
        if saved_api_key:
            print("Using saved Shodan API key.")
            api_key = saved_api_key
        else:
            api_key = input("Enter your Shodan API key: ")
            save_key = input("Would you like to save this API key for future scans? (y/n): ").lower() == 'y'
            if save_key:
                save_shodan_api_key(api_key)
        
        domain_ip = get_ip_from_domain(domain)
        if domain_ip:
            report.ip = domain_ip
            print(f"Resolved domain to IP: {domain_ip}")
            print("Initiating Shodan scan...")
            perform_shodan_scan(domain_ip, report, api_key)
        else:
            print(f"Could not resolve IP for domain: {domain}")
    else:
        print("Skipping Shodan scan.")

    # Perform the domain scan
    scan_domain(domain, threads, report)
    
    # Display and save report
    display_report(report, verbose)
    
    # Save report to file
    report_file = report.save_to_file()
    print(f"\nFull report has been saved to: {report_file}")
