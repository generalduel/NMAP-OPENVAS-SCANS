import nmap
import argparse
from ipaddress import ip_network
import socket

def resolve_targets(targets):
    resolved_ips = []
    for target in targets:
        try:
            ip = socket.gethostbyname(target)
            resolved_ips.append(ip)
        except socket.gaierror:
            print(f"Unable to resolve IP address for {target}")
    return resolved_ips

def nmap_scan(targets):
    nm = nmap.PortScanner()
    
    for target in targets:
        print(f"Starting Nmap scan on {target}...\n")
        nm.scan(target, arguments='-sV --script=vuln')
        
        scan_data = nm.analyse_nmap_xml_scan()
        
        for host in nm.all_hosts():
            print(f"Host: {host} ({nm[host].hostname()})\n")
            print(f"State: {nm[host].state()}\n")
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}\n")
                lport = nm[host][proto].keys()
                for port in lport:
                    print(f"Port: {port}\tState: {nm[host][proto][port]['state']}\n")
                    print(f"Service: {nm[host][proto][port]['name']}\n")
                    if 'script' in nm[host][proto][port]:
                        print("Vulnerabilities:\n")
                        for script_name, output in nm[host][proto][port]['script'].items():
                            print(f"  {script_name}: {output}\n")
        
        with open(f'../results/nmap_scan_results_{target}.txt', 'w') as f:
            f.write(str(scan_data))
        
        print(f"Scan results for {target} saved to nmap_scan_results_{target}.txt\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Automate Nmap Vulnerability Scanning')
    parser.add_argument('targets', nargs='+', help='Target IP address(es) or domain name(s)')
    args = parser.parse_args()
    
    resolved_ips = resolve_targets(args.targets)
    nmap_scan(resolved_ips)
