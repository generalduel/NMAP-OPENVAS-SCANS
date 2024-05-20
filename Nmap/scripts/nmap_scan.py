import nmap
import argparse
from ipaddress import ip_network

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
        
        with open(f'Nmap/results/nmap_scan_results_{target}.txt', 'w') as f:
            f.write(str(scan_data))
        
        print(f"Scan results for {target} saved to nmap_scan_results_{target}.txt\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Automate Nmap Vulnerability Scanning')
    parser.add_argument('target_range', help='Target IP address or network range (e.g., 192.168.1.0/24)')
    args = parser.parse_args()
    
    network = ip_network(args.target_range, strict=False)
    nmap_scan([str(ip) for ip in network.hosts()])
