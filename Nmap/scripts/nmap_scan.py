import nmap
import argparse
from ipaddress import ip_network

def nmap_scan(targets):
    nm = nmap.PortScanner()
    
    for target in targets:
        print(f"Starting Nmap scan on {target}...")
        nm.scan(target, arguments='-sV --script=vuln')
        
        scan_data = nm.analyse_nmap_xml_scan()
        
        for host in nm.all_hosts():
            print(f"Host: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                lport = nm[host][proto].keys()
                for port in lport:
                    print(f"Port: {port}\tState: {nm[host][proto][port]['state']}")
                    print(f"Service: {nm[host][proto][port]['name']}")
                    if 'script' in nm[host][proto][port]:
                        print("Vulnerabilities:")
                        for script_name, output in nm[host][proto][port]['script'].items():
                            print(f"  {script_name}: {output}")
        
        with open(f'nmap_scan_results_{target}.txt', 'w') as f:
            f.write(str(scan_data))
        
        print(f"Scan results for {target} saved to nmap_scan_results_{target}.txt")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Automate Nmap Vulnerability Scanning')
    parser.add_argument('target_range', help='Target IP address or network range (e.g., 192.168.1.0/24)')
    args = parser.parse_args()
    
    network = ip_network(args.target_range, strict=False)
    nmap_scan([str(ip) for ip in network.hosts()])
