import nmap
import argparse
from ipaddress import ip_network
import socket
import json
import os
import logging

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

    if not os.path.exists('../results'):
        os.makedirs('../results')
    
    for target in targets:
        print(f"Starting Nmap scan on {target}...\n")
        try:
            nm.scan(target, arguments='-sV --script=vuln')
        except nmap.PortScannerError as e:
            print(f"Nmap scan failed for {target}: {e}")
            continue
    
        
        scan_data = nm.analyse_nmap_xml_scan()
        
        formatted_output = ""
        json_output = {"host": target, "scan": []}

        for host in nm.all_hosts():
            host_info = {
                "host": host,
                "hostname": nm[host].hostname(),
                "state": nm[host].state(),
                "protocols": []
            }
            formatted_output += f"Host: {host} ({nm[host].hostname()})\n"
            formatted_output += f"State: {nm[host].state()}\n"
            for proto in nm[host].all_protocols():
                proto_info = {"protocol": proto, "ports": []}
                formatted_output += f"Protocol: {proto}\n"
                lport = nm[host][proto].keys()
                for port in lport:
                    port_info = {
                        "port": port,
                        "state": nm[host][proto][port]['state'],
                        'service': nm[host][proto][port]['name']
                    }
                    formatted_output += f"  Port: {port}\tState: {nm[host][proto][port]['state']}\n"
                    formatted_output += f"  Service: {nm[host][proto][port]['name']}\n"
                    if 'product' in nm[host][proto][port]:
                        port_info["product"] = nm[host][proto][port]['product']
                        formatted_output += f"  Product: {nm[host][proto][port]['product']}\n"
                    if 'version' in nm[host][proto][port]:
                        port_info["version"] = nm[host][proto][port]['version']
                        formatted_output += f"  Version: {nm[host][proto][port]['version']}\n"
                    if 'extrainfo' in nm[host][proto][port]:
                        port_info["extrainfo"] = nm[host][proto][port]['extrainfo']
                        formatted_output += f"  Extra Info: {nm[host][proto][port]['extrainfo']}\n"
                    if 'script' in nm[host][proto][port]:
                        port_info["vulnerabilities"] = nm[host][proto][port]['script']
                        formatted_output += "  Vulnerabilities:\n"
                        for script_name, output in nm[host][proto][port]['script'].items():
                            formatted_output += f"    {script_name}: {output}\n"
                    proto_info["ports"].append(port_info)
                host_info["protocols"].append(proto_info)
            json_output["scan"].append(host_info)

        text_file_path = f'../results/nmap_scan_results_{target}.txt'
        json_file_path = f'../results/nmap_scan_results_{target}.json'

        with open(text_file_path, 'w') as f:
            f.write(formatted_output)
        
        with open(json_file_path, 'w') as f:
            json.dump(json_output, f, indent=4)
        
        logging.info(f"Scan results for {target} saved to {text_file_path} and {json_file_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Automate Nmap Vulnerability Scanning')
    parser.add_argument('targets', nargs='+', help='Target IP address(es) or domain name(s)')
    args = parser.parse_args()
    
    resolved_ips = resolve_targets(args.targets)
    if resolved_ips:
        nmap_scan(resolved_ips)
    else:
        logging.error("No valid IP addresses to scan.")
