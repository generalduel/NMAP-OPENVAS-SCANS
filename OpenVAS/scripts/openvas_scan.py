from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print
import argparse
from ipaddress import ip_network

def openvas_scan(targets):
    connection = TLSConnection(hostname='localhost')
    transform = EtreeTransform()

    with Gmp(connection, transform=transform) as gmp:
        # Authenticate with GVM
        gmp.authenticate('admin', 'admin')

        for target in targets:
            # Create target
            target_id = gmp.create_target(name=f'Automated Target {target}', hosts=[target])

            # Create task
            task_id = gmp.create_task(name=f'Automated Scan {target}', config_id='daba56c8-73ec-11df-a475-002264764cea', target_id=target_id)

            # Start task
            gmp.start_task(task_id)

            print(f"Started scan on {target}...")

            # Get the status of the task
            task_status = gmp.get_task_status(task_id)
            while task_status != 'Done':
                task_status = gmp.get_task_status(task_id)

            # Get the report
            report_id = gmp.get_report_id(task_id)
            report = gmp.get_report(report_id=report_id)

            # Print and save the report
            pretty_print(report)
            with open(f'openvas_scan_results_{target}.xml', 'wb') as f:
                f.write(report)

            print(f"Scan results for {target} saved to openvas_scan_results_{target}.xml")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Automate OpenVAS Vulnerability Scanning')
    parser.add_argument('target_range', help='Target IP address or network range (e.g., 192.168.1.0/24)')
    args = parser.parse_args()
    
    network = ip_network(args.target_range, strict=False)
    openvas_scan([str(ip) for ip in network.hosts()])
