# Nmap Vulnerability Scanning

## Overview
This project contains a Python script to automate vulnerability scanning using Nmap on a range of IP addresses. The script performs scans and saves the results to a file for each IP address scanned.

## Requirements
- Python 3.x
- Nmap
- `python-nmap` library

## Installation

### 1. Install Nmap
Ensure Nmap is installed on your system. You can download and install Nmap from [the official Nmap website](https://nmap.org/download.html).

For example, on a Debian-based system (like Ubuntu), you can install Nmap using:
```bash
sudo apt-get install nmap
```

### 2. Install Python and 'python-nmap' Library
If you don't have Python 3.x installed, download and install it from the official Python website.

Install the python-nmap library using pip:
```bash
pip install python-nmap
```

## Installation

### 1. Clone the Repository
Clone this repository to your local machine:
```bash
git clone https://github.com/iaskeyz69/NMAP-OPENVAS-SCANS.git
cd NMAP-OPENVAS-SCANS
```
### 2. Create results folder
Create a Directory/Folder called results:
```bash
cd NMAP-OPENVAS-SCANS/Nmap/
mkdir results
```
### 3. Run the Nmap Scan Script
The script nmap_scan.py can scan a single IP, a range of IPs, or an entire network.

***Scan a Single IP***
To scan a single IP address, run the script as follows:
```bash
cd NMAP-OPENVAS-SCANS/Nmap/scripts
python3 nmap_scan.py 192.168.1.1
```

***Scan Network Range***
To scan a range of IP addresses within a network, run the script with the network range in CIDR notation:
```bash
python3 nmap_scan.py 192.168.1.0/24
```

### 4. Find the Results
The results of the scan will be saved in the results directory with filenames in the format nmap_scan_results_<IP>.txt.
```bash
cd NMAP-OPENVAS-SCANS/Nmap/results
ls
```

This will scan the entire 192.168.1.0/24 network and save each IP's scan results to a separate file in the results directory.

### Directory Structure
```bash
NMAP-OPENVAS-SCANS/
├── Nmap/
│   ├── scripts/
│   │   └── nmap_scan.py
│   ├── results/
│   │   ├── nmap_scan_results_192.168.1.1.txt
│   │   ├── nmap_scan_results_192.168.1.2.txt
│   │   └── ... (additional result files)
│   
```

----

# OpenVAS Vulnerability Scanning

## Overview
This project contains a Python script to automate vulnerability scanning using OpenVAS on a range of IP addresses. The script performs scans and saves the results to a file for each IP address scanned.

## Requirements
- Python 3.x
- `gvm-tools` library
- `python-gvm` library
- OpenVAS (Greenbone Vulnerability Manager) setup and running

## Installation

### 1. Install `gvm-tools` and `python-gvm` Libraries
Install the required libraries using pip:
```bash
pip install gvm-tools python-gvm
```
### 2. Set Up and Configure OpenVAS
Ensure OpenVAS is set up and running on your machine. Refer to the [OpenVAS documentation](https://greenbone.github.io/docs/latest/) for installation and configuration instructions.

### 3. Clone the Repository
Clone this repository to your local machine:
```bash
git clone https://github.com/iaskeyz69/NMAP-OPENVAS-SCANS.git
cd NMAP-OPENVAS-SCANS/OpenVAS/scripts
```
### 4. Create results folder
Create a Directory/Folder called results:
```bash
cd NMAP-OPENVAS-SCANS/OpenVAS/
mkdir results
```

### 5. Run the Nmap Scan Script
The script openvas_scan.py can scan a single IP, a range of IPs, or an entire network.

***Scan a Single IP***
To scan a single IP address, run the script as follows:
```bash
python3 openvas_scan.py 192.168.1.1
```

***Scan Network Range***
To scan a range of IP addresses within a network, run the script with the network range in CIDR notation:
```bash
python3 openvas_scan.py 192.168.1.0/24
```

### 6. Find the Results
The results of the scan will be saved in the results directory with filenames in the format openvas_scan_results_<IP>.xml.
```bash
cd NMAP-OPENVAS-SCANS/OpenVAS/results
ls
```

This will scan the entire 192.168.1.0/24 network and save each IP's scan results to a separate file in the results directory.

### Directory Structure
```bash
NMAP-OPENVAS-SCANS/
├── OpenVAS/
│   ├── scripts/
│   │   └── openvas_scan.py
│   ├── results/
│   │   ├── openvas_scan_results_192.168.1.1.xml
│   │   ├── openvas_scan_results_192.168.1.2.xml
│   │   └── ... (additional result files)
│   

```
