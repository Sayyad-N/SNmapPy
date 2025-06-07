# SNmapPy - Network Analysis and WiFi Tool

# New Update V2
- Added Ai (Arabic)
- Added in CLI Arabic
- Added Root-Checker
- Repleaced Book with DataSheet Simple
  
## Overview

SNmapPy is a Python-based network analysis and WiFi tool designed for ethical hacking and network security assessments. It leverages the `nmap` library to perform various network scans and provides a user-friendly interface for both beginners and experienced users.

**Author:** SayyadN

**Version:** 2.0

**Disclaimer:** This tool is for educational purposes only. Use responsibly and ethically.

## Features

-   **Port Scanning:** Scan for open ports on a target machine.
-   **OS Detection:** Identify the operating system of a target.
-   **Service Detection:** Determine the services running on open ports.
-   **Network Mapping:** Discover hosts on a network.
-   **Firewall Detection:** Attempt to identify firewall rules.
-   **Vulnerability Scanning:** Scan for common vulnerabilities.
-   **WiFi Scanning:** Gather information about WiFi networks.
-   **DNS Enumeration:** Perform DNS-related scans.
-   **SNMP Scanning:** Scan for SNMP-enabled devices.
-   **Protocol-Specific Scans:** Includes HTTP, FTP, SSH, Telnet, SMTP, POP3, IMAP, LDAP, RDP, SMB, MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, Docker, and Kubernetes scans.
-   **SSL Scanning:** Check SSL/TLS configuration.
-   **IPv6/IPv4 Support:** Perform scans on both IPv4 and IPv6 networks.
-   **WiFi Client Scanning:** Discover active clients on a WiFi network.
-   **Custom Scan:** Allows users to specify custom `nmap` arguments.
-   **AI Assistance:** Provides AI-powered help for troubleshooting and understanding scan results.

## Requirements

-   Python 3.6+
-   `nmap` installed on your system.

### Python Packages

-   `python-nmap`
-   `google-genai`
-   `colorama`

Bro Now Setup.sh in Linux Will Auto Install Nmap and Reqired Libs

```bash
sudo bash setup.sh
