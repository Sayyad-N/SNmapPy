# Code Written By SayyadN
# This code is for educational purposes only.
# Use responsibly and ethically.
# Version 1.0

# Importing necessary libraries
import nmap
import time
import shutil
import google.generativeai as GenAI
import logging
import argparse
from colorama import Fore, Back, init

# Initialize colorama
init(autoreset=True)

# Define aliases for print and input
p = print
i = input

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to get AI help for package management
def ai_help(error_message):
    try:
        GenAI.configure(api_key="AIzaSyCD9b_cGg1Aw0yI_Awt6ufO80V88OlkdbY")
        model = GenAI.GenerativeModel("gemini-2.0-flash")
        while True:
            response = model.generate_content(error_message)
            p(Fore.GREEN + Back.WHITE + response.text + "\nPowered By SayyadN")
            user_input = i("You can exit by typing 'exit'. Do you need more help? (Y/N): ").lower()
            if user_input in ["exit", "n"]:
                break
            elif user_input == "y":
                error_message = i("Please provide more details about the issue: ")
            else:
                p(Fore.RED + "Invalid input, please try again.")
    except Exception as ex:
        p(Fore.RED + f"AI help is currently unavailable: {ex}")

# --- Utility Functions ---
def ask_continue(message="Do you want to continue? (Y/N): "):
    try:
        while True:
            choice = input(message).strip().lower()
            if choice in ['y', 'yes']:
                return True
            elif choice in ['n', 'no']:
                print("Exiting...")
                exit(0)
            else:
                print("Invalid input. Please enter 'Y' or 'N'.")
    except Exception as e:
        ai_help(str(e))

def check_tool(cmd):
    try:
        if shutil.which(cmd) is None:
            logging.warning(f"'{cmd}' is not installed. Some features may not work correctly.")
            return False
        return True
    except Exception as e:
        ai_help(str(e))

def animate_loading():
    try:
        animation = ["[=     ]", "[==    ]", "[===   ]", "[====  ]", "[===== ]", "[======]"]
        for frame in animation:
            print(f"\rLoading {frame}", end="", flush=True)
            time.sleep(0.1)  # Reduced sleep time for faster animation
        print("\n")
    except Exception as e:
        ai_help(str(e))

# --- Scan Functions ---
def perform_scan(target, arguments, scan_type):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments=arguments)
        print(f"{scan_type} scan results for {target}:")
        for host in nm.all_hosts():
            print(f"Host: {host}")
            if 'tcp' in nm[host]:
                for port, data in nm[host]['tcp'].items():
                    print(f"  Port: {port}\tState: {data['state']}\tService: {data.get('name', 'Unknown')}")
            if 'udp' in nm[host]:
                for port, data in nm[host]['udp'].items():
                    print(f"  Port: {port}\tState: {data['state']}\tService: {data.get('name', 'Unknown')}")
    except Exception as e:
        logging.error(f"Error during {scan_type} scan: {e}")
        ai_help(str(e))
    ask_continue()

def scan_ports(target):
    try:
        perform_scan(target, '-sS', 'Port')
    except Exception as e:
        ai_help(str(e))

def scan_os(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-O')
        print(f"OS scan results for {target}:")
        if 'osclass' in nm[target]:
            for osclass in nm[target]['osclass']:
                print(f"OS Class: {osclass['osfamily']}")
        if 'osmatch' in nm[target]:
            print(f"OS Match: {nm[target]['osmatch'][0]['name']}")
    except Exception as e:
        print(f"Error scanning OS: {e}")
        ai_help(str(e))
    ask_continue()

def scan_services(target):
    try:
        perform_scan(target, '-sV', 'Service')
    except Exception as e:
        ai_help(str(e))

def network_mapping(target):
    try:
        perform_scan(target, '-sn', 'Network Mapping')
    except Exception as e:
        ai_help(str(e))

def scan_firewall(target):
    try:
        perform_scan(target, '-sA', 'Firewall')
    except Exception as e:
        ai_help(str(e))

def scan_vulnerabilities(target):
    try:
        perform_scan(target, '--script vuln', 'Vulnerability')
    except Exception as e:
        ai_help(str(e))

def scan_wifi(target):
    try:
        perform_scan(target, '--script wifi', 'WiFi')
    except Exception as e:
        ai_help(str(e))

def scan_dns(target):
    try:
        perform_scan(target, '-sL', 'DNS')
    except Exception as e:
        ai_help(str(e))

def scan_snmp(target):
    try:
        perform_scan(target, '-sU -p 161', 'SNMP')
    except Exception as e:
        ai_help(str(e))

def scan_http(target):
    try:
        perform_scan(target, '-p 80,443', 'HTTP')
    except Exception as e:
        ai_help(str(e))

def scan_ftp(target):
    try:
        perform_scan(target, '-p 21', 'FTP')
    except Exception as e:
        ai_help(str(e))

def scan_ssh(target):
    try:
        perform_scan(target, '-p 22', 'SSH')
    except Exception as e:
        ai_help(str(e))

def scan_telnet(target):
    try:
        perform_scan(target, '-p 23', 'Telnet')
    except Exception as e:
        ai_help(str(e))

def scan_smtp(target):
    try:
        perform_scan(target, '-p 25', 'SMTP')
    except Exception as e:
        ai_help(str(e))

def scan_pop3(target):
    try:
        perform_scan(target, '-p 110', 'POP3')
    except Exception as e:
        ai_help(str(e))

def scan_imap(target):
    try:
        perform_scan(target, '-p 143', 'IMAP')
    except Exception as e:
        ai_help(str(e))

def scan_ldap(target):
    try:
        perform_scan(target, '-p 389', 'LDAP')
    except Exception as e:
        ai_help(str(e))

def scan_rdp(target):
    try:
        perform_scan(target, '-p 3389', 'RDP')
    except Exception as e:
        ai_help(str(e))

def scan_smb(target):
    try:
        perform_scan(target, '-p 445', 'SMB')
    except Exception as e:
        ai_help(str(e))

def scan_mysql(target):
    try:
        perform_scan(target, '-p 3306', 'MySQL')
    except Exception as e:
        ai_help(str(e))

def scan_postgresql(target):
    try:
        perform_scan(target, '-p 5432', 'PostgreSQL')
    except Exception as e:
        ai_help(str(e))

def scan_mongodb(target):
    try:
        perform_scan(target, '-p 27017', 'MongoDB')
    except Exception as e:
        ai_help(str(e))

def scan_redis(target):
    try:
        perform_scan(target, '-p 6379', 'Redis')
    except Exception as e:
        ai_help(str(e))

def scan_elasticsearch(target):
    try:
        perform_scan(target, '-p 9200', 'Elasticsearch')
    except Exception as e:
        ai_help(str(e))

def scan_docker(target):
    try:
        perform_scan(target, '-p 2375', 'Docker')
    except Exception as e:
        ai_help(str(e))

def scan_kubernetes(target):
    try:
        perform_scan(target, '-p 6443', 'Kubernetes')
    except Exception as e:
        ai_help(str(e))

def scan_ssl(target):
    try:
        perform_scan(target, '-p 443 --script ssl-enum-ciphers', 'SSL')
    except Exception as e:
        ai_help(str(e))

def scan_ipv6(target):
    try:
        perform_scan(target, '-6', 'IPv6')
    except Exception as e:
        ai_help(str(e))

def scan_ipv4(target):
    try:
        perform_scan(target, '-4', 'IPv4')
    except Exception as e:
        ai_help(str(e))

def check_for_updates():
    try:
        nm = nmap.PortScanner()
        nm.scan('localhost', arguments='--script update')
        print("Update check results:")
        for proto in nm['localhost'].all_protocols():
            print(f"Protocol: {proto}")
            lport = nm['localhost'][proto].keys()
            for port in sorted(lport):
                print(f"Port: {port}\tState: {nm['localhost'][proto][port]['state']}")
    except Exception as e:
        print(f"Error checking for updates: {e}")
        ai_help(str(e))
    ask_continue()

def scan_wifi_clients(subnet):
    try:
        nm = nmap.PortScanner()
        print(f"Scanning for clients on subnet {subnet}...")
        nm.scan(hosts=subnet, arguments='-sn')
        print("\nActive Clients on the Network:")
        for host in nm.all_hosts():
            mac_address = nm[host]['addresses'].get('mac', "Unknown")
            hostname = nm[host].hostname() or "No Hostname"
            ip_address = nm[host]['addresses'].get('ipv4', "Unknown")
            state = nm[host].state()
            print(f"IP: {ip_address}\tMAC: {mac_address}\tHostname: {hostname}\tState: {state}")
    except Exception as e:
        print(f"Error scanning WiFi clients: {e}")
        ai_help(str(e))
    ask_continue()

def custom_scan(target, arguments):
    try:
        perform_scan(target, arguments, 'Custom')
    except Exception as e:
        ai_help(str(e))

# --- Main Function ---
def main():
    try:
        parser = argparse.ArgumentParser(description="SWifiKit - Network Analysis and WiFi Tool")
        parser.add_argument("-t", "--target", help="Target IP address or hostname")
        parser.add_argument("-s", "--scan", help="Specific scan to run (e.g., ports, os, services)")
        parser.add_argument("-c", "--custom", help="Custom Nmap arguments")
        args = parser.parse_args()

        print("****************************************")
        print("*           SNmapPy 1.0               *")
        print("*      Authored by SayyadN             *")
        print("****************************************\n")

        # Dependency Check
        tools = ['nmap']
        print("Checking required tools...")
        for tool in tools:
            check_tool(tool)
        print("Dependency check complete.")

        animate_loading()

        if args.target and args.scan:
            # Run specific scan on target
            target = args.target
            scan_type = args.scan.lower()

            if scan_type == "ports":
                scan_ports(target)
            elif scan_type == "os":
                scan_os(target)
            elif scan_type == "services":
                scan_services(target)
            elif scan_type == "network_mapping":
                network_mapping(target)
            elif scan_type == "firewall":
                scan_firewall(target)
            elif scan_type == "vulnerabilities":
                scan_vulnerabilities(target)
            elif scan_type == "wifi":
                scan_wifi(target)
            elif scan_type == "dns":
                scan_dns(target)
            elif scan_type == "snmp":
                scan_snmp(target)
            elif scan_type == "http":
                scan_http(target)
            elif scan_type == "ftp":
                scan_ftp(target)
            elif scan_type == "ssh":
                scan_ssh(target)
            elif scan_type == "telnet":
                scan_telnet(target)
            elif scan_type == "smtp":
                scan_smtp(target)
            elif scan_type == "pop3":
                scan_pop3(target)
            elif scan_type == "imap":
                scan_imap(target)
            elif scan_type == "ldap":
                scan_ldap(target)
            elif scan_type == "rdp":
                scan_rdp(target)
            elif scan_type == "smb":
                scan_smb(target)
            elif scan_type == "mysql":
                scan_mysql(target)
            elif scan_type == "postgresql":
                scan_postgresql(target)
            elif scan_type == "mongodb":
                scan_mongodb(target)
            elif scan_type == "redis":
                scan_redis(target)
            elif scan_type == "elasticsearch":
                scan_elasticsearch(target)
            elif scan_type == "docker":
                scan_docker(target)
            elif scan_type == "kubernetes":
                scan_kubernetes(target)
            elif scan_type == "ssl":
                scan_ssl(target)
            elif scan_type == "ipv6":
                scan_ipv6(target)
            elif scan_type == "ipv4":
                scan_ipv4(target)
            else:
                print("Invalid scan type specified.")

            return  # Exit after running the specific scan
        elif args.target and args.custom:
            target = args.target
            custom_args = args.custom
            custom_scan(target, custom_args)
            return

        while True:
            print("\nMain Menu:")
            print("1.  Port Scan")
            print("2.  OS Scan")
            print("3.  Service Scan")
            print("4.  Network Mapping")
            print("5.  Firewall Scan")
            print("6.  Vulnerability Scan")
            print("7.  WiFi Scan")
            print("8.  DNS Scan")
            print("9.  SNMP Scan")
            print("10. HTTP Scan")
            print("11. FTP Scan")
            print("12. SSH Scan")
            print("13. Telnet Scan")
            print("14. SMTP Scan")
            print("15. POP3 Scan")
            print("16. IMAP Scan")
            print("17. LDAP Scan")
            print("18. RDP Scan")
            print("19. SMB Scan")
            print("20. MySQL Scan")
            print("21. PostgreSQL Scan")
            print("22. MongoDB Scan")
            print("23. Redis Scan")
            print("24. Elasticsearch Scan")
            print("25. Docker Scan")
            print("26. Kubernetes Scan")
            print("27. Check for Updates")
            print("28. SSL Scan")
            print("29. IPv6 Scan")
            print("30. IPv4 Scan")
            print("31. Scan WiFi Clients")
            print("32. Custom Scan")
            print("0. Exit")

            choice = input("\nEnter your choice: ").strip()

            if choice == "0":
                print("Exiting... Goodbye!")
                exit(0)

            target = input("Enter the target IP address: ").strip() if choice not in ["27", "31", "32"] else None

            try:
                if choice == "1":
                    scan_ports(target)
                elif choice == "2":
                    scan_os(target)
                elif choice == "3":
                    scan_services(target)
                elif choice == "4":
                    network_mapping(target)
                elif choice == "5":
                    scan_firewall(target)
                elif choice == "6":
                    scan_vulnerabilities(target)
                elif choice == "7":
                    scan_wifi(target)
                elif choice == "8":
                    scan_dns(target)
                elif choice == "9":
                    scan_snmp(target)
                elif choice == "10":
                    scan_http(target)
                elif choice == "11":
                    scan_ftp(target)
                elif choice == "12":
                    scan_ssh(target)
                elif choice == "13":
                    scan_telnet(target)
                elif choice == "14":
                    scan_smtp(target)
                elif choice == "15":
                    scan_pop3(target)
                elif choice == "16":
                    scan_imap(target)
                elif choice == "17":
                    scan_ldap(target)
                elif choice == "18":
                    scan_rdp(target)
                elif choice == "19":
                    scan_smb(target)
                elif choice == "20":
                    scan_mysql(target)
                elif choice == "21":
                    scan_postgresql(target)
                elif choice == "22":
                    scan_mongodb(target)
                elif choice == "23":
                    scan_redis(target)
                elif choice == "24":
                    scan_elasticsearch(target)
                elif choice == "25":
                    scan_docker(target)
                elif choice == "26":
                    scan_kubernetes(target)
                elif choice == "27":
                    check_for_updates()
                elif choice == "28":
                    scan_ssl(target)
                elif choice == "29":
                    scan_ipv6(target)
                elif choice == "30":
                    scan_ipv4(target)
                elif choice == "31":
                    subnet = input("Enter subnet (e.g., 192.168.1.0/24): ")
                    scan_wifi_clients(subnet)
                elif choice == "32":
                    target = input("Enter the target IP address: ").strip()
                    custom_arguments = input("Enter custom Nmap arguments: ").strip()
                    custom_scan(target, custom_arguments)
                else:
                    print("Invalid choice, please try again.")
            except Exception as e:
                print(f"An error occurred: {e}")
                ai_help(str(e))

            time.sleep(1)
    except Exception as e:
        ai_help(str(e))

if __name__ == "__main__":
    main()
