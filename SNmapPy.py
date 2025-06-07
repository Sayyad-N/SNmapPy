# Code Written By SayyadN
# Update Date : 7-June-2025
# This code is for educational purposes only.
# Use responsibly and ethically.
# Version 2

# Importing necessary libraries
import nmap
import time
import shutil
#For Skip Modeul Error While ROot (Lib aleardy installed)
try:
    import google.generativeai as GenAI
    has_GenAI = True
except ImportError:
    has_GenAI = False
import logging
import argparse
from colorama import Fore, Back, init
import os 

# Initialize colorama
init(autoreset=True)

# Define aliases for p and input
p = print
i = input

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

#Function For Root Run 
def root_checker():
    if os.geteuid() != 0:
        p("Please ReRun App With sudo Command - Sudo يرجي تشغيل البرنامج من فضلك باستعمال ")
        exit()


# Function to get AI help for package management
def ai_help(error_message):
    try:
        GenAI.configure(api_key="AIzaSyCD9b_cGg1Aw0yI_Awt6ufO80V88OlkdbY")
        model = GenAI.GenerativeModel("gemini-2.0-flash")
        while True:
            response = model.generate_content(error_message)
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
            choice = i(message).strip().lower()
            if choice in ['y', 'yes']:
                return True
            elif choice in ['n', 'no']:
                p("Exiting...")
                exit(0)
            else:
                p("Invalid input. Please enter 'Y' or 'N'.")
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


# --- Scan Functions ---
def perform_scan(target, arguments, scan_type):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments=arguments)
        p(f"{scan_type} scan results for {target}:")
        for host in nm.all_hosts():
            p(f"Host: {host}")
            if 'tcp' in nm[host]:
                for port, data in nm[host]['tcp'].items():
                    p(f"  Port: {port}\tState: {data['state']}\tService: {data.get('name', 'Unknown')}")
            if 'udp' in nm[host]:
                for port, data in nm[host]['udp'].items():
                    p(f"  Port: {port}\tState: {data['state']}\tService: {data.get('name', 'Unknown')}")
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
        p(f"OS scan results for {target}:")
        if 'osclass' in nm[target]:
            for osclass in nm[target]['osclass']:
                p(f"OS Class: {osclass['osfamily']}")
        if 'osmatch' in nm[target]:
            p(f"OS Match: {nm[target]['osmatch'][0]['name']}")
    except Exception as e:
        p(f"Error scanning OS: {e}")
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
        p("Update check results:")
        for proto in nm['localhost'].all_protocols():
            p(f"Protocol: {proto}")
            lport = nm['localhost'][proto].keys()
            for port in sorted(lport):
                p(f"Port: {port}\tState: {nm['localhost'][proto][port]['state']}")
    except Exception as e:
        p(f"Error checking for updates: {e}")
        ai_help(str(e))
    ask_continue()

def scan_wifi_clients(subnet):
    try:
        nm = nmap.PortScanner()
        p(f"Scanning for clients on subnet {subnet}...")
        nm.scan(hosts=subnet, arguments='-sn')
        p("\nActive Clients on the Network:")
        for host in nm.all_hosts():
            mac_address = nm[host]['addresses'].get('mac', "Unknown")
            hostname = nm[host].hostname() or "No Hostname"
            ip_address = nm[host]['addresses'].get('ipv4', "Unknown")
            state = nm[host].state()
            p(f"IP: {ip_address}\tMAC: {mac_address}\tHostname: {hostname}\tState: {state}")
    except Exception as e:
        p(f"Error scanning WiFi clients: {e}")
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
        parser = argparse.ArgumentParser(description="SNmapPy - Network Analysis and WiFi Tool")
        parser.add_argument("-t", "--target", help="Target IP address or hostname")
        parser.add_argument("-s", "--scan", help="Specific scan to run (e.g., ports, os, services)")
        parser.add_argument("-c", "--custom", help="Custom Nmap arguments")
        args = parser.parse_args()

        p("""
 ____  _   _                       ____            
/ ___|| \ | |_ __ ___   __ _ _ __ |  _ \ _   _           
\___ \|  \| | '_ ` _ \ / _` | '_ \| |_) | | | |          
 ___) | |\  | | | | | | (_| | |_) |  __/| |_| |          
|____/|_| \_|_|_|_| |_|\__,_| .__/|_|    \__, |  _ _   _ 
| |__  _   _  / ___|  __ _ _|_|_ _   _  _|___/__| | \ | |
| '_ \| | | | \___ \ / _` | | | | | | |/ _` |/ _` |  \| |
| |_) | |_| |  ___) | (_| | |_| | |_| | (_| | (_| | |\  |
|_.__/ \__, | |____/ \__,_|\__, |\__, |\__,_|\__,_|_| \_|
       |___/               |___/ |___/                   
        """)

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
                p("Invalid scan type specified.")

            return  # Exit after running the specific scan
        elif args.target and args.custom:
            target = args.target
            custom_args = args.custom
            custom_scan(target, custom_args)
            return

        while True:
            p("\nMain Menu / القائمة الرئيسية:")
            p("1.  Port Scan / فحص البورتات")
            p("2.  OS Scan / فحص نظام التشغيل")
            p("3.  Service Scan / فحص الخدمات")
            p("4.  Network Mapping / رسم خريطة الشبكة")
            p("5.  Firewall Scan / فحص الجدار الناري")
            p("6.  Vulnerability Scan / فحص الثغرات")
            p("7.  WiFi Scan / فحص الواي فاي")
            p("8.  DNS Scan / فحص نظام أسماء النطاقات")
            p("9.  SNMP Scan / فحص SNMP")
            p("10. HTTP Scan / فحص HTTP")
            p("11. FTP Scan / فحص FTP")
            p("12. SSH Scan / فحص SSH")
            p("13. Telnet Scan / فحص Telnet")
            p("14. SMTP Scan / فحص SMTP")
            p("15. POP3 Scan / فحص POP3")
            p("16. IMAP Scan / فحص IMAP")
            p("17. LDAP Scan / فحص LDAP")
            p("18. RDP Scan / فحص RDP")
            p("19. SMB Scan / فحص SMB")
            p("20. MySQL Scan / فحص MySQL")
            p("21. PostgreSQL Scan / فحص PostgreSQL")
            p("22. MongoDB Scan / فحص MongoDB")
            p("23. Redis Scan / فحص Redis")
            p("24. Elasticsearch Scan / فحص Elasticsearch")
            p("25. Docker Scan / فحص Docker")
            p("26. Kubernetes Scan / فحص Kubernetes")
            p("27. Check for Updates / التحقق من التحديثات")
            p("28. SSL Scan / فحص SSL")
            p("29. IPv6 Scan / فحص IPv6")
            p("30. IPv4 Scan / فحص IPv4")
            p("31. Scan WiFi Clients / فحص عملاء الواي فاي")
            p("32. Custom Scan / فحص مخصص")
            p("0. Exit / خروج")


            choice = i("\nEnter your choice: ").strip()

            if choice == "0":
                p("Exiting... Goodbye!")
                exit(0)

            target = i("Enter the target IP address: ").strip() if choice not in ["27", "31", "32"] else None

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
                    subnet = i("Enter subnet (e.g., 192.168.1.0/24): ")
                    scan_wifi_clients(subnet)
                elif choice == "32":
                    target = i("Enter the target IP address: ").strip()
                    custom_arguments = i("Enter custom Nmap arguments: ").strip()
                    custom_scan(target, custom_arguments)
                else:
                    p("Invalid choice, please try again.")
            except Exception as e:
                p(f"An error occurred: {e}")
                ai_help(str(e))

            time.sleep(1)
    except Exception as e:
        ai_help(str(e))

if __name__ == "__main__":
    root_checker()
    main()
