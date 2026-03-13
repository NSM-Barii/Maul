# THIS WILL BE FOR RESOLVING 



# UI IMPORTS
from rich.table import Table
from rich.panel import Panel



# ETC IMPORTS
import dns.resolver, socket, ssl, sys, time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor



# NSM IMPORTS
from nsm_vars import Variables
from nsm_database import File_Saver


# CONSTANTS
console = Variables.console





class Reverse_IP_Domain():
    """This class will be responsible for pulling domains from ips"""


    scan_socket = 0
    scan_ssl    = 0
    scan_ptr    = 0



    @classmethod
    def _ips_sanitzer(cls, ips, verbose=True) -> set:
        """This will sanitize and validate ips list"""


        c1 = "bold green"
        c2 = "bold yellow"
        c4 = "bold blue"
        c5 = "yellow"
        c6 = "bold red"

        valid_ips = set()

        
        try:

            path = Path() / str(ips)
            if not path.exists(): console.print(f"[{c6}][-] Invalid wordlist given, please check README.md for help!"); sys.exit()
            console.print(path)
            with open(path, "r") as file:

                for word in file:
                    ip = word.strip().split('\t'); ip = ''.join(ip)
                    console.print(ip)
                    Variables.panel_text = (f"Target:[{c5}] {ip}[/{c5}]  -  Max_Workers:[{c5}] {Variables.max_threads}[/{c5}]  -  Errors:[{c5}] {Variables.errors}[/{c5}]")
                    valid_ips.add(ip)

            if verbose: console.print(f"\n\n[{c1}][+] Successfully sanitized list <-- ips.txt ")
            return valid_ips
 
        except Exception as e: console.print(f"[{c6}][-] Exception Error:[/{c6}] {e}"); sys.exit()
        

    @classmethod
    def _pull_domains_socket(cls, ip, verbose=False):
        """This will pull domains using the socket library"""


        c1 = "bold green"
        c2 = "bold yellow"
        c4 = "bold blue"
        c5 = "yellow"
        c6 = "bold red"



        try:

            domain = socket.gethostbyaddr(ip)[0]
            if not domain: return False


            with Variables.LOCK:
                console.print(f"[{c1}][*] Socket:[{c2}] {domain}")
                Variables.found_doms.append(domain)
                cls.scan_socket += 1

                # Update panel text
                c5 = "yellow"
                Variables.panel_text = (f"Socket:[{c5}] {cls.scan_socket}[/{c5}]  -  SSL:[{c5}] {cls.scan_ssl}[/{c5}]  -  PTR:[{c5}] {cls.scan_ptr}[/{c5}]  -  Max_Workers:[{c5}] {Variables.max_threads}[/{c5}]  -  Errors:[{c5}] {Variables.errors}[/{c5}]")


        except Exception as e: 
            if verbose: console.print(f"[{c6}][-] Socket Exception Error:[{c2}] {e}")
            Variables.errors +=1
    

    @classmethod
    def _pull_domains_ssl(cls, ip, verbose=False):
        """This will pull domains using the ssl library"""


        c1 = "bold green"
        c2 = "bold yellow"
        c4 = "bold blue"
        c5 = "yellow"
        c6 = "bold red"



        try:

            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, 443))

            # Wrap with SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            ssl_sock = context.wrap_socket(sock, server_hostname=ip)

            # Get certificate in binary DER format
            cert_bin = ssl_sock.getpeercert(binary_form=True)
            ssl_sock.close()

            # Parse certificate using x509
            import OpenSSL.crypto
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)

            # Extract all domains from certificate
            domains = set()

            # Get CN from subject
            subject = x509.get_subject()
            cn = subject.CN
            if cn:
                domains.add(cn)

            # Get all SANs (Subject Alternative Names)
            for i in range(x509.get_extension_count()):
                ext = x509.get_extension(i)
                if 'subjectAltName' in str(ext.get_short_name()):
                    san_str = str(ext)
                    # Parse SANs from the extension string
                    for san in san_str.split(','):
                        san = san.strip()
                        if san.startswith('DNS:'):
                            domain = san.replace('DNS:', '')
                            domains.add(domain)

            # Print and store all found domains
            if domains:
                with Variables.LOCK:
                    cls.scan_ssl += 1
                    for domain in domains:
                        console.print(f"[{c1}][*] SSL:[{c2}] {domain}")
                        if domain not in Variables.found_doms:
                            Variables.found_doms.append(domain)

                    # Update panel text
                    Variables.panel_text = (f"Socket:[{c5}] {cls.scan_socket}[/{c5}]  -  SSL:[{c5}] {cls.scan_ssl}[/{c5}]  -  PTR:[{c5}] {cls.scan_ptr}[/{c5}]  -  Max_Workers:[{c5}] {Variables.max_threads}[/{c5}]  -  Errors:[{c5}] {Variables.errors}[/{c5}]")




        except socket.timeout:
            if verbose: console.print(f"[{c6}][-] SSL: Timeout connecting to {ip}:443")
            Variables.errors +=1
        except ConnectionRefusedError:
            if verbose: console.print(f"[{c6}][-] SSL: Connection refused for {ip}:443")
            Variables.errors +=1
        except Exception as e:
            if verbose: console.print(f"[{c6}][-] SSL Exception Error:[{c2}] {e}")
            Variables.errors +=1


    @classmethod
    def _pull_domains_ptr(cls, ip, verbose=False):
        """This will pull domains using PTR DNS records"""


        c1 = "bold green"
        c2 = "bold yellow"
        c4 = "bold blue"
        c5 = "yellow"
        c6 = "bold red"



        try:

            # Reverse DNS lookup using PTR records
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3

            # Create reverse IP address for PTR lookup
            rev_ip = dns.reversename.from_address(ip)
            answers = resolver.resolve(rev_ip, 'PTR')

            with Variables.LOCK:
                cls.scan_ptr += 1
                for rdata in answers:
                    domain = str(rdata).rstrip('.')
                    console.print(f"[{c1}][*] PTR:[{c2}] {domain}")
                    if domain not in Variables.found_doms:
                        Variables.found_doms.append(domain)

                # Update panel text
                Variables.panel_text = (f"Socket:[{c5}] {cls.scan_socket}[/{c5}]  -  SSL:[{c5}] {cls.scan_ssl}[/{c5}]  -  PTR:[{c5}] {cls.scan_ptr}[/{c5}]  -  Max_Workers:[{c5}] {Variables.max_threads}[/{c5}]  -  Errors:[{c5}] {Variables.errors}[/{c5}]")


        except dns.resolver.NXDOMAIN:
            if verbose: console.print(f"[{c6}][-] PTR: No PTR record for {ip}")
            Variables.errors +=1
        except dns.resolver.NoAnswer:
            if verbose: console.print(f"[{c6}][-] PTR: No answer for {ip}")
            Variables.errors +=1
        except Exception as e:
            if verbose: console.print(f"[{c6}][-] PTR Exception Error:[/{c6}] {e}")
            Variables.errors +=1
    

    @classmethod
    def _threader(cls, max_threads, ips):
        """Thread that task"""



        c1 = "bold green"
        c2 = "bold yellow"
        c4 = "bold blue"
        c5 = "yellow"
        c6 = "bold red"


        max_threads = int(max_threads)
        futures = []

        with ThreadPoolExecutor(max_workers=max_threads) as executor:

            try:

                for ip in ips:
                    # Submit all three lookup methods for each IP
                    futures.append(executor.submit(Reverse_IP_Domain._pull_domains_socket, ip))
                    futures.append(executor.submit(Reverse_IP_Domain._pull_domains_ssl, ip))
                    futures.append(executor.submit(Reverse_IP_Domain._pull_domains_ptr, ip))

                    #Variables.panel_text = (f"Target:[{c5}] {ip}[/{c5}]  -  Max_Workers:[{c5}] {Variables.max_threads}[/{c5}]  -  Errors:[{c5}] {Variables.errors}[/{c5}]")
                    Variables.panel_text = (f"Socket:[{c5}] {cls.scan_socket}[/{c5}]  -  SSL:[{c5}] {cls.scan_ssl}[/{c5}]  -  PTR:[{c5}] {cls.scan_ptr}[/{c5}]  -  Max_Workers:[{c5}] {Variables.max_threads}[/{c5}]  -  Errors:[{c5}] {Variables.errors}[/{c5}]")



            except Exception as e: console.print(f"[{c6}][-] Exception Error:[/{c6}] {e}");  Variables.errors +=1



    @classmethod
    def main(cls):
        """This will control domain <-- ip  // mapping"""


        ips         = Variables.ips
        max_threads = Variables.max_threads
        
        
        ips = Reverse_IP_Domain._ips_sanitzer(ips=ips)

        p = "=" * 10
        console.print(f"[bold red]\n{p}  IP Enumeration  {p}\n")
        Reverse_IP_Domain._threader(max_threads=max_threads, ips=ips)
        File_Saver.push_scan_results(data=Variables.found_doms, reverse=True)









if __name__ == "__main__":


    domains = [
        "google.com",
        "x.com",
        "youtube.com",
        "proton.me",
        "instagram.com"
    ]
    ips = []

    for d in domains:
        ip = socket.gethostbyname(d)
        ips.append(ip)


    for ip in ips: Reverse_IP_Domain._pull_domains_socket(ip=ip)
    for ip in ips: Reverse_IP_Domain._pull_domains_ssl(ip=ip)

 

    for ip in ips: Reverse_IP_Domain._pull_domains_socket(ip=ip)

    ip_addresses = [
        "44.208.142.85",
        "130.163.184.153",
        "195.60.107.196",
        "147.227.61.110",
        "31.220.61.72",
        "34.121.157.122",
        "20.36.222.137",
        "94.206.76.166",
        "54.157.202.255",
        "34.149.17.238",
        "113.23.20.130",
        "167.86.89.245",
        "199.232.148.93",
        "95.49.68.236",
        "168.119.154.184",
        "37.59.164.72",
        "104.168.162.14",
        "35.201.86.6",
        "168.221.49.114",
        "164.46.32.220",
        "199.191.53.59",
        "128.34.214.236",
        "54.220.103.203",
        "195.201.142.34",
        "64.23.225.154",
        "140.110.207.71",
        "192.3.187.113",
        "62.244.177.68",
        "23.35.103.87",
        "85.128.228.159",
        "4.180.148.206",
        "191.61.189.70",
        "103.13.228.80",
        "38.131.128.105",
        "35.164.219.117",
        "34.120.38.163",
        "129.213.182.88",
        "45.119.54.69",
        "174.141.141.79",
        "116.203.22.210",
        "3.99.9.119",
        "172.205.88.33",
        "95.67.68.35",
        "72.255.49.82",
        "159.89.182.251",
        "34.225.253.231",
        "116.202.10.157",
        "90.117.62.182",
        "106.75.226.195",
        "52.80.210.2",
        "157.245.222.170",
        "23.106.37.228",
        "23.204.100.210",
        "202.19.20.88",
        "23.208.244.244",
        "35.214.25.72",
        "164.191.217.91",
        "13.224.76.95",
        "181.214.179.168",
        "51.8.232.199",
        "111.89.135.81",
        "140.31.169.153",
        "34.217.153.223",
        "79.129.121.21",
        "156.244.118.235",
        "167.235.241.73",
        "193.111.190.21",
        "172.247.106.88",
        "104.130.236.46",
        "98.98.62.11",
        "104.210.219.12",
        "18.235.130.146",
        "43.217.111.229",
        "23.64.42.27",
        "219.147.85.131",
        "54.83.236.134",
        "23.207.56.45",
        "172.205.61.137",
        "46.28.70.130",
        "37.140.241.200",
        "91.103.253.86",
        "147.227.175.201",
        "107.191.56.37",
        "118.98.236.36",
        "159.89.140.146",
        "13.227.186.71",
        "54.174.0.172",
        "176.128.30.193",
        "138.100.201.9",
        "61.108.104.103",
        "155.102.23.20",
        "184.25.248.83",
        "96.127.99.201",
        "15.207.220.146",
        "52.34.153.119",
        "23.39.173.75",
        "16.182.74.46",
        "35.220.193.105",
        "99.84.219.90",
        "15.223.51.168",
        "117.45.3.71",
        "23.82.231.46",
        "140.32.33.79",
        "89.45.237.90",
        "34.149.44.184",
        "99.83.248.211",
        "23.8.33.155",
        "202.80.6.249",
        "2.32.151.250",
        "4.188.250.55",
        "2.20.210.28",
        "3.94.46.28",
        "63.196.206.78",
        "104.42.208.141",
        "90.3.136.123",
        "184.84.193.98",
        "82.144.248.36",
        "109.170.191.156",
        "208.23.227.226",
        "116.90.57.30",
        "54.230.247.33",
        "135.181.254.56",
        "208.68.38.33",
        "34.159.227.113",
        "18.161.206.219",
        "104.97.189.33",
        "148.230.110.149",
        "23.192.104.196",
        "13.124.76.139",
        "220.135.64.7",
        "23.44.148.107",
        "98.89.158.52",
        "18.133.41.190",
        "150.60.91.197",
        "172.237.104.219",
        "184.29.224.124",
        "34.95.101.199",
        "121.130.232.75",
        "82.157.46.137",
        "184.29.189.198",
        "3.216.118.132",
        "51.219.236.158",
        "178.253.30.30",
        "202.44.33.119",
        "23.194.133.213",
        "176.179.101.227",
        "6.2.24.77",
        "119.205.197.153",
        "23.192.178.28",
        "174.138.8.152",
        "217.104.28.110",
        "65.21.53.122",
        "24.44.60.47",
        "70.53.11.84",
        "193.123.122.53",
        "34.94.41.157",
        "62.215.27.209",
        "23.212.12.174",
        "109.164.94.96",
        "24.147.233.104",
        "108.186.23.219",
        "202.28.34.210",
        "80.229.81.182",
        "216.252.186.116",
        "195.145.53.227",
        "37.228.165.249",
        "37.219.13.178",
        "195.133.31.79",
        "65.8.83.238"
    ]
    

    for ip in ip_addresses: 
        Reverse_IP_Domain._pull_domains_socket(ip=ip)
        Reverse_IP_Domain._pull_domains_ssl(ip=ip)