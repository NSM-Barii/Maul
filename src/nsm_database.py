# THIS WILL HOUSE AND CONTROL MAIN DATAPOINTS FROM FILES

# UI IMPORTS
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.console import Console


# NSM IMPORTS
from nsm_vars import Variables



# ETC IMPORTS
from pathlib import Path
from datetime import datetime
import sys



# CONSTANTS
console = Variables.console


"""
DOWNLOAD LINKS

curl {url} > {name}.txt


// SUBDOMAINS
tiny:   https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/fierce-hostlist.txt
small:  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt
medium: https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt
large:  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt


// DIRECTORIES
tiny:   https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
small:  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt
medium: https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt
large:  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt

"""









class File_Saver():
    """This class will save files"""


    path     = False
    path_dir = Path(__file__).parent.parent / "database" / "saved_scans"



    @classmethod
    def push_scan_results(cls, data, verbose=False):
        """This will push current set of ips"""



        
        try:

            if cls.path_dir.exists():


                with open(cls.path, "w") as file:
                    
                    ahh = ''.join(d for d in data)
                    file.write(ahh)

                console.print(f"[bold green][+] Data Successfully pushed")
            

            else: console.print(f"\n[bold red][-] Your missing the database/saved_scans directory, please check README.md for info you skidd!!!"); sys.exit()


        except Exception as e: console.print(f"[bold red][-] Exception Error:[bold yellow] {e}")
        
    


    @classmethod
    def make_path(cls):
        """This will be called upon at the beginning fo the program to then make the path stamp"""

        
        if not cls.path:  


            timestamp = datetime.now().strftime("%Y_%m_%d__%H_%M_%S")

            if Variables.url:  cls.path = cls.path_dir / f"{Variables.url.replace(".", "_")}_{timestamp}.txt" 
            else:              cls.path = cls.path_dir / f"{timestamp}.txt"

            console.print(f"[bold green][*] File Path successfully made:[/bold green] {cls.path}")










"""
Amount of code written per stream


Stream 1: 580 LOC





Well see how long this last as i am one tired ass nigga frl // LOL
"""



# FOUND SOME LIBARIES TO TRY OUT
"""
IP-TO-DOMAIN MAPPING METHODS (FOR INFRASTRUCTURE MODULE)

Libraries Needed:
- ssl (built-in)
- socket (built-in)

1. SSL/TLS Certificate Extraction
   Method: ssl.create_default_context() + socket.create_connection()
   Extract: cert.get('subject') for CN, cert.get('subjectAltName') for SANs
   Port: 443

2. Reverse DNS (PTR) Lookup
   Method: socket.gethostbyaddr(ip)
   Returns: hostname string
   Fast UDP query

"""


"""
SSL CERTIFICATE EXTRACTION - DETAILED IMPLEMENTATION

Why the current implementation doesn't work:
1. socket.create_connection() takes (address, timeout) NOT (address, socket_type)
   - WRONG: socket.create_connection((ip, 443), socket.SOCK_STREAM)
   - RIGHT: socket.create_connection((ip, 443), timeout=5)

2. When connecting to IPs (not domains), SSL hostname verification MUST be disabled
   - SSL certs are issued for DOMAINS not IPs
   - Default context tries to verify hostname → fails on IP connections
   - Fix: context.check_hostname = False + context.verify_mode = ssl.CERT_NONE

3. Only grabbing Common Name (CN) misses most domains
   - CN = 1 domain (main domain on cert)
   - SANs = 10-100+ domains (Subject Alternative Names)
   - SANs are the goldmine for infrastructure mapping

Correct Implementation:

def _pull_domains_ssl(ip):
    # Step 1: Create SSL context and disable hostname verification
    context = ssl.create_default_context()
    context.check_hostname = False      # Don't verify hostname (we're using IP)
    context.verify_mode = ssl.CERT_NONE # Don't verify cert validity

    # Step 2: Connect to IP on port 443 with timeout
    with socket.create_connection((ip, 443), timeout=5) as sock:

        # Step 3: Wrap socket with SSL
        with context.wrap_socket(sock, server_hostname=ip) as ssock:
            cert = ssock.getpeercert()  # Get certificate

            # Step 4: Extract Common Name (CN)
            for sub in cert.get('subject', ()):
                for key, value in sub:
                    if key == 'commonName':
                        print(f"CN: {value}")  # Main domain

            # Step 5: Extract SANs (Subject Alternative Names) - THE GOLDMINE
            for key, value in cert.get('subjectAltName', ()):
                if key == 'DNS':
                    print(f"SAN: {value}")  # Additional domains

Key Points:
- cert.get('subject') returns nested tuples: ((('commonName', 'example.com'),),)
- cert.get('subjectAltName') returns tuples: (('DNS', 'example.com'), ('DNS', 'www.example.com'))
- SANs can contain wildcards: *.example.com
- Single cert can reveal entire infrastructure (all subdomains)
- Always use timeout to prevent hanging on dead IPs
- Wrap in try/except - many IPs won't have port 443 open or valid cert

"""