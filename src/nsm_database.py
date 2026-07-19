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
import sys, json



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



# WHAT I RAN
"""

subfinder -df domain.txt -o subdomains.txt
httpx -l subdomains.txt -title -tech-detect -status-code -u -o live_host.txt
grep -iE "(admin|login|portal|api|panel|vpn|mail|dashboard|auth|cpanel|webmail)" live_host.txt > priorities.txt
sudo venv/bin/python -d ../database/iran_analysis/top/priorities.txt --dirs --dir-wordlist 4 -t 750 --save --x sub_directories.txt
httpx -l juicy_finds.txt -title -status-code -server -tech-detect -cdn -mc 200,301,302 -o juicy_finds_live.txt
theHarvester -d khamenei.ir -b all -f emails_khamenei.json
theHarvester -d petroleumbs.ir -b all -f emails_petroleumbs.json
theHarvester -d vahdat.ac.ir -b all -f emails_vahdat.json
"""



# SEPERATE IRAN DIR
"""
subfinder -dL domains.txt -all -recursive -timeout 30 -o subdomains_full.txt

"""






class File_Saver():
    """This class will save files"""


    base_name    = False
    path_dir     = Path(__file__).parent.parent / "database" / "saved_scans"



    @classmethod
    def push_scan_results(cls, data, label, f_type="txt", verbose=False):
        """This will push current set of results to its own labeled file // one file per scan type"""


        try:

            if cls.path_dir.exists():

                if Variables.save_path: 
                      p = cls.path_dir / Variables.save_path
                      p.mkdir(parents=True, exist_ok=True)

                      pathway = cls.path_dir / Variables.save_path /  f"{cls.base_name}_{label}.{f_type}"
                else: 
                    pathway = cls.path_dir / f"{cls.base_name}_{label}.{f_type}"

                if f_type == "txt":
                    with open(f"{pathway}", "w") as file:

                        ahh = '\n'.join(d for d in data)
                        file.write(ahh)

                elif f_type == "json":
                    with open(f"{pathway}", "w") as file:
                        json.dump(data, file, indent=4)

                console.print(f"[bold green][+] Data Successfully pushed:[/bold green] {pathway}")


            else: console.print(f"\n[bold red][-] Your missing the database/saved_scans directory, please check README.md for info you skidd!!!"); sys.exit()


        except Exception as e: console.print(f"[bold red][-] Exception Error:[bold yellow] {e}")
        
    
    
    @classmethod
    def ips_sanitizer(cls, ips, verbose=True):
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
                    Variables.panel_text = (f"Target:[{c5}] {ip}[/{c5}]  -  Length:[{c5}] {len(word)}[/{c5}]")
                    valid_ips.add(ip)

            if verbose: console.print(f"\n\n[{c1}][+] Successfully sanitized list <-- ips.txt ")
            return valid_ips

        except Exception as e: console.print(f"[{c6}][-] Exception Error:[/{c6}] {e}"); sys.exit()


    @classmethod
    def domain_sanitizer(cls, domains, verbose=True) -> list:
        """This will sanitize a domain list file given by user --> coming from Vader --> Maul // shared by sub/live/dir scanners"""


        c1 = "bold green"
        c2 = "bold yellow"
        c6 = "bold red"


        valid_domains = []


        try:

            path = Path() / str(domains)
            if not path.exists(): console.print(f"[{c6}][-] Invalid domain wordlist given, please check README.md for help!"); sys.exit()

            with open(str(path), "r") as file:

                for word in file:
                    text = word.strip()
                    if text: valid_domains.append(text)


            if verbose: console.print(f"[{c1}][+] Successfully validated domain wordlist: {path}")
            return valid_domains


        except Exception as e: console.print(f"[{c6}][-] Exception Error:[{c2}] {e}"); Variables.add_error(); sys.exit()


    @classmethod
    def make_path(cls):
        """This will be called upon at the beginning fo the program to then make the path stamp"""

        
        if not cls.base_name:


            timestamp = datetime.now().strftime("%Y_%m_%d__%H_%M_%S")



            if Variables.save_name:   cls.base_name = f"{Variables.save_name}_{timestamp}"
            elif Variables.url:       cls.base_name = f"{Variables.url.replace(".", "_")}_{timestamp}"
            else:                     cls.base_name = timestamp

            console.print(f"[bold green][*] File Path successfully made:[/bold green] {cls.path_dir / cls.base_name}_*")










"""
Amount of code written per stream


Stream 1: 580 LOC





Well see how long this last as i am one tired ass nigga frl // LOL
"""



# FOUND SOME LIBARIES TO TRY OUT
"""
IP-TO-DOMAIN MAPPING METHODS (FOR INFRASTRUCTURE MODULE)

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

"""