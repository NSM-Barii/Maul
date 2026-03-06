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