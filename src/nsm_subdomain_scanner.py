# THIS WILL BE RESPONSIBLE FOR SUBDOMAIN SCAN // AND SUBDOMAIN SCAN ONLY


# UI IMPORTS
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.console import Console



# ETC IMPORTS
import requests, ipaddress, sys, time
import dns.resolver
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor



# NSM IMPORTS
from nsm_vars import Variables



# CONSTANTS
console = Variables.console




class Subdomain_Scanner():
    """subdomain scanner"""

    
    done = 0
    scan = True
    creations = []
    total = 0
    current_sub = False


    
    @classmethod
    def _iter_controller(cls, url=False, domains=False, subdomains=False, CONSOLE=console):
        """This will be respomsible for passing domain and sub arguments"""
       

        if not cls.creations:
            if domains: targets = [domain for domain in domains] 
            else:       targets = []; targets.append(url)
            cls.total = len(targets) * len(subdomains)
            for dom in targets:
                for sub in subdomains:
                    #console.print(sub, dom)
                    cls.creations.append((sub, dom))
            
            CONSOLE.print(f"Iterations made: {len(cls.creations)}"); return False
        
        s, d = cls.creations.pop(0)
        if cls.current_sub != s: cls.current_sub = s
        #console.print(s,d)
        return s,d
         

        
    @staticmethod
    def _sub_sanitzer(wordlist, CONSOLE=console, verbose=True) -> list:
        """This method will be responsible for santizing the subdomain wordlist"""
        
        
        c1 = "bold green"
        c2 = "bold yellow"
        c4 = "bold blue"
        c5 = "yellow"
        c6 = "bold red"


        valid_wordlist = set()

        path_main = Path(__file__).parent.parent / "database" / "subdomains" 
        path  = False


        try:

            if   wordlist=="1" or wordlist=="tiny.txt":     path = path_main / "tiny.txt"
            elif wordlist=="2" or wordlist=="small.txt":    path = path_main / "small.txt"
            elif wordlist=="3" or wordlist=="medium.txt":   path = path_main / "medium.txt"   
            elif wordlist=="4" or wordlist=="large.txt":    path = path_main / "large.txt"


            if not path: path = Path(__file__).parent.parent / "database" / f"subdomains" / str(wordlist)
            if not path.exists(): CONSOLE.print(f"[{c6}][-] Invalid wordlist given, please check README.md for help!"); sys.exit()


            with open(str(path), "r") as file:

                for word in file:
                    text = word.strip().split("\t"); text = ''.join(text)
                    valid_wordlist.add(text)
                 

                
            if verbose: CONSOLE.print(f"[{c1}][+] Successfully validated sub wordlist: {path}")
            return valid_wordlist
                

        except FileNotFoundError as e: CONSOLE.print(f"[{c6}][-] File Not Found Error:[{c2}] {e}"); Variables.errors += 1; return

        except Exception as e: CONSOLE.print(f"[{c6}][-] Exception Error:[{c2}] {e}"); Variables.errors += 1; sys.exit()
    

    @staticmethod
    def _domain_sanitzer(domains, CONSOLE=console, verbose=True) -> list:
        """This will sanitize domain wordlist given by user --> coming from Vader --> Maul"""


        c1 = "bold green"
        c2 = "bold yellow"
        c4 = "bold blue"
        c5 = "yellow"
        c6 = "bold red"


        valid_domains = []


        try:

            path = Path() / str(domains)
            if not path.exists(): CONSOLE.print(f"[{c6}][-] Invalid domain wordlist given, please check README.md for help!"); sys.exit()

            with open(str(path), "r") as file:

                for word in file:
                    text = word.strip().split("\n"); text = '\n'.join(text)
                    valid_domains.append(text)


            if verbose: CONSOLE.print(f"[{c1}][+] Successfully validated domain wordlist: {path}")
            return valid_domains
            
        

        except FileNotFoundError as e: CONSOLE.print(f"[{c6}][-] Exception Error:[{c2}] {e}"); Variables.errors += 1; sys.exit()

        except Exception as e: CONSOLE.print(f"[{c6}][-] Exception Error:[{c2}] {e}"); Variables.errors += 1; sys.exit()
    

    @classmethod
    def _subdomain_scanner(cls, mutations=False, CONSOLE=console, verbose=False):
        """Subdomain scan happens here"""


        c1 = "bold green"
        c2 = "bold yellow"
        c4 = "bold blue"
        c5 = "yellow"
        c6 = "green"
        c7 = "bold red"

        if not cls.scan: return Exception
        with Variables.LOCK: sub, domain = Subdomain_Scanner._iter_controller()



        try:

            with Variables.LOCK: Variables.completed_sub += 1; cls.scanned += 1
            subdomain = (f"{sub}.{domain}")
            rdata = dns.resolver.resolve(subdomain, "A")

            # Update counter and panel text with FRESH values
                # Rebuild f-string here with current cls.done value
                #Variables.panel_text = f"Target:[{c5}] {domain}[/{c5}]  -  Enumeration:[{c5}] {Variables.completed_sub}/{total}[/{c5}]  -  Max_Workers:[{c5}] {Variables.max_threads}[/{c5}]  -  Wordlist:[{c5}] {Variables.s_name}[/{c5}]  -  Errors:[{c5}] {Variables.errors}[/{c5}]"

            if rdata:

                response = requests.get(url=f"https://{subdomain}")
                if response.status_code not in [200,204]: return False
                
                CONSOLE.print(f"[{c1}][*][{c2}] {subdomain}")
                with Variables.LOCK: Variables.found_subs.append(subdomain); return True


        except Exception as e: 
            if verbose: CONSOLE.print(f"[{c7}][-] Exception Error:[{c2}] {e}")
            Variables.errors += 1; return False
        

    @classmethod
    def _threader(cls, max_threads, CONSOLE=console, verbose=True):
        """This will iter through and thread --> _subdomain_scanner"""


        c1 = "bold green"
        c2 = "bold yellow"
        c4 = "bold blue"
        c5 = "yellow"
        c6 = "bold red"


        futures = []  
        cls.scanned = 0


        try:              max_threads = int(max_threads)
        except Exception: max_threads = 250
        Variables.panel_text = f"Target:[{c5}] {cls.current_sub}.*[/{c5}]  -  Enumeration:[{c5}] {cls.scanned}/{cls.total}[/{c5}]  -  Max_Workers:[{c5}] {Variables.max_threads}[/{c5}]  -  Wordlist:[{c5}] {Variables.s_name}[/{c5}]  -  Errors:[{c5}] {Variables.errors}[/{c5}]"



        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            while cls.scan:

                try:

                    while len(futures) < max_threads and cls.scan:
                        futures.append(executor.submit(Subdomain_Scanner._subdomain_scanner))

                    futures = [f for f in futures if not f.done()]
                    Variables.panel_text = f"Target:[{c5}] {cls.current_sub}.*[/{c5}]  -  Enumeration:[{c5}] {cls.scanned}/{cls.total}[/{c5}]  -  Max_Workers:[{c5}] {Variables.max_threads}[/{c5}]  -  Wordlist:[{c5}] {Variables.s_name}[/{c5}]  -  Errors:[{c5}] {Variables.errors}[/{c5}]"
            

                except KeyboardInterrupt as e:  CONSOLE.print(f"[{c6}][-] Exception Error:[{c5}] {e}"); Variables.errors += 1; cls.scan = False; exit()
                except Exception as e: Variables.errors += 1; cls.scan = False


                if not cls.creations:
                    cls.scan = False
                    CONSOLE.print(f"\n[{c1}][+] Subdomain Enumeration Results:[/{c1}] {len(Variables.found_subs)}/{cls.total}")
        
    
    @staticmethod
    def main():
        """This will run class wide logic"""

        
        max_threads = Variables.max_threads
        timeout     = Variables.timeout
        url         = Variables.url
        domains     = Variables.domains
        wordlist    = Variables.wordlist_sub
        mutations   = Variables.mutations

        
        if domains: domains = Subdomain_Scanner._domain_sanitzer(domains=domains)
        else:       domains = Variables.found_doms
        wordlist  = Subdomain_Scanner._sub_sanitzer(wordlist=wordlist)
        
        p = "=" * 10
        console.print(f"[bold red]\n{p}  Subdomain Enumeration  {p}\n")
        Subdomain_Scanner._iter_controller(url=url, domains=domains, subdomains=wordlist)
        Subdomain_Scanner._threader(max_threads=max_threads)
    
        



if __name__ == "__main__":

    t = 2


    if t==1:Subdomain_Scanner._domain_sanitzer(domains=input("enter path: "))

    elif t==2:
        for num in range(1,5): 
            print(num)
            Subdomain_Scanner._sub_sanitzer(wordlist=num)