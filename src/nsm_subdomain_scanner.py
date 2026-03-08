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
    def _subdomain_scanner(cls, domain, sub, mutations=False, CONSOLE=console, verbose=False):
        """Subdomain scan happens here"""


        c1 = "bold green"
        c2 = "bold yellow"
        c4 = "bold blue"
        c5 = "yellow"
        c6 = "green"
        c7 = "bold red"



        try:

            cls.done += 1
 
            subdomain = (f"{sub}.{domain}")
            rdata = dns.resolver.resolve(subdomain, "A")

            if rdata:
                
                with Variables.LOCK:

                    CONSOLE.print(f"[{c1}][*][{c2}] {subdomain}")
                    Variables.found_subs.append(subdomain)
                    return True


        except Exception as e: 
            if verbose: CONSOLE.print(f"[{c7}][-] Exception Error:[{c2}] {e}")
            Variables.errors += 1
        


    @classmethod
    def _threader(cls, max_threads, url, domains, wordlist, CONSOLE=console, verbose=True):
        """This will iter through and thread --> _subdomain_scanner"""


        c1 = "bold green"
        c2 = "bold yellow"
        c4 = "bold blue"
        c5 = "yellow"
        c6 = "bold red"


        futures = []  # CHANGED: list instead of set for easier iteration
        total   = len(wordlist)


        with ThreadPoolExecutor(max_workers=max_threads) as executor:

            try:

                if domains:
                    print("1")
                    for domain in domains:
                        for sub in wordlist:

                            # REMOVED: if len(futures) < max_threads check - executor handles queue automatically
                            future = executor.submit(Subdomain_Scanner._subdomain_scanner, domain, sub)
                            futures.append(future)  # CHANGED: append instead of add
                            Variables.panel.renderable = (f"Target:[{c5}] {url}[/{c5}]  -  Max_Workers:[{c5}] {Variables.max_threads}[/{c5}]  -  Wordlist:[{c5}] {Variables.s_name}[/{c5}]  -  Errors:[{c5}] {Variables.errors}[/{c5}]")

                            # REMOVED: manual futures cleanup - not needed


                elif url:
                    print("2")
                    for sub in wordlist:

                        # REMOVED: if len(futures) < max_threads check - executor handles queue automatically
                        # REMOVED: time.sleep(0.1) - was killing performance
                        future = executor.submit(Subdomain_Scanner._subdomain_scanner, url, sub)
                        futures.append(future)  # CHANGED: append instead of add
                        # -  Enumeration:[{c5}] {cls.done}/{total}[/{c5}]
                        Variables.panel.renderable = (f"Target:[{c5}] {url}[/{c5}]  -  Enumeration:[{c5}] {cls.done}/{total}[/{c5}]  -  Max_Workers:[{c5}] {Variables.max_threads}[/{c5}]  -  Wordlist:[{c5}] {Variables.s_name}[/{c5}]  -  Errors:[{c5}] {Variables.errors}[/{c5}]")

                        # REMOVED: manual futures cleanup - not needed


                # ADDED: Wait for all futures to complete
                for future in futures:
                    future.result()


            except Exception as e: CONSOLE.print(f"[[{c6}]][-] Exception Error:[{c5}] {e}"); Variables.errors += 1


            CONSOLE.print(f"\n[{c1}][+] Subdomain Enumeration Results:[/{c1}] {len(Variables.found_subs)}/{total}")
    
    
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
        Subdomain_Scanner._threader(max_threads=max_threads, url=url, domains=domains, wordlist=wordlist)
    
        



if __name__ == "__main__":

    t = 2


    if t==1:Subdomain_Scanner._domain_sanitzer(domains=input("enter path: "))

    elif t==2:
        for num in range(1,5): 
            print(num)
            Subdomain_Scanner._sub_sanitzer(wordlist=num)