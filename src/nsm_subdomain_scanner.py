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
from collections import deque


# NSM IMPORTS
from nsm_vars import Variables
from nsm_database import File_Saver



# CONSTANTS
console  = Variables.console
resolver = dns.resolver.Resolver(configure=False)

resolver.timeout = 2
resolver.lifetime = 2

resolver.nameservers = [
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9"
]



class Subdomain_Scanner():
    """subdomain scanner"""

    
    done = 0
    scan = True

    creations = False

    total = 0
    current_sub = False


    
    @classmethod
    def _iter_controller(cls, url=False, domains=False, subdomains=False, CONSOLE=console):
        """This will be respomsible for passing domain and sub arguments"""
    

        if not cls.creations:
            if domains: targets = [domain for domain in domains] 
            else:       targets = [url]
            cls.total = len(targets) * len(subdomains)

            # GENERATOR (note the ROUND brackets) // lazy: builds NOTHING now, hands out one (sub,dom) at a time via next()
            # a list [..] would build EVERY combo upfront (domains x wordlist = millions of tuples = OOM) // () keeps memory flat
            # one-way + single-use: no len(), no indexing, dies when drained -> main() resets it to False to rebuild a fresh one
            cls.creations = ((sub,dom) for dom in targets for sub in subdomains)
           
            
            # INEFFECIENT FOR MEMORY // KEEPING FOR REFERENCE
            #for dom in targets:
            #    for sub in subdomains:
            #        #console.print(sub, dom)
            #        cls.creations.append((sub, dom))
            
            CONSOLE.print(f"Iterations made: {cls.total}"); return False
        
        
        
        try: return next(cls.creations)
        except StopIteration: return False
        
        
        # DEAPPRECIATED
        #s, d = cls.creations.popleft()
  
        #return s,d
        

        
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
                

        except FileNotFoundError as e: CONSOLE.print(f"[{c6}][-] File Not Found Error:[{c2}] {e}"); Variables.add_error(); return

        except Exception as e: CONSOLE.print(f"[{c6}][-] Exception Error:[{c2}] {e}"); Variables.add_error(); sys.exit()
    

    @staticmethod
    def _domain_sanitzer(domains, CONSOLE=console, verbose=True) -> list:
        """Now just delegates to the shared File_Saver.domain_sanitizer // logic lives in one place so its not copy-pasted across scanners"""


        return File_Saver.domain_sanitizer(domains=domains, verbose=verbose)
    

    @classmethod
    def _subdomain_scanner(cls, work, mutations=False, CONSOLE=console, verbose=False):
        """Subdomain scan happens here // work = (sub, domain) already pulled by the worker"""


        c1 = "bold green"
        c2 = "bold yellow"
        c4 = "bold blue"
        c5 = "yellow"
        c6 = "green"
        c7 = "bold red"

        sub, domain = work


        try:

            subdomain = (f"{sub}.{domain}")#; cls.current_sub = subdomain
            Variables.panel_text = f"Target:[{c5}] {sub}.*[/{c5}]  -  Enumeration:[{c5}] {cls.scanned}/{cls.total}[/{c5}]  -  Max_Workers:[{c5}] {Variables.max_threads}[/{c5}]  -  Wordlist:[{c5}] {Variables.s_name}[/{c5}]  -  Errors:[{c5}] {Variables.errors}[/{c5}]"
            if Variables.delay: time.sleep(float(Variables.delay))
            rdata = resolver.resolve(subdomain, "A")

            if rdata:

                #response = requests.get(url=f"https://{subdomain}", timeout=Variables.timeout)
                #if response.status_code not in Variables.status_codes:
                
                CONSOLE.print(f"[{c1}][*][{c2}] {subdomain}") # - {cls.scanned}/{cls.total}")
                with Variables.LOCK: Variables.found_subs.append(subdomain); return True


        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout, dns.resolver.NoNameservers):
            Variables.add_error(); return False
        except Exception as e:
            if verbose: CONSOLE.print(f"[{c7}][-] Exception Error:[{c2}] {e}")
            Variables.add_error(); File_Saver.push_errors(e); return False
        
    
    
    @classmethod
    def _worker(cls):
        """Worker pulls the next (sub, domain) under the lock // stops when the generator is drained"""

        while cls.scan:

            with Variables.LOCK:
                work = cls._iter_controller()
                if not work: return                              # generator drained -> this worker is done
                Variables.completed_sub += 1; cls.scanned += 1

            cls._subdomain_scanner(work)


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
        cls.time_start = time.time()


        try:              max_threads = int(max_threads)
        except Exception: max_threads = 250
        

        with ThreadPoolExecutor(max_workers=max_threads) as executor:

            try:

                for _ in range(max_threads): futures.append(executor.submit(cls._worker))

                for f in futures: f.result()


            except KeyboardInterrupt as e:
                if verbose: CONSOLE.print(f"[{c6}][-] Exception Error:[{c5}] {e}")
                Variables.add_error()
                cls.scan = False
                exit()

            except Exception as e:
                if verbose: CONSOLE.print(f"[{c6}][-] Exception Error:[{c5}] {e}")
                Variables.add_error()
                cls.scan = False
                exit()


    
    @classmethod
    def main(cls):
        """This will run class wide logic"""


        max_threads = Variables.max_threads
        timeout     = Variables.timeout
        url         = Variables.url
        domains     = Variables.domains
        wordlist    = Variables.wordlist_sub
        mutations   = Variables.mutations

        
        if Variables.domains:      domains = Subdomain_Scanner._domain_sanitzer(domains=domains)
        elif Variables.found_doms: domains = Variables.found_doms
        else:                      domains = False
        if not domains and not url: console.print("\n[bold red][-] Input a valid domain goofy")

        wordlist  = Subdomain_Scanner._sub_sanitzer(wordlist=wordlist)
        
        p = "=" * 10
        console.print(f"[bold red]\n{p}  Subdomain Enumeration  {p}\n")
        Subdomain_Scanner._iter_controller(url=url, domains=domains, subdomains=wordlist)
        Subdomain_Scanner._threader(max_threads=max_threads)
        
        from run import Run
        time_total = time.time() - cls.time_start
        Run.title(text="Subdomain Results", results=len(Variables.found_subs), total_scans=cls.total, total_time=time_total)
    
        



if __name__ == "__main__":

    t = 2


    if t==1:Subdomain_Scanner._domain_sanitzer(domains=input("enter path: "))

    elif t==2:
        for num in range(1,5): 
            print(num)
            Subdomain_Scanner._sub_sanitzer(wordlist=num)