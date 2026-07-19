# THIS WILL BE FOR DIRECTORY BRUTEFORCING AND THAT ALONE



# UI IMPORTS 
from rich.panel import Panel


# ETC IMPORTS
import requests, sys, time, urllib3
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from collections import deque

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



# NSM IMPORTS
from nsm_vars import Variables
from nsm_database import File_Saver



# CONSTANTS
console = Variables.console




class Directory_Scanner():
    """subdomain scanner"""

    
    done  = 0
    total = 0
    scanned = 0
    scan = True
    current_dir = False
    creations = deque()
    session = None
   

    @classmethod
    def _iter_controller(cls, url=False, domains=False, directores=False, CONSOLE=console):
        """This will be respomsible for passing domain and sub arguments"""
    

        if not cls.creations:
            if domains: targets = [domain for domain in domains] 
            else:       targets = []; targets.append(url)
            cls.total = len(targets) * len(directores)
            for dom in targets:
                for sub in directores:
                    #console.print(sub, dom)
                    cls.creations.append((dom, sub))
            
            CONSOLE.print(f"Iterations made: {len(cls.creations)}"); return False
        
        s, d = cls.creations.popleft()
        #if cls.current_dir != s: cls.current_dir = s
        #console.print(s,d)
        return s,d
    

    @staticmethod
    def _domain_sanitzer(domains, CONSOLE=console, verbose=True) -> list:
        """Now just delegates to the shared File_Saver.domain_sanitizer // logic lives in one place so its not copy-pasted across scanners"""
        return File_Saver.domain_sanitizer(domains=domains, verbose=verbose)
    

    @staticmethod
    def _dir_sanitzer(wordlist, CONSOLE=console, verbose=True) -> list:
        """This method will be responsible for santizing the subdomain wordlist"""
        
        
        c1 = "bold green"
        c2 = "bold yellow"
        c4 = "bold blue"
        c5 = "yellow"
        c6 = "bold red"


        valid_wordlist = set()

        path_main = Path(__file__).parent.parent / "database" / "directories" 
        path  = False


        try:

            if   wordlist=="1" or wordlist=="tiny.txt":     path = path_main / "tiny.txt"
            elif wordlist=="2" or wordlist=="small.txt":    path = path_main / "small.txt"
            elif wordlist=="3" or wordlist=="medium.txt":   path = path_main / "medium.txt"   
            elif wordlist=="4" or wordlist=="large.txt":    path = path_main / "large.txt"


            if not path: path = Path(__file__).parent.parent / "database" / f"directories" / str(wordlist)
            if not path.exists(): CONSOLE.print(f"[{c6}][-] Invalid wordlist given, please check README.md for help!"); sys.exit()


            with open(str(path), "r") as file:

                for word in file:
                    text = word.strip().split("\t"); text = ''.join(text)
                    valid_wordlist.add(text)


                
            if verbose: CONSOLE.print(f"[{c1}][+] Successfully validated dir wordlist: {path}")
            return valid_wordlist
                

        except FileNotFoundError as e: CONSOLE.print(f"[{c6}][-] File Not Found Error:[{c2}] {e}"); Variables.add_error(); return

        except Exception as e: CONSOLE.print(f"[{c6}][-] Exception Error:[{c2}] {e}"); Variables.add_error(); sys.exit()
    

    @classmethod
    def _directory_scanner(cls, mutations=False, CONSOLE=console, verbose=False):
        """Subdomain scan happens here"""


        c1 = "bold green"
        c2 = "bold yellow"
        c4 = "bold blue"
        c5 = "yellow"
        c6 = "green"
        c7 = "bold red"

        if not cls.scan: return Exception
        with Variables.LOCK: subdomain, dir = Directory_Scanner._iter_controller(); Variables.completed_dir += 1; cls.scanned += 1


        try:

            domain = f"{subdomain}/{dir}"
            if subdomain.startswith("http://") or subdomain.startswith("https://"):
                url = domain
            else:
                url = f"http://{domain}"
            Variables.panel_text = f"Target:[{c5}] {subdomain}/*[/{c5}]  -  Enumeration:[{c5}] {cls.scanned}/{cls.total}[/{c5}]  -  Max_Workers:[{c5}] {Variables.max_threads}[/{c5}]  -  Wordlist:[{c5}] {Variables.s_name}[/{c5}]  -  Errors:[{c5}] {Variables.errors}[/{c5}]"


            if Variables.delay: time.sleep(float(Variables.delay))
            response = cls.session.get(url=url, timeout=int(Variables.timeout), allow_redirects=False, verify=False)
            code     = response.status_code
            headers  = response.headers
           

            if code in Variables.status_codes:
                
                with Variables.LOCK:

                    if code in [200,204]:cc = c6
                    elif code in [300,301,302,303,304]: cc = c2


                    CONSOLE.print(f"[{c1}][[{cc}]{code}[/{cc}]][/{c1}][white] {domain}")
                    Variables.found_dirs.append(domain)
                    return True


        except requests.exceptions.SSLError as e:
            if verbose: CONSOLE.print(f"[{c7}][-] SSL Error:[{c2}] {e}")
            Variables.add_error()
        except (requests.exceptions.Timeout, requests.exceptions.ConnectTimeout) as e: 
            if verbose: CONSOLE.print(f"[{c7}][-] Timeout Error:[{c2}] {e}")
            Variables.add_error()
        except requests.ConnectionError as e: 
            if verbose: CONSOLE.print(f"[{c7}][-] Connection Error:[{c2}] {e}")
            Variables.add_error()
        except Exception as e: 
            if verbose: CONSOLE.print(f"[{c7}][-] Exception Error:[{c2}] {e}")
            Variables.add_error()
    


    @classmethod
    def _worker(cls):
        """Worker thread that repeatedly runs the scanner"""

        while cls.scan:

            with Variables.LOCK:
                if not cls.creations:
                    return

            cls._directory_scanner()


    @classmethod
    def _threader(cls, max_threads, CONSOLE=console, verbose=True):
        """This will iter through and thread --> _subdomain_scanner"""


        c1 = "bold green"
        c2 = "bold yellow"
        c4 = "bold blue"
        c5 = "yellow"
        c6 = "bold red"


        futures = []
        cls.time_start = time.time()


        try: max_threads = int(max_threads)
        except Exception: max_threads = 250


        # ONE SHARED SESSION // POOL SIZED TO THREADS SO WE REUSE CONNECTIONS INSTEAD OF A NEW TCP/TLS HANDSHAKE PER REQUEST
        adapter = requests.adapters.HTTPAdapter(pool_connections=max_threads, pool_maxsize=max_threads)
        cls.session = requests.Session()
        cls.session.mount("http://", adapter)
        cls.session.mount("https://", adapter)


        with ThreadPoolExecutor(max_workers=max_threads) as executor:

            try:

                for _ in range(max_threads): futures.append(executor.submit(cls._worker))

                for f in futures: f.result()


            except KeyboardInterrupt as e:
                CONSOLE.print(f"[[{c6}]][-] Exception Error:[{c5}] {e}")
                Variables.add_error()
                cls.scan = False
            except Exception as e:
                Variables.add_error()
                cls.scan = False
    
    

    @classmethod
    def main(cls):
        """This will run class wide logic"""

        
        subdomains  = Variables.domains 
        max_threads = Variables.max_threads
        timeout     = Variables.timeout
        url         = Variables.url
        wordlist    = Variables.wordlist_dir

        

        # PREFER RESULTS FROM EARLIER PHASES SO --live/--subs CHAIN FORWARD // fall back to the -d file only if nothing ran before us
        if   Variables.found_live:  subdomains = Variables.found_live
        elif Variables.found_subs:  subdomains = Variables.found_subs
        elif Variables.found_doms:  subdomains = Variables.found_doms
        elif Variables.domains:     subdomains = Directory_Scanner._domain_sanitzer(domains=Variables.domains)
        else:                       subdomains = False
        if not subdomains and not url: console.print("\n[bold red][-] Input a valid domain goofy")

        wordlist  = Directory_Scanner._dir_sanitzer(wordlist=wordlist)
        p = "=" * 10
        console.print(f"[bold red]\n{p}  Directory Enumeration  {p}\n")
        Directory_Scanner._iter_controller(url=url, domains=subdomains, directores=wordlist)
        Directory_Scanner._threader(max_threads=max_threads)


        from run import Run
        time_total = time.time() - cls.time_start
        Run.title(text="Directory Results", results=len(Variables.found_dirs), total_scans=cls.total, total_time=time_total)
    
    
        
