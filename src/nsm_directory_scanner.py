# THIS WILL BE FOR DIRECTORY BRUTEFORCING AND THAT ALONE



# UI IMPORTS 
from rich.panel import Panel


# ETC IMPORTS
import requests, ipaddress, sys, time, dns.resolver
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor



# NSM IMPORTS
from nsm_vars import Variables



# CONSTANTS
console = Variables.console







class Directory_Scanner():
    """subdomain scanner"""

    
    done = 0


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
                

        except FileNotFoundError as e: CONSOLE.print(f"[{c6}][-] File Not Found Error:[{c2}] {e}"); Variables.errors += 1; return

        except Exception as e: CONSOLE.print(f"[{c6}][-] Exception Error:[{c2}] {e}"); Variables.errors += 1; sys.exit()
    

    @classmethod
    def _directory_scanner(cls, subdomain, dir, mutations=False, CONSOLE=console, verbose=False):
        """Subdomain scan happens here"""


        c1 = "bold green"
        c2 = "bold yellow"
        c4 = "bold blue"
        c5 = "yellow"
        c6 = "green"
        c7 = "bold red"



        try: 
            
            with Variables.LOCK: cls.done += 1
            url = f"http://{subdomain}/{dir}"

            response = requests.get(url=url, timeout=int(Variables.timeout), allow_redirects=False, verify=False)
            code     = response.status_code
            headers  = response.headers
           

            if code in Variables.status_codes:
                
                #with Variables.LOCK:

                    if code in [200,204]:cc = c6
                    elif code in [300,301,302,303,304]: cc = c2


                    CONSOLE.print(f"[{c1}][[{cc}]{code}[/{cc}]][/{c1}][white] {url}")
                    Variables.found_dirs.append(url)
                    return True


        except requests.exceptions.SSLError as e:
            if verbose: CONSOLE.print(f"[{c7}][-] SSL Error:[{c2}] {e}")
            Variables.errors += 1
        except (requests.exceptions.Timeout, requests.exceptions.ConnectTimeout) as e: 
            if verbose: CONSOLE.print(f"[{c7}][-] Timeout Error:[{c2}] {e}")
            Variables.errors += 1
        except requests.ConnectionError as e: 
            if verbose: CONSOLE.print(f"[{c7}][-] Connection Error:[{c2}] {e}")
            Variables.errors += 1
        except Exception as e: 
            if verbose: CONSOLE.print(f"[{c7}][-] Exception Error:[{c2}] {e}")
            Variables.errors += 1


    @classmethod
    def _threader(cls, max_threads, subdomains, wordlist, CONSOLE=console, verbose=True):
        """This will iter through and thread --> _subdomain_scanner"""


        c1 = "bold green"
        c2 = "bold yellow"
        c4 = "bold blue"
        c5 = "yellow"
        c6 = "bold red"


        futures = []
        total   = len(wordlist) * len(subdomains)  # CHANGED: Total = dirs × subdomains


        try: max_threads = int(max_threads)
        except Exception: max_threads = 250



        with ThreadPoolExecutor(max_workers=max_threads) as executor:

            try:

                # OPTIMIZATION: Submit all tasks at once (executor handles queue)
                for domain in subdomains:
                    for dir in wordlist:
                        future = executor.submit(Directory_Scanner._directory_scanner, domain, dir)
                        futures.append(future)  # CHANGED: append instead of add

                # OPTIMIZATION: Update panel less frequently (not in loop)
                CONSOLE.print(f"[{c5}][*] Submitted {total} directory scan tasks across {len(subdomains)} subdomains")

                # OPTIMIZATION: Wait for all futures to complete
                for future in futures:
                    future.result()


            except Exception as e: CONSOLE.print(f"[[{c6}]][-] Exception Error:[{c5}] {e}"); Variables.errors += 1


            CONSOLE.print(f"[{c1}][+] Directory Scan Results:[/{c1}] {len(Variables.found_dirs)}/{total}")
    
    
    @staticmethod
    def main():
        """This will run class wide logic"""

        
        subdomains  = Variables.found_subs
        max_threads = Variables.max_threads
        timeout     = Variables.timeout
        url         = Variables.url
        wordlist    = Variables.wordlist_dir

        
        wordlist  = Directory_Scanner._dir_sanitzer(wordlist=wordlist)
        p = "=" * 10
        console.print(f"[bold red]\n{p}  Directory Enumeration  {p}\n")
        Directory_Scanner._threader(max_threads=max_threads, subdomains=subdomains, wordlist=wordlist)
    
        
