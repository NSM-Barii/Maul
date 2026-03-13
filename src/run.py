# THIS WILL RUN ALL SCANS AS A MAIN INSTANCE // ITS REALLY FOR THE LIVE FEATURE // LOL


# ONE IMPORT
from rich.live import Live
from rich.panel import Panel
from rich.console import Console
console = Console()



# NSM IMPORTS
from nsm_vars import Variables
from nsm_reverser import Reverse_IP_Domain
#from nsm_subdomain_scanner import Subdomain_Scanner
#from nsm_directory_scanner import Directory_Scanner
from nsm_subdomain_scanner_async import Async_Subdomain_Scanner
from nsm_directory_scanner_async import Async_Directory_Scanner
from nsm_database import File_Saver



# ETC IMPORTS
import time, threading, asyncio



class Run():
    """Run scans"""


    @staticmethod
    def update():
        """This will auto update the panel.renderable // since doing it within a thread fucks it up and doesnt work"""


        Variables.console.print(f"\n[yellow][*] Background Thread started")

        while True:
            
            text = Variables.panel_text
            Variables.panel.renderable = text

            time.sleep(1)

    

    @staticmethod
    def runner():
        """I need no comment // LOL"""



        with Live(Variables.panel, console=Variables.console, refresh_per_second=Variables.refresh_per_second):


            threading.Thread(target=Run.update, args=(), daemon=True).start()


            if Variables.save: File_Saver.make_path()
            if Variables.ips: Reverse_IP_Domain.main()

            # OLD THREADED SCANNERS
            #if Variables.url or Variables.domains or Variables.found_doms: Subdomain_Scanner.main()
            #if Variables.found_subs: Directory_Scanner.main()

            # NEW ASYNC SCANNERS
            if Variables.url or Variables.domains or Variables.found_doms:
                from nsm_subdomain_scanner import Subdomain_Scanner
                wordlist = Subdomain_Scanner._sub_sanitzer(wordlist=Variables.wordlist_sub)
                asyncio.run(Async_Subdomain_Scanner.run(url=Variables.url, domains=Variables.domains if Variables.domains else Variables.found_doms, wordlist=wordlist))

            if Variables.found_subs:
                from nsm_directory_scanner import Directory_Scanner
                wordlist = Directory_Scanner._dir_sanitzer(wordlist=Variables.wordlist_dir)
                asyncio.run(Async_Directory_Scanner.run(subdomains=Variables.found_subs, wordlist=wordlist))

            if Variables.save: File_Saver.push_scan_results(data=Variables.found_subs)