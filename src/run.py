# THIS WILL RUN ALL SCANS AS A MAIN INSTANCE // ITS REALLY FOR THE LIVE FEATURE // LOL


# ONE IMPORT
from rich.live import Live
from rich.panel import Panel
from rich.console import Console
console = Console()



# NSM IMPORTS
from nsm_vars import Variables
from nsm_reverser import Reverse_IP_Domain
from nsm_subdomain_scanner import Subdomain_Scanner
from nsm_directory_scanner import Directory_Scanner
from nsm_database import File_Saver



# ETC IMPORTS
import time, threading



class Run():
    """Run scans"""


    @staticmethod
    def update():
        """This will auto update the panel.renderable // since doing it within a thread fucks it up and doesnt work"""


        Variables.console.print(f"\n[yellow][*] Background Thread started")

        while True:

            Variables.panel.renderable = Variables.panel_text

            time.sleep(1)

    
    
    @staticmethod
    def runner():
        """I need no comment // LOL"""


    
        with Live(Variables.panel, console=Variables.console, refresh_per_second=Variables.refresh_per_second):


            #threading.Thread(target=Run.update, args=(), daemon=True).start()
            

            if Variables.save: File_Saver.make_path()
            if Variables.ips: Reverse_IP_Domain.main()
            if Variables.url or Variables.domains or Variables.found_doms: Subdomain_Scanner.main()
            if Variables.found_subs: Directory_Scanner.main()          
            if Variables.save: File_Saver.push_scan_results(data=Variables.found_subs)