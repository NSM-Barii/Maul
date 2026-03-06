# THIS WILL RUN ALL SCANS AS A MAIN INSTANCE // ITS REALLY FOR THE LIVE FEATURE // LOL


# ONE IMPORT
from rich.live import Live
from rich.panel import Panel
from rich.console import Console
console = Console()



# NSM IMPORTS
from nsm_vars import Variables
from nsm_subdomain_scanner import Subdomain_Scanner
from nsm_database import File_Saver



# ETC IMPORTS
import time



class Run():
    """Run scans"""

    
    
    @staticmethod
    def runner():
        """I need no comment // LOL"""


    
        with Live(Variables.panel, console=Variables.console, refresh_per_second=Variables.refresh_per_second):
            

            if Variables.save: File_Saver.make_path(); time.sleep(2)
            if Variables.url or Variables.domains: Subdomain_Scanner.main()
            if Variables.save: File_Saver.push_scan_results(data=Variables.found_subs)