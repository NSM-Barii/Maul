# THIS WILL RUN ALL SCANS AS A MAIN INSTANCE // ITS REALLY FOR THE LIVE FEATURE // LOL


# UI IMPORT
from rich.live import Live
from rich.panel import Panel
from rich.console import Console


# ETC IMPORTS
import time, threading, asyncio


# NSM IMPORTS
from nsm_vars import Variables
from nsm_reverser import Reverse_IP_Domain
from nsm_port_scanner import Socket_Port_Scanner
from nsm_subdomain_scanner import Subdomain_Scanner
from nsm_subdomain_async import Subdomain_Scanner_Async
from nsm_liveness_scanner import Liveness_Scanner
from nsm_directory_scanner import Directory_Scanner
from nsm_database import File_Saver



# CONSTANTS
console = Variables.console



class Run():
    """Run scans"""



    @staticmethod
    def title(text, results, total_scans, total_time=False):
        """This will be used to print text"""


        if total_time:
            hours = int(total_time // 3600) 
            minutes = int((total_time % 3600) // 60)  
            seconds = int(total_time % 60) 
            total_time = (f"{hours}:{minutes}:{seconds}")


        c1 = "red"; c2 = "bold green"; c3 = "bold blue"; c4 = "bold yellow"

        stats = (
            f"[{c2}] [+] Results:[{c4}] {results}"
            f"\n[{c2}]  [+] Total Scans:[{c4}] {total_scans}"
            f"\n[{c2}]  [+] Elapsed Time:[{c4}] {total_time}"
        )

        
        console.print(
            f"\n\n[{c1}]=========   {text}   =========\n",
            stats,
            f"\n[{c1}]=================================\n\n",
        )



    @staticmethod
    def _update():
        """This will auto update the panel.renderable // since doing it within a thread fucks it up and doesnt work"""


        Variables.console.print(f"\n[yellow][*] Background Thread started")

        while True:
            
            text = Variables.panel_text
            Variables.panel.renderable = text

            time.sleep(0.1)

    

    @classmethod
    def finish(cls):
        """This will be used to call upon shit letting yk what was found as a result"""



        c1 = "bold green"
        c2 = "yellow"
        line = " " * 20


        ips  = Variables.ips
        doms = Variables.found_doms
        subs = Variables.found_subs
        dirs = Variables.found_dirs


        data = (
            f"\n[{c1}]=========   Results   =========\n",
            f"\n[{c1}][+] IPs Found:[{c2}] {ips}"
            f"\n[{c1}][+] Domains Found:[{c2}] {doms}"
            f"\n[{c1}][+] Subdomains Found:[{c2}] {subs}"
            f"\n[{c1}][+] Directories Found:[{c2}] {dirs}"
            f"\n[{c1}]=================================",

        )

        console.print(data)


    @classmethod
    def runner(cls):
        """I need no comment // LOL"""



        with Live(Variables.panel, console=Variables.console, refresh_per_second=Variables.refresh_per_second):


            threading.Thread(target=Run._update, args=(), daemon=True).start()


            # SAVE = only the non-autosave path writes per-module here // autosave handles it live and flushes at the end
            save_now      = Variables.save and not Variables.autosave
            durations     = {}
            program_start = time.time()

            if Variables.save: File_Saver.init()

            if Variables.ips and Variables.scan_rdns:
                t = time.time(); Reverse_IP_Domain.main(); durations["rdns"] = time.time() - t
            #if Variables.ips and Variables.scan_ports: Socket_Port_Scanner.main()

            if Variables.scan_sub:
                t = time.time(); Subdomain_Scanner.main(); durations["subs"] = time.time() - t
                if save_now and Variables.found_subs: File_Saver.push_scan_results(data=Variables.found_subs, label="subs")

            if Variables.scan_live:
                t = time.time(); Liveness_Scanner.main(); durations["live"] = time.time() - t
                if save_now and Variables.found_live: File_Saver.push_scan_results(data=Variables.found_live, label="live")
                if save_now and Variables.found_priority: File_Saver.push_scan_results(data=Variables.found_priority, label="priority")

            if Variables.scan_dir:
                t = time.time(); Directory_Scanner.main(); durations["dirs"] = time.time() - t
                if save_now and Variables.found_dirs: File_Saver.push_scan_results(data=Variables.found_dirs, label="dirs")

            if Variables.save: File_Saver.init(stop=True)

            durations["total"] = time.time() - program_start
            File_Saver.push_report(durations)
        

        cls.finish()
