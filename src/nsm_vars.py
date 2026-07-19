# TRYING SOMETHING NEW // WILL HOST ALL MULTI-MODULE VARS HERE


# ONE IMPORT // LOL
import threading
from rich.console import Console
from rich.panel import Panel


class Variables():
    """Host multi-module vars in here"""



    # TYPE OF SCAN
    scan_rdns  = False
    scan_ports = False
    scan_sub   = False
    scan_live  = False
    scan_dir   = False
    scan_sd    = False
 
    
    ips          = False
    url          = False
    domains      = False

    wordlist_sub = False
    wordlist_dir = False
    mutations    = False

    s_name       = False
    d_name       = False

    status_codes = False

    max_threads = 250
    timeout     = 1
    delay       = 0
    save        = False
    save_name   = False
    save_path   = False
    LOCK        = threading.RLock()
    
    found_doms     = []
    found_subs     = []
    found_live     = []
    found_priority = []
    found_dirs     = []

    
    console = Console()
    panel_text = "False"
    panel   = Panel(renderable="Starting", style="bold red", border_style="bold purple", expand=False)
    refresh_per_second = 1

 


 
    completed_sub = 0
    completed_dir = 0
    # COLLECT ALL ERRORS
    errors = 0



    @classmethod
    def add_error(cls):
        """Thread-safe error bump // increment under the lock so the count isnt a race"""
        with cls.LOCK: cls.errors += 1

