# TRYING SOMETHING NEW // WILL HOST ALL MULTI-MODULE VARS HERE


# ONE IMPORT // LOL
import threading
from rich.console import Console
from rich.panel import Panel


class Variables():
    """Host multi-module vars in here"""
 
    
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
    timeout     = 3
    save        = False
    LOCK        = threading.Lock()
    
    found_doms = []
    found_subs = []
    found_dirs = []


    console = Console()
    panel   = Panel(renderable="Starting", style="bold red", border_style="bold purple", expand=False)
    refresh_per_second = 1

 




    # COLLECT ALL ERRORS
    errors = 0

