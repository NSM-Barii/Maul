# THIS WILL LAUCNH THE MAIN CODE RUNNING FROM ALL OTHER MODULES
# THIS PROGRAM IS THE BROTHER PROGRAM OF "Vader" AND IS MEANT TO BE USED ALONGSIDE IT (Optional)


# UI IMPORTS
from rich.console import Console
from rich.panel import Panel
import pyfiglet


# NSM IMPORTS
from run import Run
from nsm_vars import Variables


# ETC IMPORTS
import argparse, time


# CONSTANTS
console = Console()




# LETS GET SOMETHING STRAIGHT
"""

AMERICA FIRST
AMERICA ONLY
AMERICA ALWAYS

"""
# PRO USA
# PRO WESTERN 




class Main():
    """This will launch program wide logic""" 



    # COLORS

    c1 = "bold green"
    c2 = "bold yellow"
    c4 = "bold blue"
    c5 = "yellow"
    c6 = "green"
    c7 = "bold red"




    parser = argparse.ArgumentParser(description="Scanning tool for deep infrastructure analysis")

    
    parser.add_argument("-i",             help="pass a list of ips")
    parser.add_argument("-u",             help="pass a single url for scanning")
    parser.add_argument("-d",             help="Pass .txt file filled with domains")
    parser.add_argument("-t",             help="Max amount of threads to spawn")

    parser.add_argument("--status-codes",       help="Set status codes to filter for")
    parser.add_argument("--sub-wordlist", 
                        choices=["1","2","3","4","tiny.txt", "small.txt", "medium.txt", "large.txt"],
                        help="Pass wordlist you want to use")
    parser.add_argument("--dir-wordlist", 
                        choices=["1","2","3","4","tiny.txt", "small.txt", "medium.txt", "large.txt"],
                        help="Pass wordlist you want to use")
    parser.add_argument("--mutations",    help="Pass a mutations wordlist that you want to use")

    parser.add_argument("--timeout", help="Set custom timeout for scanning/enumeration")
    parser.add_argument("--save",    action="store_true", help="To save your scan results")
    parser.add_argument("--x", help="Use this to set a name for file saving txt")



    args = parser.parse_args()

    
    Variables.ips          = args.i            or False
    Variables.url          = args.u            or False
    Variables.domains      = args.d            or False
    Variables.max_threads  = args.t            or 250
    
    Variables.status_codes = args.status_codes or False
    Variables.wordlist_sub = args.sub_wordlist or "2"
    Variables.wordlist_dir = args.dir_wordlist or "2"

    Variables.timeout      = args.timeout      or 5
    Variables.save         = args.save         or False
    Variables.save_name    = args.x            or False
    


    if Variables.wordlist_sub=="1":   Variables.s_name="tiny.txt"
    elif Variables.wordlist_sub=="2": Variables.s_name="small.txt"
    elif Variables.wordlist_sub=="3": Variables.s_name="medium.txt"
    elif Variables.wordlist_sub=="4": Variables.s_name="large.txt"
    else: Variables.s_name=False

    if Variables.wordlist_dir=="1":   Variables.d_name="tiny.txt"
    elif Variables.wordlist_dir=="2": Variables.d_name="small.txt"
    elif Variables.wordlist_dir=="3": Variables.d_name="medium.txt"
    elif Variables.wordlist_dir=="4": Variables.d_name="large.txt"
    else: Variables.d_name=False




    try: Variables.max_threads = int(Variables.max_threads)
    except Exception: Variables.max_threads = 250


    if args.status_codes:
        codes = []
        for c in args.status_codes.split(','): codes.append(int(c))
        Variables.status_codes = codes  
    else: Variables.status_codes = [200,204,301,302,303,304]


     
    stats = (
        f"[{c1}][+] Url:[{c4}] {Variables.url}"
        f"\n[{c1}] [+] Domains:[{c4}] {Variables.domains}"
        f"\n[{c1}] [+] Max_Threads:[{c4}] {Variables.max_threads}"
        f"\n[{c1}] [+] Sub-Wordlist:[{c4}] {Variables.s_name}"
        f"\n[{c1}] [+] Dir-Wordlist:[{c4}] {Variables.d_name}"
        f"\n[{c1}] [+] Mutations:[{c4}] {Variables.mutations}"
        f"\n[{c1}] [+] Status_Codes:[{c4}] {Variables.status_codes}"
        f"\n[{c1}] [+] Timeout:[{c4}] {Variables.timeout}"
        f"\n[{c1}] [+] File_Saving:[{c4}] {Variables.save}"

    )

    panel  = Panel(renderable= stats,        
        title="Constants",
        border_style="purple",
        style="bold red",
        expand=False 
    )
    
    console.print(
        f"\n[{c1}]=========   CONSTANTS   =========\n",
        stats,
        f"\n[{c1}]=================================",
    )

    #time.sleep(5); print("")
    
    Run.runner()