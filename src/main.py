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


# RAISE OPEN-FILE LIMIT SO HIGH -t DOESNT HIT "too many open files"
try:
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
except Exception:
    pass


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




    parser = argparse.ArgumentParser(description="Deep infrastructure scanning and enumeration framework")


    # INPUT OPTIONS
    parser.add_argument("-i",             help="Input file containing list of IPs")
    parser.add_argument("-u",             help="Single URL target for scanning")
    parser.add_argument("-d",             help="Input file containing list of domains")
    parser.add_argument("-t",             help="Maximum threads (default: 250)")

    # SCAN TYPES
    parser.add_argument("--rdns",  action="store_true", help="Perform reverse DNS lookup on IPs")
    parser.add_argument("--ports", action="store_true", help="Perform port scanning on IPs")
    parser.add_argument("--subs",  action="store_true", help="Perform subdomain enumeration")
    parser.add_argument("--live",  action="store_true", help="Check which subs/domains are alive and split out priority (keyword) hits")
    parser.add_argument("--dirs",  action="store_true", help="Perform directory/file bruteforce")
    parser.add_argument("--all",   action="store_true", help="Run all available scan types")

    # SCAN CONFIG
    parser.add_argument("--status-codes",       help="Comma-separated HTTP status codes to filter (default: 200,204,301,302,303,304)")
    parser.add_argument("--sub-wordlist",
                        help="Subdomain wordlist: 1=tiny, 2=small, 3=medium, 4=large, or a custom filename in database/subdomains/ (default: 2)")
    parser.add_argument("--dir-wordlist",
                        help="Directory wordlist: 1=tiny, 2=small, 3=medium, 4=large, or a custom filename in database/directories/ (default: 2)")
    parser.add_argument("--mutations",    help="Custom mutations wordlist for subdomain permutations")

    # OUTPUT
    parser.add_argument("--timeout", help="Request timeout in seconds (default: 5)")
    parser.add_argument("--delay",   help="Seconds to sleep between requests per thread // be a good neighbor / avoid hammering (default: 0)")
    parser.add_argument("--save",    action="store_true", help="Save scan results to file")
    parser.add_argument("--autosave", help="Seconds between incremental autosaves of results to disk while scanning (0 = off)")
    parser.add_argument("--save-path", help="This will be used to save files in a custom path inside the database/saved_scans/{your_path}/{your_scan_results}")
    parser.add_argument("--x",       help="Custom output filename")



    args = parser.parse_args()


    Variables.ips          = args.i            or False
    Variables.url          = args.u            or False
    Variables.domains      = args.d            or False
    Variables.max_threads  = args.t            or 1000

    Variables.scan_rdns    = args.rdns         or False
    Variables.scan_ports   = args.ports        or False
    Variables.scan_sub     = args.subs         or False
    Variables.scan_live    = args.live         or False
    Variables.scan_dir     = args.dirs         or False

    if args.all:
        Variables.scan_rdns = Variables.scan_ports = Variables.scan_sub = Variables.scan_live = Variables.scan_dir = True

    Variables.status_codes = args.status_codes or False
    Variables.wordlist_sub = args.sub_wordlist or "2"
    Variables.wordlist_dir = args.dir_wordlist or "2"

    Variables.timeout      = args.timeout      or 5
    Variables.delay        = args.delay        or 0
    Variables.autosave     = args.autosave     or (30 if args.all else 0)
    Variables.save         = args.save         or False
    Variables.save_name    = args.x            or False
    Variables.save_path    = args.save_path    or False
    


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