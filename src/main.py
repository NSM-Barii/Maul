import argparse
import sys

from rich.console import Console

from run import Run
from nsm_vars import Variables

console = Console()

WORDLIST_MAP = {
    "1": "tiny.txt",
    "2": "small.txt",
    "3": "medium.txt",
    "4": "large.txt",
}

DEFAULT_STATUS_CODES = [200, 204, 301, 302, 303, 304]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Deep infrastructure scanning and enumeration framework"
    )

    # Input options
    parser.add_argument("-i", help="Input file containing list of IPs")
    parser.add_argument("-u", help="Single URL target for scanning")
    parser.add_argument("-d", help="Input file containing list of domains")
    parser.add_argument("-t", type=int, default=250, help="Maximum threads (default: 250)")

    # Scan types
    parser.add_argument("--rdns", action="store_true", help="Perform reverse DNS lookup on IPs")
    parser.add_argument("--ports", action="store_true", help="Perform port scanning on IPs")
    parser.add_argument("--subs", action="store_true", help="Perform subdomain enumeration")
    parser.add_argument("--dirs", action="store_true", help="Perform directory/file bruteforce")
    parser.add_argument("--all", action="store_true", help="Run all available scan types")

    # Scan config
    parser.add_argument("--status-codes", help="Comma-separated HTTP status codes to filter")
    parser.add_argument(
        "--sub-wordlist",
        choices=["1", "2", "3", "4"],
        default="2",
        help="Subdomain wordlist: 1=tiny, 2=small, 3=medium, 4=large (default: 2)",
    )
    parser.add_argument(
        "--dir-wordlist",
        choices=["1", "2", "3", "4"],
        default="2",
        help="Directory wordlist: 1=tiny, 2=small, 3=medium, 4=large (default: 2)",
    )
    parser.add_argument("--mutations", help="Custom mutations wordlist for subdomain permutations")

    # Output
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds (default: 5)")
    parser.add_argument("--save", action="store_true", help="Save scan results to file")
    parser.add_argument("--x", help="Custom output filename")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()

    return parser.parse_args()


def resolve_status_codes(raw):
    if not raw:
        return DEFAULT_STATUS_CODES
    return [int(code.strip()) for code in raw.split(",")]


def main():
    args = parse_args()

    Variables.ips = args.i
    Variables.url = args.u
    Variables.domains = args.d
    Variables.max_threads = args.t

    if args.all:
        Variables.scan_rdns = True
        Variables.scan_ports = True
        Variables.scan_sub = True
        Variables.scan_dir = True
    else:
        Variables.scan_rdns = args.rdns
        Variables.scan_ports = args.ports
        Variables.scan_sub = args.subs
        Variables.scan_dir = args.dirs

    Variables.status_codes = resolve_status_codes(args.status_codes)
    Variables.wordlist_sub = args.sub_wordlist
    Variables.wordlist_dir = args.dir_wordlist
    Variables.s_name = WORDLIST_MAP[args.sub_wordlist]
    Variables.d_name = WORDLIST_MAP[args.dir_wordlist]
    Variables.mutations = args.mutations
    Variables.timeout = args.timeout
    Variables.save = args.save
    Variables.save_name = args.x

    c1 = "bold green"
    c4 = "bold blue"

    console.print(
        f"\n[{c1}]=========   CONSTANTS   =========\n",
        f"[{c1}][+] Url:[{c4}] {args.u}"
        f"\n[{c1}] [+] Domains:[{c4}] {args.d}"
        f"\n[{c1}] [+] Max_Threads:[{c4}] {args.t}"
        f"\n[{c1}] [+] Sub-Wordlist:[{c4}] {Variables.s_name}"
        f"\n[{c1}] [+] Dir-Wordlist:[{c4}] {Variables.d_name}"
        f"\n[{c1}] [+] Mutations:[{c4}] {args.mutations}"
        f"\n[{c1}] [+] Status_Codes:[{c4}] {Variables.status_codes}"
        f"\n[{c1}] [+] Timeout:[{c4}] {args.timeout}"
        f"\n[{c1}] [+] File_Saving:[{c4}] {args.save}",
        f"\n[{c1}]=================================",
    )

    Run.runner()


main()
