#!/usr/bin/env python3
# =====================================================================================
# diagnose_maul.py  --  lives in maul/src/. Run it from here:
#
#   python3 diagnose_maul.py
#
# Runs maul's ACTUAL subdomain scanner against a known domain, so we know if the CODE
# works on this box (=> no-results is a usage thing) or not (=> a real code bug here).
# Read the >>> VERDICT <<< at the bottom.
# =====================================================================================

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent        # maul/src   (this file lives here now)
DB  = SRC.parent / "database"                 # maul/database
sys.path.insert(0, str(SRC))                  # so the nsm_* modules import

try:
    from nsm_vars import Variables
    from nsm_subdomain_scanner import Subdomain_Scanner
except Exception as e:
    print("Could not import maul modules. This file must sit in maul/src and be run from there.")
    print("import error:", type(e).__name__, e)
    sys.exit()

wldir = DB / "subdomains"
if not wldir.is_dir():
    print(f"Could not find wordlist dir: {wldir}")
    sys.exit()

# throwaway tiny wordlist so the sanitizer has something to load
wl = wldir / "_diag_tmp.txt"
wl.write_text("www\nmail\napi\ndev\n")

Variables.url          = "google.com"
Variables.max_threads  = 5
Variables.timeout      = 5
Variables.wordlist_sub = "_diag_tmp.txt"
Variables.status_codes = [200, 301, 302]

print("Running maul's REAL subdomain scanner against google.com ...\n")
try:
    Subdomain_Scanner.main()
except Exception as e:
    print("\n!! maul scanner CRASHED:", type(e).__name__, e)

try:
    wl.unlink()
except Exception:
    pass

print("\n>>> VERDICT <<<\n")
if Variables.found_subs:
    print("MAUL CODE WORKS on this box. It found:", Variables.found_subs)
    print()
    print("=> So 'no results' is a USAGE thing, not code or environment.")
    print("   Almost always one of:")
    print("     - running --subs / --dirs WITHOUT --rdns first")
    print("       (-i feeds rdns/ports only; subs needs DOMAINS, not raw IPs --")
    print("        use --rdns to turn the IPs into domains first, e.g.")
    print("        python3 main.py -i ips.txt --rdns --subs)")
    print("     - the input file isn't the one you think (wrong path / empty)")
    print("   Tell Claude the EXACT command you're running.")
else:
    print("MAUL's own scanner found NOTHING even for google.com.")
    print("=> real problem in the code path on THIS box (network already passed).")
    print("   Tell Claude: 'maul test found nothing for google' + any error above.")
print()
