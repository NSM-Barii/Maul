#!/usr/bin/env python3
# =====================================================================================
# diagnose_vps.py  --  lives in maul/src/. Run it from here:
#
#   python3 diagnose_vps.py
#
# Runs every check maul depends on, then prints a >>> VERDICT <<< with the problem
# and the fix. You don't have to paste anything -- just read the verdict.
# =====================================================================================

import sys, socket
from pathlib import Path

SRC = Path(__file__).resolve().parent        # maul/src   (this file lives here now)
DB  = SRC.parent / "database"                 # maul/database

try:
    import urllib3; urllib3.disable_warnings()
except Exception:
    pass

results = []

def check(n, label, fn):
    try:
        ok, detail = fn()
    except Exception as e:
        ok, detail = False, f"{type(e).__name__}: {str(e)[:60]}"
    results.append(1 if ok else 0)
    dots = "." * max(2, 38 - len(label))
    print(f"[{n:>2}] {label} {dots} {'PASS' if ok else 'FAIL'}" + (f"  ({detail})" if detail else ""))


# ---- 1: python version ----
def _py():
    v = sys.version_info
    return (v >= (3, 10), f"{v.major}.{v.minor}.{v.micro}")
check(1, "Python 3.10+", _py)

# ---- 2-5: dependencies maul imports ----
def _dep(mod):
    def f(): __import__(mod); return (True, "")
    return f
check(2, "dep: rich", _dep("rich"))
check(3, "dep: dnspython (dns.resolver)", _dep("dns.resolver"))
check(4, "dep: requests", _dep("requests"))
check(5, "dep: pyOpenSSL (OpenSSL)", _dep("OpenSSL"))

# ---- 6: system DNS via socket ----
def _sysdns():
    return (True, socket.gethostbyname("one.one.one.one"))
check(6, "system DNS (socket.gethostbyname)", _sysdns)

# ---- 7: external resolver 1.1.1.1 -- the one the subdomain scanner FORCES ----
def _extdns():
    import dns.resolver
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = ["1.1.1.1"]; r.timeout = 3; r.lifetime = 3
    return (True, str(r.resolve("google.com", "A")[0]))
check(7, "external resolver 1.1.1.1 (subs uses)", _extdns)

# ---- 8: reverse PTR via socket -- rdns uses this ----
def _ptr():
    return (True, socket.gethostbyaddr("1.1.1.1")[0])
check(8, "reverse DNS PTR (socket.gethostbyaddr)", _ptr)

# ---- 9: outbound TCP 443 -- rdns SSL + all https ----
def _t443():
    s = socket.socket(); s.settimeout(5); s.connect(("1.1.1.1", 443)); s.close()
    return (True, "connected")
check(9, "outbound TCP 443", _t443)

# ---- 10: full HTTPS GET via requests -- live/dirs use this ----
def _https():
    import requests
    r = requests.get("https://one.one.one.one", timeout=6, verify=False)
    return (True, f"HTTP {r.status_code}")
check(10, "HTTPS GET via requests", _https)

# ---- 11: database/ dir present ----
def _dbdir():
    return (DB.is_dir(), str(DB) if DB.is_dir() else f"{DB} not found")
check(11, "database/ dir found", _dbdir)

# ---- 12: wordlist dirs present ----
def _wl():
    s = (DB / "subdomains").is_dir(); d = (DB / "directories").is_dir()
    return (s and d, f"subdomains={s} directories={d}")
check(12, "wordlist dirs present", _wl)

# ---- 13: saved_scans/ exists and is writable ----
def _save():
    sd = DB / "saved_scans"
    if not sd.is_dir(): return (False, "saved_scans/ missing")
    t = sd / ".diag_write_test"; t.write_text("x"); t.unlink()
    return (True, "writable")
check(13, "saved_scans/ writable", _save)


print("\n" + "=" * 64)
print(" ".join(str(x) for x in results))
print("=" * 64)


# =====================================================================================
# SELF-DIAGNOSIS  --  decodes its own results.
# =====================================================================================
py     = results[0]
deps   = results[1:5]
sysdns = results[5]
extdns = results[6]
ptr    = results[7]
t443   = results[8]
https  = results[9]
files  = results[10:13]

dep_names  = ["rich", "dnspython", "requests", "pyOpenSSL"]
file_names = ["database/", "wordlist dirs", "saved_scans/"]

print("\n>>> VERDICT <<<\n")

if not py:
    print("PROBLEM: Python too old.")
    print("FIX:     need Python 3.10+ on the VPS.")

elif 0 in deps:
    missing = [dep_names[i] for i, ok in enumerate(deps) if not ok]
    print(f"PROBLEM: missing dependencies -> {', '.join(missing)}")
    print("FIX:     pip install -r requirements.txt")
    print("         (REBUILD the venv on the VPS, don't copy it: python3 -m venv venv)")

elif 0 in files:
    missing = [file_names[i] for i, ok in enumerate(files) if not ok]
    print(f"PROBLEM: missing files/dirs -> {', '.join(missing)}")
    print("FIX:     make sure the whole database/ tree is present next to src/")

elif not (extdns or ptr or t443 or https):
    print("PROBLEM: ALL outbound network is blocked (DNS + 443 both fail).")
    print("FIX:     it's the VPS, not maul -- open outbound in the provider firewall /")
    print("         security group / iptables (UDP 53, TCP 443).")

elif sysdns and not extdns:
    print("PROBLEM: your VPS blocks the external resolver 1.1.1.1/8.8.8.8 that the")
    print("         SUBDOMAIN scanner hardcodes -- but your system DNS works fine.")
    print("         => rdns may work, but subs silently finds nothing. THIS is the bug.")
    print("FIX:     make the subdomain scanner use the SYSTEM resolver instead of")
    print("         hardcoded ones. Tell Claude 'fix the hardcoded resolver'.")

elif not https or not t443:
    print("PROBLEM: outbound HTTPS/443 is failing (live + dirs can't reach hosts).")
    print("FIX:     check the VPS firewall for outbound TCP 443.")

else:
    print("GOOD: everything maul needs actually works on this box.")
    print("So 'no results' is a USAGE thing, not the environment. Most likely:")
    print("  - the input file is empty, OR")
    print("  - you ran --subs/--dirs WITHOUT --rdns first (those need domains, not raw IPs;")
    print("    -i feeds rdns/ports only -- use --rdns to turn IPs into domains first), OR")
    print("  - wrong wordlist / 0 matches.")
    print("Try:  python3 main.py -i ips.txt --rdns   (watch the Results + Errors counts)")

print()
