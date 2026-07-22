# ASYNC VERSION OF THE SUBDOMAIN SCANNER // SAME JOB AS Subdomain_Scanner, BUT ASYNCIO + A ROTATING RESOLVER POOL INSTEAD OF THREADS
# only 3 methods differ from the old class: _subdomain_scanner + _worker  ->  _aworker (async),  and _threader -> asyncio launcher


# UI IMPORTS
from rich.console import Console


# ETC IMPORTS
import sys, time, asyncio, random
import dns.resolver, dns.asyncresolver
from pathlib import Path


# NSM IMPORTS
from nsm_vars import Variables
from nsm_database import File_Saver



# CONSTANTS
console = Variables.console



# RESOLVER POOL // loaded from database/resolvers.txt once, then rotated per-query to spread load + dodge rate-limits
def _load_resolvers():
    """Read the resolver IPs from database/resolvers.txt // fall back to a few majors if the file is missing"""

    path = Path(__file__).parent.parent / "database" / "resolvers.txt"
    ips  = []

    try:
        with open(path) as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith("#"): ips.append(line)
    except Exception: pass

    if not ips: ips = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    return ips


def _build_resolvers():
    """Build one async resolver per IP so we can random.choice() a fresh one each query"""

    pool = []
    for ip in _load_resolvers():
        r = dns.asyncresolver.Resolver(configure=False)
        r.nameservers = [ip]
        r.timeout  = 2
        r.lifetime = 2
        pool.append(r)
    return pool


RESOLVERS = _build_resolvers()




class Subdomain_Scanner_Async():
    """async subdomain scanner"""


    done = 0
    scan = True

    creations = False

    total   = 0
    scanned = 0

    resolvers = RESOLVERS



    @classmethod
    def _iter_controller(cls, url=False, domains=False, subdomains=False, CONSOLE=console):
        """This will be respomsible for passing domain and sub arguments // lazy generator, one (sub,dom) at a time"""


        if not cls.creations:
            if domains: targets = [domain for domain in domains]
            else:       targets = [url]
            cls.total = len(targets) * len(subdomains)

            cls.creations = ((sub, dom) for dom in targets for sub in subdomains)

            CONSOLE.print(f"Iterations made: {cls.total}"); return False


        try: return next(cls.creations)
        except StopIteration: return False



    @staticmethod
    def _sub_sanitzer(wordlist, CONSOLE=console, verbose=True) -> list:
        """This method will be responsible for santizing the subdomain wordlist"""


        c1 = "bold green"
        c2 = "bold yellow"
        c4 = "bold blue"
        c5 = "yellow"
        c6 = "bold red"


        valid_wordlist = set()

        path_main = Path(__file__).parent.parent / "database" / "subdomains"
        path  = False


        try:

            if   wordlist=="1" or wordlist=="tiny.txt":     path = path_main / "tiny.txt"
            elif wordlist=="2" or wordlist=="small.txt":    path = path_main / "small.txt"
            elif wordlist=="3" or wordlist=="medium.txt":   path = path_main / "medium.txt"
            elif wordlist=="4" or wordlist=="large.txt":    path = path_main / "large.txt"


            if not path: path = Path(__file__).parent.parent / "database" / f"subdomains" / str(wordlist)
            if not path.exists(): CONSOLE.print(f"[{c6}][-] Invalid wordlist given, please check README.md for help!"); sys.exit()


            with open(str(path), "r") as file:

                for word in file:
                    text = word.strip().split("\t"); text = ''.join(text)
                    valid_wordlist.add(text)


            if verbose: CONSOLE.print(f"[{c1}][+] Successfully validated sub wordlist: {path}")
            return valid_wordlist


        except FileNotFoundError as e: CONSOLE.print(f"[{c6}][-] File Not Found Error:[{c2}] {e}"); Variables.add_error(); return

        except Exception as e: CONSOLE.print(f"[{c6}][-] Exception Error:[{c2}] {e}"); Variables.add_error(); sys.exit()



    @staticmethod
    def _domain_sanitzer(domains, CONSOLE=console, verbose=True) -> list:
        """Now just delegates to the shared File_Saver.domain_sanitizer // logic lives in one place so its not copy-pasted across scanners"""


        return File_Saver.domain_sanitizer(domains=domains, verbose=verbose)



    # ===================== THE ASYNC METHODS (this is all that changed from the thread version) =====================


    @classmethod
    async def _aworker(cls, CONSOLE=console):
        """ASYNC replacement for _worker + _subdomain_scanner // pulls the next (sub,dom) and resolves it, loops until drained"""


        c1 = "bold green"
        c2 = "bold yellow"
        c5 = "yellow"
        c7 = "bold red"


        while cls.scan:

            work = cls._iter_controller()
            if not work: return
            Variables.completed_sub += 1; cls.scanned += 1

            sub, domain = work
            subdomain   = f"{sub}.{domain}"

            Variables.panel_text = f"Target:[{c5}] {sub}.*[/{c5}]  -  Enumeration:[{c5}] {cls.scanned}/{cls.total}[/{c5}]  -  Concurrency:[{c5}] {Variables.max_threads}[/{c5}]  -  Wordlist:[{c5}] {Variables.s_name}[/{c5}]  -  Errors:[{c5}] {Variables.errors}[/{c5}]"

            if Variables.delay: await asyncio.sleep(float(Variables.delay))

            resolver = random.choice(cls.resolvers)


            try:

                await resolver.resolve(subdomain, "A")
                CONSOLE.print(f"[{c1}][*][{c2}] {subdomain}")
                with Variables.LOCK: Variables.found_subs.append(subdomain)


            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout, dns.resolver.NoNameservers):
                Variables.add_error()
            except Exception as e:
                Variables.add_error(); File_Saver.push_errors(e)



    @classmethod
    async def _validate_resolvers(cls, probe="google.com", CONSOLE=console):
        """Fire a known-good query at each resolver, keep only the ones that answer // drops blocked/dead, falls back to the system resolver if none work"""


        async def _check(r):
            try:              await r.resolve(probe, "A"); return r
            except Exception: return None


        results = await asyncio.gather(*[_check(r) for r in RESOLVERS])
        good    = [r for r in results if r]


        if not good:
            sysr = dns.asyncresolver.Resolver(configure=True)
            sysr.timeout = 2; sysr.lifetime = 2
            good = [sysr]
            CONSOLE.print(f"[bold yellow][!] No external resolvers reachable -> falling back to the system resolver")
        else:
            CONSOLE.print(f"[bold green][+] Validated resolvers: {len(good)}/{len(RESOLVERS)} working")


        cls.resolvers = good



    @classmethod
    async def _arunner(cls, concurrency):
        """Spawn <concurrency> async workers all draining the same generator // bounded memory, one event loop"""


        await cls._validate_resolvers()

        workers = [asyncio.create_task(cls._aworker()) for _ in range(concurrency)]
        await asyncio.gather(*workers)



    @classmethod
    def _threader(cls, max_threads, CONSOLE=console, verbose=True):
        """ASYNC replacement for the old ThreadPoolExecutor // just kicks off the asyncio event loop"""


        cls.scanned    = 0
        cls.time_start = time.time()


        try:              concurrency = int(max_threads)
        except Exception: concurrency = 1000


        try:
            asyncio.run(cls._arunner(concurrency))

        except KeyboardInterrupt:
            CONSOLE.print(f"[bold red][-] Interrupted"); cls.scan = False



    @classmethod
    def main(cls):
        """This will run class wide logic"""


        max_threads = Variables.max_threads
        timeout     = Variables.timeout
        url         = Variables.url
        domains     = Variables.domains
        wordlist    = Variables.wordlist_sub
        mutations   = Variables.mutations


        if Variables.domains:      domains = Subdomain_Scanner_Async._domain_sanitzer(domains=domains)
        elif Variables.found_doms: domains = Variables.found_doms
        else:                      domains = False
        if not domains and not url: console.print("\n[bold red][-] Input a valid domain goofy")

        wordlist  = Subdomain_Scanner_Async._sub_sanitzer(wordlist=wordlist)

        p = "=" * 10
        console.print(f"[bold red]\n{p}  Subdomain Enumeration  {p}\n")
        Subdomain_Scanner_Async._iter_controller(url=url, domains=domains, subdomains=wordlist)
        Subdomain_Scanner_Async._threader(max_threads=max_threads)

        from run import Run
        time_total = time.time() - cls.time_start
        Run.title(text="Subdomain Results", results=len(Variables.found_subs), total_scans=cls.total, total_time=time_total)
