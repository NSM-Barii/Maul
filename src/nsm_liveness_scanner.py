# THIS WILL BE FOR CHECKING WHICH SUBS/DOMAINS ARE ACTUALLY ALIVE // AND SPLITTING OUT PRIORITY TARGETS



# UI IMPORTS
from rich.panel import Panel


# ETC IMPORTS
import requests, sys, time, urllib3
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from collections import deque

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



# NSM IMPORTS
from nsm_vars import Variables
from nsm_database import File_Saver



# CONSTANTS
console = Variables.console




class Liveness_Scanner():
    """checks which hosts are alive and splits out priority (keyword) hits"""


    done    = 0
    total   = 0
    scanned = 0
    scan    = True
    creations = deque()
    session = None

    KEYWORDS = [
        "admin", "login", "portal", "api", "dev", "stage", "staging",
        "panel", "auth", "vpn", "webmail", "mail", "upload", "files",
        "docs", "cpanel", "dashboard",
    ]


    @classmethod
    def _iter_controller(cls, targets=False, CONSOLE=console):
        """This will be responsible for passing targets one at a time"""


        if not cls.creations:
            cls.total = len(targets)
            for t in targets: cls.creations.append(t)

            CONSOLE.print(f"Iterations made: {len(cls.creations)}"); return False

        return cls.creations.popleft()


    @staticmethod
    def _domain_sanitzer(domains, CONSOLE=console, verbose=True) -> list:
        """Now just delegates to the shared File_Saver.domain_sanitizer // logic lives in one place so its not copy-pasted across scanners"""
        return File_Saver.domain_sanitizer(domains=domains, verbose=verbose)


    @classmethod
    def _is_priority(cls, host):
        """Keyword match against hostname // simple on purpose"""

        host = host.lower()
        for word in cls.KEYWORDS:
            if word in host: return True
        return False


    @classmethod
    def _liveness_check(cls, CONSOLE=console, verbose=False):
        """This is where the actual live probe happens"""


        c1 = "bold green"
        c2 = "bold yellow"
        c4 = "bold blue"
        c5 = "yellow"
        c6 = "green"
        c7 = "bold red"

        if not cls.scan: return Exception
        with Variables.LOCK: target = Liveness_Scanner._iter_controller(); cls.scanned += 1


        if target.startswith("http://") or target.startswith("https://"):
            schemes = [""]
        else:
            schemes = ["https://", "http://"]


        for prefix in schemes:

            url = f"{prefix}{target}" if prefix else target

            try:

                Variables.panel_text = f"Target:[{c5}] {target}[/{c5}]  -  Liveness:[{c5}] {cls.scanned}/{cls.total}[/{c5}]  -  Max_Workers:[{c5}] {Variables.max_threads}[/{c5}]  -  Errors:[{c5}] {Variables.errors}[/{c5}]"

                if Variables.delay: time.sleep(float(Variables.delay))
                response = cls.session.get(url=url, timeout=int(Variables.timeout), allow_redirects=True, verify=False)
                code     = response.status_code

                if code in Variables.status_codes:

                    with Variables.LOCK:

                        if code in [200,204]: cc = c6
                        elif code in [300,301,302,303,304]: cc = c2
                        else: cc = c4

                        CONSOLE.print(f"[{c1}][[{cc}]{code}[/{cc}]][/{c1}][white] {url}")
                        Variables.found_live.append(url)

                        if Liveness_Scanner._is_priority(target):
                            CONSOLE.print(f"[{c1}][*][bold magenta] Priority:[/bold magenta] {url}")
                            Variables.found_priority.append(url)

                    return True


            except requests.exceptions.SSLError as e:
                if verbose: CONSOLE.print(f"[{c7}][-] SSL Error:[{c2}] {e}")
                Variables.add_error()
            except (requests.exceptions.Timeout, requests.exceptions.ConnectTimeout) as e:
                if verbose: CONSOLE.print(f"[{c7}][-] Timeout Error:[{c2}] {e}")
                Variables.add_error()
            except requests.ConnectionError as e:
                if verbose: CONSOLE.print(f"[{c7}][-] Connection Error:[{c2}] {e}")
                Variables.add_error()
            except Exception as e:
                if verbose: CONSOLE.print(f"[{c7}][-] Exception Error:[{c2}] {e}")
                Variables.add_error(); File_Saver.push_errors(e)

        return False


    @classmethod
    def _worker(cls):
        """Worker thread that repeatedly runs the scanner"""

        while cls.scan:

            with Variables.LOCK:
                if not cls.creations:
                    return

            cls._liveness_check()


    @classmethod
    def _threader(cls, max_threads, CONSOLE=console, verbose=True):
        """This will iter through and thread --> _liveness_check"""


        c1 = "bold green"
        c2 = "bold yellow"
        c4 = "bold blue"
        c5 = "yellow"
        c6 = "bold red"


        futures = []
        cls.time_start = time.time()


        try:              max_threads = int(max_threads)
        except Exception: max_threads = 250


        # ONE SHARED SESSION // POOL SIZED TO THREADS SO WE REUSE CONNECTIONS INSTEAD OF A NEW TCP/TLS HANDSHAKE PER REQUEST
        adapter = requests.adapters.HTTPAdapter(pool_connections=max_threads, pool_maxsize=max_threads)
        cls.session = requests.Session()
        cls.session.mount("http://", adapter)
        cls.session.mount("https://", adapter)


        with ThreadPoolExecutor(max_workers=max_threads) as executor:

            try:

                for _ in range(max_threads): futures.append(executor.submit(cls._worker))

                for f in futures: f.result()


            except KeyboardInterrupt as e:
                CONSOLE.print(f"[{c6}][-] Exception Error:[{c5}] {e}")
                Variables.add_error()
                cls.scan = False
            except Exception as e:
                CONSOLE.print(f"[{c6}][-] Exception Error:[{c5}] {e}")
                Variables.add_error()
                cls.scan = False


    @classmethod
    def main(cls):
        """This will run class wide logic"""


        max_threads = Variables.max_threads


        # PREFER RESULTS FROM EARLIER PHASES SO --subs CHAINS FORWARD // fall back to the -d file / -u only if nothing ran before us
        if   Variables.found_subs:  targets = Variables.found_subs
        elif Variables.found_doms:  targets = Variables.found_doms
        elif Variables.domains:     targets = Liveness_Scanner._domain_sanitzer(domains=Variables.domains)
        elif Variables.url:         targets = [Variables.url]
        else:                       targets = False

        if not targets: console.print("\n[bold red][-] Input a valid domain goofy"); return


        p = "=" * 10
        console.print(f"[bold red]\n{p}  Liveness Check  {p}\n")
        Liveness_Scanner._iter_controller(targets=targets)
        Liveness_Scanner._threader(max_threads=max_threads)

        from run import Run
        time_total = time.time() - cls.time_start
        Run.title(text="Liveness Results", results=len(Variables.found_live), total_scans=cls.total, total_time=time_total)




if __name__ == "__main__":

    Variables.status_codes = [200,204,301,302,303,304]
    Variables.timeout = 5
    Liveness_Scanner.session = requests.Session()

    for host in ["example.com", "admin.example.com"]:
        Liveness_Scanner.creations.append(host)
    Liveness_Scanner.total = 2

    while Liveness_Scanner.creations:
        Liveness_Scanner._liveness_check()
