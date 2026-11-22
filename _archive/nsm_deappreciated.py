# =====================================================================================
# nsm_deappreciated.py  --  GRAVEYARD / REFERENCE ONLY
# =====================================================================================
# This file is NEVER imported and NEVER run. It's a snapshot of code we retired,
# kept so future-me can look back at the old approach and remember WHY it changed.
# Lives OUTSIDE src/ on purpose so it doesn't show up when grepping the live modules.
#
# The real history (with commit messages + diffs) is in git — this is just the
# highlight reel of the bigger swaps.
# =====================================================================================

from collections import deque   # only here so the old snippets reference something real


# =====================================================================================
# nsm_subdomain_scanner.py  --  OLD _iter_controller (materialized deque)
# WHY RETIRED: built EVERY (sub, domain) combo upfront. len(domains)*len(wordlist) =
#   millions of tuples in RAM before a single lookup = OOM at scale.
# REPLACED BY: a lazy generator  ((sub,dom) for dom in targets for sub in subdomains)
#   + next().  Round brackets = generator = builds nothing, hands out one at a time.
# =====================================================================================
class Subdomain_Scanner_OLD:

    creations = deque()

    @classmethod
    def _iter_controller(cls, url=False, domains=False, subdomains=False, CONSOLE=None):
        if not cls.creations:
            if domains: targets = [domain for domain in domains]
            else:       targets = []; targets.append(url)
            cls.total = len(targets) * len(subdomains)
            for dom in targets:
                for sub in subdomains:
                    cls.creations.append((sub, dom))          # <-- the memory bomb
            CONSOLE.print(f"Iterations made: {len(cls.creations)}"); return False

        s, d = cls.creations.popleft()
        return s, d


# =====================================================================================
# nsm_subdomain_scanner.py / nsm_directory_scanner.py  --  OLD worker + self-pull scan
# WHY RETIRED: used TWO flags (cls.scan AND cls.exhausted) that had to be kept in sync,
#   and the scan method pulled its own work. "exhausted" was just caching "generator is
#   empty" — derived state we had to remember to reset (and got wrong -> rerun bug).
# REPLACED BY (Option C): drop exhausted entirely. Worker pulls under the lock and stops
#   when the generator returns False. "Done" is the generator being empty, not a flag.
# =====================================================================================
class Worker_OLD:

    @classmethod
    def _subdomain_scanner_OLD(cls):
        with_lock = None
        # with Variables.LOCK:
        work = cls._iter_controller()
        if not work: cls.exhausted = True; return False       # <-- second flag
        sub, domain = work
        # ... scan ...

    @classmethod
    def _worker_OLD(cls):
        while cls.scan and not cls.exhausted:                  # <-- two flags
            cls._subdomain_scanner_OLD()


# =====================================================================================
# nsm_directory_scanner.py  --  OLD _iter_controller + confusing naming
# WHY RETIRED: same materialized-deque memory bomb, PLUS names copy-pasted from the sub
#   scanner (`sub`, `subdomain`) that lied about what they held -> tuple order got flipped
#   and built "admin/microsoft.com" instead of "microsoft.com/admin".
# REPLACED BY: lazy generator with honest names  ((dom, dir) for dom in targets for dir in directores)
#   unpack `dom, dir = work`, build f"{dom}/{dir}".
# =====================================================================================
class Directory_Scanner_OLD:

    creations = deque()

    @classmethod
    def _iter_controller(cls, url=False, domains=False, directores=False, CONSOLE=None):
        if not cls.creations:
            if domains: targets = [domain for domain in domains]
            else:       targets = []; targets.append(url)
            cls.total = len(targets) * len(directores)
            for dom in targets:
                for sub in directores:
                    cls.creations.append((dom, sub))
            CONSOLE.print(f"Iterations made: {len(cls.creations)}"); return False

        s, d = cls.creations.popleft()
        return s, d


# =====================================================================================
# nsm_reverser.py  --  OLD _threader (submit everything at once)
# WHY RETIRED: queued 3 futures per IP for the WHOLE list upfront (20k IPs = 60k futures
#   in memory). Scaled 1:1 with the list.
# REPLACED BY: chunked submission — batches of (max_threads * 4) IPs, drain each batch
#   before queueing the next. In-flight futures bounded to a constant.
# =====================================================================================
class Reverse_IP_Domain_OLD:

    @classmethod
    def _threader(cls, max_threads, ips, executor=None):
        futures = []
        for ip in ips:                                         # <-- whole list at once
            futures.append(executor.submit(cls._pull_domains_socket, ip))
            futures.append(executor.submit(cls._pull_domains_ssl, ip))
            futures.append(executor.submit(cls._pull_domains_ptr, ip))


# =====================================================================================
# nsm_database.py  --  OLD File_Saver two-slot path system
# WHY RETIRED: one `path` + one `path_reverse`, so every phase's --save write clobbered
#   the previous phase's file. Also a `reverse=` bool instead of naming the output.
# REPLACED BY: `base_name` + a `label` arg per call -> one labeled file per scan type
#   (rdns_raw, rdns_clean, subs, live, priority, dirs, ports), no clobbering.
# =====================================================================================
class File_Saver_OLD:

    path         = False
    path_reverse = False

    @classmethod
    def push_scan_results(cls, data, f_type="txt", reverse=False, verbose=False):
        if reverse: pathway = cls.path_reverse
        else:       pathway = cls.path
        # ... write to the single shared pathway (gets overwritten each phase) ...
