# ASYNC SUBDOMAIN SCANNER USING AIODNS + AIOHTTP

import asyncio
import aiodns
import aiohttp
from nsm_vars import Variables

console = Variables.console


class Async_Subdomain_Scanner:
    """Async subdomain scanner"""

    scanned = 0
    creations = []
    total = 0
    current_sub = False

    @classmethod
    def _iter_controller(cls, url=False, domains=False, subdomains=False):
        """Generate subdomain combinations"""

        if not cls.creations:
            if domains:
                targets = [domain for domain in domains]
            else:
                targets = []
                targets.append(url)
            cls.total = len(targets) * len(subdomains)
            for dom in targets:
                for sub in subdomains:
                    cls.creations.append((sub, dom))

            console.print(f"Iterations made: {len(cls.creations)}")
            return False

        s, d = cls.creations.pop(0)
        if cls.current_sub != s:
            cls.current_sub = s
        return s, d

    @classmethod
    async def _subdomain_scanner(cls, resolver, session):
        """Scan a single subdomain"""

        c1 = "bold green"
        c2 = "bold yellow"

        with Variables.LOCK:
            sub, domain = cls._iter_controller()
            cls.scanned += 1

        subdomain = f"{sub}.{domain}"

        try:
            result = await resolver.query(subdomain, 'A')

            if result:
                async with session.get(f"https://{subdomain}", timeout=5) as resp:
                    if resp.status in [200, 204]:
                        console.print(f"[{c1}][*][{c2}] {subdomain}")
                        with Variables.LOCK:
                            Variables.found_subs.append(subdomain)
                            return True
        except:
            Variables.errors += 1
            return False

    @classmethod
    async def run(cls, url=False, domains=False, wordlist=False):
        """Main async runner"""

        c1 = "bold green"
        c5 = "yellow"

        cls.scanned = 0
        cls._iter_controller(url=url, domains=domains, subdomains=wordlist)

        resolver = aiodns.DNSResolver()

        async with aiohttp.ClientSession() as session:
            tasks = []
            for _ in range(cls.total):
                task = cls._subdomain_scanner(resolver, session)
                tasks.append(task)
                Variables.panel_text = f"Target:[{c5}] {cls.current_sub}.*[/{c5}]  -  Enumeration:[{c5}] {cls.scanned}/{cls.total}[/{c5}]"

            await asyncio.gather(*tasks)

        console.print(f"\n[{c1}][+] Subdomain Enumeration Results:[/{c1}] {len(Variables.found_subs)}/{cls.total}")
