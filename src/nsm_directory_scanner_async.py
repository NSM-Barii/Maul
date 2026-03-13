# ASYNC DIRECTORY SCANNER USING AIOHTTP

import asyncio
import aiohttp
from nsm_vars import Variables

console = Variables.console


class Async_Directory_Scanner:
    """Async directory scanner"""

    scanned = 0
    creations = []
    total = 0
    current_domain = False

    @classmethod
    def _iter_controller(cls, subdomains=False, directories=False):
        """Generate directory combinations"""

        if not cls.creations:
            cls.total = len(subdomains) * len(directories)
            for subdomain in subdomains:
                for directory in directories:
                    cls.creations.append((subdomain, directory))

            console.print(f"Iterations made: {len(cls.creations)}")
            return False

        subdomain, directory = cls.creations.pop(0)
        if cls.current_domain != subdomain:
            cls.current_domain = subdomain
        return subdomain, directory

    @classmethod
    async def _directory_scanner(cls, session):
        """Scan a single directory"""

        c1 = "bold green"
        c2 = "bold yellow"
        c5 = "yellow"
        c6 = "green"
        c7 = "bold red"

        with Variables.LOCK:
            subdomain, directory = cls._iter_controller()
            cls.scanned += 1

        url = f"http://{subdomain}/{directory}"

        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=int(Variables.timeout)), allow_redirects=False, ssl=False) as resp:
                code = resp.status

                if code in Variables.status_codes:
                    if code in [200, 204]:
                        cc = c6
                    elif code in [300, 301, 302, 303, 304]:
                        cc = c2

                    console.print(f"[{c1}][[{cc}]{code}[/{cc}]][/{c1}][white] {url}")
                    with Variables.LOCK:
                        Variables.found_dirs.append(url)
                        return True

        except asyncio.TimeoutError:
            Variables.errors += 1
            return False
        except aiohttp.ClientError:
            Variables.errors += 1
            return False
        except Exception:
            Variables.errors += 1
            return False

    @classmethod
    async def run(cls, subdomains=False, wordlist=False):
        """Main async runner"""

        c1 = "bold green"
        c5 = "yellow"

        cls.scanned = 0
        cls._iter_controller(subdomains=subdomains, directories=wordlist)

        connector = aiohttp.TCPConnector(limit=500, limit_per_host=50, ttl_dns_cache=300)
        timeout = aiohttp.ClientTimeout(total=int(Variables.timeout))
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = []
            for _ in range(cls.total):
                task = cls._directory_scanner(session)
                tasks.append(task)
                Variables.panel_text = f"Target:[{c5}] {cls.current_domain}/*[/{c5}]  -  Enumeration:[{c5}] {cls.scanned}/{cls.total}[/{c5}]"

            await asyncio.gather(*tasks, return_exceptions=True)

        console.print(f"\n[{c1}][+] Directory Scan Results:[/{c1}] {len(Variables.found_dirs)}/{cls.total}")
