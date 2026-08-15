"""Shared proxy loading and failover for the token utilities."""

import asyncio
from urllib.parse import quote, urlsplit
from pathlib import Path

import httpx


PROXY_FAILURE_RETRIES = 3


def read_proxy_file(path: Path) -> list[str]:
    proxies = []
    if not path.is_file():
        return proxies
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "://" not in line:
            fields = line.split(":")
            if len(fields) == 4 and fields[1].isdigit():
                host, port, username, password = fields
                line = (
                    f"http://{quote(username, safe='')}:{quote(password, safe='')}"
                    f"@{host}:{port}"
                )
            elif fields[-1] == "1080":
                # The supplied bare port-1080 endpoints are SOCKS proxies.
                line = f"socks5://{line}"
            else:
                line = f"http://{line}"
        if line.startswith(("http://", "https://", "socks5://", "socks5h://")):
            proxies.append(line)
    return proxies



class ProxyPool:
    """Round-robin proxy selection with per-run failure quarantine."""

    def __init__(self, proxies: list[str], max_attempts: int = PROXY_FAILURE_RETRIES):
        self.proxies = proxies
        self.max_attempts = max_attempts
        self.failed: set[str] = set()
        self.claimed: set[str] = set()

    def candidates(self, index: int) -> list[str | None]:
        if not self.proxies:
            return [None]
        candidates = []
        for offset in range(len(self.proxies)):
            proxy = self.proxies[(index + offset) % len(self.proxies)]
            if proxy in self.failed:
                continue
            candidates.append(proxy)
            if len(candidates) == self.max_attempts:
                break
        return candidates or [None]

    def mark_failed(self, proxy: str | None) -> None:
        if proxy:
            self.failed.add(proxy)

    def candidate_for_attempt(self, index: int, attempt: int) -> str | None:
        """Claim an unused proxy for this attempt; never reuse one in a run."""
        if not self.proxies:
            return None
        start = (index + attempt) % len(self.proxies)
        for offset in range(len(self.proxies)):
            proxy = self.proxies[(start + offset) % len(self.proxies)]
            if proxy not in self.claimed:
                self.claimed.add(proxy)
                return proxy
        return None

    async def run(self, index: int, operation):
        """Run an async operation again through another proxy on transport failure."""
        last_error = None
        for attempt in range(self.max_attempts):
            proxy = self.candidate_for_attempt(index, attempt)
            try:
                return await operation(proxy)
            except (httpx.TransportError, asyncio.TimeoutError) as exc:
                self.mark_failed(proxy)
                last_error = exc
                if proxy and attempt + 1 < self.max_attempts:
                    print(f"[*] Proxy {proxy_label(proxy)} failed; retrying with another proxy...")
        if last_error:
            raise last_error
        return await operation(None)

def choose_proxies(directory: str = ".") -> list[str]:
    """Prompt to use proxy.txt/proxies.txt when either file exists."""
    root = Path(directory)
    paths = [root / "proxy.txt", root / "proxies.txt"]
    existing = [path for path in paths if path.is_file()]
    if not existing:
        return []

    proxies = []
    for path in existing:
        proxies.extend(read_proxy_file(path))
    if not proxies:
        print("[*] Proxy file found, but it contains no usable proxies.")
        return []

    answer = input(f"Use {len(proxies)} proxy/proxies from proxy.txt/proxies.txt? [Y/n]: ").strip().lower()
    if answer in {"n", "no"}:
        print("[*] Using direct connections.")
        return []
    print(f"[*] Using {len(proxies)} proxy/proxies (round-robin).")
    return proxies


def proxy_for(proxies: list[str], index: int) -> str | None:
    return proxies[index % len(proxies)] if proxies else None


def proxy_label(proxy: str | None) -> str:
    if not proxy:
        return "direct"
    parsed = urlsplit(proxy)
    return f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"
