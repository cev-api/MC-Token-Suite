"""Shared proxy loading and failover for the token utilities."""

import asyncio
import sys
from urllib.parse import quote, urlsplit
from pathlib import Path

import httpx


PROXY_FAILURE_RETRIES = 3

# Networking defaults. A dead proxy has to fail fast: with a long connect
# timeout, one unreachable endpoint burns the whole per-token budget before
# failover even starts.
HTTP_CONNECT_TIMEOUT = 6.0
HTTP_READ_TIMEOUT = 12.0


def http_timeout(read: float = HTTP_READ_TIMEOUT) -> httpx.Timeout:
    """Timeout with a short connect phase so dead proxies fail quickly."""
    return httpx.Timeout(read, connect=HTTP_CONNECT_TIMEOUT)


class ClientCache:
    """One long-lived HTTP client per proxy, reused for the whole run.

    A client per request (the old behaviour of refresh_to_token.py) forces a
    fresh TCP + TLS handshake through the proxy for every step of every token.
    That is what turns a 9-second chain into a 45-second one as soon as a few
    workers run at once, and then the chain budget expires and the proxy gets
    the blame.
    """

    def __init__(self, max_connections: int = 4):
        self._max_connections = max_connections
        self._clients: dict[str, httpx.AsyncClient] = {}

    def get(self, proxy: str | None) -> httpx.AsyncClient:
        key = proxy or ""
        client = self._clients.get(key)
        if client is None:
            client = httpx.AsyncClient(
                timeout=http_timeout(),
                proxy=proxy,
                follow_redirects=False,
                limits=httpx.Limits(
                    max_connections=self._max_connections,
                    max_keepalive_connections=self._max_connections,
                ),
            )
            self._clients[key] = client
        return client

    async def aclose(self) -> None:
        for client in self._clients.values():
            try:
                await client.aclose()
            except Exception:
                pass
        self._clients.clear()


CLIENTS = ClientCache()


def client_for(proxy: str | None) -> httpx.AsyncClient:
    """Shared client for this proxy; connections are pooled and reused."""
    return CLIENTS.get(proxy)


async def close_clients() -> None:
    """Close every pooled client. Call once, at the end of a run."""
    await CLIENTS.aclose()


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

    def mark_failed(self, proxy: str | None) -> None:
        if proxy:
            self.failed.add(proxy)

    def candidate_for_attempt(self, index: int, attempt: int) -> str | None:
        """Claim a healthy proxy for this attempt.

        Endpoints already proven dead in this run are skipped, and a proxy
        claimed by another attempt is not handed out twice. When everything is
        claimed or dead the pool cycles back to the least-bad option rather than
        returning None: a silent direct connection would leak the real IP.
        """
        if not self.proxies:
            return None
        start = (index + attempt) % len(self.proxies)
        for offset in range(len(self.proxies)):
            proxy = self.proxies[(start + offset) % len(self.proxies)]
            if proxy not in self.claimed and proxy not in self.failed:
                self.claimed.add(proxy)
                return proxy
        # Every endpoint is claimed; free the round and try the healthy ones.
        self.claimed.clear()
        for offset in range(len(self.proxies)):
            proxy = self.proxies[(start + offset) % len(self.proxies)]
            if proxy not in self.failed:
                self.claimed.add(proxy)
                return proxy
        # Every endpoint has failed at least once. Start a fresh cycle with the
        # proxy that failed longest ago instead of connecting directly.
        self.failed.clear()
        proxy = self.proxies[start % len(self.proxies)]
        self.claimed.add(proxy)
        return proxy

    async def run(self, index: int, operation):
        """Run an async operation, retrying transport failures on another proxy.

        Only a transport failure blames the proxy. A chain that overruns its own
        budget raises asyncio.TimeoutError - that is retried on another proxy
        but does not quarantine the endpoint, because the proxy usually still
        works and the request was merely slow. Blaming it was what made a run
        under load report "every proxy failed" while the same proxies were
        perfectly usable one request at a time.
        """
        last_error = None
        for attempt in range(self.max_attempts):
            proxy = self.candidate_for_attempt(index, attempt)
            try:
                return await operation(proxy)
            except httpx.TransportError as exc:
                self.mark_failed(proxy)
                last_error = exc
                if attempt + 1 < self.max_attempts:
                    print(
                        f"[*] Proxy {proxy_label(proxy)} failed "
                        f"({type(exc).__name__}); retrying with another proxy...",
                        flush=True,
                    )
            except asyncio.TimeoutError as exc:
                last_error = exc
                if attempt + 1 < self.max_attempts:
                    print(
                        f"[*] Attempt through {proxy_label(proxy)} ran out of time; "
                        f"retrying with another proxy...",
                        flush=True,
                    )
        if last_error:
            raise last_error
        return None

def choose_proxies(directory: str = ".") -> list[str]:
    """Use proxy.txt/proxies.txt when either file exists.

    Asks for confirmation only when someone is actually there to answer: a
    prompt on a non-interactive stdin blocks forever, which hangs automated
    runs. Pass --proxies/--no-proxies to the callers to skip asking entirely.
    """
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

    if not sys.stdin or not sys.stdin.isatty():
        print(f"[*] Non-interactive input; using {len(proxies)} proxy/proxies from proxy.txt.")
        return proxies

    try:
        answer = input(f"Use {len(proxies)} proxy/proxies from proxy.txt/proxies.txt? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("[*] No answer received; using the configured proxies.")
        return proxies
    if answer in {"n", "no"}:
        print("[*] Using direct connections.")
        return []
    print(f"[*] Using {len(proxies)} proxy/proxies (round-robin).")
    return proxies


def proxy_for(proxies: list[str], index: int) -> str | None:
    return proxies[index % len(proxies)] if proxies else None


class ProxyRotator:
    """Round-robin proxies that quarantine endpoints as they fail.

    A long run over a big free proxy list degrades: proxies die midway and then
    every request through them waits out the connect timeout. Rotating without
    memory means those dead endpoints keep getting picked for the rest of the
    run, which is what turns a working run into a wall of network errors.
    Quarantining drops them after a few failures instead.
    """

    def __init__(self, proxies: list[str], quarantine_after: int = 2):
        self.proxies = list(proxies)
        self.quarantine_after = max(1, quarantine_after)
        self.failures: dict[str, int] = {}
        self.quarantined: set[str] = set()
        self._cursor = 0

    def next(self) -> str | None:
        """Next usable proxy, or None when no proxies are configured."""
        if not self.proxies:
            return None
        for _ in range(len(self.proxies)):
            proxy = self.proxies[self._cursor % len(self.proxies)]
            self._cursor += 1
            if proxy not in self.quarantined:
                return proxy
        # Everything is quarantined. Releasing them beats stalling the run, and
        # it still never falls back to an unproxied connection.
        self.quarantined.clear()
        return self.next()

    def mark_failed(self, proxy: str | None) -> None:
        if not proxy:
            return
        self.failures[proxy] = self.failures.get(proxy, 0) + 1
        if self.failures[proxy] >= self.quarantine_after:
            self.quarantined.add(proxy)

    def mark_ok(self, proxy: str | None) -> None:
        if proxy:
            self.failures.pop(proxy, None)

    @property
    def usable_count(self) -> int:
        return len(self.proxies) - len(self.quarantined)

    def describe(self) -> str:
        if not self.proxies:
            return "direct connection"
        if not self.quarantined:
            return f"{len(self.proxies)} proxy/proxies"
        return f"{self.usable_count}/{len(self.proxies)} proxy/proxies ({len(self.quarantined)} quarantined)"


def proxy_label(proxy: str | None) -> str:
    if not proxy:
        return "direct"
    parsed = urlsplit(proxy)
    return f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"


# --- Proxy health checking ---

# Any HTTP reply proves the proxy works; the endpoint itself does not need to
# authorise us, so this returns 401 for a healthy proxy and never costs a login.
PROXY_TEST_URL = "https://api.minecraftservices.com/minecraft/profile"


async def probe_proxy(proxy: str, url: str = PROXY_TEST_URL, timeout: float = 8.0) -> bool:
    """True when the proxy returns any HTTP response at all."""
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=timeout),
            proxy=proxy,
            follow_redirects=False,
        ) as client:
            await client.get(url, headers={"Accept": "application/json"})
            return True
    except Exception:
        return False


async def filter_working_proxies(
    proxies: list[str],
    url: str = PROXY_TEST_URL,
    timeout: float = 8.0,
    concurrency: int = 100,
    on_progress=None,
) -> tuple[list[str], list[str]]:
    """Probe every proxy and return (alive, dead) keeping the input order.

    Bulk token runs are dominated by dead proxies: every request through one
    burns the full connect timeout, so a list that is 90% dead turns a run into
    a wall of timeouts. Filtering first is far faster than discovering them
    one token at a time.
    """
    if not proxies:
        return [], []

    semaphore = asyncio.Semaphore(max(1, concurrency))
    results: list[bool] = [False] * len(proxies)
    done = 0

    async def worker(position: int, proxy: str) -> None:
        nonlocal done
        async with semaphore:
            results[position] = await probe_proxy(proxy, url, timeout)
        done += 1
        if on_progress and (done % 50 == 0 or done == len(proxies)):
            on_progress(done, len(proxies), sum(results))

    await asyncio.gather(*(worker(i, p) for i, p in enumerate(proxies)))

    alive = [p for p, ok in zip(proxies, results) if ok]
    dead = [p for p, ok in zip(proxies, results) if not ok]
    return alive, dead


def read_proxy_list(path: Path) -> list[str]:
    """Read a plain proxy list file (alive-proxy cache and similar)."""
    if not path.is_file():
        return []
    proxies = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("http://", "https://", "socks5://", "socks5h://")):
            proxies.append(line)
    return proxies


def write_proxy_list(path: Path, proxies: list[str], header: str) -> None:
    path.write_text(
        f"# {header}\n" + "".join(p + "\n" for p in proxies),
        encoding="utf-8",
    )
