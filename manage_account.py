"""
Account Manager - Name Change & Skin Change
Reads token.txt or refresh.txt, or accepts a pasted cookie export, refresh
token, or access token, and allows:
  - Showing the account's username (name change) history and cooldown
  - Changing the Minecraft username (if eligible)
  - Changing the Minecraft skin (from URL or local file)
  - Resetting the skin to default
  - Checking name availability
"""

import os
import sys
import time
import asyncio
import base64
import json
import hashlib
import secrets
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
from proxy_utils import (
    ProxyRotator,
    choose_proxies,
    http_timeout,
    probe_proxy,
    proxy_label,
)

# --- Constants ---

MC_PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile"
MC_NAME_CHANGE_URL = "https://api.minecraftservices.com/minecraft/profile/namechange"
MC_NAME_AVAIL_URL = "https://api.minecraftservices.com/minecraft/profile/name/{name}/available"
MC_SKIN_URL = "https://api.minecraftservices.com/minecraft/profile/skins"

# Public username-history sources, tried in order.
MOJANG_NAME_HISTORY_URL = "https://api.mojang.com/user/profiles/{uuid}/names"
LIFORRA_NAME_HISTORY_URL = "https://liforra.de/api/namehistory"
ASHCON_PROFILE_URL = "https://api.ashcon.app/mojang/v2/user/{username}"

LIVE_CONNECT_AUTHORIZE_URL = "https://login.live.com/oauth20_authorize.srf"
LIVE_CONNECT_TOKEN_URL = "https://login.live.com/oauth20_token.srf"
LIVE_CONNECT_DESKTOP_REDIRECT_URI = "https://login.live.com/oauth20_desktop.srf"
MINECRAFT_LAUNCHER_V1_CLIENT_ID = "00000000402b5328"
LIVE_CONNECT_SCOPE_MBI_SSL = "service::user.auth.xboxlive.com::MBI_SSL"

XBL_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate"
XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize"
MC_LOGIN_WITH_XBOX_URL = "https://api.minecraftservices.com/authentication/login_with_xbox"

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Token / cookie shapes used to recognise pasted credentials.
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
COOKIE_NAME_HINT = re.compile(
    r"(?:^|[;\s])(uaid|MSPAuth|MSPPre|MSPCID|RPSSecAuth|WLSSC|OPARACHUTE|"
    r"AADSSO|AMCSecAuth|__Host-|CkTst|PPAuth|MBI_SSL)=",
    re.IGNORECASE,
)

# Valid skin variants
SLIM = "slim"
CLASSIC = "classic"

# Proxy settings. A large free proxy list is mostly dead endpoints, so every
# request must be able to move on to the next one instead of aborting the run.
PROXY_ATTEMPTS = 6
PROXY_CHECK_TIMEOUT = 5.0
PROXY_DISCOVERY_BATCH = 40
PROXY_DISCOVERY_TARGET = 5
PROXY_DISCOVERY_BUDGET = 45.0

ROTATOR = ProxyRotator([])

# Raised before a request can have reached the server, so a retry through
# another proxy cannot repeat a name or skin change.
RETRYABLE_CONNECT_ERRORS = (httpx.ConnectError, httpx.ConnectTimeout, httpx.ProxyError)
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Minecraft allows one username change per this window.
NAME_CHANGE_COOLDOWN = timedelta(days=30)


class ProxyFailoverClient:
    """AsyncClient stand-in that retries a request through the next proxy.

    Every request used to be pinned to proxies[0]. When that endpoint was
    unreachable the whole program died on an uncaught ConnectTimeout.
    """

    def __init__(self, timeout: float = 15.0, attempts: int = PROXY_ATTEMPTS):
        self._timeout = timeout
        self._attempts = max(1, attempts)
        self._clients: dict[str, httpx.AsyncClient] = {}
        self._preferred: str | None = None

    async def __aenter__(self) -> "ProxyFailoverClient":
        return self

    async def __aexit__(self, *exc_info) -> None:
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()

    def _client_for(self, proxy: str | None) -> httpx.AsyncClient:
        key = proxy or ""
        client = self._clients.get(key)
        if client is None:
            client = httpx.AsyncClient(timeout=http_timeout(self._timeout), proxy=proxy)
            self._clients[key] = client
        return client

    def _pick_proxy(self) -> str | None:
        # Stay on the last working proxy so connections are reused, and only
        # rotate once it starts failing or gets quarantined.
        if self._preferred and self._preferred not in ROTATOR.quarantined:
            return self._preferred
        return ROTATOR.next()

    def _attempt_count(self) -> int:
        configured = len(ROTATOR.proxies)
        return max(1, min(self._attempts, configured if configured > 1 else 3))

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        last_error: httpx.HTTPError | None = None
        for _ in range(self._attempt_count()):
            proxy = self._pick_proxy()
            try:
                response = await self._client_for(proxy).request(method, url, **kwargs)
            except RETRYABLE_CONNECT_ERRORS as exc:
                last_error = exc
                ROTATOR.mark_failed(proxy)
                self._preferred = None
                print(f"    [!] {proxy_label(proxy)}: {type(exc).__name__}; trying the next proxy")
                continue
            except httpx.TransportError as exc:
                ROTATOR.mark_failed(proxy)
                self._preferred = None
                if method.upper() not in SAFE_METHODS:
                    raise
                last_error = exc
                continue
            ROTATOR.mark_ok(proxy)
            self._preferred = proxy
            return response
        if last_error is None:
            raise httpx.ConnectError(f"No proxy could reach {url}")
        raise last_error

    async def get(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("DELETE", url, **kwargs)


# --- Token acquisition ---

def read_lines(filepath: str) -> list[str]:
    if not os.path.isfile(filepath):
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def parse_refresh_entry(line: str) -> tuple[str, str]:
    """Return (optional username label, refresh token)."""
    if ":" in line:
        username, token = line.split(":", 1)
        if username.strip() and token.strip():
            return username.strip(), token.strip()
    return "", line.strip()


def mask_token(token: str) -> str:
    """Return a short, non-sensitive identifier for a token."""
    if len(token) <= 8:
        return "*" * len(token)
    return f"{token[:4]}...{token[-4:]}"


def choose_entry(entries: list[str], source: str, labels: list[str] | None = None) -> str:
    """Prompt for an entry when a token file contains more than one."""
    if len(entries) == 1:
        return entries[0]

    print(f"[*] Multiple entries found in {source}:")
    for index, entry in enumerate(entries, start=1):
        label = labels[index - 1] if labels else mask_token(entry)
        print(f"  [{index}] {label}")

    while True:
        choice = input(f"  Choose an entry [1-{len(entries)}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(entries):
            return entries[int(choice) - 1]
        print("  Please enter a valid number.")



def choose_source() -> str | None:
    """Ask which credential source to use: token.txt, refresh.txt, or a paste."""
    print("[*] Credential sources:")
    print("  [1] token.txt   (cached Minecraft access tokens)")
    print("  [2] refresh.txt (Microsoft refresh tokens)")
    print("  [3] Paste cookies, a refresh token, or an access token")
    while True:
        try:
            choice = input("  Read from [1-3], q to cancel: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return None
        if choice == "1":
            return "token"
        if choice == "2":
            return "refresh"
        if choice == "3":
            return "paste"
        if choice in ("q", "quit", "cancel", ""):
            return None
        print("  Please enter 1, 2, 3, or q.")


async def get_token_labels(tokens: list[str]) -> list[str]:
    """Fetch Minecraft names for cached tokens, marking invalid entries."""
    async with ProxyFailoverClient(10) as client:
        async def fetch_label(token: str) -> str:
            try:
                resp = await client.get(
                    MC_PROFILE_URL,
                    headers={"Authorization": f"Bearer {token}"},
                )
            except httpx.HTTPError:
                return f"UNREACHABLE - {mask_token(token)}"
            if resp.status_code == 200:
                return resp.json().get("name", "Unknown account")
            return f"INVALID ({resp.status_code}) - {mask_token(token)}"

        return await asyncio.gather(*(fetch_label(token) for token in tokens))


async def refresh_msa_token(refresh_token: str) -> str | None:
    """Exchange a Microsoft refresh token for a fresh MSA access token."""
    print("  [1/4] Refreshing MSA...")
    async with ProxyFailoverClient(30) as client:
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
            print(f"  [-] MSA refresh failed: {resp.status_code} {resp.text[:200]}")
            return None
        return resp.json().get("access_token")


async def msa_to_mc_token(msa_token: str) -> str | None:
    """Run an MSA access token through XBL -> XSTS -> Minecraft."""
    # v1 Live-Connect opaque tokens (Ew...) need t=; v2 Azure AD JWTs need d=.
    if msa_token.startswith("eyJ"):
        rps_ticket = f"d={msa_token}"
    elif msa_token.startswith(("t=", "d=")):
        rps_ticket = msa_token
    else:
        rps_ticket = f"t={msa_token}"

    async with ProxyFailoverClient(30) as client:
        # 2. XBL
        print("  [2/4] Authenticating XBL...")
        resp = await client.post(
            XBL_AUTH_URL,
            json={
                "Properties": {"AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com", "RpsTicket": rps_ticket},
                "RelyingParty": "http://auth.xboxlive.com",
                "TokenType": "JWT",
            },
            headers={"Accept": "application/json", "x-xbl-contract-version": "1"},
        )
        if resp.status_code != 200:
            print(f"  [-] XBL failed: {resp.status_code}")
            return None
        xbl_token = resp.json()["Token"]

        # 3. XSTS
        print("  [3/4] Authenticating XSTS...")
        resp = await client.post(
            XSTS_AUTH_URL,
            json={
                "Properties": {"SandboxId": "RETAIL", "UserTokens": [xbl_token]},
                "RelyingParty": "rp://api.minecraftservices.com/",
                "TokenType": "JWT",
            },
            headers={"Accept": "application/json", "x-xbl-contract-version": "1"},
        )
        if resp.status_code != 200:
            print(f"  [-] XSTS failed: {resp.status_code}")
            try:
                err = resp.json()
                print(f"     XErr={err.get('XErr', '?')} {err.get('Message', '')}")
            except Exception:
                pass
            return None
        data = resp.json()
        xsts_token = data["Token"]
        uhs = data["DisplayClaims"]["xui"][0]["uhs"]

        # 4. Minecraft
        print("  [4/4] Minecraft login...")
        resp = await client.post(
            MC_LOGIN_WITH_XBOX_URL,
            json={"identityToken": f"XBL3.0 x={uhs};{xsts_token}"},
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            print(f"  [-] Minecraft login failed: {resp.status_code}")
            return None
        mc_token = resp.json()["access_token"]
        print(f"  [+] MC token obtained ({len(mc_token)} chars)")
        return mc_token


async def get_mc_token_from_refresh(refresh_token: str) -> str | None:
    """Turn a refresh token into a fresh MC token via the full chain."""
    msa_token = await refresh_msa_token(refresh_token)
    if not msa_token:
        return None
    return await msa_to_mc_token(msa_token)


# --- Pasted credential helpers ---

def read_multiline_input(prompt: str) -> str:
    """Read pasted text until an empty line so cookies can span multiple lines."""
    print(prompt)
    lines: list[str] = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line.strip():
            break
        lines.append(line)
    return "\n".join(lines)


def looks_like_cookies(text: str) -> bool:
    """True when the pasted text is a cookie export / Cookie header, not tokens."""
    lines = [line for line in text.splitlines() if line.strip()]
    if any("\t" in line for line in lines):
        return True
    if any(line.lstrip("#").lower().startswith("httponly_") for line in lines):
        return True
    return bool(COOKIE_NAME_HINT.search(text))


def parse_cookie_text(text: str) -> list[dict]:
    """Parse Netscape .txt lines, a Cookie header, or name=value pairs."""
    cookies: list[dict] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.lower().startswith("cookie:"):
            line = line.split(":", 1)[1].strip()
        if line.startswith("#HttpOnly_"):
            line = line[len("#HttpOnly_"):]
        elif line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 7:
            domain, _flag, path, _secure, _expires, name, value = parts[:7]
            if name:
                cookies.append({"name": name, "value": value, "domain": domain, "path": path})
            continue
        for pair in line.split(";"):
            pair = pair.strip()
            if "=" in pair:
                name, value = pair.split("=", 1)
                if name.strip():
                    cookies.append({
                        "name": name.strip(), "value": value.strip(),
                        "domain": ".login.live.com", "path": "/",
                    })
    return cookies


def build_cookie_header(cookies: list[dict]) -> str:
    return "; ".join(f"{cookie['name']}={cookie['value']}" for cookie in cookies)


def make_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:128]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def extract_code_from_location(location: str) -> str | None:
    codes = parse_qs(urlparse(location).query).get("code", [])
    return codes[0] if codes else None


def decode_jwt_payload(token: str) -> dict | None:
    """Decode a JWT payload without verifying its signature."""
    try:
        _header, payload, _signature = token.split(".")
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        return json.loads(raw)
    except Exception:
        return None


def looks_like_minecraft_jwt(token: str) -> bool:
    claims = decode_jwt_payload(token)
    return bool(claims) and (claims.get("token_type") == "Minecraft" or "xuid" in claims)


async def get_msa_token_from_cookies(cookies: list[dict]) -> str | None:
    """Exchange login.live.com session cookies for an MSA access token."""
    verifier, challenge = make_pkce()
    uaid = next((cookie["value"] for cookie in cookies if cookie["name"] == "uaid"), None)
    params = {
        "client_id": MINECRAFT_LAUNCHER_V1_CLIENT_ID,
        "redirect_uri": LIVE_CONNECT_DESKTOP_REDIRECT_URI,
        "response_type": "code",
        "scope": LIVE_CONNECT_SCOPE_MBI_SSL,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "display": "touch",
        "locale": "en",
        "lw": "1",
        "fl": "dob,easi2",
        "xsup": "1",
        "nopa": "2",
    }
    if uaid:
        params["uaid"] = uaid

    async with ProxyFailoverClient(30) as client:
        print("  [1/4] Authorizing with cookies...")
        resp = await client.get(
            f"{LIVE_CONNECT_AUTHORIZE_URL}?{urlencode(params)}",
            headers={"Cookie": build_cookie_header(cookies), "User-Agent": DEFAULT_USER_AGENT},
        )
        if resp.status_code != 302:
            print(f"  [-] Cookie authorize returned {resp.status_code} (expected 302)")
            return None
        code = extract_code_from_location(resp.headers.get("location", ""))
        if not code:
            print("  [-] No authorization code in the redirect")
            return None
        print("  [+] Got an authorization code, exchanging for a token...")
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
            print(f"  [-] MSA token exchange returned {token_resp.status_code}")
            return None
        return token_resp.json().get("access_token")


async def get_token_from_cookies(cookies: list[dict]) -> str | None:
    """Exchange cookies for a Minecraft token, salvaging stored JWTs if needed."""
    msa_token = await get_msa_token_from_cookies(cookies)
    if msa_token:
        return await msa_to_mc_token(msa_token)
    for cookie in cookies:
        match = JWT_RE.search(str(cookie.get("value", "")))
        if match:
            token = await credential_to_mc_token(match.group(0))
            if token:
                return token
    return None


async def credential_to_mc_token(credential: str) -> str | None:
    """Turn a pasted access/refresh/MSA token into a Minecraft access token."""
    credential = credential.strip()
    if credential.lower().startswith("bearer "):
        credential = credential[7:].strip()
    if not credential:
        return None
    if looks_like_minecraft_jwt(credential):
        print("  [+] Using the pasted Minecraft access token directly")
        return credential
    if credential.startswith("M."):
        return await get_mc_token_from_refresh(credential)
    if credential.startswith("Ew"):
        # "Ew..." values are either MSA v1 refresh or access tokens; try both.
        token = await get_mc_token_from_refresh(credential)
        return token if token else await msa_to_mc_token(credential)
    if credential.startswith("eyJ"):
        return await msa_to_mc_token(credential)
    return credential  # opaque/legacy token - try it as-is


async def resolve_pasted_credentials(text: str) -> list[tuple[str, str]]:
    """Detect pasted cookies / refresh / access tokens as (label, Minecraft token)."""
    text = text.strip()
    if not text:
        return []
    if looks_like_cookies(text):
        cookies = parse_cookie_text(text)
        if not cookies:
            return []
        print(f"[*] Parsed {len(cookies)} cookie(s); running the MSA -> XBL -> XSTS -> Minecraft chain...")
        token = await get_token_from_cookies(cookies)
        return [("cookies", token)] if token else []
    tokens: list[tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        label, credential = parse_refresh_entry(line)
        if label.lower() in ("authorization", "bearer", "cookie"):
            label = ""
        print(f"[*] Resolving {label or 'pasted'} credential...")
        token = await credential_to_mc_token(credential)
        if token:
            tokens.append((label, token))
        else:
            print(f"[!] Could not derive a Minecraft token from {label or 'the pasted credential'}")
    return tokens


async def resolve_token() -> str | None:
    """Select a credential source, then resolve it to a Minecraft token."""
    cwd = os.getcwd()
    while True:
        source = choose_source()
        if source is None:
            return None

        if source == "token":
            tokens = read_lines(os.path.join(cwd, "token.txt"))
            if not tokens:
                print("[!] token.txt is missing or empty.")
                continue
            labels = await get_token_labels(tokens) if len(tokens) > 1 else None
            token = choose_entry(tokens, "token.txt", labels)
            async with ProxyFailoverClient(10) as client:
                resp = await client.get(MC_PROFILE_URL, headers={"Authorization": f"Bearer {token}"})
                if resp.status_code == 200:
                    print("[*] Using cached MC token from token.txt")
                    return token
            print("[!] Selected MC token is invalid or expired. Choose another source.")
            continue

        if source == "refresh":
            refresh_lines = read_lines(os.path.join(cwd, "refresh.txt"))
            if not refresh_lines:
                print("[!] refresh.txt is missing or empty.")
                continue
            refresh_labels = []
            for entry in refresh_lines:
                username, refresh_token = parse_refresh_entry(entry)
                refresh_labels.append(username or mask_token(refresh_token))
            selected_refresh = choose_entry(refresh_lines, "refresh.txt", refresh_labels)
            username, refresh_token = parse_refresh_entry(selected_refresh)
            label = f" for {username}" if username else ""
            print(f"[*] Using refresh token{label} from refresh.txt")
            token = await get_mc_token_from_refresh(refresh_token)
            if token:
                return token
            print("[!] That refresh token did not reach a Minecraft account. Choose another source.")
            continue

        # Pasted cookies, refresh token, or access token.
        text = read_multiline_input(
            "Paste cookies, a refresh token, or an access token "
            "(a 'username:token' label is fine); finish with an empty line:"
        )
        if not text.strip():
            print("[!] Nothing was pasted.")
            continue
        candidates = await resolve_pasted_credentials(text)
        if not candidates:
            print("[!] Could not derive a Minecraft access token from that input. Choose another source.")
            continue
        if len(candidates) > 1:
            labels = [label or mask_token(token) for label, token in candidates]
            return choose_entry([token for _label, token in candidates], "pasted credentials", labels)
        return candidates[0][1]


# --- Name operations ---

async def check_name_available(token: str, name: str) -> bool:
    """Check if a Minecraft username is available."""
    url = MC_NAME_AVAIL_URL.replace("{name}", name)
    async with ProxyFailoverClient(15) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
        if resp.status_code == 200:
            data = resp.json()
            return data.get("status") == "AVAILABLE"
        return False


async def change_name(token: str, new_name: str) -> bool:
    """Change the Minecraft username."""
    async with ProxyFailoverClient(15) as client:
        resp = await client.post(
            MC_NAME_CHANGE_URL,
            json={"name": new_name},
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code == 200:
            data = resp.json()
            print(f"    New name:     {data.get('name', '?')}")
            print(f"    Changed at:   {data.get('changedAt', '?')}")
            return True
        if resp.status_code == 400:
            err = resp.json()
            print(f"    Error: {err.get('error', '?')} - {err.get('errorMessage', '?')}")
        elif resp.status_code == 403:
            print(f"    Forbidden - name change not allowed (cooldown or not eligible)")
        elif resp.status_code == 409:
            print(f"    Conflict - name already taken")
        else:
            print(f"    HTTP {resp.status_code}: {resp.text[:200]}")
        return False


# --- Skin operations ---

async def change_skin_from_url(token: str, skin_url: str, variant: str = CLASSIC) -> bool:
    """Set skin from a URL (must be a direct PNG link)."""
    if variant not in (SLIM, CLASSIC):
        print(f"    Invalid variant: {variant} (use 'classic' or 'slim')")
        return False

    async with ProxyFailoverClient(30) as client:
        # Download the skin first to check it's valid
        print(f"    Downloading skin from URL...")
        img_resp = await client.get(skin_url)
        if img_resp.status_code != 200:
            print(f"    Failed to download image: HTTP {img_resp.status_code}")
            return False

        content_type = img_resp.headers.get("content-type", "")
        if "png" not in content_type and "image" not in content_type:
            print(f"    Warning: Content-Type is '{content_type}', expected image/png")

        skin_data = img_resp.content
        print(f"    Downloaded {len(skin_data)} bytes")

        # Upload via multipart
        resp = await client.post(
            MC_SKIN_URL,
            headers={"Authorization": f"Bearer {token}"},
            files={"file": ("skin.png", skin_data, "image/png")},
            data={"variant": variant},
            follow_redirects=True,
        )
        # The API may 302 or 200
        if resp.status_code in (200, 201, 204, 302):
            print(f"    Skin changed! variant={variant}")
            return True

        print(f"    HTTP {resp.status_code}: {resp.text[:300]}")
        return False


async def change_skin_from_file(token: str, filepath: str, variant: str = CLASSIC) -> bool:
    """Set skin from a local PNG file."""
    if not os.path.isfile(filepath):
        print(f"    File not found: {filepath}")
        return False

    if variant not in (SLIM, CLASSIC):
        print(f"    Invalid variant: {variant} (use 'classic' or 'slim')")
        return False

    with open(filepath, "rb") as f:
        skin_data = f.read()

    print(f"    Read {len(skin_data)} bytes from {filepath}")

    async with ProxyFailoverClient(30) as client:
        resp = await client.post(
            MC_SKIN_URL,
            headers={"Authorization": f"Bearer {token}"},
            files={"file": ("skin.png", skin_data, "image/png")},
            data={"variant": variant},
            follow_redirects=True,
        )
        if resp.status_code in (200, 201, 204, 302):
            print(f"    Skin changed! variant={variant}")
            return True

        print(f"    HTTP {resp.status_code}: {resp.text[:300]}")
        return False


async def reset_skin(token: str) -> bool:
    """Reset skin to default (Steve/Alex)."""
    async with ProxyFailoverClient(15) as client:
        resp = await client.delete(
            MC_SKIN_URL,
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code in (200, 204):
            print(f"    Skin reset to default!")
            return True
        print(f"    HTTP {resp.status_code}: {resp.text[:200]}")
        return False


# --- Username (name change) history ---

def ordinal(number: int) -> str:
    if 10 < number % 100 < 14:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(number % 10, "th")
    return f"{number}{suffix}"


def format_datetime(value: datetime) -> str:
    local = value.astimezone()
    hour = local.hour % 12 or 12
    timezone_name = local.tzname() or "local time"
    return (
        f"{local.strftime('%B')} {ordinal(local.day)} {local.year}, "
        f"{hour}:{local.strftime('%M:%S %p')} {timezone_name}"
    )


def parse_timestamp(value) -> datetime | None:
    """Accept ISO strings, epoch milliseconds, or epoch seconds."""
    if isinstance(value, (int, float)):
        # 1e11 seconds is year 5138, so smaller values are seconds, not ms.
        millis = value if abs(value) >= 1e11 else value * 1000
        try:
            return datetime.fromtimestamp(millis / 1000, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.isdigit():
            return parse_timestamp(int(text))
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def format_duration(delta: timedelta) -> str:
    seconds = int(max(delta.total_seconds(), 0))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes = seconds // 60
    if days:
        return f"{days} day{'s' if days != 1 else ''}"
    if hours:
        return f"{hours} hour{'s' if hours != 1 else ''}"
    if minutes:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    return "less than a minute"


def decode_jwt_claims(token: str) -> dict | None:
    """Return the JWT payload, or None for opaque or malformed tokens."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    try:
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        claims = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return claims if isinstance(claims, dict) else None


def print_token_details(token: str) -> None:
    """Decode the Minecraft JWT so a rejected token still identifies its account."""
    claims = decode_jwt_claims(token)
    if not claims:
        return

    username = None
    profile_fields = claims.get("pfd")
    if isinstance(profile_fields, list):
        for entry in profile_fields:
            if isinstance(entry, dict) and entry.get("type") == "mc" and isinstance(entry.get("name"), str):
                username = entry["name"]
                break

    profiles = claims.get("profiles")
    uuid_ = profiles.get("mc") if isinstance(profiles, dict) else None
    if not isinstance(uuid_, str):
        uuid_ = None

    expires_at = parse_timestamp(claims.get("exp"))

    print("\n  Token details (decoded from the JWT)")
    print(f"    Username:        {username or 'unknown'}")
    print(f"    UUID:            {uuid_ or 'unknown'}")
    if expires_at:
        detail = format_datetime(expires_at)
        now = datetime.now(timezone.utc)
        if expires_at <= now:
            detail += f" - EXPIRED {format_duration(now - expires_at)} ago"
        else:
            detail += f" - valid for {format_duration(expires_at - now)}"
        print(f"    Expires:         {detail}")
    else:
        print("    Expires:         unknown")


def history_entry_name(entry: dict) -> str | None:
    for key in ("name", "username"):
        if isinstance(entry.get(key), str) and entry[key]:
            return entry[key]
    return None


def history_entry_timestamp(entry: dict) -> datetime | None:
    for key in ("changed_at", "changedToAt", "changedAt"):
        if key in entry:
            timestamp = parse_timestamp(entry[key])
            if timestamp:
                return timestamp
    return None


async def get_name_history(client: ProxyFailoverClient, uuid: str, username: str) -> tuple[str, list[dict]]:
    """Try Mojang first, then public username-history archives."""
    try:
        resp = await client.get(MOJANG_NAME_HISTORY_URL.format(uuid=uuid.replace("-", "")))
        if resp.status_code == 200:
            history = resp.json()
            if isinstance(history, list) and all(isinstance(item, dict) for item in history):
                return "Mojang API", history
    except (httpx.HTTPError, ValueError):
        pass

    try:
        resp = await client.get(LIFORRA_NAME_HISTORY_URL, params={"username": username}, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            history = data.get("history") if isinstance(data, dict) else None
            if isinstance(history, list) and all(isinstance(item, dict) for item in history):
                return "Liforra public archive", history
    except (httpx.HTTPError, ValueError):
        pass

    try:
        resp = await client.get(ASHCON_PROFILE_URL.format(username=username), timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            history = data.get("username_history") if isinstance(data, dict) else None
            if isinstance(history, list) and all(isinstance(item, dict) for item in history):
                return "Ashcon public archive", history
    except (httpx.HTTPError, ValueError):
        pass

    return "Unavailable", []


def print_name_history(source: str, history: list[dict], current_name: str) -> None:
    print("\n  Username history")
    if not history:
        print("    Status:           unavailable")
        return
    print(f"    Source:           {source}")
    print(f"    Entries:          {len(history)}")
    for entry in history:
        name = history_entry_name(entry) or "Unknown"
        suffix = " (current)" if name.casefold() == current_name.casefold() else ""
        timestamp = history_entry_timestamp(entry)
        detail = format_datetime(timestamp) if timestamp else "original name / no date"
        print(f"    - {name}{suffix} - {detail}")


# --- Main menu ---

async def select_live_proxies(proxies: list[str]) -> list[str]:
    """Find working endpoints instead of trusting the first entry in the file.

    Probing stops as soon as enough proxies answer, so a healthy list costs one
    short round rather than a full scan of hundreds of dead entries.
    """
    if len(proxies) < 2:
        return proxies

    print(f"[*] Looking for working proxies among {len(proxies)} entries...", flush=True)
    alive: list[str] = []
    checked = 0
    deadline = time.monotonic() + PROXY_DISCOVERY_BUDGET

    async def probe(proxy: str) -> bool:
        try:
            return await asyncio.wait_for(
                probe_proxy(proxy, timeout=PROXY_CHECK_TIMEOUT),
                PROXY_CHECK_TIMEOUT + 1,
            )
        except asyncio.TimeoutError:
            return False

    for start in range(0, len(proxies), PROXY_DISCOVERY_BATCH):
        if len(alive) >= PROXY_DISCOVERY_TARGET or time.monotonic() >= deadline:
            break
        batch = proxies[start:start + PROXY_DISCOVERY_BATCH]
        results = await asyncio.gather(*(probe(proxy) for proxy in batch))
        checked += len(batch)
        alive.extend(proxy for proxy, ok in zip(batch, results) if ok)
        print(f"    {checked}/{len(proxies)} checked, {len(alive)} working", flush=True)

    if not alive:
        print("[!] No proxy answered the health check; using the full list with per-request failover.")
        return proxies
    print(f"[*] Using {len(alive)} working proxy/proxies (checked {checked}).")
    return alive


async def main():
    global ROTATOR
    proxies = choose_proxies(os.getcwd())
    proxies = await select_live_proxies(proxies)
    ROTATOR = ProxyRotator(proxies, quarantine_after=2)
    print("=" * 55)
    print("  Minecraft Account Manager")
    print("=" * 55)

    token = await resolve_token()
    if not token:
        sys.exit(1)

    print_token_details(token)

    # Show current profile
    async with ProxyFailoverClient(15) as client:
        resp = await client.get(MC_PROFILE_URL, headers={"Authorization": f"Bearer {token}"})
        if resp.status_code != 200:
            print("[!] Token rejected by Minecraft API.")
            sys.exit(1)
        profile = resp.json()

        name = profile.get("name", "?")
        uuid_ = profile.get("id", "?")
        skins = profile.get("skins", [])
        active_skin = next((s for s in skins if s.get("state") == "ACTIVE"), None)

        print(f"\n  Current account: {name}")
        print(f"  UUID:            {uuid_}")
        if active_skin:
            print(f"  Active skin:     {active_skin.get('variant', 'classic').upper()} "
                  f"({active_skin.get('id', '?')[:16]}...)")
        else:
            print(f"  Active skin:     default (Steve/Alex)")

        # Check name change eligibility, timing, and history
        nc_resp = await client.get(
            MC_NAME_CHANGE_URL,
            headers={"Authorization": f"Bearer {token}"},
        )
        name_change_allowed = False
        if nc_resp.status_code == 200:
            nc = nc_resp.json() if isinstance(nc_resp.json(), dict) else {}
            name_change_allowed = bool(nc.get("nameChangeAllowed", False))
            created_at = parse_timestamp(nc.get("createdAt"))
            changed_at = parse_timestamp(nc.get("changedAt"))
            if created_at:
                print(f"  Account created: {format_datetime(created_at)}")
            if changed_at:
                print(f"  Last changed:    {format_datetime(changed_at)}")
            if name_change_allowed:
                print("  Name change:     ALLOWED")
            else:
                next_allowed = changed_at + NAME_CHANGE_COOLDOWN if changed_at else None
                now = datetime.now(timezone.utc)
                if next_allowed and next_allowed > now:
                    remaining = next_allowed - now
                    print(f"  Name change:     ON COOLDOWN until "
                          f"{format_datetime(next_allowed)} (about {remaining.days} days)")
                else:
                    print("  Name change:     ON COOLDOWN")

        if uuid_ and uuid_ != "?":
            history_source, history = await get_name_history(client, uuid_, name)
            print_name_history(history_source, history, name)

    # Show options
    print(f"\n{'─'*55}")
    print(f"  Options:")
    print(f"  [1] Change username")
    print(f"  [2] Change skin (from URL)")
    print(f"  [3] Change skin (from local file)")
    print(f"  [4] Reset skin to default")
    print(f"  [5] Check name availability")
    print(f"  [q] Quit")
    print(f"{'─'*55}")

    choice = input("\n  Choice: ").strip()

    if choice == "1":
        if not name_change_allowed:
            print("\n[!] Name change is currently on cooldown. Try again later.")
            return
        new_name = input("  New username: ").strip()
        if not new_name:
            print("[!] No name entered.")
            return
        print(f"\n  Changing name: {name} → {new_name}")
        ok = await change_name(token, new_name)
        if ok:
            print(f"\n[+] Name changed successfully!")
        else:
            print(f"\n[-] Name change failed.")

    elif choice == "2":
        url = input("  Skin image URL (direct PNG): ").strip()
        variant = input("  Variant [classic/slim] (default: classic): ").strip().lower() or CLASSIC
        print(f"\n  Setting skin from URL...")
        ok = await change_skin_from_url(token, url, variant)
        if ok:
            print(f"\n[+] Skin changed!")
        else:
            print(f"\n[-] Skin change failed.")

    elif choice == "3":
        filepath = input("  Path to skin PNG file: ").strip()
        variant = input("  Variant [classic/slim] (default: classic): ").strip().lower() or CLASSIC
        print(f"\n  Setting skin from file...")
        ok = await change_skin_from_file(token, filepath, variant)
        if ok:
            print(f"\n[+] Skin changed!")
        else:
            print(f"\n[-] Skin change failed.")

    elif choice == "4":
        confirm = input("  Reset skin to default? [y/N]: ").strip().lower()
        if confirm != "y":
            print("  Cancelled.")
            return
        print(f"\n  Resetting skin...")
        ok = await reset_skin(token)
        if ok:
            print(f"\n[+] Skin reset!")
        else:
            print(f"\n[-] Skin reset failed.")

    elif choice == "5":
        check_name = input("  Username to check: ").strip()
        if not check_name:
            print("[!] No name entered.")
            return
        print(f"\n  Checking '{check_name}'...")
        available = await check_name_available(token, check_name)
        if available:
            print(f"[+] '{check_name}' is AVAILABLE!")
        else:
            print(f"[-] '{check_name}' is TAKEN or invalid.")

    elif choice.lower() == "q":
        print("  Bye.")
        return

    else:
        print(f"  Unknown option: {choice}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except httpx.HTTPError as exc:
        print(f"\n[!] Network error: {type(exc).__name__}: {exc}")
        print("[!] No proxy could reach the Minecraft API. Check the proxy list and try again.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n  Cancelled.")
        sys.exit(130)
