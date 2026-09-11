"""
Token Validator (detailed)
Reads token.txt (Minecraft JWTs) and refresh.txt (MSA refresh tokens),
validates them, shows username/UUID, account details, and best-effort expiry.

A token only counts as VALID when it resolves to a real Minecraft username, so
working Microsoft credentials for an account without Minecraft are not accepted.

Output files:
  validated_refresh_<ts>.txt  refresh tokens with a username, as username:token
  validated_tokens_<ts>.txt   access tokens with a username, as username:token
  rejected_refresh_<ts>.txt   refresh tokens without a username, with the reason
  rejected_tokens_<ts>.txt    access tokens without a username, with the reason
  verbose_<ts>.txt            full per-token trace
"""

import os
import sys
import time
import asyncio
import argparse
import base64
import json
import re
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import httpx
from proxy_utils import (
    PROXY_FAILURE_RETRIES,
    ProxyRotator,
    choose_proxies,
    filter_working_proxies,
    proxy_label as shared_proxy_label,
    read_proxy_file,
    write_proxy_list,
)

# --- Constants ---

MC_PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile"
MC_NAME_CHANGE_URL = "https://api.minecraftservices.com/minecraft/profile/namechange"
XBL_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate"
XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize"
MC_LOGIN_WITH_XBOX_URL = "https://api.minecraftservices.com/authentication/login_with_xbox"
MC_SESSIONSERVER_URL = "https://sessionserver.mojang.com/session/minecraft/profile/{uuid}"
LIVE_CONNECT_TOKEN_URL = "https://login.live.com/oauth20_token.srf"
LIVE_CONNECT_DESKTOP_REDIRECT_URI = "https://login.live.com/oauth20_desktop.srf"
MINECRAFT_LAUNCHER_V1_CLIENT_ID = "00000000402b5328"
LIVE_CONNECT_SCOPE_MBI_SSL = "service::user.auth.xboxlive.com::MBI_SSL"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
# v1 public UUID lookup (no auth) - urls built inline

# Networking defaults. A dead proxy must fail fast: with a 15s connect timeout,
# three failover attempts burn the whole per-account budget on a single token,
# which is exactly how a bad proxy list turns into "every account timed out".
HTTP_CONNECT_TIMEOUT = 6.0
HTTP_READ_TIMEOUT = 12.0

ALIVE_PROXY_FILE = "proxy_alive.txt"
DEAD_PROXY_FILE = "proxy_dead.txt"

DEFAULT_CONCURRENCY = 32
PROXY_CHECK_CONCURRENCY = 120


def http_timeout(read: float = HTTP_READ_TIMEOUT) -> httpx.Timeout:
    """Timeout with a short connect phase so dead proxies fail quickly."""
    return httpx.Timeout(read, connect=HTTP_CONNECT_TIMEOUT)


class ClientCache:
    """One long-lived HTTP client per proxy, reused for the whole run.

    A client per request (the previous behaviour) opened fresh TCP/TLS
    connections for every call. A 2000-account run meant tens of thousands of
    sockets, which is slow, chews through proxy connection quotas and
    eventually exhausts local ports - after which every request fails at once,
    exactly the cliff seen partway through a big run.
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


class FailureGuard:
    """Pause the run when the network collapses instead of burning the list.

    Without this, a run whose proxies have all died races to the end of the
    token list marking every account as a network error, wasting the whole
    batch. After a full window of consecutive failures the run backs off, which
    gives the proxies and the local socket pool time to recover.
    """

    def __init__(self, window: int = 25, pause: float = 15.0):
        self.window = max(5, window)
        self.pause = pause
        self._recent: deque[bool] = deque(maxlen=self.window)
        self._lock = asyncio.Lock()
        self.trips = 0

    async def note(self, failed: bool) -> None:
        trip = False
        async with self._lock:
            self._recent.append(failed)
            if len(self._recent) == self.window and all(self._recent):
                self.trips += 1
                self._recent.clear()
                trip = True
        if trip:
            print(
                f"[!] {self.window} accounts in a row failed with network/proxy "
                f"errors - pausing {self.pause:.0f}s before continuing",
                flush=True,
            )
            await asyncio.sleep(self.pause)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate Minecraft access tokens and MSA refresh tokens. A token is "
            "only valid when it resolves to a real Minecraft username."
        )
    )
    parser.add_argument(
        "--dir", dest="directory", default=None,
        help="Folder holding token.txt / refresh.txt (default: current directory).",
    )
    parser.add_argument(
        "--concurrency", type=int, default=0,
        help=(
            f"Accounts checked at the same time (default: {DEFAULT_CONCURRENCY}, "
            "or 2x the number of working proxies)."
        ),
    )
    parser.add_argument(
        "--timeout", type=float, default=60.0,
        help="Seconds allowed for one account incl. proxy retries (default: 60).",
    )
    parser.add_argument(
        "--limit", type=int, default=0,
        help="Only check the first N accounts; 0 checks all of them.",
    )
    parser.add_argument(
        "--details", action="store_true",
        help="Also fetch name-change and name-history data (slower: extra requests per account).",
    )
    parser.add_argument(
        "--only-tokens", dest="only_tokens", default=None, metavar="FILE",
        help="Check this token file instead of token.txt (use it to retry errors_tokens_*.txt).",
    )
    parser.add_argument(
        "--proxies", dest="proxy_file", default=None, metavar="FILE",
        help="Use this proxy list file and skip the interactive prompt.",
    )
    parser.add_argument(
        "--no-proxies", dest="no_proxies", action="store_true",
        help="Ignore proxy.txt and connect directly.",
    )
    parser.add_argument(
        "--check-proxies", dest="check_proxies", action="store_true", default=False,
        help=(
            f"Optional: probe every proxy before starting and keep the working ones in "
            f"{ALIVE_PROXY_FILE}. Off by default - proxies are just used as given."
        ),
    )
    parser.add_argument(
        "--proxy-timeout", type=float, default=8.0,
        help="Seconds allowed for one proxy probe when --check-proxies is used (default: 8).",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print the full per-token report instead of one line per account.",
    )
    return parser.parse_args(argv)


# --- JWT helpers ---

def decode_jwt(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        payload = parts[1]
        payload += "=" * (4 - len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return None


def same_account(token_a: str, token_b: str) -> bool:
    """True when two Minecraft tokens belong to the same account.

    Compares the xuid/sub claims. This keeps the refresh-token fallback honest:
    the refresh token in refresh.txt must not be allowed to stand in for a
    different account's access token from token.txt.
    """
    claims_a = decode_jwt(token_a) or {}
    claims_b = decode_jwt(token_b) or {}
    for claim in ("xuid", "sub"):
        value_a, value_b = claims_a.get(claim), claims_b.get(claim)
        if value_a and value_b:
            return str(value_a) == str(value_b)
    return False


def jwt_expiry(payload: dict) -> str:
    exp = payload.get("exp")
    iat = payload.get("iat")
    nbf = payload.get("nbf")
    now = datetime.now(timezone.utc)
    lines = []

    if exp:
        exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
        remaining = exp_dt - now
        total_secs = remaining.total_seconds()
        if total_secs > 0:
            lines.append(f"    Expires:   {exp_dt.strftime('%Y-%m-%d %H:%M:%S UTC')} (in {total_secs:.0f}s / {total_secs/3600:.1f}h)")
        else:
            lines.append(f"    EXPIRED:   {exp_dt.strftime('%Y-%m-%d %H:%M:%S UTC')} ({abs(total_secs):.0f}s ago - DEAD)")
    if iat:
        iat_dt = datetime.fromtimestamp(iat, tz=timezone.utc)
        lines.append(f"    Issued:    {iat_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    if nbf:
        nbf_dt = datetime.fromtimestamp(nbf, tz=timezone.utc)
        lines.append(f"    NotBefore: {nbf_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    return "\n".join(lines) if lines else "    (no time claims in token)"


# --- Minecraft API queries ---

async def query_mc_api(token: str, url: str, proxy: str | None = None) -> dict | None:
    """Generic GET to a Mojang authed endpoint."""
    try:
        resp = await client_for(proxy).get(
            url, headers={"Authorization": f"Bearer {token}"}, timeout=http_timeout()
        )
    except Exception:
        return None
    if resp.status_code == 200:
        try:
            return resp.json()
        except Exception:
            return None
    return None


async def fetch_profile(
    token: str,
    proxy: str | None = None,
) -> tuple[dict | None, int, str]:
    """Minecraft profile plus the HTTP status and any transport error.

    The status matters: 404 means the token is fine but the account owns no
    Minecraft profile, while 401/403 means the token itself is dead. Status 0
    means the request never completed, which is a proxy/network problem rather
    than a verdict on the token.
    """
    try:
        resp = await client_for(proxy).get(
            MC_PROFILE_URL,
            headers={"Authorization": f"Bearer {token}"},
            timeout=http_timeout(),
        )
    except Exception as exc:
        return None, 0, f"{type(exc).__name__}: {exc}"[:200]
    if resp.status_code != 200:
        return None, resp.status_code, ""
    try:
        return resp.json(), 200, ""
    except Exception as exc:
        return None, 200, f"{type(exc).__name__}: {exc}"[:200]


async def confirm_username(uuid: str, proxy: str | None = None) -> str:
    """Independent public check: resolve a UUID to its current Java username.

    Returns the public name, or '' when the lookup cannot answer. Never used to
    invalidate a token - the authenticated profile is authoritative - but it is
    worth knowing when the two disagree.
    """
    clean_uuid = (uuid or "").replace("-", "")
    if len(clean_uuid) != 32:
        return ""
    url = MC_SESSIONSERVER_URL.format(uuid=clean_uuid)
    try:
        resp = await client_for(proxy).get(url, timeout=http_timeout())
        if resp.status_code == 200:
            return str(resp.json().get("name") or "")
    except Exception:
        pass
    return ""


async def get_name_change_info(token: str, proxy: str | None = None) -> dict | None:
    """Name change eligibility & history."""
    return await query_mc_api(token, MC_NAME_CHANGE_URL, proxy)


async def get_name_history(uuid: str, proxy: str | None = None) -> list | None:
    """Public endpoint: full name history for a UUID (no auth needed).
    Tries the new Minecraft API first, falls back to legacy api.mojang.com."""
    clean_uuid = uuid.replace("-", "")
    # Newer endpoint (often works)
    urls = [
        f"https://api.minecraftservices.com/minecraft/profile/lookup/name/{clean_uuid}/names",
        f"https://api.mojang.com/user/profiles/{clean_uuid}/names",
    ]
    client = client_for(proxy)
    for url in urls:
        try:
            resp = await client.get(url, timeout=http_timeout())
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            continue
    return None


def uuid_to_creation_estimate(uuid: str) -> str | None:
    """UUID v4 uses random bytes, but early Mojang UUIDs can hint at time.
    This is a best-effort guess based on name history + API heuristics."""
    # Mojang UUIDs are random - no timestamp embedded.
    # We rely on name history API instead.
    return None


def fmt_iso(ts: str) -> str:
    """Try to pretty-print an ISO timestamp."""
    if not ts:
        return "N/A"
    try:
        # Handle milliseconds
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ts


def plural(n: int, word: str) -> str:
    return f"{n} {word}{'s' if n != 1 else ''}"


# --- Validity rules ---
# A token is only VALID when it resolves to a real Minecraft username. Working
# Microsoft/Xbox credentials for an account without Minecraft do not count.

MC_USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,16}$")

VALID_STATUSES = {"VALID", "REFRESHED"}

# Refresh-token outcomes
STATUS_VALID = "VALID"                # Minecraft username resolved and saved
STATUS_NO_XBOX = "NO_XBOX"            # MSA refresh worked, Xbox/Minecraft exchange failed
STATUS_NO_MINECRAFT = "NO_MINECRAFT"  # no Minecraft profile on the Microsoft account
STATUS_NO_USERNAME = "NO_USERNAME"    # profile returned without a usable username
STATUS_DEAD = "DEAD"                  # refresh token rejected by Microsoft
STATUS_ERROR = "ERROR"                # transient/technical failure (still retryable)
STATUS_TIMEOUT = "TIMEOUT"
STATUS_NOT_TESTED = "JWT_NOT_TESTED"

# Minecraft access-token outcomes
STATUS_MC_INVALID = "INVALID"        # token rejected by the Minecraft API

# The order statuses are summarised in.
SUMMARY_ORDER = (
    STATUS_VALID, "REFRESHED", STATUS_NO_MINECRAFT, STATUS_NO_USERNAME,
    STATUS_NO_XBOX, STATUS_MC_INVALID, STATUS_DEAD, STATUS_TIMEOUT,
    STATUS_ERROR, STATUS_NOT_TESTED,
)


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


def classify_profile_failure(
    profile: dict | None,
    http_status: int,
    error_text: str = "",
) -> tuple[str, str]:
    """Map a failed Minecraft profile lookup to (status, human reason)."""
    if http_status in (401, 403):
        return STATUS_MC_INVALID, "the Minecraft API rejected this access token"
    if http_status == 404:
        return STATUS_NO_MINECRAFT, "no Minecraft profile on this Microsoft account"
    if http_status == 0:
        detail = f" ({error_text})" if error_text else ""
        return STATUS_ERROR, f"the Minecraft profile request never completed{detail}"
    if http_status in (429, 500, 502, 503, 504):
        return STATUS_ERROR, f"the Minecraft profile request returned HTTP {http_status}"
    if profile is not None:
        return STATUS_NO_USERNAME, "the Minecraft profile contains no usable username"
    return STATUS_ERROR, f"the Minecraft profile request returned HTTP {http_status}"


def status_reason(result: dict) -> str:
    """Why a result was not accepted as valid (used in logs and the reject list)."""
    # A refresh-token mismatch explains the outcome best, so it wins over the
    # generic profile failure recorded during classification.
    if result.get("refresh_mismatch"):
        profile_status = result.get("profile_status") or 0
        if profile_status:
            return (
                "the refresh token in refresh.txt belongs to a different account, "
                f"so this token was not validated (profile HTTP {profile_status})"
            )
        return (
            "the refresh token in refresh.txt belongs to a different account, "
            "so this token was not validated"
        )
    if result.get("error"):
        return result["error"]
    if result.get("profile_error"):
        return result["profile_error"]
    profile_status = result.get("profile_status") or 0
    status = result.get("status") or result.get("token_status") or "?"
    if status == STATUS_NO_MINECRAFT:
        if profile_status in (0, 404):
            return "no Minecraft profile on this Microsoft account"
        return classify_profile_failure(None, profile_status)[1]
    if status == STATUS_NO_USERNAME:
        return "the Minecraft profile contains no usable username"
    if status == STATUS_MC_INVALID:
        if profile_status:
            return f"the Minecraft API rejected this access token (HTTP {profile_status})"
        return "the Minecraft API rejected this access token"
    if status == STATUS_ERROR:
        return classify_profile_failure(None, profile_status)[1]
    if status == STATUS_NO_XBOX:
        return "the account could not authenticate with Xbox Live"
    if status == STATUS_DEAD:
        return "Microsoft rejected the refresh token"
    if status == STATUS_TIMEOUT:
        return "validation timed out"
    if status == STATUS_NOT_TESTED:
        return "input is a Minecraft JWT, not a refresh token"
    return status


def username_check_note(result: dict) -> str:
    """Human note about the independent public username confirmation."""
    if result.get("name_confirmed") is True:
        return "confirmed by the public Mojang lookup"
    if result.get("name_confirmed") is False and result.get("confirmed_name"):
        return (
            f"public lookup currently returns '{result['confirmed_name']}' "
            "(rename in progress?)"
        )
    return "not confirmed publicly; the authenticated profile is authoritative"


def status_note(result: dict) -> str:
    """Short console label: status plus the Minecraft username or the reason."""
    status = result.get("status") or result.get("token_status") or "?"
    if status in VALID_STATUSES:
        name = result.get("profile_name") or profile_username(result.get("profile"))
        return f"{status} (Minecraft username: {name})"
    return f"{status} ({status_reason(result)})"


# --- Quick refresh to get a valid MC token for profile queries ---

async def refresh_mc_token(
    refresh_token: str,
    proxy: str | None = None,
    diagnostics: dict | None = None,
) -> str | None:
    """Refresh MSA -> XBL -> XSTS -> MC, return fresh MC token or None.

    When `diagnostics` is passed it receives the stage that failed and a short
    reason, so callers can tell "not a Minecraft account" apart from a
    transient network problem.
    """

    def fail(stage: str, reason: str) -> None:
        if diagnostics is not None:
            diagnostics["stage"] = stage
            diagnostics["reason"] = reason

    try:
        client = client_for(proxy)
        chain_timeout = http_timeout(30)
        # 1. Refresh MSA
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
            timeout=chain_timeout,
        )
        if resp.status_code != 200:
            fail("msa", f"MSA refresh returned HTTP {resp.status_code}")
            return None
        msa = (resp.json() or {}).get("access_token")
        if not msa:
            fail("msa", "MSA refresh returned no access_token")
            return None

        # 2. XBL
        if not msa.startswith("t=") and not msa.startswith("d=") and not msa.startswith("eyJ"):
            msa = f"t={msa}"
        resp = await client.post(
            XBL_AUTH_URL,
            json={
                "Properties": {"AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com", "RpsTicket": msa},
                "RelyingParty": "http://auth.xboxlive.com",
                "TokenType": "JWT",
            },
            headers={"Accept": "application/json", "x-xbl-contract-version": "1"},
            timeout=chain_timeout,
        )
        if resp.status_code != 200:
            fail("xbl", f"Xbox Live authentication returned HTTP {resp.status_code}")
            return None
        xbl_token = (resp.json() or {}).get("Token")
        if not xbl_token:
            fail("xbl", "Xbox Live authentication returned no token")
            return None

        # 3. XSTS
        resp = await client.post(
            XSTS_AUTH_URL,
            json={
                "Properties": {"SandboxId": "RETAIL", "UserTokens": [xbl_token]},
                "RelyingParty": "rp://api.minecraftservices.com/",
                "TokenType": "JWT",
            },
            headers={"Accept": "application/json", "x-xbl-contract-version": "1"},
            timeout=chain_timeout,
        )
        if resp.status_code != 200:
            xerr = ""
            try:
                err = resp.json() or {}
                if err.get("XErr"):
                    xerr = f" (XErr {err['XErr']})"
            except Exception:
                pass
            fail("xsts", f"XSTS authorize returned HTTP {resp.status_code}{xerr}")
            return None
        try:
            data = resp.json()
            xsts_token = data["Token"]
            uhs = data["DisplayClaims"]["xui"][0]["uhs"]
        except Exception:
            fail("xsts", "XSTS authorize returned an unexpected payload")
            return None

        # 4. Minecraft
        resp = await client.post(
            MC_LOGIN_WITH_XBOX_URL,
            json={"identityToken": f"XBL3.0 x={uhs};{xsts_token}"},
            headers={"Accept": "application/json"},
            timeout=chain_timeout,
        )
        if resp.status_code != 200:
            fail("mc", f"Minecraft login returned HTTP {resp.status_code}")
            return None
        token = (resp.json() or {}).get("access_token")
        if not token:
            fail("mc", "Minecraft login returned no access_token")
            return None
        return token
    except Exception as exc:
        fail("network", f"{type(exc).__name__}: {exc}")
        return None


# --- Refresh token validation ---

async def validate_refresh_token(refresh_token: str, proxy: str | None = None) -> dict | None:
    try:
        resp = await client_for(proxy).post(
            LIVE_CONNECT_TOKEN_URL,
            data={
                "client_id": MINECRAFT_LAUNCHER_V1_CLIENT_ID,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
                "redirect_uri": LIVE_CONNECT_DESKTOP_REDIRECT_URI,
                "scope": LIVE_CONNECT_SCOPE_MBI_SSL,
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": DEFAULT_USER_AGENT,
            },
            timeout=http_timeout(),
        )
    except Exception as exc:
        return {
            "valid": False,
            "status": 0,
            "body": f"{type(exc).__name__}: {exc}"[:200],
            "network_error": True,
        }
    if resp.status_code == 200:
        data = resp.json()
        return {
            "valid": True,
            "new_refresh": data.get("refresh_token"),
            "expires_in": data.get("expires_in"),
            "user_id": data.get("user_id"),
        }
    network_error = resp.status_code in (429, 500, 502, 503, 504)
    return {
        "valid": False,
        "status": resp.status_code,
        "body": resp.text[:200],
        "network_error": network_error,
    }


def parse_refresh_entry(line: str) -> tuple[str, str]:
    """Return (optional USERNAME label, refresh token)."""
    if ":" in line:
        username, token = line.split(":", 1)
        if username.strip() and token.strip():
            return username.strip(), token.strip()
    return "", line.strip()


def format_refresh_entry(username: str, refresh_token: str) -> str:
    return f"{username}:{refresh_token}" if username else refresh_token


def output_refresh_entry(result: dict) -> str:
    """Format a successful refresh result with the best available username."""
    # Prefer the resolved profile name because input labels can be stale after a rename.
    label = result["profile_name"] or result["username_label"]
    if result["new_refresh_entry"]:
        token = result["new_refresh_entry"].split(":", 1)[-1]
    else:
        token = result["refresh_token"]
    return format_refresh_entry(label, token)


def read_lines(filepath: str) -> list[str]:
    if not os.path.isfile(filepath):
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def read_proxies(filepath: str) -> list[str]:
    """Read proxy URLs, ignoring blank lines and comments.

    Accepted: http://host:port, https://host:port, socks5://host:port,
    socks5h://host:port, bare host:port, and host:port:username:password
    (the last two are treated as HTTP).
    """
    from urllib.parse import quote
    proxies = []
    for line in read_lines(filepath):
        if line.startswith("#"):
            continue
        if "://" not in line:
            fields = line.split(":")
            if len(fields) == 4 and fields[1].isdigit():
                host, port, username, password = fields
                proxy = (
                    f"http://{quote(username, safe='')}:{quote(password, safe='')}"
                    f"@{host}:{port}"
                )
            elif fields[-1] == "1080":
                proxy = f"socks5://{line}"
            else:
                proxy = f"http://{line}"
        else:
            proxy = line
        if proxy.startswith(("http://", "https://", "socks5://", "socks5h://")):
            proxies.append(proxy)
    return proxies


def proxy_label(proxy: str) -> str:
    """Display a proxy endpoint without exposing credentials."""
    from urllib.parse import urlsplit
    try:
        parsed = urlsplit(proxy)
        return f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"
    except Exception:
        return "configured proxy"


def choose_proxy(rotator, proxies: list[str] | None = None, index: int = 0, attempt: int = 0) -> str | None:
    """Proxy for one attempt via the health-aware rotator.

    Never silently falls back to a direct connection: when no proxies are
    configured there is nothing to route through, and otherwise the rotator
    always returns one.
    """
    return rotator.next()


async def validate_refresh_entry(
    username_label: str,
    refresh_token: str,
    proxy: str | None,
) -> dict:
    """Validate one refresh entry and resolve its Minecraft profile.

    The entry only counts as VALID when the whole chain ends in an actual
    Minecraft username. A refresh token that merely exchanges for an MSA token,
    or whose account owns no Minecraft, is reported as not valid.
    """
    validated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    result = {
        "username_label": username_label,
        "refresh_token": refresh_token,
        "proxy": proxy,
        "validated_at": validated_at,
        "status": "UNKNOWN",
        "profile_name": "",
        "profile_uuid": "",
        "profile_status": 0,
        "name_confirmed": None,
        "confirmed_name": "",
        "new_refresh_entry": "",
        "result": None,
        "profile_error": "",
        "error": "",
    }

    if refresh_token.startswith("eyJ"):
        result["status"] = STATUS_NOT_TESTED
        result["profile_error"] = status_reason(result)
        return result

    try:
        validation = await validate_refresh_token(refresh_token, proxy)
        result["result"] = validation
        if not validation or not validation.get("valid"):
            result["status"] = STATUS_DEAD
            result["profile_error"] = status_reason(result)
            return result

        new_refresh = validation.get("new_refresh")
        if new_refresh:
            result["new_refresh_entry"] = format_refresh_entry(username_label, new_refresh)

        # The MSA token is not enough on its own: the account must reach
        # Minecraft and expose a username.
        diagnostics: dict = {}
        profile_token = await refresh_mc_token(
            new_refresh or refresh_token, proxy, diagnostics
        )
        if not profile_token:
            stage = diagnostics.get("stage", "")
            if stage == "msa":
                result["status"] = STATUS_DEAD
            elif stage in ("xbl", "xsts"):
                result["status"] = STATUS_NO_XBOX
            else:
                result["status"] = STATUS_ERROR
                result["network_error"] = True
            result["profile_error"] = diagnostics.get(
                "reason", "Minecraft exchange failed"
            )
            return result

        profile, http_status, profile_error = await fetch_profile(profile_token, proxy)
        result["profile_status"] = http_status

        name = profile_username(profile)
        if not name:
            result["status"], result["profile_error"] = classify_profile_failure(
                profile, http_status, profile_error
            )
            if result["status"] == STATUS_ERROR:
                result["network_error"] = True
            return result

        # A real username came back, so the entry is valid.
        result["profile_name"] = name
        result["profile_uuid"] = str((profile or {}).get("id") or "")
        public_name = await confirm_username(result["profile_uuid"], proxy)
        if public_name:
            result["confirmed_name"] = public_name
            result["name_confirmed"] = public_name.lower() == name.lower()
        result["status"] = STATUS_VALID
    except Exception as exc:
        result["status"] = STATUS_ERROR
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["profile_error"] = result["error"]
    return result


async def validate_mc_entry(
    index: int,
    token: str,
    fallback_refresh_token: str | None,
    proxy: str | None,
    details: bool = False,
) -> dict:
    """Validate one Minecraft access token and collect detailed account data.

    As with refresh tokens, the access token is only VALID when it resolves to a
    real Minecraft username; an access token for an account without Minecraft
    is reported as not valid. `details` adds the extra name-history lookups,
    which cost more requests per account.
    """
    result = {
        "index": index,
        "token": token,
        "proxy": proxy,
        "payload": decode_jwt(token),
        "profile": None,
        "probe_token": token,
        "token_status": STATUS_MC_INVALID,
        "profile_status": 0,
        "name_confirmed": None,
        "confirmed_name": "",
        "refresh_attempted": False,
        "refresh_mismatch": False,
        "network_error": False,
        "name_change": None,
        "name_history": None,
        "profile_error": "",
        "error": "",
    }
    try:
        profile, http_status, profile_error = await fetch_profile(token, proxy)
        result["profile_status"] = http_status

        # A stale access token can be replaced with a fresh one derived from the
        # paired refresh token in refresh.txt, then the profile is looked up
        # again. A 404 is definitive (no Minecraft on the account) and a status
        # of 0 means the request never completed, so neither is worth retrying
        # with a refresh token.
        if (
            not profile_username(profile)
            and fallback_refresh_token
            and http_status in (401, 403)
        ):
            result["refresh_attempted"] = True
            probe_token = await refresh_mc_token(fallback_refresh_token, proxy)
            if probe_token and same_account(token, probe_token):
                result["probe_token"] = probe_token
                profile, http_status, profile_error = await fetch_profile(probe_token, proxy)
                result["profile_status"] = http_status
            elif probe_token:
                # The refresh token in refresh.txt belongs to somebody else. Using
                # it would credit this token with another account's username.
                result["refresh_mismatch"] = True
                print(
                    f"[!] Token {result['index']}: the refresh token in refresh.txt "
                    f"belongs to a different account; not using it."
                )

        name = profile_username(profile)
        if not name:
            result["profile"] = None
            result["token_status"], reason = classify_profile_failure(
                profile, result["profile_status"], profile_error
            )
            result["profile_error"] = reason
            if result["token_status"] == STATUS_ERROR:
                result["network_error"] = True
                result["error"] = reason
            return result

        result["profile"] = profile
        result["token_status"] = "REFRESHED" if result["refresh_attempted"] else "VALID"

        probe_token = result["probe_token"]
        uuid_ = str((profile or {}).get("id") or "")
        if details:
            result["name_change"] = await get_name_change_info(probe_token, proxy)
        public_name = await confirm_username(uuid_, proxy)
        if public_name:
            result["confirmed_name"] = public_name
            result["name_confirmed"] = public_name.lower() == name.lower()
        name_history = (
            result["name_change"].get("history")
            or result["name_change"].get("nameChanges")
            if result["name_change"]
            else None
        )
        if details and not name_history and uuid_:
            name_history = await get_name_history(uuid_, proxy)
        result["name_history"] = name_history
    except Exception as exc:
        result["token_status"] = STATUS_ERROR
        result["network_error"] = True
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def format_mc_summary(result: dict, position: int, total: int) -> str:
    """One console line per account; the detail belongs in the verbose log."""
    status = result["token_status"]
    label = f"[{position:>{len(str(total))}}/{total}]"
    if status in VALID_STATUSES:
        name = profile_username(result.get("profile")) or "?"
        return f"{label} + {name} ({status})"
    return f"{label} . {status} - {status_reason(result)}"


def format_mc_result(result: dict) -> list[str]:
    """Format detailed Minecraft-token output for screen and verbose log."""
    token = result["token"]
    lines = [
        "\n" + "-" * 64,
        f"  [{result['index']}] Token ({len(token)} chars)",
        f"      Prefix: {token[:55]}...",
    ]
    payload = result["payload"]
    if payload:
        lines.append("      JWT claims:")
        lines.extend(jwt_expiry(payload).splitlines())
        for key in ("sub", "xuid", "iss"):
            if payload.get(key):
                lines.append(f"      {key}: {payload[key]}")
    else:
        lines.append("      (not a decodable JWT)")

    profile = result["profile"]
    if not profile:
        lines.append(
            f"  >>> NOT VALID ({result['token_status']}) - no Minecraft username"
        )
        lines.append(f"      Reason: {status_reason(result)}")
        if result["error"]:
            lines.append(f"      Error: {result['error']}")
        return lines

    name = profile_username(profile) or "?"
    uuid_ = profile.get("id", "?")
    skins = profile.get("skins", [])
    capes = profile.get("capes", [])
    lines.extend([
        f"\n  ---- Account: {name} ----",
        f"  Status:       VALID (Minecraft username resolved"
        + (
            " after refreshing the token from refresh.txt)"
            if result["token_status"] == "REFRESHED"
            else ")"
        ),
        f"  UUID:         {uuid_}",
        f"  Username check: {username_check_note(result)}",
        f"  Skins:        {len(skins)} ({', '.join(s.get('variant', '?').upper() for s in skins) or 'none'})",
        f"  Capes:        {len(capes)} ({', '.join(c.get('alias', '?') for c in capes) or 'none'})",
    ])
    for skin in skins:
        if skin.get("state") == "ACTIVE":
            lines.append(
                f"  Active skin:  {skin.get('variant', 'CLASSIC').upper()} "
                f"({skin.get('id', '?')[:16]}...)"
            )

    nc = result["name_change"]
    if nc:
        changeable = nc.get("nameChangeAllowed", nc.get("changeable"))
        if changeable is not None:
            lines.append(f"  Name change:  {'YES' if changeable else 'NO (cooldown)'}")
        changed_at = nc.get("changedAt") or nc.get("lastChangedAt")
        if changed_at:
            lines.append(f"  Last changed: {fmt_iso(changed_at)}")
        created_at = nc.get("createdAt")
        if created_at:
            lines.append(f"  Account age:  {fmt_iso(created_at)}")

    history = result["name_history"]
    if history:
        lines.append(f"  Name history: {len(history)} name(s)")
        for entry in history:
            changed = entry.get("changedToAt")
            lines.append(
                f"    * {entry.get('name', '?')} "
                f"({'since ' + fmt_iso(changed) if changed else 'original'})"
            )
    elif history is not None:
        lines.append("  Name history: 1 name (no past changes)")
    else:
        lines.append("  Name history: unavailable")
    return lines


# --- Main ---

async def prepare_proxies(args, cwd: str, proxies: list[str]) -> list[str]:
    """Return the proxies to use.

    By default the proxy list is used exactly as given - no probing. Only
    `--check-proxies` opts into testing them first.
    """
    if not proxies:
        print("[*] No proxy.txt found or no usable proxies; using direct connections.\n")
        return []

    if not args.check_proxies:
        print(f"[*] Using {len(proxies)} proxy/proxies as given (no proxy check).\n")
        return proxies

    print(
        f"[*] Probing {len(proxies)} proxy/proxies "
        f"({args.proxy_timeout:.0f}s each, {PROXY_CHECK_CONCURRENCY} at a time)..."
    )

    def progress(done: int, total: int, working: int) -> None:
        print(f"    {done}/{total} probed, {working} working", flush=True)

    alive, dead = await filter_working_proxies(
        proxies,
        timeout=args.proxy_timeout,
        concurrency=PROXY_CHECK_CONCURRENCY,
        on_progress=progress,
    )
    alive_path = Path(cwd) / ALIVE_PROXY_FILE
    write_proxy_list(alive_path, alive, "proxies that answered during the last check")
    write_proxy_list(Path(cwd) / DEAD_PROXY_FILE, dead, "proxies that failed the last check")
    print(f"[*] {len(alive)}/{len(proxies)} proxy/proxies working -> {ALIVE_PROXY_FILE}")
    if not alive:
        print("[!] No working proxy found; running with the full list instead.")
        return proxies
    print()
    return alive


def resolve_proxies(args, cwd: str) -> list[str]:
    """Proxy list for this run, without ever prompting when flags are given."""
    if args.no_proxies:
        print("[*] --no-proxies: using direct connections.\n")
        return []
    if args.proxy_file:
        path = Path(args.proxy_file)
        if not path.is_absolute():
            path = Path(cwd) / path
        proxies = read_proxy_file(path)
        print(f"[*] --proxies: {len(proxies)} proxy/proxies from {path.name}")
        return proxies
    return choose_proxies(cwd)


async def main():
    started = time.monotonic()
    # The report draws box characters, so make sure stdio can carry them even
    # when the output is piped or redirected (Windows defaults to cp1252 there).
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

    args = parse_args()
    cwd = os.path.abspath(args.directory or os.getcwd())
    print(f"Working dir: {cwd}\n")

    proxies = await prepare_proxies(args, cwd, resolve_proxies(args, cwd))
    # Quarantine endpoints that fail so a dying proxy cannot keep poisoning the
    # rest of the run.
    rotator = ProxyRotator(proxies, quarantine_after=2)

    # Concurrency is network bound; scale with the working proxies but keep a
    # sane cap so a huge list cannot open thousands of sockets at once.
    if args.concurrency > 0:
        concurrency = args.concurrency
    elif proxies:
        concurrency = min(DEFAULT_CONCURRENCY, max(4, len(proxies) * 2))
    else:
        concurrency = DEFAULT_CONCURRENCY
    concurrency = max(1, concurrency)
    # One guard for the whole run: if the network collapses, pause instead of
    # racing to the end of the list marking everything as a network error.
    guard = FailureGuard(window=max(10, concurrency), pause=15.0)
    print(f"[*] {concurrency} account(s) at a time, {args.timeout:.0f}s per account\n")

    # ====================================================================
    #  token.txt - Minecraft access tokens
    # ====================================================================
    source_name = args.only_tokens or "token.txt"
    token_path = os.path.join(cwd, source_name)
    if not os.path.isfile(token_path):
        print(f"[!] {source_name} was not found.")
    mc_tokens = read_lines(token_path)
    print(f"{'='*64}")
    print(f"  {source_name}  -  {len(mc_tokens)} Minecraft access token(s)")
    print(f"{'='*64}")

    run_stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    verbose_output = os.path.join(cwd, f"verbose_{run_stamp}.txt")
    verbose_file = open(verbose_output, "w", encoding="utf-8")

    if not mc_tokens:
        print("  (no tokens found)\n")
    else:
        if args.limit > 0:
            print(f"[*] --limit: checking only the first {args.limit} token(s)")
            mc_tokens = mc_tokens[: args.limit]
        refresh_lines = read_lines(os.path.join(cwd, "refresh.txt"))
        fallback_refresh = parse_refresh_entry(refresh_lines[0])[1] if refresh_lines else None
        token_concurrency = concurrency
        token_semaphore = asyncio.Semaphore(token_concurrency)

        async def limited_mc(index, token, proxy):
            async with token_semaphore:
                try:
                    return await asyncio.wait_for(
                        validate_mc_entry(
                            index, token, fallback_refresh, proxy, args.details
                        ),
                        timeout=args.timeout,
                    )
                except asyncio.TimeoutError:
                    timeout_note = f"no response within {args.timeout:.0f}s"
                    return {
                        "index": index,
                        "token": token,
                        "proxy": proxy,
                        "payload": decode_jwt(token),
                        "profile": None,
                        "probe_token": token,
                        "token_status": "TIMEOUT",
                        "profile_status": 0,
                        "name_confirmed": None,
                        "confirmed_name": "",
                        "refresh_attempted": False,
                        "refresh_mismatch": False,
                        "network_error": True,
                        "name_change": None,
                        "name_history": None,
                        "profile_error": timeout_note,
                        "error": timeout_note,
                    }

        async def mc_with_failover(index, token):
            """Retry an access-token check on another proxy after a transport failure."""
            last_result = None
            for attempt in range(PROXY_FAILURE_RETRIES):
                proxy = rotator.next()
                result = await limited_mc(index, token, proxy)
                result["proxy_attempts"] = attempt + 1
                if result["token_status"] not in {STATUS_ERROR, STATUS_TIMEOUT}:
                    rotator.mark_ok(proxy)
                    return result
                rotator.mark_failed(proxy)
                last_result = result
            await guard.note(True)
            return last_result

        token_tasks = [
            asyncio.create_task(mc_with_failover(i, token))
            for i, token in enumerate(mc_tokens, 1)
        ]
        print(f"[*] Starting {len(token_tasks)} access-token checks with {token_concurrency} concurrent worker(s)...")
        mc_results = []
        completed = 0
        for task in asyncio.as_completed(token_tasks):
            result = await task
            completed += 1
            mc_results.append(result)
            detail = format_mc_result(result)
            # The full report always goes to the log; the console gets one line
            # per account so thousands of tokens cannot flood the terminal.
            for line in detail:
                verbose_file.write(line + "\n")
            verbose_file.flush()
            if args.verbose:
                for line in detail:
                    print(line)
            else:
                print(format_mc_summary(result, completed, len(token_tasks)), flush=True)
        print(f"[*] Completed {len(token_tasks)} access-token checks")

        mc_valid = [r for r in mc_results if r["token_status"] in VALID_STATUSES]
        # A network error is not a verdict on the token, so those accounts are
        # kept separate from the ones that were genuinely judged invalid.
        mc_errors = [
            r for r in mc_results
            if r["token_status"] not in VALID_STATUSES and r.get("network_error")
        ]
        mc_rejected = [
            r for r in mc_results
            if r["token_status"] not in VALID_STATUSES and not r.get("network_error")
        ]
        print(
            f"[*] {len(mc_valid)}/{len(mc_results)} access token(s) resolved to a "
            f"Minecraft username; the rest are not counted as valid."
        )
        if mc_errors:
            print(
                f"[!] {len(mc_errors)} account(s) could not be checked because of "
                f"network/proxy errors - these are NOT a verdict on the token."
            )

        # Network-failed accounts are listed as raw tokens so the run can be
        # repeated on just them with --only-tokens.
        if mc_errors:
            errors_output = os.path.join(cwd, f"errors_tokens_{run_stamp}.txt")
            with open(errors_output, "w", encoding="utf-8") as errors_file:
                for result in sorted(mc_errors, key=lambda r: r["index"]):
                    errors_file.write(result["token"] + "\n")
            print(
                f"[OK] {len(mc_errors)} uncheckable token(s) -> {os.path.basename(errors_output)}"
            )
            print(
                f"     retry them with: --only-tokens {os.path.basename(errors_output)}"
            )

        # Only the tokens that produced a username are written out, using the
        # working token (the refreshed one when the input token was stale).
        tokens_output = os.path.join(cwd, f"validated_tokens_{run_stamp}.txt")
        with open(tokens_output, "w", encoding="utf-8") as tokens_file:
            tokens_file.write(
                "# Minecraft access tokens that resolved to a username, as username:token\n"
                "# the token written is the working one (refreshed when the input was stale)\n"
            )
            for result in sorted(mc_valid, key=lambda r: r["index"]):
                tokens_file.write(
                    f"{profile_username(result['profile'])}:{result['probe_token']}\n"
                )
        print(f"[OK] {len(mc_valid)} valid access token(s) -> {os.path.basename(tokens_output)}")

        if mc_rejected:
            reason_counts: dict[str, int] = {}
            for result in mc_rejected:
                reason_counts[result["token_status"]] = reason_counts.get(result["token_status"], 0) + 1
            breakdown = " | ".join(
                f"{status}: {count}" for status, count in sorted(reason_counts.items())
            )
            print(f"[*] Not valid: {breakdown}")
            for result in mc_rejected:
                print(
                    f"      - token {result['index']}: {result['token_status']} "
                    f"({status_reason(result)})"
                )

            rejected_tokens_output = os.path.join(cwd, f"rejected_tokens_{run_stamp}.txt")
            with open(rejected_tokens_output, "w", encoding="utf-8") as rejected_tokens_file:
                rejected_tokens_file.write(
                    "# access tokens that did NOT resolve to a Minecraft username\n"
                    "# status<TAB>label<TAB>reason<TAB>token prefix\n"
                )
                for result in sorted(mc_rejected, key=lambda r: r["index"]):
                    label = profile_username(result["profile"]) or f"token {result['index']}"
                    rejected_tokens_file.write(
                        f"{result['token_status']}\t{label}\t{status_reason(result)}\t"
                        f"{result['token'][:30]}...\n"
                    )
            print(
                f"[OK] {len(mc_rejected)} token(s) without a username -> "
                f"{os.path.basename(rejected_tokens_output)}"
            )

    # ====================================================================
    #  refresh.txt - MSA refresh tokens
    # ====================================================================
    refresh_entries = [parse_refresh_entry(line) for line in read_lines(os.path.join(cwd, "refresh.txt"))]
    print(f"\n{'='*64}")
    print(f"  refresh.txt  -  {len(refresh_entries)} MSA refresh token(s)")
    print(f"{'='*64}")

    validation_output = os.path.join(cwd, f"validated_refresh_{run_stamp}.txt")
    validation_file = open(validation_output, "w", encoding="utf-8")
    rejected_output = os.path.join(cwd, f"rejected_refresh_{run_stamp}.txt")

    if not refresh_entries:
        print("  (no refresh tokens found)\n")
    else:
        if args.limit > 0:
            print(f"[*] --limit: checking only the first {args.limit} refresh token(s)")
            refresh_entries = refresh_entries[: args.limit]
        refresh_concurrency = concurrency
        semaphore = asyncio.Semaphore(refresh_concurrency)

        async def limited_validate(index, entry, proxy):
            async with semaphore:
                try:
                    result = await asyncio.wait_for(
                        validate_refresh_entry(entry[0], entry[1], proxy),
                        timeout=args.timeout,
                    )
                except asyncio.TimeoutError:
                    timeout_note = f"no response within {args.timeout:.0f}s"
                    result = {
                        "username_label": entry[0],
                        "refresh_token": entry[1],
                        "proxy": proxy,
                        "validated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "status": STATUS_TIMEOUT,
                        "profile_name": "",
                        "profile_uuid": "",
                        "profile_status": 0,
                        "name_confirmed": None,
                        "confirmed_name": "",
                        "new_refresh_entry": "",
                        "result": {"status": "timeout", "body": timeout_note},
                        "profile_error": timeout_note,
                        "error": timeout_note,
                        "network_error": True,
                    }
                result["index"] = index
                return result

        async def validate_with_failover(index, entry):
            last_result = None
            for attempt in range(PROXY_FAILURE_RETRIES):
                proxy = rotator.next()
                result = await limited_validate(index, entry, proxy)
                result["proxy_attempts"] = attempt + 1
                if result["status"] not in {STATUS_ERROR, STATUS_TIMEOUT}:
                    rotator.mark_ok(proxy)
                    return result
                rotator.mark_failed(proxy)
                last_result = result
            await guard.note(True)
            return last_result

        tasks = [
            asyncio.create_task(validate_with_failover(i, entry))
            for i, entry in enumerate(refresh_entries)
        ]
        results = [None] * len(tasks)
        completed = 0
        print(f"[*] Starting {len(tasks)} refresh checks with {refresh_concurrency} concurrent worker(s)...")
        for completed_task in asyncio.as_completed(tasks):
            result = await completed_task
            results[result["index"]] = result
            completed += 1
            account_label = (
                result["profile_name"]
                or result["username_label"]
                or f"line {result['index'] + 1}"
            )
            print(f"[*] Progress: {completed}/{len(tasks)} completed ({account_label}: {status_note(result)})")
            if result["status"] == STATUS_VALID:
                output_entry = output_refresh_entry(result)
                validation_file.write(output_entry + "\n")
                validation_file.flush()
                print(
                    f"[*] Saved validated token for {account_label} "
                    f"(Minecraft username: {result['profile_name']})"
                )
        print(f"[*] Completed {len(results)} refresh checks")

        timed_out = [result for result in results if result["status"] == STATUS_TIMEOUT]
        if timed_out:
            print(f"[*] Retrying {len(timed_out)} timed-out account(s)...")
            retry_tasks = [
                asyncio.create_task(
                    validate_with_failover(
                        result["index"],
                        refresh_entries[result["index"]],
                    )
                )
                for result in timed_out
            ]
            retry_completed = 0
            for retry_task in asyncio.as_completed(retry_tasks):
                result = await retry_task
                results[result["index"]] = result
                retry_completed += 1
                account_label = (
                    result["profile_name"]
                    or result["username_label"]
                    or f"line {result['index'] + 1}"
                )
                print(f"[*] Retry progress: {retry_completed}/{len(retry_tasks)} ({account_label}: {status_note(result)})")
                if result["status"] == STATUS_VALID:
                    output_entry = output_refresh_entry(result)
                    validation_file.write(output_entry + "\n")
                    validation_file.flush()
                    print(
                        f"[*] Saved validated token for {account_label} "
                        f"(Minecraft username: {result['profile_name']})"
                    )

        for i, result in enumerate(results, 1):
            username_label = result["username_label"]
            rt = result["refresh_token"]
            validation = result["result"] or {}
            print(f"\n{'-'*64}")
            print(f"  [{i}] Refresh token ({len(rt)} chars)")
            if username_label:
                print(f"      Username label: {username_label}")
            if result["proxy"]:
                print(f"      Proxy: {proxy_label(result['proxy'])}")
            if result.get("proxy_attempts", 1) > 1:
                print(f"      Proxy attempts: {result['proxy_attempts']}")
            print(f"      Prefix: {rt[:50]}...")

            if rt.startswith("eyJ"):
                payload = decode_jwt(rt)
                if payload:
                    print(f"      JWT claims:")
                    print(jwt_expiry(payload))
            else:
                if validation.get("valid"):
                    print("      MSA refresh: OK")
                    if validation.get("expires_in"):
                        print(f"      MSA token TTL: {validation['expires_in']}s ({int(validation['expires_in'])/3600:.1f}h)")
                    if validation.get("user_id"):
                        print(f"      MSA user_id:   {validation['user_id']}")
                    if validation.get("new_refresh"):
                        print(f"      Rotated:       new refresh token issued ({len(validation['new_refresh'])} chars)")
                    if result["status"] == STATUS_VALID:
                        print(f"OK - Minecraft username: {result['profile_name']}")
                        print(f"      Minecraft UUID:  {result['profile_uuid']}")
                        print(f"      Username check:  {username_check_note(result)}")
                    else:
                        print(f"NOT VALID ({result['status']}): {status_reason(result)}")
                else:
                    status_code = validation.get("status", "?")
                    print(f"DEAD (HTTP {status_code})" if status_code != "?" else "ERROR")
                    body = validation.get("body", "")
                    if body:
                        print(f"      Response: {body[:200]}")

        verbose_file.write("\n" + "=" * 64 + "\nRefresh-token validation details\n" + "=" * 64 + "\n")
        for result in results:
            validation = result["result"] or {}
            verbose_file.write(
                f"[{result['index'] + 1}] "
                f"{result['profile_name'] or result['username_label'] or '(no username label)'}\n"
                f"Status: {result['status']} ({'VALID - Minecraft username resolved' if result['status'] == STATUS_VALID else 'NOT VALID'})\n"
                f"Reason: {status_reason(result)}\n"
                f"Input label: {result['username_label'] or '(none)'}\n"
                f"Token prefix: {result['refresh_token'][:50]}...\n"
                f"Proxy: {proxy_label(result['proxy']) if result['proxy'] else 'direct'}\n"
                f"Proxy attempts: {result.get('proxy_attempts', 1)}\n"
                f"Minecraft name: {result['profile_name'] or '(none - not valid)'}\n"
                f"Minecraft UUID: {result['profile_uuid'] or '(unknown)'}\n"
                f"Public lookup: {username_check_note(result)}\n"
                f"Profile HTTP: {result.get('profile_status') or '(none)'}\n"
                f"MSA user ID: {validation.get('user_id', '(unknown)')}\n"
                f"Expires in: {validation.get('expires_in', '(unknown)')}\n"
                f"HTTP status: {validation.get('status', '(none)')}\n"
                f"Response: {validation.get('body', '(none)')}\n"
                f"Error: {result.get('error') or result.get('profile_error') or '(none)'}\n"
                f"Saved refresh entry: {output_refresh_entry(result) if result['status'] == STATUS_VALID else '(none)'}\n\n"
            )
        verbose_file.flush()

        counts: dict[str, int] = {}
        for result in results:
            status = result["status"]
            counts[status] = counts.get(status, 0) + 1
        summary = " | ".join(
            f"{status}: {counts[status]}"
            for status in SUMMARY_ORDER
            if counts.get(status)
        )
        print(f"\nValidation summary: {summary or 'no refresh entries processed'}")

        valid_results = [r for r in results if r["status"] == STATUS_VALID]
        # Keep uncheckable accounts out of the "rejected" file: an ERROR is a
        # network failure, not a judgement about the token.
        error_results = [r for r in results if r["status"] != STATUS_VALID and r.get("network_error")]
        rejected_results = [
            r for r in results if r["status"] != STATUS_VALID and not r.get("network_error")
        ]
        print(
            f"  {len(valid_results)} of {len(results)} refresh token(s) produced a Minecraft "
            f"username and were saved to {os.path.basename(validation_output)}."
        )
        if error_results:
            errors_output = os.path.join(cwd, f"errors_refresh_{run_stamp}.txt")
            with open(errors_output, "w", encoding="utf-8") as errors_file:
                for result in error_results:
                    errors_file.write(result["refresh_token"] + "\n")
            print(
                f"  {len(error_results)} token(s) could not be checked (network/proxy) "
                f"-> {os.path.basename(errors_output)}"
            )
        if rejected_results:
            with open(rejected_output, "w", encoding="utf-8") as rejected_file:
                rejected_file.write(
                    "# refresh tokens that did NOT resolve to a Minecraft username "
                    "(not valid)\n"
                )
                rejected_file.write("# status<TAB>label<TAB>reason<TAB>token prefix\n")
                for result in rejected_results:
                    label = (
                        result["profile_name"]
                        or result["username_label"]
                        or "(no label)"
                    )
                    rejected_file.write(
                        f"{result['status']}\t{label}\t{status_reason(result)}\t"
                        f"{result['refresh_token'][:30]}...\n"
                    )
            print(
                f"  {len(rejected_results)} token(s) produced no Minecraft username "
                f"and were NOT saved -> {os.path.basename(rejected_output)}"
            )

    validation_file.close()
    verbose_file.close()
    await CLIENTS.aclose()
    elapsed = time.monotonic() - started
    print(f"\n[OK] Validation results -> {validation_output}")
    print(f"[OK] Detailed output -> {verbose_output}")
    print(f"[*] Took {elapsed:.0f}s with {rotator.describe()}")
    if guard.trips:
        print(
            f"[!] The run paused {guard.trips} time(s) because the network kept failing - "
            "your proxy list is the likely bottleneck."
        )

    print(f"\n{'='*64}")
    print("  Done.")
    print(f"{'='*64}")


if __name__ == "__main__":
    asyncio.run(main())
