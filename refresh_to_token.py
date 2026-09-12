"""
Refresh Token → Minecraft Access Token
Takes one or more Microsoft refresh tokens (one per line in a .txt file) and
runs each through the MSA refresh → XBL → XSTS → Minecraft chain. Successful
Minecraft JWTs are written one per line to token.txt.

Usage:
    python refresh_to_token.py                     # refresh.txt -> token.txt
    python refresh_to_token.py --limit 5           # convert the first 5 only
    python refresh_to_token.py --concurrency 8     # even gentler on the pool
    python refresh_to_token.py --refresh validated_refresh_2026-09-12_20-40-04.txt
"""

import argparse
import asyncio
import os
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from proxy_utils import (
    ProxyPool,
    choose_proxies,
    client_for,
    close_clients,
    http_timeout,
    read_proxy_file,
)

# --- Constants ---

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

# Concurrency. The chain makes four requests per token, so one worker per token
# floods the pool: with 255 tokens in refresh.txt this script used to start 255
# simultaneous chains, every proxy and every Microsoft endpoint slowed to ~45s
# instead of ~9s, the chain budget expired and the run reported "every proxy is
# dead" while the same proxies worked fine one request at a time.
DEFAULT_CONCURRENCY = 16
MAX_CONCURRENCY = 64

# Per-request read timeout for the chain steps, and the budget for the whole
# four-step chain before it is retried through another proxy.
CHAIN_STEP_TIMEOUT = 30.0
DEFAULT_CHAIN_TIMEOUT = 180.0

# These APIs answer 429/5xx long before the tokens are a problem. Retrying the
# same request briefly beats reporting a healthy account as failed.
TRANSIENT_STATUSES = {429, 500, 502, 503, 504}
TRANSIENT_ATTEMPTS = 3


# --- Helpers ---

def parse_refresh_entry(line: str) -> tuple[str, str]:
    """Return (optional username label, refresh token)."""
    if ":" in line:
        username, token = line.split(":", 1)
        if username.strip() and token.strip():
            return username.strip(), token.strip()
    return "", line.strip()


def format_refresh_entry(username: str, refresh_token: str) -> str:
    return f"{username}:{refresh_token}" if username else refresh_token


def read_refresh_tokens(filepath: str) -> list[tuple[str, str]]:
    """Read every non-empty line as (optional username, refresh token)."""
    with open(filepath, "r", encoding="utf-8") as f:
        return [parse_refresh_entry(line.strip()) for line in f if line.strip()]


def looks_like_netscape_cookie_file(lines: list[str]) -> bool:
    """Recognise a browser-exported Netscape cookie file before processing it.

    A cookie export contains tab-separated cookie columns. It is an input for
    cookie_to_token.py, not a list of MSA refresh tokens.
    """
    return any("\t" in token for _, token in lines)


# --- Request helper ---

async def post_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    data: dict | None = None,
    json: dict | None = None,
    headers: dict | None = None,
    timeout: httpx.Timeout | None = None,
) -> httpx.Response:
    """POST that backs off on the transient statuses these APIs return.

    A bulk run gets rate limited (429) long before any token is at fault, so a
    single attempt turns one rate limit into a lost account.
    """
    request_kwargs: dict = {}
    if timeout is not None:
        request_kwargs["timeout"] = timeout

    delay = 2.0
    response: httpx.Response | None = None
    for attempt in range(TRANSIENT_ATTEMPTS):
        response = await client.post(url, data=data, json=json, headers=headers, **request_kwargs)
        if response.status_code not in TRANSIENT_STATUSES:
            return response
        if attempt + 1 < TRANSIENT_ATTEMPTS:
            retry_after = response.headers.get("retry-after", "")
            try:
                wait = max(delay, float(retry_after))
            except ValueError:
                wait = delay
            print(
                f"[*] HTTP {response.status_code} from {urlsplit(url).netloc}; "
                f"waiting {wait:.0f}s before retrying...",
                flush=True,
            )
            await asyncio.sleep(wait)
            delay *= 2
    return response


# --- Step 1: Refresh MSA token ---

async def refresh_msa_token(
    refresh_token: str,
    proxy: str | None = None,
    timeout: httpx.Timeout | None = None,
) -> tuple[str, str] | None:
    """Exchange a refresh token for a fresh MSA access_token.
    Returns (access_token, new_refresh_token) or None."""
    print("[1/4] Refreshing MSA token...", flush=True)
    resp = await post_with_retry(
        client_for(proxy),
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
        timeout=timeout,
    )

    if resp.status_code != 200:
        print(f"[-] Refresh returned {resp.status_code}: {resp.text[:300]}", flush=True)
        return None

    data = resp.json()
    access_token = data.get("access_token")
    new_refresh = data.get("refresh_token")

    if access_token:
        print(f"[+] MSA access_token refreshed ({len(access_token)} chars)", flush=True)
        if new_refresh:
            print(f"[*] New refresh_token issued ({len(new_refresh)} chars)", flush=True)
        return access_token, new_refresh or refresh_token

    print(f"[-] No access_token in response. Keys: {list(data.keys())}", flush=True)
    return None


# --- Step 2: XBL authenticate ---

async def authenticate_xbl(
    msa_token: str,
    proxy: str | None = None,
    timeout: httpx.Timeout | None = None,
) -> tuple[str, str] | None:
    """Exchange MSA token for Xbox Live token. Returns (token, userhash)."""
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

    print("[2/4] Authenticating with XBL...", flush=True)
    resp = await post_with_retry(
        client_for(proxy),
        XBL_AUTH_URL,
        json=payload,
        headers={"Accept": "application/json", "x-xbl-contract-version": "1"},
        timeout=timeout,
    )

    if resp.status_code != 200:
        print(f"[-] XBL returned {resp.status_code}: {resp.text[:300]}", flush=True)
        return None

    data = resp.json()
    token = data.get("Token")
    userhash = data.get("DisplayClaims", {}).get("xui", [{}])[0].get("uhs", "")

    if token and userhash:
        print(f"[+] XBL token obtained ({len(token)} chars), userhash={userhash}", flush=True)
        return token, userhash

    print("[-] XBL response missing Token/uhs", flush=True)
    return None


# --- Step 3: XSTS authorize ---

async def authenticate_xsts(
    xbl_token: str,
    proxy: str | None = None,
    timeout: httpx.Timeout | None = None,
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

    print("[3/4] Authenticating with XSTS...", flush=True)
    resp = await post_with_retry(
        client_for(proxy),
        XSTS_AUTH_URL,
        json=payload,
        headers={"Accept": "application/json", "x-xbl-contract-version": "1"},
        timeout=timeout,
    )

    if resp.status_code != 200:
        print(f"[-] XSTS returned {resp.status_code}: {resp.text[:500]}", flush=True)
        try:
            err = resp.json()
            print(f"    XErr={err.get('XErr', '?')} {err.get('Message', '')}", flush=True)
        except Exception:
            pass
        return None

    data = resp.json()
    token = data.get("Token")
    userhash = data.get("DisplayClaims", {}).get("xui", [{}])[0].get("uhs", "")

    if token and userhash:
        print(f"[+] XSTS token obtained ({len(token)} chars)", flush=True)
        return token, userhash

    print("[-] XSTS response missing Token/uhs", flush=True)
    return None


# --- Step 4: Minecraft login ---

async def minecraft_login(
    userhash: str,
    xsts_token: str,
    proxy: str | None = None,
    timeout: httpx.Timeout | None = None,
) -> str | None:
    """Exchange XSTS for Minecraft access token (JWT, eyJra...)."""
    identity_token = f"XBL3.0 x={userhash};{xsts_token}"

    print("[4/4] Logging into Minecraft...", flush=True)
    resp = await post_with_retry(
        client_for(proxy),
        MC_LOGIN_WITH_XBOX_URL,
        json={"identityToken": identity_token},
        headers={"Accept": "application/json"},
        timeout=timeout,
    )

    if resp.status_code != 200:
        print(f"[-] Minecraft login returned {resp.status_code}: {resp.text[:300]}", flush=True)
        return None

    data = resp.json()
    access_token = data.get("access_token")
    if access_token and access_token.startswith("eyJ"):
        print(f"[+] Minecraft access_token obtained! eyJra... ({len(access_token)} chars)", flush=True)
        return access_token

    print(f"[-] No valid Minecraft token. Keys: {list(data.keys())}", flush=True)
    return None


# --- Full chain ---

async def refresh_chain(
    refresh_token: str,
    proxy: str | None = None,
    step_timeout: httpx.Timeout | None = None,
) -> tuple[str | None, str]:
    """Return (Minecraft access token or None, the refresh token to keep).

    The refresh token is returned even when a later step fails: Microsoft
    rotates it during step 1, so discarding the replacement would leave the
    account holding a token that is on its way out.
    """
    print(f"[*] Refresh token: {refresh_token[:40]}... ({len(refresh_token)} chars)", flush=True)

    result = await refresh_msa_token(refresh_token, proxy, step_timeout)
    if not result:
        return None, refresh_token
    msa, current_refresh = result

    xbl = await authenticate_xbl(msa, proxy, step_timeout)
    if not xbl:
        return None, current_refresh
    xbl_token, _xbl_uhs = xbl

    xsts = await authenticate_xsts(xbl_token, proxy, step_timeout)
    if not xsts:
        return None, current_refresh
    xsts_token, xsts_uhs = xsts

    mc_token = await minecraft_login(xsts_uhs, xsts_token, proxy, step_timeout)
    return mc_token, current_refresh


def default_concurrency(entry_count: int, proxy_count: int) -> int:
    """Workers to use when the caller does not pick a number.

    One worker per token was the old behaviour: 255 tokens in refresh.txt meant
    255 simultaneous chains, so every proxy and every Microsoft endpoint slowed
    from ~9s to ~45s per token, the chain budget expired and the run reported a
    dead proxy list while the same proxies worked one request at a time.
    """
    if proxy_count:
        return max(1, min(DEFAULT_CONCURRENCY, MAX_CONCURRENCY, entry_count, proxy_count))
    return max(1, min(DEFAULT_CONCURRENCY, entry_count))


async def process_refresh_entries(
    refresh_entries: list[tuple[str, str]],
    proxy_pool: ProxyPool,
    token_output,
    output_path: str,
    concurrency: int = DEFAULT_CONCURRENCY,
    chain_timeout: float = DEFAULT_CHAIN_TIMEOUT,
    step_timeout: httpx.Timeout | None = None,
    source_name: str = "refresh.txt",
    rotated_output=None,
) -> tuple[list[str], list[str], int, dict[str, int]]:
    """Process bulk refresh entries concurrently and stream successful tokens."""
    semaphore = asyncio.Semaphore(max(1, concurrency))
    outcomes = {"converted": 0, "not_converted": 0, "network": 0, "timeout": 0}

    async def worker(index: int, username: str, refresh_token: str) -> dict:
        async with semaphore:
            print(f"\n{'='*60}", flush=True)
            print(f"[*] Processing: line {index + 1}/{len(refresh_entries)}", flush=True)
            if username:
                print(f"[*] Username label: {username}", flush=True)
            print(f"[*] Refresh token detected ({len(refresh_token)} chars)", flush=True)
            result = None
            mc_token = None
            current_refresh = refresh_token
            outcome = "not_converted"
            try:
                result = await proxy_pool.run(
                    index,
                    lambda proxy: asyncio.wait_for(
                        refresh_chain(refresh_token, proxy, step_timeout),
                        timeout=chain_timeout,
                    ),
                )
                if result:
                    mc_token, current_refresh = result
                    if mc_token:
                        outcome = "converted"
            except asyncio.TimeoutError:
                outcome = "timeout"
                print(f"[-] The chain exceeded {chain_timeout:.0f}s; skipped.", flush=True)
            except httpx.TransportError as exc:
                outcome = "network"
                print(f"[-] Every proxy attempt failed: {type(exc).__name__}: {exc}", flush=True)
            except Exception as exc:
                outcome = "network"
                print(f"[-] Error: {type(exc).__name__}: {exc}", flush=True)
            outcomes[outcome] += 1
            return {
                "index": index,
                "username": username,
                "refresh_token": refresh_token,
                "token": mc_token,
                "rotated": current_refresh,
                "outcome": outcome,
            }

    tasks = [
        asyncio.create_task(worker(i, username, token))
        for i, (username, token) in enumerate(refresh_entries)
    ]
    all_tokens = []
    all_refresh = []
    completed = 0
    print(
        f"[*] Starting {len(tasks)} refresh conversion(s) with {concurrency} concurrent worker(s)...",
        flush=True,
    )
    for task in asyncio.as_completed(tasks):
        item = await task
        completed += 1
        token = item["token"]
        label = item["username"] or f"line {item['index'] + 1}"
        rotated = item["rotated"] != item["refresh_token"]
        if token:
            print(f"\n[+] SUCCESS for {label}! Minecraft access_token (eyJra...):")
            print(f"    {token[:80]}...{token[-30:]}")
            all_tokens.append(token)
            token_output.write(token + "\n")
            token_output.flush()
            print(f"[OK] Access token staged for -> {output_path}")
        elif rotated:
            print(f"[-] Failed for {label} ({item['outcome']}).")
            print("[i] Microsoft had already rotated this refresh token; the replacement is kept in the rotated file.")
        else:
            print(f"[-] Failed for {label} ({item['outcome']}); the {source_name} line is unchanged.")
        # Microsoft rotates the refresh token during step 1 even when a later
        # step fails, so the replacement is always kept - and written out
        # immediately, because a run that dies later would otherwise lose it
        # while the input file still holds the old value.
        if rotated:
            rotated_entry = format_refresh_entry(item["username"], item["rotated"])
            all_refresh.append(rotated_entry)
            if rotated_output is not None:
                rotated_output.write(rotated_entry + "\n")
                rotated_output.flush()
        print(f"[*] Progress: {completed}/{len(tasks)} completed", flush=True)
    return all_tokens, all_refresh, len(tasks), outcomes


# --- CLI ---

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Convert Microsoft refresh tokens into Minecraft access tokens "
            "(MSA refresh -> XBL -> XSTS -> Minecraft login)."
        )
    )
    parser.add_argument(
        "--dir", dest="directory", default=None,
        help="Folder holding refresh.txt / token.txt (default: current directory).",
    )
    parser.add_argument(
        "--refresh", dest="refresh_file", default="refresh.txt", metavar="FILE",
        help="Input list of refresh tokens (default: refresh.txt).",
    )
    parser.add_argument(
        "--concurrency", type=int, default=0,
        help=(
            f"Tokens converted at the same time (default: {DEFAULT_CONCURRENCY}, "
            "also capped by the number of proxies)."
        ),
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_CHAIN_TIMEOUT,
        help=f"Seconds allowed for one token's whole chain (default: {DEFAULT_CHAIN_TIMEOUT:.0f}).",
    )
    parser.add_argument(
        "--limit", type=int, default=0,
        help="Only convert the first N tokens; 0 converts all of them.",
    )
    parser.add_argument(
        "--proxies", dest="proxy_file", default=None, metavar="FILE",
        help="Use this proxy list file and skip the interactive prompt.",
    )
    parser.add_argument(
        "--no-proxies", dest="no_proxies", action="store_true",
        help="Ignore proxy.txt and connect directly.",
    )
    return parser.parse_args(argv)


def resolve_proxies(args: argparse.Namespace, cwd: str) -> list[str]:
    if args.no_proxies:
        print("[*] --no-proxies: connecting directly.")
        return []
    if args.proxy_file:
        path = Path(args.proxy_file)
        if not path.is_absolute():
            path = Path(cwd) / path
        proxies = read_proxy_file(path)
        print(f"[*] --proxies: {len(proxies)} proxy/proxies from {path.name}")
        return proxies
    return choose_proxies(cwd)


# --- Main ---

async def run(args: argparse.Namespace, cwd: str) -> int:
    proxy_pool = ProxyPool(resolve_proxies(args, cwd))

    # Only the refresh list is treated as input. This avoids accidentally
    # reading browser-cookie exports or unrelated .txt files in the folder.
    refresh_path = args.refresh_file
    if not os.path.isabs(refresh_path):
        refresh_path = os.path.join(cwd, refresh_path)
    if not os.path.isfile(refresh_path):
        print(f"[!] {os.path.basename(refresh_path)} was not found.")
        print("    Put one MSA refresh token per line in it, or point --refresh at another file.")
        return 1

    source_name = os.path.basename(refresh_path)
    print(f"[*] Input file: {source_name}")

    refresh_tokens = read_refresh_tokens(refresh_path)
    if not refresh_tokens:
        print(f"[!] {source_name} is empty.")
        return 1

    if looks_like_netscape_cookie_file(refresh_tokens):
        print(f"[!] {source_name} is a Netscape cookie file, not a refresh-token list.")
        print("    Run cookie_to_token.py with it first, then put the resulting refresh token(s) here.")
        return 1

    print(f"\n[*] {source_name}: {len(refresh_tokens)} refresh token(s) found")
    processable_entries = []
    for token_index, (username, refresh_token) in enumerate(refresh_tokens, start=1):
        if refresh_token.startswith("eyJra"):
            print(f"\n[!] {source_name} line {token_index} is already a Minecraft JWT, skipping.")
            continue
        processable_entries.append((username, refresh_token))

    if args.limit > 0 and len(processable_entries) > args.limit:
        skipped = len(processable_entries) - args.limit
        processable_entries = processable_entries[:args.limit]
        print(f"[*] --limit {args.limit}: skipping the remaining {skipped} refresh token(s).")

    if not processable_entries:
        print("[!] Nothing to convert.")
        return 1

    if proxy_pool.proxies:
        print(f"[*] {len(proxy_pool.proxies)} proxy/proxies available")
    else:
        print("[*] No proxies configured; connecting directly")

    concurrency = args.concurrency if args.concurrency > 0 else default_concurrency(
        len(processable_entries), len(proxy_pool.proxies)
    )

    output_path = os.path.join(cwd, "token.txt")
    # Stream into a .part file. The old version opened token.txt with "w" before
    # it knew whether anything would succeed, so a run where every token failed
    # left an empty token.txt behind and destroyed the previous batch.
    part_path = output_path + ".part"
    run_stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    rotated_path = os.path.join(cwd, f"rotated_refresh_{run_stamp}.txt")

    with open(part_path, "w", encoding="utf-8") as token_output, open(
        rotated_path, "w", encoding="utf-8"
    ) as rotated_output:
        try:
            processed_tokens, rotated_tokens, processed, outcomes = await process_refresh_entries(
                processable_entries,
                proxy_pool,
                token_output,
                output_path,
                concurrency=concurrency,
                chain_timeout=args.timeout,
                step_timeout=http_timeout(CHAIN_STEP_TIMEOUT),
                source_name=source_name,
                rotated_output=rotated_output,
            )
        finally:
            await close_clients()

    if processed_tokens:
        os.replace(part_path, output_path)
        print(f"\n[OK] {len(processed_tokens)} MC token(s), one per line -> {output_path}")
    else:
        try:
            os.remove(part_path)
        except OSError:
            pass
        print(f"\n[XX] No tokens extracted; the existing {os.path.basename(output_path)} was left untouched.")

    # The rotated refresh tokens are already on disk; keep the file only when it
    # has content. The input file stays unchanged as the source, so failed
    # entries can be retried later.
    if rotated_tokens:
        print(f"[OK] {len(rotated_tokens)} rotated refresh token(s) -> {rotated_path}")
    else:
        try:
            os.remove(rotated_path)
        except OSError:
            pass

    print(
        f"\nSummary: {outcomes['converted']} converted, "
        f"{outcomes['not_converted']} rejected/not convertible, "
        f"{outcomes['network']} network error(s), {outcomes['timeout']} timeout(s)."
    )
    if outcomes["not_converted"]:
        print("Rejected entries were answered by Microsoft/Xbox, so they are not a proxy problem.")
    if outcomes["network"] or outcomes["timeout"]:
        print("Retry those with a lower --concurrency (the proxies are being oversubscribed).")
    print(f"Done. Processed {processed} refresh token(s).")
    return 0


def main() -> None:
    args = parse_args()
    cwd = os.path.abspath(args.directory or os.getcwd())
    print(f"[*] Working directory: {cwd}")
    try:
        code = asyncio.run(run(args, cwd))
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        code = 130
    sys.exit(code)


if __name__ == "__main__":
    main()

