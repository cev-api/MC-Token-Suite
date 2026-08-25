"""
Token Validator (detailed)
Reads token.txt (Minecraft JWTs) and refresh.txt (MSA refresh tokens),
validates them, shows username/UUID, account details, and best-effort expiry.
"""

import os
import sys
import asyncio
import base64
import json
import re
from datetime import datetime, timezone

import httpx
from proxy_utils import PROXY_FAILURE_RETRIES, ProxyPool, choose_proxies, proxy_label as shared_proxy_label

# --- Constants ---

MC_PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile"
MC_NAME_CHANGE_URL = "https://api.minecraftservices.com/minecraft/profile/namechange"
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
    async with httpx.AsyncClient(timeout=15, proxy=proxy) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
        if resp.status_code == 200:
            return resp.json()
        return None


async def get_profile(token: str, proxy: str | None = None) -> dict | None:
    """Minecraft profile (username, UUID, skins, capes)."""
    return await query_mc_api(token, MC_PROFILE_URL, proxy)


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
    async with httpx.AsyncClient(timeout=15, proxy=proxy) as client:
        for url in urls:
            try:
                resp = await client.get(url)
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


# --- Quick refresh to get a valid MC token for profile queries ---

async def refresh_mc_token(refresh_token: str, proxy: str | None = None) -> str | None:
    """Refresh MSA -> XBL -> XSTS -> MC, return fresh MC token or None."""
    try:
        async with httpx.AsyncClient(timeout=30, proxy=proxy) as client:
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
            )
            if resp.status_code != 200:
                return None
            msa = resp.json()["access_token"]

            # 2. XBL
            if not msa.startswith("t=") and not msa.startswith("d=") and not msa.startswith("eyJ"):
                msa = f"t={msa}"
            resp = await client.post(
                "https://user.auth.xboxlive.com/user/authenticate",
                json={
                    "Properties": {"AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com", "RpsTicket": msa},
                    "RelyingParty": "http://auth.xboxlive.com",
                    "TokenType": "JWT",
                },
                headers={"Accept": "application/json", "x-xbl-contract-version": "1"},
            )
            if resp.status_code != 200:
                return None
            xbl_token = resp.json()["Token"]

            # 3. XSTS
            resp = await client.post(
                "https://xsts.auth.xboxlive.com/xsts/authorize",
                json={
                    "Properties": {"SandboxId": "RETAIL", "UserTokens": [xbl_token]},
                    "RelyingParty": "rp://api.minecraftservices.com/",
                    "TokenType": "JWT",
                },
                headers={"Accept": "application/json", "x-xbl-contract-version": "1"},
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            xsts_token = data["Token"]
            uhs = data["DisplayClaims"]["xui"][0]["uhs"]

            # 4. Minecraft
            resp = await client.post(
                "https://api.minecraftservices.com/authentication/login_with_xbox",
                json={"identityToken": f"XBL3.0 x={uhs};{xsts_token}"},
                headers={"Accept": "application/json"},
            )
            if resp.status_code != 200:
                return None
            return resp.json()["access_token"]
    except Exception:
        return None


# --- Refresh token validation ---

async def validate_refresh_token(refresh_token: str, proxy: str | None = None) -> dict | None:
    async with httpx.AsyncClient(timeout=15, proxy=proxy) as client:
        resp = await client.post(
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
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "valid": True,
                "new_refresh": data.get("refresh_token"),
                "expires_in": data.get("expires_in"),
                "user_id": data.get("user_id"),
            }
        return {"valid": False, "status": resp.status_code, "body": resp.text[:200]}


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


async def validate_refresh_entry(
    username_label: str,
    refresh_token: str,
    proxy: str | None,
) -> dict:
    """Validate one refresh entry and resolve its Minecraft profile."""
    validated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    result = {
        "username_label": username_label,
        "refresh_token": refresh_token,
        "proxy": proxy,
        "validated_at": validated_at,
        "status": "UNKNOWN",
        "profile_name": "",
        "profile_uuid": "",
        "new_refresh_entry": "",
        "result": None,
        "profile_error": "",
        "error": "",
    }

    if refresh_token.startswith("eyJ"):
        result["status"] = "JWT_NOT_TESTED"
        return result

    try:
        validation = await validate_refresh_token(refresh_token, proxy)
        result["result"] = validation
        if not validation or not validation.get("valid"):
            result["status"] = "DEAD"
            return result

        result["status"] = "VALID"
        new_refresh = validation.get("new_refresh")
        if new_refresh:
            result["new_refresh_entry"] = format_refresh_entry(username_label, new_refresh)

        profile_token = await refresh_mc_token(new_refresh or refresh_token, proxy)
        if not profile_token:
            result["profile_error"] = "Minecraft exchange failed"
            return result

        profile = await get_profile(profile_token, proxy)
        if profile:
            result["profile_name"] = profile.get("name", "")
            result["profile_uuid"] = profile.get("id", "")
        else:
            result["profile_error"] = "profile lookup failed"
    except Exception as exc:
        result["status"] = "ERROR"
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["profile_error"] = result["error"]
    return result


async def validate_mc_entry(
    index: int,
    token: str,
    fallback_refresh_token: str | None,
    proxy: str | None,
) -> dict:
    """Validate one Minecraft access token and collect detailed account data."""
    result = {
        "index": index,
        "token": token,
        "proxy": proxy,
        "payload": decode_jwt(token),
        "profile": None,
        "probe_token": token,
        "token_status": "VALID",
        "refresh_attempted": False,
        "name_change": None,
        "name_history": None,
        "error": "",
    }
    try:
        profile = await get_profile(token, proxy)
        if not profile and fallback_refresh_token:
            result["refresh_attempted"] = True
            probe_token = await refresh_mc_token(fallback_refresh_token, proxy)
            if probe_token:
                result["probe_token"] = probe_token
                profile = await get_profile(probe_token, proxy)
                result["token_status"] = "REFRESHED" if profile else "INVALID"
            else:
                result["token_status"] = "INVALID"
        elif not profile:
            result["token_status"] = "INVALID"

        result["profile"] = profile
        if profile:
            probe_token = result["probe_token"]
            result["name_change"] = await get_name_change_info(probe_token, proxy)
            uuid_ = profile.get("id", "")
            name_history = (
                result["name_change"].get("history")
                or result["name_change"].get("nameChanges")
                if result["name_change"]
                else None
            )
            if not name_history and uuid_:
                name_history = await get_name_history(uuid_, proxy)
            result["name_history"] = name_history
    except Exception as exc:
        result["token_status"] = "ERROR"
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def format_mc_result(result: dict) -> list[str]:
    """Format detailed Minecraft-token output for screen and verbose log."""
    token = result["token"]
    lines = [
        "\n" + "─" * 64,
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
        lines.append("  >>> Could not fetch account info (token dead or refresh failed)")
        if result["error"]:
            lines.append(f"      Error: {result['error']}")
        return lines

    name = profile.get("name", "?")
    uuid_ = profile.get("id", "?")
    skins = profile.get("skins", [])
    capes = profile.get("capes", [])
    lines.extend([
        f"\n  ---- Account: {name} ----",
        f"  UUID:         {uuid_}",
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

async def main():
    cwd = os.getcwd()
    print(f"Working dir: {cwd}\n")
    proxies = choose_proxies(cwd)
    proxy_pool = ProxyPool(proxies)
    if proxies:
        print(f"[*] Loaded {len(proxies)} proxy/proxies from proxy.txt (round-robin)\n")
    else:
        print("[*] No proxy.txt found or no usable proxies; using direct connections.\n")

    # ====================================================================
    #  token.txt - Minecraft access tokens
    # ====================================================================
    mc_tokens = read_lines(os.path.join(cwd, "token.txt"))
    print(f"{'='*64}")
    print(f"  token.txt  -  {len(mc_tokens)} Minecraft access token(s)")
    print(f"{'='*64}")

    run_stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    verbose_output = os.path.join(cwd, f"verbose_{run_stamp}.txt")
    verbose_file = open(verbose_output, "w", encoding="utf-8")

    if not mc_tokens:
        print("  (no tokens found)\n")
    else:
        fallback_refresh = parse_refresh_entry(read_lines(os.path.join(cwd, "refresh.txt"))[0])[1] \
            if read_lines(os.path.join(cwd, "refresh.txt")) else None
        token_concurrency = max(1, min(len(mc_tokens), len(proxies) or 5))
        token_semaphore = asyncio.Semaphore(token_concurrency)

        async def limited_mc(index, token, proxy):
            async with token_semaphore:
                try:
                    return await asyncio.wait_for(
                        validate_mc_entry(index, token, fallback_refresh, proxy),
                        timeout=45,
                    )
                except asyncio.TimeoutError:
                    return {
                        "index": index,
                        "token": token,
                        "proxy": proxy,
                        "payload": decode_jwt(token),
                        "profile": None,
                        "probe_token": token,
                        "token_status": "TIMEOUT",
                        "refresh_attempted": False,
                        "name_change": None,
                        "name_history": None,
                        "error": "45-second account timeout",
                    }

        token_tasks = [
            asyncio.create_task(
                limited_mc(i, token, proxies[i % len(proxies)] if proxies else None)
            )
            for i, token in enumerate(mc_tokens, 1)
        ]
        print(f"[*] Starting {len(token_tasks)} access-token checks with {token_concurrency} concurrent worker(s)...")
        for task in asyncio.as_completed(token_tasks):
            result = await task
            lines = format_mc_result(result)
            for line in lines:
                print(line)
                verbose_file.write(line + "\n")
            verbose_file.flush()
        print(f"[*] Completed {len(token_tasks)} access-token checks")

    # ====================================================================
    #  refresh.txt - MSA refresh tokens
    # ====================================================================
    refresh_entries = [parse_refresh_entry(line) for line in read_lines(os.path.join(cwd, "refresh.txt"))]
    print(f"\n{'='*64}")
    print(f"  refresh.txt  -  {len(refresh_entries)} MSA refresh token(s)")
    print(f"{'='*64}")

    validation_output = os.path.join(cwd, f"validated_refresh_{run_stamp}.txt")
    validation_file = open(validation_output, "w", encoding="utf-8")

    if not refresh_entries:
        print("  (no refresh tokens found)\n")
    else:
        concurrency = max(1, min(len(refresh_entries), len(proxies) or 5))
        semaphore = asyncio.Semaphore(concurrency)

        async def limited_validate(index, entry, proxy):
            async with semaphore:
                try:
                    result = await asyncio.wait_for(
                        validate_refresh_entry(entry[0], entry[1], proxy),
                        timeout=30,
                    )
                except asyncio.TimeoutError:
                    result = {
                        "username_label": entry[0],
                        "refresh_token": entry[1],
                        "proxy": proxy,
                        "validated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "status": "TIMEOUT",
                        "profile_name": "",
                        "profile_uuid": "",
                        "new_refresh_entry": "",
                        "result": {"status": "timeout", "body": "30-second account timeout"},
                        "profile_error": "30-second account timeout",
                        "error": "TimeoutError: validation exceeded 30 seconds",
                    }
                result["index"] = index
                return result

        async def validate_with_failover(index, entry):
            last_result = None
            for attempt in range(PROXY_FAILURE_RETRIES):
                proxy = proxy_pool.candidate_for_attempt(index, attempt)
                result = await limited_validate(index, entry, proxy)
                result["proxy_attempts"] = attempt + 1
                if result["status"] not in {"ERROR", "TIMEOUT"}:
                    return result
                proxy_pool.mark_failed(proxy)
                last_result = result
            return last_result

        tasks = [
            asyncio.create_task(validate_with_failover(i, entry))
            for i, entry in enumerate(refresh_entries)
        ]
        results = [None] * len(tasks)
        completed = 0
        print(f"[*] Starting {len(tasks)} refresh checks with {concurrency} concurrent worker(s)...")
        for completed_task in asyncio.as_completed(tasks):
            result = await completed_task
            results[result["index"]] = result
            completed += 1
            account_label = (
                result["profile_name"]
                or result["username_label"]
                or f"line {result['index'] + 1}"
            )
            print(f"[*] Progress: {completed}/{len(tasks)} completed ({account_label}: {result['status']})")
            if result["status"] == "VALID":
                output_entry = output_refresh_entry(result)
                validation_file.write(output_entry + "\n")
                validation_file.flush()
                print(f"[*] Saved validated token for {account_label}")
        print(f"[*] Completed {len(results)} refresh checks")

        timed_out = [result for result in results if result["status"] == "TIMEOUT"]
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
                print(f"[*] Retry progress: {retry_completed}/{len(retry_tasks)} ({account_label}: {result['status']})")
                if result["status"] == "VALID":
                    output_entry = output_refresh_entry(result)
                    validation_file.write(output_entry + "\n")
                    validation_file.flush()
                    print(f"[*] Saved validated token for {account_label}")

        for i, result in enumerate(results, 1):
            username_label = result["username_label"]
            rt = result["refresh_token"]
            validation = result["result"] or {}
            print(f"\n{'─'*64}")
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
                    print("OK")
                    if validation.get("expires_in"):
                        print(f"      MSA token TTL: {validation['expires_in']}s ({int(validation['expires_in'])/3600:.1f}h)")
                    if validation.get("user_id"):
                        print(f"      MSA user_id:   {validation['user_id']}")
                    if validation.get("new_refresh"):
                        print(f"      Rotated:       new refresh token issued ({len(validation['new_refresh'])} chars)")
                    if result["profile_name"]:
                        print(f"      Minecraft name: {result['profile_name']}")
                        print(f"      Minecraft UUID:  {result['profile_uuid']}")
                    else:
                        print(f"      Minecraft name: unavailable ({result['profile_error']})")
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
                f"Status: {result['status']}\n"
                f"Input label: {result['username_label'] or '(none)'}\n"
                f"Token prefix: {result['refresh_token'][:50]}...\n"
                f"Proxy: {proxy_label(result['proxy']) if result['proxy'] else 'direct'}\n"
                f"Proxy attempts: {result.get('proxy_attempts', 1)}\n"
                f"Minecraft name: {result['profile_name'] or '(unknown)'}\n"
                f"Minecraft UUID: {result['profile_uuid'] or '(unknown)'}\n"
                f"MSA user ID: {validation.get('user_id', '(unknown)')}\n"
                f"Expires in: {validation.get('expires_in', '(unknown)')}\n"
                f"HTTP status: {validation.get('status', '(none)')}\n"
                f"Response: {validation.get('body', '(none)')}\n"
                f"Error: {result.get('error') or result.get('profile_error') or '(none)'}\n"
                f"Saved refresh entry: {output_refresh_entry(result) if result['status'] == 'VALID' else '(none)'}\n\n"
            )
        verbose_file.flush()

        counts = {}
        for result in results:
            status = result["status"]
            counts[status] = counts.get(status, 0) + 1
        summary = " | ".join(
            f"{status}: {counts[status]}"
            for status in ("VALID", "DEAD", "TIMEOUT", "ERROR", "JWT_NOT_TESTED")
            if counts.get(status)
        )
        print(f"\nValidation summary: {summary or 'no refresh entries processed'}")

    validation_file.close()
    verbose_file.close()
    print(f"\n[OK] Validation results -> {validation_output}")
    print(f"[OK] Detailed output -> {verbose_output}")

    print(f"\n{'='*64}")
    print("  Done.")
    print(f"{'='*64}")


if __name__ == "__main__":
    asyncio.run(main())
