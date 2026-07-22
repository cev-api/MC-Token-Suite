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

async def query_mc_api(token: str, url: str) -> dict | None:
    """Generic GET to a Mojang authed endpoint."""
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
        if resp.status_code == 200:
            return resp.json()
        return None


async def get_profile(token: str) -> dict | None:
    """Minecraft profile (username, UUID, skins, capes)."""
    return await query_mc_api(token, MC_PROFILE_URL)


async def get_name_change_info(token: str) -> dict | None:
    """Name change eligibility & history."""
    return await query_mc_api(token, MC_NAME_CHANGE_URL)


async def get_name_history(uuid: str) -> list | None:
    """Public endpoint: full name history for a UUID (no auth needed).
    Tries the new Minecraft API first, falls back to legacy api.mojang.com."""
    clean_uuid = uuid.replace("-", "")
    # Newer endpoint (often works)
    urls = [
        f"https://api.minecraftservices.com/minecraft/profile/lookup/name/{clean_uuid}/names",
        f"https://api.mojang.com/user/profiles/{clean_uuid}/names",
    ]
    async with httpx.AsyncClient(timeout=15) as client:
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

async def refresh_mc_token(refresh_token: str) -> str | None:
    """Refresh MSA -> XBL -> XSTS -> MC, return fresh MC token or None."""
    try:
        async with httpx.AsyncClient(timeout=30) as client:
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

async def validate_refresh_token(refresh_token: str) -> dict | None:
    async with httpx.AsyncClient(timeout=15) as client:
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


def read_lines(filepath: str) -> list[str]:
    if not os.path.isfile(filepath):
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


# --- Main ---

async def main():
    cwd = os.getcwd()
    print(f"Working dir: {cwd}\n")

    # ====================================================================
    #  token.txt - Minecraft access tokens
    # ====================================================================
    mc_tokens = read_lines(os.path.join(cwd, "token.txt"))
    print(f"{'='*64}")
    print(f"  token.txt  -  {len(mc_tokens)} Minecraft access token(s)")
    print(f"{'='*64}")

    if not mc_tokens:
        print("  (no tokens found)\n")
    else:
        for i, token in enumerate(mc_tokens, 1):
            print(f"\n{'─'*64}")
            print(f"  [{i}] Token ({len(token)} chars)")
            print(f"      Prefix: {token[:55]}...")

            # -- Decode JWT --
            payload = decode_jwt(token)
            if payload:
                print(f"      JWT claims:")
                print(jwt_expiry(payload))
                for key in ("sub", "xuid", "iss"):
                    val = payload.get(key)
                    if val:
                        print(f"      {key}: {val}")
            else:
                print(f"      (not a decodable JWT)")

            # -- Profile -- try MC token first; if expired, refresh via refresh.txt
            profile = await get_profile(token)
            probe_token = token
            token_status = "VALID"

            if not profile:
                # Token expired - try to get a fresh one via refresh token
                print(f"      (token expired, trying refresh...)", end=" ", flush=True)
                refresh_tokens_early = read_lines(os.path.join(cwd, "refresh.txt"))
                if refresh_tokens_early:
                    probe_token = await refresh_mc_token(refresh_tokens_early[0])
                    if probe_token:
                        print("OK")
                        profile = await get_profile(probe_token)
                        token_status = "REFRESHED"
                    else:
                        print("FAILED")
                else:
                    print("no refresh.txt")

            if not profile:
                print(f"  >>> Could not fetch account info (token dead, no valid refresh)")
                continue

            name = profile.get("name", "?")
            uuid_ = profile.get("id", "?")
            skins = profile.get("skins", [])
            capes = profile.get("capes", [])

            print(f"\n  ---- Account: {name} ----")
            print(f"  UUID:         {uuid_}")
            print(f"  Skins:        {len(skins)} ({', '.join(s['variant'].upper() for s in skins) or 'none'})")
            print(f"  Capes:        {len(capes)} ({', '.join(c['alias'] for c in capes) or 'none'})")

            # Show active skin info
            for s in skins:
                if s.get("state") == "ACTIVE":
                    print(f"  Active skin:  {s['variant'].upper() if s.get('variant') else 'CLASSIC'} ({s.get('id', '?')[:16]}...)")

            # -- Name change info --
            nc = await get_name_change_info(probe_token)
            if nc:
                changeable = nc.get("nameChangeAllowed", nc.get("changeable", None))
                if changeable is not None:
                    status = "YES" if changeable else "NO (cooldown)"
                    print(f"  Name change:  {status}")
                changed_at = nc.get("changedAt") or nc.get("lastChangedAt")
                if changed_at:
                    ago = ""
                    try:
                        dt = datetime.fromisoformat(changed_at.replace("Z", "+00:00"))
                        delta = datetime.now(timezone.utc) - dt
                        ago = f" ({delta.days}d ago)"
                    except Exception:
                        pass
                    print(f"  Last changed: {fmt_iso(changed_at)}{ago}")
                created_at = nc.get("createdAt")
                if created_at:
                    ago = ""
                    try:
                        dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                        delta = datetime.now(timezone.utc) - dt
                        ago = f" ({delta.days}d ago)"
                    except Exception:
                        pass
                    print(f"  Account age:  {fmt_iso(created_at)}{ago}")

            # -- Name history --
            name_history = nc.get("history") or nc.get("nameChanges") if nc else None
            if not name_history:
                name_history = await get_name_history(uuid_) if uuid_ and uuid_ != "?" else None
            if name_history:
                print(f"  Name history: {len(name_history)} name(s)")
                for entry in name_history:
                    n = entry.get("name", "?")
                    ts = entry.get("changedToAt")
                    if ts:
                        print(f"    * {n}  (since {fmt_iso(ts)})")
                    else:
                        print(f"    * {n}  (original)")
            elif name_history is not None:
                print(f"  Name history: 1 name (no past changes)")
            else:
                print(f"  Name history: unavailable")

    # ====================================================================
    #  refresh.txt - MSA refresh tokens
    # ====================================================================
    refresh_tokens = read_lines(os.path.join(cwd, "refresh.txt"))
    print(f"\n{'='*64}")
    print(f"  refresh.txt  -  {len(refresh_tokens)} MSA refresh token(s)")
    print(f"{'='*64}")

    if not refresh_tokens:
        print("  (no refresh tokens found)\n")
    else:
        for i, rt in enumerate(refresh_tokens, 1):
            print(f"\n{'─'*64}")
            print(f"  [{i}] Refresh token ({len(rt)} chars)")
            print(f"      Prefix: {rt[:50]}...")

            if rt.startswith("eyJ"):
                payload = decode_jwt(rt)
                if payload:
                    print(f"      JWT claims:")
                    print(jwt_expiry(payload))
            else:
                print(f"      (opaque token - test-refreshing...)", end=" ", flush=True)
                result = await validate_refresh_token(rt)
                if result.get("valid"):
                    print("OK")
                    if result.get("expires_in"):
                        print(f"      MSA token TTL: {result['expires_in']}s ({int(result['expires_in'])/3600:.1f}h)")
                    if result.get("user_id"):
                        print(f"      MSA user_id:   {result['user_id']}")
                    if result.get("new_refresh"):
                        print(f"      Rotated:       new refresh token issued ({len(result['new_refresh'])} chars)")
                else:
                    status = result.get("status", "?")
                    body = result.get("body", "")
                    print(f"DEAD (HTTP {status})")
                    if body:
                        print(f"      Response: {body[:200]}")

    print(f"\n{'='*64}")
    print("  Done.")
    print(f"{'='*64}")


if __name__ == "__main__":
    asyncio.run(main())
