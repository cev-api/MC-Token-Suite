"""
Account Manager - Name Change & Skin Change
Reads token.txt (or refresh.txt → full chain) and allows:
  - Changing the Minecraft username (if eligible)
  - Changing the Minecraft skin (from URL or local file)
  - Resetting the skin to default
  - Checking name availability
"""

import os
import sys
import asyncio
import base64
import json
import hashlib
import secrets
from urllib.parse import urlencode

import httpx

# --- Constants ---

MC_PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile"
MC_NAME_CHANGE_URL = "https://api.minecraftservices.com/minecraft/profile/namechange"
MC_NAME_AVAIL_URL = "https://api.minecraftservices.com/minecraft/profile/name/{name}/available"
MC_SKIN_URL = "https://api.minecraftservices.com/minecraft/profile/skins"

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

# Valid skin variants
SLIM = "slim"
CLASSIC = "classic"


# --- Token acquisition ---

def read_lines(filepath: str) -> list[str]:
    if not os.path.isfile(filepath):
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


async def get_mc_token_from_refresh(refresh_token: str) -> str | None:
    """Turn a refresh token into a fresh MC token via full chain."""
    async with httpx.AsyncClient(timeout=30) as client:
        # 1. Refresh MSA
        print("  [1/4] Refreshing MSA...")
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
        msa = resp.json()["access_token"]

        # 2. XBL
        print("  [2/4] Authenticating XBL...")
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


async def resolve_token() -> str | None:
    """Get a valid MC token: token.txt first, fallback to refresh.txt chain."""
    cwd = os.getcwd()

    # Try token.txt first
    tokens = read_lines(os.path.join(cwd, "token.txt"))
    if tokens:
        token = tokens[0]
        # Quick check if still valid
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(MC_PROFILE_URL, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code == 200:
                print(f"[*] Using cached MC token from token.txt")
                return token
        print("[*] Cached MC token expired, refreshing...")
    else:
        print("[*] No token.txt found, trying refresh...")

    # Fallback to refresh.txt
    refresh_tokens = read_lines(os.path.join(cwd, "refresh.txt"))
    if refresh_tokens:
        print(f"[*] Using refresh token from refresh.txt")
        return await get_mc_token_from_refresh(refresh_tokens[0])

    print("[!] No token.txt or refresh.txt found. Run cookie_to_token.py first.")
    return None


# --- Name operations ---

async def check_name_available(token: str, name: str) -> bool:
    """Check if a Minecraft username is available."""
    url = MC_NAME_AVAIL_URL.replace("{name}", name)
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
        if resp.status_code == 200:
            data = resp.json()
            return data.get("status") == "AVAILABLE"
        return False


async def change_name(token: str, new_name: str) -> bool:
    """Change the Minecraft username."""
    async with httpx.AsyncClient(timeout=15) as client:
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

    async with httpx.AsyncClient(timeout=30) as client:
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

    async with httpx.AsyncClient(timeout=30) as client:
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
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.delete(
            MC_SKIN_URL,
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code in (200, 204):
            print(f"    Skin reset to default!")
            return True
        print(f"    HTTP {resp.status_code}: {resp.text[:200]}")
        return False


# --- Main menu ---

async def main():
    print("=" * 55)
    print("  Minecraft Account Manager")
    print("=" * 55)

    token = await resolve_token()
    if not token:
        sys.exit(1)

    # Show current profile
    async with httpx.AsyncClient(timeout=15) as client:
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

        # Check name change eligibility
        nc_resp = await client.get(
            MC_NAME_CHANGE_URL,
            headers={"Authorization": f"Bearer {token}"},
        )
        name_change_allowed = False
        if nc_resp.status_code == 200:
            nc = nc_resp.json()
            name_change_allowed = nc.get("nameChangeAllowed", False)
            print(f"  Name change:     {'ALLOWED' if name_change_allowed else 'ON COOLDOWN'}")

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
    asyncio.run(main())
