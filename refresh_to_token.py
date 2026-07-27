"""
Refresh Token → Minecraft Access Token
Takes one or more Microsoft refresh tokens (one per line in a .txt file) and
runs each through the MSA refresh → XBL → XSTS → Minecraft chain. Successful
Minecraft JWTs are written one per line to token.txt.
"""

import os
import sys
import asyncio
from datetime import datetime
import httpx

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


# --- Step 1: Refresh MSA token ---

async def refresh_msa_token(refresh_token: str) -> tuple[str, str] | None:
    """Exchange a refresh token for a fresh MSA access_token.
    Returns (access_token, new_refresh_token) or None."""
    async with httpx.AsyncClient(timeout=30) as client:
        print("[1/4] Refreshing MSA token...")
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

        if resp.status_code != 200:
            print(f"[-] Refresh returned {resp.status_code}: {resp.text[:300]}")
            return None

        data = resp.json()
        access_token = data.get("access_token")
        new_refresh = data.get("refresh_token")

        if access_token:
            print(f"[+] MSA access_token refreshed ({len(access_token)} chars)")
            if new_refresh:
                print(f"[*] New refresh_token issued ({len(new_refresh)} chars)")
            return access_token, new_refresh or refresh_token

        print(f"[-] No access_token in response. Keys: {list(data.keys())}")
        return None


# --- Step 2: XBL authenticate ---

async def authenticate_xbl(msa_token: str) -> tuple[str, str] | None:
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

    async with httpx.AsyncClient(timeout=30) as client:
        print("[2/4] Authenticating with XBL...")
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

        print(f"[-] XBL response missing Token/uhs")
        return None


# --- Step 3: XSTS authorize ---

async def authenticate_xsts(xbl_token: str) -> tuple[str, str] | None:
    """Exchange XBL token for XSTS token. Returns (token, userhash)."""
    payload = {
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [xbl_token],
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        print("[3/4] Authenticating with XSTS...")
        resp = await client.post(
            XSTS_AUTH_URL,
            json=payload,
            headers={"Accept": "application/json", "x-xbl-contract-version": "1"},
        )

        if resp.status_code != 200:
            print(f"[-] XSTS returned {resp.status_code}: {resp.text[:500]}")
            try:
                err = resp.json()
                print(f"    XErr={err.get('XErr', '?')} {err.get('Message', '')}")
            except Exception:
                pass
            return None

        data = resp.json()
        token = data.get("Token")
        userhash = data.get("DisplayClaims", {}).get("xui", [{}])[0].get("uhs", "")

        if token and userhash:
            print(f"[+] XSTS token obtained ({len(token)} chars)")
            return token, userhash

        print("[-] XSTS response missing Token/uhs")
        return None


# --- Step 4: Minecraft login ---

async def minecraft_login(userhash: str, xsts_token: str) -> str | None:
    """Exchange XSTS for Minecraft access token (JWT, eyJra...)."""
    identity_token = f"XBL3.0 x={userhash};{xsts_token}"

    async with httpx.AsyncClient(timeout=30) as client:
        print("[4/4] Logging into Minecraft...")
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


# --- Full chain ---

async def refresh_chain(refresh_token: str) -> tuple[str, str] | None:
    """Returns (mc_access_token, new_refresh_token) or None."""
    print(f"[*] Refresh token: {refresh_token[:40]}... ({len(refresh_token)} chars)")

    result = await refresh_msa_token(refresh_token)
    if not result:
        return None
    msa, new_refresh = result

    xbl = await authenticate_xbl(msa)
    if not xbl:
        return None
    xbl_token, _xbl_uhs = xbl

    xsts = await authenticate_xsts(xbl_token)
    if not xsts:
        return None
    xsts_token, xsts_uhs = xsts

    mc_token = await minecraft_login(xsts_uhs, xsts_token)
    if mc_token:
        return mc_token, new_refresh
    return None


# --- Main ---

def main():
    cwd = os.getcwd()
    print(f"[*] Working directory: {cwd}")

    # Only refresh.txt is treated as input. This avoids accidentally reading
    # browser-cookie exports or unrelated .txt files in the working folder.
    refresh_path = os.path.join(cwd, "refresh.txt")
    if not os.path.isfile(refresh_path):
        print("[!] refresh.txt was not found.")
        print("    Put one MSA refresh token per line in refresh.txt.")
        sys.exit(1)

    txt_files = [refresh_path]
    print("[*] Input file: refresh.txt")

    all_tokens = []
    all_refresh = []
    processed_count = 0

    for filepath in txt_files:
        refresh_tokens = read_refresh_tokens(filepath)
        filename = os.path.basename(filepath)
        if not refresh_tokens:
            print(f"\n[!] {filename} is empty, skipping.")
            continue

        if looks_like_netscape_cookie_file(refresh_tokens):
            print(f"\n[!] {filename} is a Netscape cookie file, not a refresh-token list.")
            print("    Run cookie_to_token.py with it first, then put the resulting refresh token(s) in refresh.txt.")
            continue

        print(f"\n[*] {filename}: {len(refresh_tokens)} refresh token(s) found")
        for token_index, (username, refresh_token) in enumerate(refresh_tokens, start=1):
            if refresh_token.startswith("eyJra"):
                print(f"\n[!] {filename} line {token_index} is already a Minecraft JWT, skipping.")
                continue

            processed_count += 1
            print(f"\n{'='*60}")
            print(f"[*] Processing: {filename} (line {token_index}/{len(refresh_tokens)})")
            if username:
                print(f"[*] Username label: {username}")
            print(f"[*] Refresh token detected ({len(refresh_token)} chars)")

            try:
                result = asyncio.run(refresh_chain(refresh_token))
            except Exception as e:
                print(f"[-] Error: {type(e).__name__}: {e}")
                import traceback
                traceback.print_exc()
                result = None

            if result:
                token, new_refresh = result
                print(f"\n[+] SUCCESS! Minecraft access_token (eyJra...):")
                print(f"    {token[:80]}...{token[-30:]}")
                all_tokens.append(token)
                all_refresh.append(format_refresh_entry(username, new_refresh))
            else:
                print("[-] Failed; keeping the original refresh token for retry.")

    # Save MC access tokens
    output_path = os.path.join(cwd, "token.txt")
    if all_tokens:
        with open(output_path, "w", encoding="utf-8") as f:
            for t in all_tokens:
                f.write(t + "\n")
        print(f"\n[OK] {len(all_tokens)} MC token(s), one per line -> {output_path}")
    else:
        print(f"\n[XX] No tokens extracted.")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("")

    # Save rotated refresh tokens separately. Keep refresh.txt unchanged as
    # the input/source file; failed entries remain there for a later retry.
    run_stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    rotated_path = os.path.join(cwd, f"rotated_refresh_{run_stamp}.txt")
    with open(rotated_path, "w", encoding="utf-8") as f:
        for r in all_refresh:
            f.write(r + "\n")
    print(f"[OK] {len(all_refresh)} rotated refresh token(s) -> {rotated_path}")

    print(f"Done. Processed {processed_count} refresh token(s).")


if __name__ == "__main__":
    main()
