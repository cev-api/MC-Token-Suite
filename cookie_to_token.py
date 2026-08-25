"""
Cookie to Access Token Extractor
Exchanges Microsoft login.live.com session cookies (Netscape format .txt)
for a Minecraft access_token (JWT starting with eyJra...) via the full
MSA -> XBL -> XSTS -> Minecraft chain.
"""

import os
import sys
import asyncio
import hashlib
import base64
import secrets
import re
import json
from urllib.parse import urlencode, urlparse, parse_qs

import httpx
from proxy_utils import ProxyPool, choose_proxies

# --- Constants ---

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

# --- Helpers ---

def parse_netscape_cookies(filepath: str) -> list[dict]:
    cookies = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 7:
                continue
            domain, _flag, path, _secure, _expires, name, value = parts[:7]
            cookies.append({"name": name, "value": value, "domain": domain, "path": path})
    return cookies


def find_cookie_files(directory: str) -> list[str]:
    skip = {"token.txt", "requirements.txt"}
    return [
        os.path.join(directory, f)
        for f in os.listdir(directory)
        if f.lower().endswith(".txt")
        and f.lower() not in skip
        and os.path.isfile(os.path.join(directory, f))
    ]


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

async def get_msa_token(cookies: list[dict], cookie_header: str, proxy: str | None = None) -> tuple[str | None, str | None, str | None]:
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

    async with httpx.AsyncClient(timeout=30, follow_redirects=False, proxy=proxy) as client:
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


# --- Step 2: XBL authenticate ---

async def authenticate_xbl(msa_token: str, proxy: str | None = None) -> tuple[str, str] | None:
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

    async with httpx.AsyncClient(timeout=30, proxy=proxy) as client:
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

async def authenticate_xsts(xbl_token: str, proxy: str | None = None) -> tuple[str, str] | None:
    """Exchange XBL token for XSTS token. Returns (token, userhash)."""
    payload = {
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [xbl_token],
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT",
    }

    async with httpx.AsyncClient(timeout=30, proxy=proxy) as client:
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

async def minecraft_login(userhash: str, xsts_token: str, proxy: str | None = None) -> str | None:
    """Exchange XSTS for Minecraft access token (JWT, eyJra...)."""
    identity_token = f"XBL3.0 x={userhash};{xsts_token}"

    async with httpx.AsyncClient(timeout=30, proxy=proxy) as client:
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
        found.extend(JWT_RE.findall(str(c.get("value", ""))))
    return found


def scan_body_for_jwt(body: str | None) -> list[str]:
    """Pull JWT-shaped values out of the failed authorize response body."""
    return JWT_RE.findall(body or "")


async def salvage_access_token(cookies: list[dict], failure_body: str | None, proxy: str | None = None) -> str | None:
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
        xbl = await authenticate_xbl(jwt, proxy)
        if not xbl:
            continue
        xsts = await authenticate_xsts(xbl[0], proxy)
        if not xsts:
            continue
        mc_token = await minecraft_login(xsts[1], xsts[0], proxy)
        if mc_token:
            print(f"[+] Salvaged access_token via the Xbox chain! ({len(mc_token)} chars)")
            return mc_token
    return None


# --- Full chain ---

async def extract_token(cookies: list[dict], proxy: str | None = None) -> tuple[str, str] | None:
    """Full chain. Returns (mc_access_token, msa_refresh_token) or None."""
    cookie_header = build_cookie_header(cookies)
    print(f"[*] Cookie header: {len(cookie_header)} chars, {len(cookies)} cookies")

    # Step 1: MSA token
    msa, refresh_token, failure_body = await get_msa_token(cookies, cookie_header, proxy)
    if not msa:
        # The authorize 302 failed (dead session / challenge page). Try to get
        # an access token anyway from the cookie export or the response body.
        print("[!] MSA token extraction failed - checking the cookies/response for an access token...")
        salvaged = await salvage_access_token(cookies, failure_body, proxy)
        if salvaged:
            print(f"\n[+] Access token salvaged (no refresh token available):")
            print(f"    {salvaged[:80]}...{salvaged[-30:]}")
            return salvaged, ""
        print("[!] Nothing usable in the cookies/response either.")
        return None

    # Step 2: XBL
    xbl = await authenticate_xbl(msa, proxy)
    if not xbl:
        return None
    xbl_token, _xbl_uhs = xbl

    # Step 3: XSTS
    xsts = await authenticate_xsts(xbl_token, proxy)
    if not xsts:
        return None
    xsts_token, xsts_uhs = xsts

    # Step 4: Minecraft
    mc_token = await minecraft_login(xsts_uhs, xsts_token, proxy)
    if mc_token:
        return mc_token, refresh_token or ""
    return None


def main():
    cwd = os.getcwd()
    proxies = choose_proxies(cwd)
    proxy_pool = ProxyPool(proxies)
    print(f"[*] Working directory: {cwd}")

    txt_files = find_cookie_files(cwd)
    if not txt_files:
        print("[!] No .txt cookie files found.")
        sys.exit(1)

    print(f"[*] Found {len(txt_files)} file(s):")
    for f in txt_files:
        print(f"    - {os.path.basename(f)}")

    all_tokens = []   # MC access tokens for token.txt
    all_refresh = []  # MSA refresh tokens for refresh.txt

    for file_index, filepath in enumerate(txt_files):
        print(f"\n{'='*60}")
        print(f"[*] Processing: {os.path.basename(filepath)}")

        cookies = parse_netscape_cookies(filepath)
        print(f"[*] Parsed {len(cookies)} cookies")

        if not cookies:
            print("[!] No cookies, skipping.")
            continue

        try:
            result = asyncio.run(
                proxy_pool.run(file_index, lambda proxy: extract_token(cookies, proxy))
            )
        except Exception as e:
            print(f"[-] Error: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            result = None

        if result:
            token, refresh = result
            print(f"\n[+] SUCCESS! Minecraft access_token (eyJra...):")
            print(f"    {token[:80]}...{token[-30:]}")
            all_tokens.append(token)
            if refresh:
                all_refresh.append(refresh)
        else:
            print("[-] Failed.")

    output_path = os.path.join(cwd, "token.txt")
    if all_tokens:
        with open(output_path, "w", encoding="utf-8") as f:
            for t in all_tokens:
                f.write(t + "\n")
        print(f"\n[OK] {len(all_tokens)} MC token(s) -> {output_path}")
    else:
        print(f"\n[XX] No tokens extracted.")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("")

    # Also save refresh tokens separately for refresh_to_token.py
    refresh_path = os.path.join(cwd, "refresh.txt")
    if all_refresh:
        with open(refresh_path, "w", encoding="utf-8") as f:
            for r in all_refresh:
                f.write(r + "\n")
        print(f"[OK] {len(all_refresh)} refresh token(s) -> {refresh_path}")

    print("Done.")


if __name__ == "__main__":
    main()
