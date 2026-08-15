"""Interactively check a Minecraft Java username and its possible name release.

The username entered at the prompt is the account being checked. A Minecraft
access token from token.txt (or one pasted on request) is used only for the
authenticated Minecraft Services availability endpoint. Public profile and
history APIs provide the account/name information.
"""

from __future__ import annotations

import asyncio
import getpass
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from proxy_utils import choose_proxies


AUTH_NAME_AVAILABILITY_URL = "https://api.minecraftservices.com/minecraft/profile/name/{username}/available"
MOJANG_PROFILE_BY_NAME_URL = "https://api.mojang.com/users/profiles/minecraft/{username}"
MOJANG_PROFILE_BY_UUID_URL = "https://api.mojang.com/user/profile/{uuid}"
MOJANG_NAME_HISTORY_URL = "https://api.mojang.com/user/profiles/{uuid}/names"
ASHCON_PROFILE_URL = "https://api.ashcon.app/mojang/v2/user/{username}"
VRC_PROFILE_URL = "https://vrc.lol/api"
LIFORRA_NAME_HISTORY_URL = "https://liforra.de/api/namehistory"
TOKEN_FILE = Path("token.txt")
ACTIVE_PROXY: str | None = None
NAME_HOLD = timedelta(days=37)
class CheckError(RuntimeError):
    """A required profile or availability request could not be completed."""


@dataclass(frozen=True)
class AuthAvailability:
    status: str
    token_source: str


@dataclass(frozen=True)
class NameRelease:
    previous_name: str
    current_name: str
    changed_away_at: datetime
    available_after: datetime


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


def parse_timestamp(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None


def validate_username(value: str) -> str:
    username = value.strip()
    valid_characters = all(char.isascii() and (char.isalnum() or char == "_") for char in username)
    if not (3 <= len(username) <= 16 and valid_characters):
        raise ValueError("Minecraft Java names must be 3-16 letters, numbers, or underscores")
    return username


def read_tokens() -> list[str]:
    if not TOKEN_FILE.is_file():
        return []
    return [line.strip() for line in TOKEN_FILE.read_text(encoding="utf-8").splitlines() if line.strip()]


def prompt_for_token() -> str:
    try:
        return getpass.getpass("Paste Minecraft access token: ").strip()
    except (EOFError, KeyboardInterrupt):
        return ""


async def request_availability(
    client: httpx.AsyncClient, username: str, tokens: list[str], source: str
) -> AuthAvailability | None:
    """Use each candidate token until Minecraft accepts one for this request."""
    for index, token in enumerate(tokens, start=1):
        try:
            response = await client.get(
                AUTH_NAME_AVAILABILITY_URL.format(username=username),
                headers={"Authorization": f"Bearer {token}"},
            )
        except httpx.HTTPError as exc:
            raise CheckError("Could not reach Minecraft's availability service") from exc

        if response.status_code in (401, 403):
            continue
        try:
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise CheckError("Minecraft returned an unusable availability response") from exc

        status = data.get("status") if isinstance(data, dict) else None
        if not isinstance(status, str):
            raise CheckError("Minecraft's availability response did not include a status")
        return AuthAvailability(status=status.upper(), token_source=f"{source} line {index}")
    return None


async def get_current_profile(client: httpx.AsyncClient, username: str) -> dict | None:
    """Return a profile only if the requested spelling is currently assigned."""
    try:
        response = await client.get(MOJANG_PROFILE_BY_NAME_URL.format(username=username))
    except httpx.HTTPError as exc:
        raise CheckError("Could not reach Mojang's public profile lookup") from exc
    if response.status_code == 404:
        return None
    try:
        response.raise_for_status()
        profile = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise CheckError("Mojang returned an unusable public profile response") from exc
    return profile if isinstance(profile, dict) else None


async def resolve_archived_uuid(client: httpx.AsyncClient, username: str) -> str | None:
    """Resolve an old username through third-party public archives."""
    try:
        response = await client.get(ASHCON_PROFILE_URL.format(username=username))
        if response.status_code == 200:
            data = response.json()
            uuid = data.get("uuid") if isinstance(data, dict) else None
            if isinstance(uuid, str) and len(uuid.replace("-", "")) == 32:
                return uuid.replace("-", "")
    except (httpx.HTTPError, ValueError):
        pass

    try:
        # This archive can be slower, so do not make an unavailable fallback
        # delay the entire interactive check.
        response = await client.get(VRC_PROFILE_URL, params={"username": username}, timeout=5)
        if response.status_code != 200:
            return None
        data = response.json()
    except (httpx.HTTPError, ValueError):
        return None
    java = data.get("java") if isinstance(data, dict) else None
    uuid = java.get("uuid") if isinstance(java, dict) else None
    return uuid.replace("-", "") if isinstance(uuid, str) and len(uuid.replace("-", "")) == 32 else None


async def get_current_name_by_uuid(client: httpx.AsyncClient, uuid: str) -> str | None:
    try:
        response = await client.get(MOJANG_PROFILE_BY_UUID_URL.format(uuid=uuid.replace("-", "")))
        if response.status_code != 200:
            return None
        data = response.json()
    except (httpx.HTTPError, ValueError):
        return None
    name = data.get("name") if isinstance(data, dict) else None
    return name if isinstance(name, str) and name else None


async def get_name_history(client: httpx.AsyncClient, uuid: str, current_name: str) -> tuple[str, list[dict]]:
    """Try Mojang first, then a third-party history archive."""
    try:
        response = await client.get(MOJANG_NAME_HISTORY_URL.format(uuid=uuid.replace("-", "")))
        if response.status_code == 200:
            history = response.json()
            if isinstance(history, list) and all(isinstance(item, dict) for item in history):
                return "Mojang API", history
    except (httpx.HTTPError, ValueError):
        pass

    try:
        response = await client.get(LIFORRA_NAME_HISTORY_URL, params={"username": current_name})
        if response.status_code == 200:
            data = response.json()
            history = data.get("history") if isinstance(data, dict) else None
            if isinstance(history, list) and all(isinstance(item, dict) for item in history):
                return "Liforra public archive", history
    except (httpx.HTTPError, ValueError):
        pass
    return "Unavailable", []


def find_name_release(requested_name: str, current_name: str, history: list[dict]) -> NameRelease | None:
    """Find the final point where the requested old name was changed away from."""
    matching_indexes = [
        index
        for index, entry in enumerate(history)
        if isinstance(entry.get("name"), str) and entry["name"].casefold() == requested_name.casefold()
    ]
    if not matching_indexes:
        return None

    final_match = matching_indexes[-1]
    if final_match == len(history) - 1:
        return None
    changed_at = history[final_match + 1].get("changed_at") or history[final_match + 1].get("changedToAt")
    timestamp = parse_timestamp(changed_at) if isinstance(changed_at, str) else None
    if not timestamp:
        return None
    return NameRelease(
        previous_name=requested_name,
        current_name=current_name,
        changed_away_at=timestamp,
        available_after=timestamp + NAME_HOLD,
    )


def print_history(source: str, history: list[dict]) -> None:
    print("\n  Username history")
    if not history:
        print("    Status:           unavailable")
        return
    print(f"    Source:           {source}")
    print(f"    Entries:          {len(history)}")
    for entry in history:
        name = entry.get("name", "Unknown")
        changed_at = entry.get("changed_at") or entry.get("changedToAt")
        timestamp = parse_timestamp(changed_at) if isinstance(changed_at, str) else None
        detail = format_datetime(timestamp) if timestamp else "original name / no date"
        print(f"    - {name} - {detail}")


def print_result(
    username: str,
    authenticated: AuthAvailability,
    profile: dict | None,
    history_source: str,
    history: list[dict],
    release: NameRelease | None,
) -> None:
    print("\n" + "=" * 62)
    print("  Minecraft Username & Account Checker")
    print("=" * 62)
    print(f"  Checked username:  {username}")
    print(f"  Token check:       {authenticated.status} ({authenticated.token_source})")

    if profile:
        print("\n  Current account")
        print(f"    Username:         {profile.get('name', username)}")
        print(f"    UUID:             {profile.get('id', 'unknown')}")

    now = datetime.now(timezone.utc)
    if release:
        print("\n  Name availability")
        print(f"    Previous holder:  {release.current_name}")
        print(f"    Changed away:     {format_datetime(release.changed_away_at)}")
        if now < release.available_after:
            remaining = release.available_after - now
            print("    Result:           AVAILABLE LATER")
            print(f"    Available from:   {format_datetime(release.available_after)}")
            print(f"    Countdown:        about {remaining.days} days")
        else:
            print("    Result:           RELEASE WINDOW PASSED")
            print(f"    Available since:  {format_datetime(release.available_after)}")
            print("    Note:             Minecraft's authenticated status above is authoritative.")
    elif profile:
        print("\n  Name availability")
        print("    Result:           TAKEN")
        print("    Note:             The entered name is the account's current username.")
    elif authenticated.status == "AVAILABLE":
        print("\n  Name availability")
        print("    Result:           AVAILABLE NOW")
    else:
        print("\n  Name availability")
        print(f"    Result:           {authenticated.status}")
        print("    Note:             Minecraft has not confirmed this name as claimable.")

    print_history(history_source, history)
    print("\n  Release times are history-archive estimates. Minecraft's token-backed status is the confirmation.")


async def check_username(username: str) -> None:
    tokens = read_tokens()
    if tokens:
        print(f"[*] Trying {len(tokens)} token(s) from {TOKEN_FILE} for availability confirmation...")

    async with httpx.AsyncClient(timeout=15, follow_redirects=True, proxy=ACTIVE_PROXY) as client:
        authenticated = await request_availability(client, username, tokens, "token.txt") if tokens else None
        if authenticated is None:
            if tokens:
                print("[*] No token in token.txt was accepted. Paste another token to continue.")
            else:
                print("[*] No token.txt found. Paste a token to confirm availability.")
            supplied_token = prompt_for_token()
            if not supplied_token:
                print("[!] A valid token is required for Minecraft's availability confirmation.")
                return
            authenticated = await request_availability(client, username, [supplied_token], "pasted token")
        if authenticated is None:
            print("[!] Minecraft rejected the supplied token.")
            return

        profile = await get_current_profile(client, username)
        uuid = profile.get("id") if isinstance(profile, dict) else None
        current_name = profile.get("name") if isinstance(profile, dict) else None

        if not isinstance(uuid, str):
            uuid = await resolve_archived_uuid(client, username)
            current_name = await get_current_name_by_uuid(client, uuid) if uuid else None

        if isinstance(uuid, str) and isinstance(current_name, str):
            history_source, history = await get_name_history(client, uuid, current_name)
        else:
            history_source, history = "Unavailable", []

    release = find_name_release(username, current_name, history) if isinstance(current_name, str) else None
    print_result(username, authenticated, profile, history_source, history, release)


def main() -> None:
    global ACTIVE_PROXY
    proxies = choose_proxies(".")
    ACTIVE_PROXY = proxies[0] if proxies else None
    print("Minecraft Username & Account Checker")
    print("Checks the username you enter; token.txt is only used for availability confirmation.\n")
    try:
        username = validate_username(input("Minecraft username to check: "))
        print("\nLooking up account, availability, and name history...")
        asyncio.run(check_username(username))
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
    except ValueError as exc:
        print(f"\n[!] Invalid username: {exc}")
    except CheckError as exc:
        print(f"\n[!] {exc}")


if __name__ == "__main__":
    main()
