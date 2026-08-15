# MC Token Suite

Five Python utilities for exchanging Microsoft account session cookies for
Minecraft access tokens, refreshing tokens, inspecting account information,
checking usernames, and managing names and skins.

These scripts are intended for accounts and cookie exports you own. Treat
`token.txt`, `refresh.txt`, and browser cookie exports as secrets.

## Requirements

```powershell
python -m pip install -r requirements.txt
```

Run the commands from this project directory. Python 3.10 or newer is
recommended because the scripts use modern type-annotation syntax.

If `proxy.txt` or `proxies.txt` exists, each network-using script asks whether
to use the listed proxies. Supported entries include `http://host:port`,
`https://host:port`, `socks5://host:port`, `socks5h://host:port`, bare
`host:port`, and authenticated `host:port:username:password`.

## Scripts

### 1. `cookie_to_token.py`

Converts Netscape-format `.txt` cookie files (exported from a browser for
`login.live.com`) into a Minecraft `eyJra...` access token.

```
python cookie_to_token.py
```

- Reads `.txt` files in the current folder (skips `token.txt` and `requirements.txt`)
- Runs the full chain: cookies -> MSA -> XBL -> XSTS -> Minecraft
- Outputs:
  - `token.txt` - Minecraft access token (JWT, ~1087 chars)
  - `refresh.txt` - MSA refresh token for reuse

### 2. `refresh_to_token.py`

Uses a saved MSA refresh token to get a fresh Minecraft access token
without needing the cookies again.

```
python refresh_to_token.py
```

- Reads `refresh.txt` with one refresh token per line, or `USERNAME:REFRESHTOKEN`
  entries
- Refreshes every line through MSA -> XBL -> XSTS -> Minecraft
- Processes bulk refresh entries concurrently, rotating through configured proxies
- Preserves username labels when rotated or failed tokens are written back
- Outputs:
  - `token.txt` - fresh Minecraft access tokens, written and flushed immediately
    after each successful account
  - `rotated_refresh_YYYY-MM-DD_HH-MM-SS.txt` - newly rotated refresh tokens, one per line
    (failed input tokens remain unchanged in `refresh.txt` for retry)

### 3. `validate_tokens.py`

Shows everything about the account: expiry, username, UUID, skins, capes,
name change status, account age, name history.

```
python validate_tokens.py
```

- Reads `token.txt` and `refresh.txt`
- Processes every non-empty token line in both files
- Decodes the JWT (expiry countdown, issue time)
- Queries Minecraft profile API for account details
- If the MC token is expired, auto-refreshes via `refresh.txt`
- Also validates the refresh token is still alive
- Resolves and displays the associated Minecraft name and UUID when possible
- Writes successful validated/newly rotated entries to
  `validated_refresh_YYYY-MM-DD_HH-MM-SS.txt`
- Writes detailed access-token and refresh-token information to
  `verbose_YYYY-MM-DD_HH-MM-SS.txt`
  immediately in the same format as the input: `USERNAME:REFRESHTOKEN`
- Uses proxies from `proxy.txt` in round-robin order during bulk checks. Proxy
  lines may be `http://host:port`, `https://host:port`, `socks5://host:port`,
  `socks5h://host:port`, or bare `host:port` (treated as HTTP).
- Runs refresh-token checks concurrently with a bounded worker limit and keeps
  report output in the same order as `refresh.txt`.

### 4. `manage_account.py`

Interactive menu for account changes.

```
python manage_account.py
```

Options:

| # | Action |
|---|--------|
| 1 | Change username (if off cooldown) |
| 2 | Change skin from URL (PNG link) |
| 3 | Change skin from local file (.png) |
| 4 | Reset skin to default (Steve/Alex) |
| 5 | Check if a name is available |

Auto-refreshes the token if expired. Reads `token.txt` (falls back to
`refresh.txt` -> full chain).

### 5. `mc_account_checker.py`

An interactive Minecraft username and account checker. Enter the username you
want to inspect; the script shows its current public account profile, token-
confirmed availability status, and username history when an API/archive
provides it.

```
python mc_account_checker.py
```

It uses the first accepted token in `token.txt` (one token per line) only to
call Minecraft's authenticated name-availability endpoint. If the file is
missing or every cached token is rejected, it prompts you to paste a token
without echoing it. The username entered at the prompt is always the account
being checked. It displays times using the computer's local timezone.

```
Minecraft username to check: eez
...
Result:           AVAILABLE LATER
Available from:   August 3rd 2026, 9:57:55 PM AEST
```

Mojang's previous public username-history endpoint may be unavailable. The
script tries it first and falls back to public profile/history archives. An
archive's 37-day release time is an estimate; Minecraft's authenticated
availability response is the confirmation.

## File Flow

```
browser-exported-cookies.txt
        |
        v
  cookie_to_token.py
        |
        +---> token.txt   (MC access tokens, one per line)
        +---> refresh.txt (MSA refresh tokens, one per line, optionally labeled)
                |
                v
        refresh_to_token.py  --> fresh token.txt + rotated refresh.txt
                |
                v
        validate_tokens.py    --> account info, expiry, names, validation report
        manage_account.py     --> name change, skin change, name check
        mc_account_checker.py --> username/account lookup
```

## Token Lifecycle

1. **Cookies** (from browser) - one-time use to get initial tokens
2. **MSA refresh token** - reusable, rotates on each use, good indefinitely if refreshed regularly
3. **Minecraft access token** - lasts ~24 hours; use `refresh_to_token.py` to renew

## Notes

- The `.txt` cookie files must be in **Netscape format** (tab-separated: `domain flag path secure expires name value`)
- Only `login.live.com` / `.live.com` / `.login.live.com` cookies are needed
- `refresh_to_token.py` reads only `refresh.txt`; failed refresh tokens are
  retained so temporary failures can be retried
- `mc_account_checker.py` displays times using the computer's local timezone
