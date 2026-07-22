# MC Token Suite - Microsoft cookie to Minecraft access token

Four Python scripts that exchange Microsoft account session cookies for
Minecraft access tokens, refresh them, validate account info, and manage
names/skins - **no browser required**.

## Requirements

```powershell
pip install httpx
```

## Scripts

### 1. `cookie_to_token.py`

Converts Netscape-format `.txt` cookie files (exported from a browser for
`login.live.com`) into a Minecraft `eyJra...` access token.

```
python cookie_to_token.py
```

- Reads any `.txt` file in the current folder (skips `token.txt` / `requirements.txt`)
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

- Reads `refresh.txt` (or any `.txt` with a single refresh token)
- Refreshes MSA -> XBL -> XSTS -> Minecraft
- Outputs:
  - `token.txt` - fresh Minecraft access token
  - `refresh.txt` - rotated refresh token (keep using it)

### 3. `validate_tokens.py`

Shows everything about the account: expiry, username, UUID, skins, capes,
name change status, account age, name history.

```
python validate_tokens.py
```

- Reads `token.txt` and `refresh.txt`
- Decodes the JWT (expiry countdown, issue time)
- Queries Minecraft profile API for account details
- If the MC token is expired, auto-refreshes via `refresh.txt`
- Also validates the refresh token is still alive

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

## File Flow

```
browser-exported-cookies.txt
        |
        v
  cookie_to_token.py
        |
        +---> token.txt   (MC access token, eyJra...)
        +---> refresh.txt (MSA refresh token)
                |
                v
        refresh_to_token.py  --> fresh token.txt + rotated refresh.txt
                |
                v
        validate_tokens.py   --> account info, expiry, name history
        manage_account.py    --> name change, skin change, name check
```

## Token Lifecycle

1. **Cookies** (from browser) - one-time use to get initial tokens
2. **MSA refresh token** - reusable, rotates on each use, good indefinitely if refreshed regularly
3. **Minecraft access token** - lasts ~24 hours, use `refresh_to_token.py` to renew

## Notes

- Works on Windows command prompt - uses ASCII-safe characters only
- The `.txt` cookie files must be in **Netscape format** (tab-separated: `domain flag path secure expires name value`)
- Only `login.live.com` / `.live.com` / `.login.live.com` cookies are needed
