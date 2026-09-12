# MC Token Suite

This is a set of tools for Minecraft accounts that you own.

It turns Microsoft login cookies into Minecraft tokens. It can refresh those
tokens, check that they work, look up Minecraft usernames, and manage your
account name or skin.

Think of it like this:

```text
Browser cookies
    -> cookie_to_token.py
    -> refresh.txt and token.txt
    -> refresh_to_token.py or validate_tokens.py
    -> a fresh, checked Minecraft token
```

Keep `token.txt`, `refresh.txt`, and cookie exports private. They can give
access to your account.

## Setup

Install Python 3.10 or newer. Then install the required packages:

```powershell
python -m pip install -r requirements.txt
```

Run all commands from this folder.

## The files that matter

| File | What it contains | What it is for |
|---|---|---|
| `token.txt` | Minecraft access tokens | Lets tools talk to Minecraft. These normally expire in about one day. |
| `refresh.txt` | Microsoft refresh tokens | Lets you get new Minecraft access tokens. |
| Cookie `.txt` file | Cookies from `login.live.com` | Lets you create the first tokens. |
| `proxy.txt` | Optional proxies | Lets the tools send requests through proxies. |

A token file can have one token per line. It can also use this format:

```text
Username:token
```

## Start here: turn cookies into tokens

Use `cookie_to_token.py` when you have a Netscape-format cookie export from
`login.live.com`.

```powershell
python cookie_to_token.py
```

Put the cookie `.txt` files in this folder first.

The script reads the cookies and signs in through Microsoft, Xbox, and
Minecraft. It saves a token only when the account has a real Minecraft
username.

It writes these files:

- `token.txt` contains Minecraft access tokens.
- `refresh.txt` contains Microsoft refresh tokens.
- `validated_access.txt` and `validated_refresh.txt` contain `username:token` entries.
- `results.txt` tells you what happened to each cookie file.

Useful options:

```powershell
python cookie_to_token.py --recursive
python cookie_to_token.py --concurrency 20
python cookie_to_token.py --verbose
```

## Get a new Minecraft token

Use `refresh_to_token.py` when you already have `refresh.txt`.

```powershell
python refresh_to_token.py
```

The script uses each refresh token to get a new Minecraft access token.

It writes the successful access tokens to `token.txt`. They are staged in
`token.txt.part` while the run is going, so a run where nothing succeeds leaves
the previous `token.txt` alone.

It writes rotated refresh tokens to a file such as:

```text
rotated_refresh_2026-09-11_12-00-00.txt
```

### Options

```powershell
python refresh_to_token.py --limit 10          # try 10 tokens first
python refresh_to_token.py --concurrency 8     # fewer tokens at once
python refresh_to_token.py --refresh validated_refresh_2026-09-12_20-40-04.txt
python refresh_to_token.py --proxies proxy.txt
python refresh_to_token.py --no-proxies        # ignore proxy.txt
python refresh_to_token.py --dir C:\path\to\folder
```

Keep `--concurrency` at or below the default (16) when the proxy list is free
proxies. The chain makes four requests per token, and pushing more at once is
what makes the proxies slow enough to time out.

## Check your tokens

Use `validate_tokens.py` to see which tokens work and what account they belong
to.

```powershell
python validate_tokens.py
```

The script reads `token.txt` and `refresh.txt`. It checks the token with the
Minecraft profile service.

A token counts as valid only when it reaches a Minecraft profile with a
username. A Microsoft account that does not own Minecraft does not count as a
valid result.

The script can show the username, UUID, skin, cape, token expiry, and account
information.

It writes files such as:

- `validated_tokens_YYYY-MM-DD_HH-MM-SS.txt`
- `validated_refresh_YYYY-MM-DD_HH-MM-SS.txt`
- `rejected_tokens_YYYY-MM-DD_HH-MM-SS.txt`
- `rejected_refresh_YYYY-MM-DD_HH-MM-SS.txt`
- `errors_tokens_YYYY-MM-DD_HH-MM-SS.txt`
- `errors_refresh_YYYY-MM-DD_HH-MM-SS.txt`
- `verbose_YYYY-MM-DD_HH-MM-SS.txt`

Useful options:

```powershell
python validate_tokens.py --details
python validate_tokens.py --verbose
python validate_tokens.py --only-tokens errors_tokens_YYYY-MM-DD_HH-MM-SS.txt
python validate_tokens.py --no-proxies
```

Use `--details` when you also want name-change and name-history information.

## Change your name or skin

Use `manage_account.py` to manage one account.

```powershell
python manage_account.py
```

The script lets you:

- Change the Minecraft username.
- Change the skin from a PNG URL.
- Change the skin from a local PNG file.
- Reset the skin to Steve or Alex.
- Check whether a username is available.

You can use `token.txt`, `refresh.txt`, or paste credentials directly.

You can paste cookie lines, a `Cookie:` header, a refresh token, or a
Minecraft access token. Press `q` when the script asks for credentials if you
want to cancel.

The script also shows the name-change cooldown and username history when that
data is available.

## Check a Minecraft username

Use `mc_account_checker.py` to look up a Minecraft username.

```powershell
python mc_account_checker.py
```

The script shows public profile data, name history when available, and the
Minecraft name-availability result.

It uses a working token from `token.txt`. If it cannot find one, it asks you
to paste a token.

## Use the browser userscript

`mc_refresh_extractor.user.js` is a Tampermonkey userscript.

Install Tampermonkey. Create a new userscript. Paste in the file contents.
Enable cookie API access in the userscript settings.

Open `minecraft.net` or `login.live.com`. Select **Extract Tokens** in the
userscript. It gets a refresh token and a Minecraft access token from your
live Microsoft sign-in session.

Copy the tokens into `refresh.txt` and `token.txt`.

## Optional proxies

Create `proxy.txt` or `proxies.txt` if you want to use proxies.

Put one proxy on each line. These formats work:

```text
http://host:port
https://host:port
socks5://host:port
socks5h://host:port
host:port
host:port:username:password
```

The scripts ask if you want to use the proxy list. `validate_tokens.py` can
test the proxies first with `--check-proxies`.

## Cookie format

`cookie_to_token.py` uses Netscape cookie files. Each cookie line looks like
this:

```text
domain    flag    path    secure    expires    name    value
```

Use cookies for `login.live.com`, `.live.com`, or `.login.live.com`.

## Safety

Do not share your cookie files.

Do not share `token.txt` or `refresh.txt`.

Do not commit these files to Git.

Use this project only with accounts that you own or have permission to manage.