# StackWorkShop Auth: Python example

A complete Python 3.8+ desktop app that uses [StackWorkShop Auth](https://auth.stackworkshop.com) for login, registration, license keys, subscriptions, protected variables/files, custom scripts, sessions and a staff overview.

It uses only Python's standard library (including Tkinter), so there is no `pip install` step.

## Run it

1. Install Python 3.8 or newer. On Linux, install your distribution's Tk package if it is not included.
2. Download this repository or clone it.
3. Run:

```bash
python app.py
```

On Windows, you can also double-click `run.bat`.

## Demo accounts

| Account | Username | Password |
|---|---|---|
| Lifetime member | `demo_member` | `DemoMember!2026` |
| Staff/admin (read-only) | `demo_admin` | `DemoAdmin!2026` |

The two demo buttons fill these shared accounts. You can also register, use a license key, redeem a key, or reset a member HWID.

## What the app demonstrates

- Signed init, login, registration, license login, refresh-token rotation and logout
- Member subscription/expiration checks and staff-role detection
- Public and secured variables, including Fake mode behavior configured by the app owner
- Protected files loaded and verified in memory or streamed to disk
- Encrypted-file containers that are decrypted only in memory by the SDK
- GET/POST custom scripts with login sent in headers, URL parameters or a POST body
- Session/device listing, update checks and signed application logs
- Staff overview for staff-level members
- HTTPS verification, HMAC-signed requests and verified server response signatures
- A stable SHA-256 example HWID without exposing raw machine values

The interface is in `app.py`; the reusable, dependency-free SDK is `stackauth.py`.

## Use your own application

Edit `config.py`:

```python
APP_ID = "YOUR_APP_ID"
APP_SECRET = "YOUR_APP_SECRET"
VERSION = "1.0.0"
```

Get these values from **Auth dashboard → your app → Overview**. Replace the demo variable, file and script IDs with ones from your own app.

The demo secret in this public repository is public intentionally. A real desktop secret ships with your program, so use startup/dependency hash checks, protect the packaged build and rotate the secret if it leaks.

For scripts, `params_in` must match **Scripts → Send login in**:

```python
text = auth.script("member-welcome", method="GET", params_in="headers")
text = auth.script("lua-loader", method="GET", params_in="url")
text = auth.script("builder", method="POST", params_in="body")
```

Prefer headers or POST bodies for credentials. URL parameters may appear in history and proxy logs.

Docs: [auth.stackworkshop.com/docs](https://auth.stackworkshop.com/docs/) · Other examples: [C#](https://github.com/StackKingTheDev/StackAuth-CSharp-Example) · [C++](https://github.com/StackKingTheDev/StackAuth-CPP-Example) · [PHP](https://github.com/StackKingTheDev/StackAuth-PHP-Example) · [Node](https://github.com/StackKingTheDev/StackAuth-Node-Example)

MIT licensed.
