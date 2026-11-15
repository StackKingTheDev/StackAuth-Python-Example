"""StackWorkShop Auth client for Python 3.8+ (standard library only).

https://auth.stackworkshop.com/docs/
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

_REFRESHABLE = {"SESSION_INVALID", "SESSION_REPLACED"}
_FILE_MAGIC = b"SWE1"


def _file_hmac(key, *parts):
    value = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        value.update(part)
    return value.digest()


def _decrypt_file_container(container, secret, app_id, name):
    data = bytes(container)
    if len(data) < 68 or data[:4] != _FILE_MAGIC:
        raise StackAuthError("FILE_DECRYPT_FAILED", "The encrypted file container is invalid.")
    salt, nonce, encrypted, tag = data[4:20], data[20:36], data[36:-32], data[-32:]
    context = ("\0" + app_id + "\0" + name).encode()
    prk = _file_hmac(salt, secret)
    encryption_key = _file_hmac(prk, b"stackauth-file-encryption", context, b"\x01")
    authentication_key = _file_hmac(prk, b"stackauth-file-authentication", context, b"\x01")
    expected = _file_hmac(authentication_key, data[:36], encrypted, (app_id + "\0" + name).encode())
    if not hmac.compare_digest(tag, expected):
        raise StackAuthError("FILE_DECRYPT_FAILED", "The encrypted file failed authentication.")
    output = bytearray(len(encrypted))
    for block, offset in enumerate(range(0, len(encrypted), 32)):
        stream = _file_hmac(encryption_key, nonce, block.to_bytes(4, "big"))
        length = min(32, len(encrypted) - offset)
        for index in range(length):
            output[offset + index] = encrypted[offset + index] ^ stream[index]
    return bytes(output)


def _decrypt_credential_variable(envelope, username, password):
    if envelope.get("version") != 1 or envelope.get("algorithm") != "AES-256-GCM" or envelope.get("kdf") != "PBKDF2-SHA256":
        raise StackAuthError("VARIABLE_DECRYPT_FAILED", "The encrypted variable envelope is not supported.")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as error:
        raise StackAuthError(
            "VARIABLE_CRYPTO_UNAVAILABLE",
            "Credential-encrypted variables need the optional cryptography package: pip install cryptography",
        ) from error
    try:
        salt = base64.b64decode(envelope["salt"], validate=True)
        iv = base64.b64decode(envelope["iv"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        tag = base64.b64decode(envelope["tag"], validate=True)
        key = hashlib.pbkdf2_hmac(
            "sha256", (str(username) + "\0" + str(password)).encode(), salt, int(envelope["iterations"]), 32
        )
        plaintext = AESGCM(key).decrypt(
            iv, ciphertext + tag, b"StackWorkShop Auth credential variable v1"
        )
        return plaintext.decode()
    except StackAuthError:
        raise
    except Exception as error:
        raise StackAuthError(
            "VARIABLE_DECRYPT_FAILED", "The encrypted variable could not be decrypted with these credentials."
        ) from error


class StackAuthError(Exception):
    def __init__(self, code, message, details=None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.details = details or {}


class StackAuth:
    def __init__(self, app_id, app_secret, version="", file_hash="", files=None, hwid="",
                 base_url="https://auth.stackworkshop.com", device="", on_tokens=None):
        self.app_id = app_id
        self.secret = app_secret.encode()
        self.version = version
        self.file_hash = file_hash
        self.files = files or {}
        self.hwid = hwid
        self.device = device
        self.on_tokens = on_tokens
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme != "https" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
            raise ValueError("base_url must use HTTPS so its certificate and hostname are verified")
        self.base_url = base_url.rstrip("/")
        self.init_token = None
        self.session_token = None
        self.refresh_token = None
        self.session_id = None
        self.app = None
        self.member = None

    def _sign(self, text):
        return hmac.new(self.secret, text.encode(), hashlib.sha256).hexdigest()

    def call(self, action, payload=None):
        """Sends one signed request and verifies the signed response."""
        path = f"/api/v1/client/{action}"
        clean = {k: v for k, v in (payload or {}).items() if v not in (None, "")}
        body = json.dumps(clean, separators=(",", ":")).encode()
        timestamp = str(int(time.time()))
        nonce = secrets.token_urlsafe(18)
        request = urllib.request.Request(
            self.base_url + path,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "StackAuthClient/1.8 (python)",
                "X-App-Id": self.app_id,
                "X-Timestamp": timestamp,
                "X-Nonce": nonce,
                "X-Signature": self._sign(f"{timestamp}\n{nonce}\nPOST\n{path}\n{hashlib.sha256(body).hexdigest()}"),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                status, text, headers = response.status, response.read(), response.headers
        except urllib.error.HTTPError as error:
            status, text, headers = error.code, error.read(), error.headers
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        signature = headers.get("X-Signature")
        if not signature:
            data = data or {}
            raise StackAuthError(data.get("code", f"HTTP_{status}"), data.get("message", "Request failed"), {"verified": False})
        response_time = int(headers.get("X-Timestamp", "0"))
        expected = self._sign(f"{response_time}\n{nonce}\n{status}\n{hashlib.sha256(text).hexdigest()}")
        if not hmac.compare_digest(signature, expected) or abs(time.time() - response_time) > 120 or data is None:
            raise StackAuthError("BAD_SERVER_SIGNATURE", "The response was not signed by StackWorkShop Auth.")
        if not data.get("ok"):
            raise StackAuthError(data.get("code"), data.get("message"), data)
        return data

    def _session_call(self, action, payload=None):
        """Session call that refreshes once and retries when the access token ran out or was replaced."""
        payload = dict(payload or {})
        try:
            return self.call(action, {**payload, "session_token": self.session_token})
        except StackAuthError as error:
            if error.code not in _REFRESHABLE or not self.refresh_token:
                raise
            self.refresh()
            return self.call(action, {**payload, "session_token": self.session_token})

    def init(self):
        data = self.call("init", {"version": self.version, "hash": self.file_hash, "files": self.files, "hwid": self.hwid})
        self.init_token, self.app = data["init_token"], data["app"]
        return data

    def _session(self, data):
        self.session_token = data["session_token"]
        self.refresh_token = data.get("refresh_token") or self.refresh_token
        self.session_id = data.get("session_id") or self.session_id
        if data.get("member"):
            self.member = data["member"]
        if self.on_tokens:
            self.on_tokens(self.session_token, self.refresh_token)
        return data

    def register(self, username, password, license=None, email=None, captcha_token=None):
        return self._session(self.call("register", {"init_token": self.init_token, "username": username,
                                                    "password": password, "license": license, "email": email,
                                                    "captcha_token": captcha_token, "hwid": self.hwid, "device": self.device}))

    def login(self, username, password, captcha_token=None, totp=None):
        return self._session(self.call("login", {"init_token": self.init_token, "username": username, "password": password,
                                                 "captcha_token": captcha_token, "totp": totp, "hwid": self.hwid, "device": self.device}))

    def license(self, key, totp=None):
        return self._session(self.call("license", {"init_token": self.init_token, "license": key, "totp": totp,
                                                   "hwid": self.hwid, "device": self.device}))

    def refresh(self, refresh_token=None):
        """Swaps the refresh token for a new access token and a new refresh token (the old ones stop working)."""
        token = refresh_token or self.refresh_token
        if not token:
            raise StackAuthError("REFRESH_INVALID", "No refresh token. Log in again.")
        return self._session(self.call("refresh", {"refresh_token": token, "hwid": self.hwid}))

    def redeem(self, key):
        data = self._session_call("redeem", {"license": key})
        self.member = data["member"]
        return data

    def upgrade(self, key):
        return self.redeem(key)

    # ---- devices

    def sessions(self):
        return self._session_call("sessions")["sessions"]

    def revoke_session(self, session_id):
        return self._session_call("sessions/revoke", {"session_id": session_id})

    def revoke_other_sessions(self):
        return self._session_call("sessions/revoke-others")

    # ---- two-step verification

    def setup_2fa(self):
        return self._session_call("2fa/setup")

    def enable_2fa(self, code):
        return self._session_call("2fa/enable", {"totp": code})

    def disable_2fa(self, password, code):
        return self._session_call("2fa/disable", {"password": password, "totp": code})

    # ---- account

    def reset_password(self, current_password, new_password):
        return self._session_call("password/reset", {"current_password": current_password, "new_password": new_password})

    def reset_hwid(self, username, password, totp=None):
        return self.call("hwid/reset", {"init_token": self.init_token, "username": username, "password": password, "totp": totp})

    def reset_ip(self, username, password, totp=None):
        return self.call("ip/reset", {"init_token": self.init_token, "username": username, "password": password, "totp": totp})

    def set_avatar(self, avatar_url):
        return self._session_call("profile/avatar", {"avatar_url": avatar_url})

    def check(self):
        data = self._session_call("check", {"hwid": self.hwid})
        self.member = data["member"]
        return data

    # ---- variables

    def variable(self, name, username=None, password=None):
        payload = {"name": name, "username": username, "password": password}
        if self.session_token:
            data = self._session_call("var", payload)
        else:
            data = self.call("var", dict(payload, init_token=self.init_token))
        if not data.get("encrypted"):
            return data["value"]
        if not username or not password:
            raise StackAuthError(
                "VARIABLE_CREDENTIALS_REQUIRED",
                "Pass username and password to read this credential-encrypted variable.",
            )
        return _decrypt_credential_variable(data["envelope"], username, password)

    def get_user_var(self, name):
        return self._session_call("uservar/get", {"name": name})["value"]

    def set_user_var(self, name, value):
        return self._session_call("uservar/set", {"name": name, "value": str(value)})

    # ---- licensed string vault

    def encrypt(self, username, password, plaintext, totp=None):
        return self.call("crypto/encrypt", {"init_token": self.init_token, "username": username, "password": password,
                                            "totp": totp, "plaintext": plaintext})["ciphertext"]

    def decrypt(self, username, password, ciphertext, totp=None):
        return self.call("crypto/decrypt", {"init_token": self.init_token, "username": username, "password": password,
                                            "totp": totp, "ciphertext": ciphertext})["plaintext"]

    def rewrap(self, username, password, ciphertext, totp=None):
        return self.call("crypto/rewrap", {"init_token": self.init_token, "username": username, "password": password,
                                           "totp": totp, "ciphertext": ciphertext})

    def send_webhook(self, content, event=None):
        payload = {"init_token": self.init_token, "content": content, "event": event}
        return self._session_call("webhook", payload) if self.session_token else self.call("webhook", payload)

    # ---- files and updates

    def file_info(self, name):
        """Signed metadata and a 5-minute download ticket for a protected file."""
        payload = {"name": name, "init_token": self.init_token}
        return self._session_call("file", payload) if self.session_token else self.call("file", payload)

    def _open(self, info):
        request = urllib.request.Request(self.base_url + info["download_path"], headers={"User-Agent": "StackAuthClient/1.8 (python)"})
        try:
            return urllib.request.urlopen(request, timeout=60)
        except urllib.error.HTTPError as error:
            try:
                data = json.loads(error.read())
            except ValueError:
                data = {}
            raise StackAuthError(data.get("code", f"HTTP_{error.code}"), data.get("message", "Download failed"))

    def file_bytes(self, name):
        """Downloads and verifies a file; encrypted files are decrypted only in memory."""
        info = self.file_info(name)
        with self._open(info) as response:
            container = response.read()
        if len(container) != info["size"] or not hmac.compare_digest(hashlib.sha256(container).hexdigest(), info["sha256"]):
            raise StackAuthError("FILE_HASH_MISMATCH", "The downloaded file does not match its signed SHA-256.")
        data = self.decrypt_file_bytes(name, container) if info.get("encrypted") else container
        expected_size = info.get("plaintext_size", info["size"])
        expected_hash = info.get("plaintext_sha256", info["sha256"])
        if len(data) != expected_size or not hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected_hash):
            raise StackAuthError("FILE_HASH_MISMATCH", "The decrypted file does not match its signed SHA-256.")
        return data

    def decrypt_file_bytes(self, name, container):
        """Decrypts a downloaded SWE1 container in memory without writing plaintext to disk."""
        return _decrypt_file_container(container, self.secret, self.app_id, name)

    def _stream_to(self, info, destination):
        partial = destination + ".part"
        digest = hashlib.sha256()
        size = 0
        try:
            with self._open(info) as response, open(partial, "wb") as output:
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    digest.update(chunk)
                    output.write(chunk)
                    size += len(chunk)
            if size != info["size"] or not hmac.compare_digest(digest.hexdigest(), info["sha256"]):
                raise StackAuthError("FILE_HASH_MISMATCH", "The downloaded file does not match its signed SHA-256.")
            os.replace(partial, destination)
        except BaseException:
            if os.path.exists(partial):
                os.remove(partial)
            raise
        return {"path": destination, "size": info["size"], "sha256": info["sha256"], "encrypted": bool(info.get("encrypted")), "plaintext_size": info.get("plaintext_size"), "plaintext_sha256": info.get("plaintext_sha256")}

    def download_file(self, name, destination):
        """Streams a protected file to disk (written as .part, verified, then renamed)."""
        return self._stream_to(self.file_info(name), destination)

    def update(self):
        """Update info; works even after UPDATE_REQUIRED because it only needs a signed request."""
        return self.call("update", {})

    def download_update(self, destination):
        """Downloads the uploaded update package and verifies it. Returns None when the app uses a download link."""
        info = self.update()
        if info.get("mode") != "file":
            return None
        return {"version": info["version"], **self._stream_to(info, destination)}

    # ---- custom scripts (plain text; dashboard -> Scripts)

    def script(self, script_id, method="GET", params_in="headers"):
        """Read a custom script as text. params_in must match its "Send login in" setting."""
        method, params_in = method.upper(), params_in.lower()
        if method not in ("GET", "POST") or params_in not in ("url", "headers", "body") or (method == "GET" and params_in == "body"):
            raise StackAuthError("INVALID_INPUT", "Use GET or POST; params_in must be headers or url (POST also allows body).")

        def run():
            fields = {k: v for k, v in {"token": self.session_token, "hwid": self.hwid}.items() if v}
            url = f"{self.base_url}/api/v1/scripts/{urllib.parse.quote(self.app_id, safe='')}/{urllib.parse.quote(script_id, safe='')}"
            headers = {"User-Agent": "StackAuthClient/1.8 (python)"}
            body = None
            if params_in == "url" and fields:
                url += "?" + urllib.parse.urlencode(fields)
            elif params_in == "headers":
                if self.session_token:
                    headers["Authorization"] = "Bearer " + self.session_token
                if self.hwid:
                    headers["X-Hwid"] = self.hwid
            elif params_in == "body":
                body = urllib.parse.urlencode(fields).encode()
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            request = urllib.request.Request(url, data=body, method=method, headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=15) as response:
                    return response.read().decode("utf-8")
            except urllib.error.HTTPError as error:
                text = error.read().decode("utf-8", errors="replace").strip()
                code = error.headers.get("X-StackAuth-Error", f"HTTP_{error.code}")
                message = urllib.parse.unquote(error.headers.get("X-StackAuth-Message", "")) or text
                raise StackAuthError(code, message, {"status": error.code})

        try:
            return run()
        except StackAuthError as error:
            if error.code not in _REFRESHABLE or not self.refresh_token:
                raise
            self.refresh()
            return run()

    # ---- reporting

    # ---- in-app staff panel (member["staff"] is True; Settings -> Staff level)

    def staff_overview(self):
        return self._session_call("staff/overview")

    def staff_members(self, page=1, search=None, status=None):
        return self._session_call("staff/members", {"page": page, "search": search, "status": status})

    def staff_licenses(self, page=1, search=None, status=None):
        return self._session_call("staff/licenses", {"page": page, "search": search, "status": status})

    def staff_logs(self, page=1, kind=None, search=None):
        return self._session_call("staff/logs", {"page": page, "kind": kind, "search": search})

    def staff_create_licenses(self, count=1, level=1, days=30):
        """Up to 25 keys below your own level. days=0 is lifetime."""
        return self._session_call("staff/licenses/create", {"count": count, "level": level, "days": days})

    def staff_update_member(self, username, action, reason=None, days=None):
        """action: ban (reason), unban, reset_hwid or add_days (days)."""
        return self._session_call("staff/members/update", {"username": username, "action": action, "reason": reason, "days": days})

    def log(self, message):
        return self._session_call("log", {"message": message})

    def ban(self, reason):
        return self._session_call("ban", {"reason": reason})

    def logout(self):
        data = self.call("logout", {"session_token": self.session_token})
        self.session_token, self.refresh_token, self.member = None, None, None
        return data


if __name__ == "__main__":
    auth = StackAuth("YOUR_APP_ID", "YOUR_APP_SECRET", version="1.0", hwid="example-device", device="My PC")
    print(auth.init()["app"])
