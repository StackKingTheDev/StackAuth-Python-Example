"""StackWorkShop Auth Python desktop example (Python 3.8+, standard library only)."""

import hashlib
import json
import os
import platform
import threading
import tkinter as tk
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

import config
from stackauth import StackAuth, StackAuthError


COLORS = {
    "accent": "#4f46e5",
    "accent_dark": "#3730a3",
    "header": "#111827",
    "surface": "#f8fafc",
    "border": "#cbd5e1",
    "text": "#0f172a",
    "muted": "#64748b",
    "danger": "#dc2626",
    "success": "#16a34a",
    "warning": "#d97706",
    "white": "#ffffff",
    "code": "#f1f5f9",
}


def machine_id():
    """Return a stable example HWID without sending raw machine values."""
    raw = "|".join((platform.node(), platform.system(), platform.machine(), os.getenv("USERNAME", "")))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def date_text(value):
    if value in (None, ""):
        return "—"
    try:
        return datetime.fromtimestamp(int(value)).strftime("%x %X")
    except (TypeError, ValueError, OSError):
        return str(value)


def expiry_text(member):
    expires = member.get("expires_at")
    return date_text(expires) if expires else "Lifetime"


def json_text(value):
    return json.dumps(value, indent=2, ensure_ascii=False)


class ScrollPage(ttk.Frame):
    """A vertical, scrollable page similar to the C# example's flow panels."""

    def __init__(self, parent):
        super().__init__(parent, style="Page.TFrame")
        self.canvas = tk.Canvas(self, bg=COLORS["white"], highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.body = ttk.Frame(self.canvas, style="Page.TFrame", padding=(22, 14, 22, 22))
        self.window = self.canvas.create_window((0, 0), window=self.body, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        self.body.bind("<Configure>", self._sync_scroll)
        self.canvas.bind("<Configure>", self._sync_width)
        self.canvas.bind("<Enter>", lambda _event: self.canvas.bind_all("<MouseWheel>", self._wheel))
        self.canvas.bind("<Leave>", lambda _event: self.canvas.unbind_all("<MouseWheel>"))

    def _sync_scroll(self, _event=None):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _sync_width(self, event):
        self.canvas.itemconfigure(self.window, width=event.width)

    def _wheel(self, event):
        self.canvas.yview_scroll(int(-event.delta / 120), "units")


class StackAuthExample(tk.Tk):
    SESSION_ERRORS = {
        "BANNED",
        "SESSION_EXPIRED",
        "SUBSCRIPTION_EXPIRED",
        "REFRESH_REUSED",
        "HWID_MISMATCH",
    }

    def __init__(self):
        super().__init__()
        self.auth = StackAuth(
            config.APP_ID,
            config.APP_SECRET,
            version=config.VERSION,
            hwid=machine_id(),
            device=f"{platform.system()} · Python {platform.python_version()}",
            base_url=config.BASE_URL,
        )
        self.app_data = {}
        self.member = {}
        self.status = tk.StringVar(value="Connecting…")
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.remember = tk.BooleanVar(value=False)
        self.reg_username = tk.StringVar()
        self.reg_email = tk.StringVar()
        self.reg_password = tk.StringVar()
        self.reg_license = tk.StringVar()
        self.license_key = tk.StringVar()
        self._busy = []
        self._style()
        self.protocol("WM_DELETE_WINDOW", self.close_app)
        self.build_login()
        self.after(100, self.initialize)

    # ------------------------------------------------------------------ common UI

    def _style(self):
        self.option_add("*Font", "{Segoe UI} 10")
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=COLORS["white"], foreground=COLORS["text"])
        style.configure("Page.TFrame", background=COLORS["white"])
        style.configure("Surface.TFrame", background=COLORS["surface"])
        style.configure("Header.TFrame", background=COLORS["header"])
        style.configure("Header.TLabel", background=COLORS["header"], foreground=COLORS["white"])
        style.configure(
            "Title.TLabel",
            background=COLORS["header"],
            foreground=COLORS["white"],
            font=("Segoe UI Semibold", 16),
        )
        style.configure("TLabel", background=COLORS["white"], foreground=COLORS["text"])
        style.configure("Surface.TLabel", background=COLORS["surface"], foreground=COLORS["text"])
        style.configure("Muted.TLabel", foreground=COLORS["muted"])
        style.configure("SurfaceMuted.TLabel", background=COLORS["surface"], foreground=COLORS["muted"])
        style.configure("Section.TLabel", font=("Segoe UI Semibold", 12), padding=(0, 12, 0, 4))
        style.configure("Profile.TLabel", background=COLORS["surface"], font=("Segoe UI Semibold", 15))
        style.configure("Badge.TLabel", background=COLORS["surface"], foreground=COLORS["accent"], font=("Segoe UI Semibold", 9))
        style.configure("TEntry", padding=7, fieldbackground=COLORS["white"])
        style.configure("TCombobox", padding=6)
        style.configure("TCheckbutton", background=COLORS["white"])
        style.configure("TButton", padding=(12, 7), background=COLORS["white"], bordercolor=COLORS["border"])
        style.map("TButton", background=[("active", "#eef2ff")])
        style.configure(
            "Primary.TButton",
            background=COLORS["accent"],
            foreground=COLORS["white"],
            bordercolor=COLORS["accent_dark"],
            font=("Segoe UI Semibold", 10),
        )
        style.map("Primary.TButton", background=[("active", COLORS["accent_dark"])])
        style.configure("Danger.TButton", foreground=COLORS["danger"])
        style.configure("TNotebook", background=COLORS["white"], borderwidth=0)
        style.configure("TNotebook.Tab", padding=(15, 9), background=COLORS["surface"], foreground=COLORS["muted"])
        style.map(
            "TNotebook.Tab",
            background=[("selected", COLORS["white"])],
            foreground=[("selected", COLORS["accent"])],
        )
        style.configure("Treeview", rowheight=27, background=COLORS["white"], fieldbackground=COLORS["white"])
        style.configure("Treeview.Heading", font=("Segoe UI Semibold", 9), background=COLORS["surface"])
        style.map("Treeview", background=[("selected", "#e0e7ff")], foreground=[("selected", COLORS["text"])])

    def clear(self):
        for child in self.winfo_children():
            child.destroy()
        self._busy.clear()

    def section(self, parent, text):
        ttk.Label(parent, text=text, style="Section.TLabel").pack(fill="x")

    def text(self, parent, text, muted=False, color=None, wrap=680, style=None):
        label = ttk.Label(parent, text=text, style=style or ("Muted.TLabel" if muted else "TLabel"), wraplength=wrap)
        if color:
            label.configure(foreground=color)
        label.pack(fill="x", pady=(2, 4))
        return label

    def entry(self, parent, variable=None, show=None, width=36):
        widget = ttk.Entry(parent, textvariable=variable, show=show, width=width)
        widget.pack(fill="x", pady=(2, 8))
        return widget

    def button(self, parent, text, command, primary=False, danger=False, width=None, busy=False):
        style = "Primary.TButton" if primary else ("Danger.TButton" if danger else "TButton")
        widget = ttk.Button(parent, text=text, command=command, style=style, width=width)
        widget.pack(side="left", padx=(0, 8), pady=4)
        if busy:
            self._busy.append(widget)
        return widget

    def row(self, parent):
        frame = ttk.Frame(parent, style="Page.TFrame")
        frame.pack(fill="x", pady=2)
        return frame

    def output(self, parent, height=5):
        widget = tk.Text(
            parent,
            height=height,
            wrap="word",
            bg=COLORS["code"],
            fg=COLORS["text"],
            insertbackground=COLORS["text"],
            relief="solid",
            borderwidth=1,
            highlightthickness=0,
            font=("Cascadia Mono", 9),
            padx=10,
            pady=8,
        )
        widget.pack(fill="x", pady=(2, 8))
        return widget

    @staticmethod
    def set_output(widget, value, append=False):
        widget.configure(state="normal")
        if not append:
            widget.delete("1.0", "end")
        elif widget.get("1.0", "end-1c"):
            widget.insert("end", "\n")
        widget.insert("end", str(value))
        widget.see("end")
        widget.configure(state="disabled")

    def make_table(self, parent, columns, height=6):
        frame = ttk.Frame(parent, style="Page.TFrame")
        frame.pack(fill="x", pady=(4, 8))
        table = ttk.Treeview(frame, columns=[key for key, _label, _width in columns], show="headings", height=height)
        for key, label, width in columns:
            table.heading(key, text=label)
            table.column(key, width=width, minwidth=45, stretch=True)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=table.yview)
        table.configure(yscrollcommand=scrollbar.set)
        table.pack(side="left", fill="x", expand=True)
        scrollbar.pack(side="right", fill="y")
        return table

    @staticmethod
    def fill_table(table, rows, columns):
        table.delete(*table.get_children())
        for row in rows:
            values = []
            for key in columns:
                value = row.get(key)
                if key.endswith("_at"):
                    value = date_text(value)
                elif isinstance(value, bool):
                    value = "Yes" if value else "No"
                elif value is None:
                    value = "Lifetime" if key == "expires_at" else "—"
                values.append(value)
            table.insert("", "end", values=values)

    def page(self, notebook, title):
        page = ScrollPage(notebook)
        notebook.add(page, text=title)
        return page.body

    def set_busy(self, busy):
        for control in self._busy:
            try:
                control.configure(state="disabled" if busy else "normal")
            except tk.TclError:
                pass
        self.configure(cursor="watch" if busy else "")

    def set_status(self, text, color=None):
        self.status.set(text)
        if getattr(self, "status_label", None):
            self.status_label.configure(foreground=color or COLORS["muted"])

    def run_task(self, operation, on_success=None, message="Working…", on_error=None):
        self.set_busy(True)
        self.set_status(message)

        def worker():
            try:
                result = operation()
            except Exception as error:
                self.after(0, lambda current=error: self.finish_error(current, on_error))
            else:
                self.after(0, lambda current=result: self.finish_success(current, on_success))

        threading.Thread(target=worker, daemon=True).start()

    def finish_success(self, result, callback):
        self.set_busy(False)
        self.set_status("Ready", COLORS["success"])
        if callback:
            callback(result)

    def finish_error(self, error, callback=None):
        self.set_busy(False)
        if callback and callback(error):
            return
        text = self.error_text(error)
        self.set_status(text, COLORS["danger"])
        if isinstance(error, StackAuthError) and error.code in self.SESSION_ERRORS:
            messagebox.showwarning("Signed out", text, parent=self)
            self.show_login_again()
            return
        messagebox.showerror("StackWorkShop Auth", text, parent=self)

    @staticmethod
    def error_text(error):
        if isinstance(error, StackAuthError):
            return f"{error.code}: {error.message}"
        return str(error)

    def with_fresh_init(self, operation):
        try:
            return operation()
        except StackAuthError as error:
            if error.code != "INIT_REQUIRED":
                raise
            self.auth.init()
            return operation()

    # ------------------------------------------------------------------ login

    def build_login(self):
        self.clear()
        self.title("Sign in · StackWorkShop Auth Python example")
        self.geometry("500x670")
        self.resizable(False, False)
        self.configure(bg=COLORS["white"])

        header = ttk.Frame(self, style="Header.TFrame", padding=(20, 13, 20, 10))
        header.pack(fill="x")
        self.login_title = ttk.Label(header, text="StackWorkShop Auth", style="Title.TLabel")
        self.login_title.pack(anchor="w")
        self.login_subtitle = ttk.Label(header, text="Connecting…", style="Header.TLabel")
        self.login_subtitle.pack(anchor="w", pady=(3, 0))

        announcement = ttk.Frame(self, style="Surface.TFrame", padding=(20, 10))
        announcement.pack(fill="x")
        self.announcement_label = ttk.Label(
            announcement,
            text="Loading the application announcement…",
            style="Surface.TLabel",
            wraplength=450,
        )
        self.announcement_label.pack(fill="x")

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)
        self.login_notebook = notebook

        signin = ttk.Frame(notebook, style="Page.TFrame", padding=(28, 20))
        register = ttk.Frame(notebook, style="Page.TFrame", padding=(28, 16))
        license_page = ttk.Frame(notebook, style="Page.TFrame", padding=(28, 20))
        notebook.add(signin, text="Sign in")
        notebook.add(register, text="Register")
        notebook.add(license_page, text="License key")

        self.text(signin, "Username")
        self.entry(signin, self.username)
        self.text(signin, "Password")
        password_entry = self.entry(signin, self.password, show="•")
        remember = ttk.Checkbutton(
            signin,
            text="Remember me while this app stays open",
            variable=self.remember,
        )
        remember.pack(anchor="w", pady=(0, 8))
        signin_actions = self.row(signin)
        self.button(signin_actions, "Sign in", self.login, primary=True, width=32, busy=True)
        password_entry.bind("<Return>", lambda _event: self.login())

        self.text(register, "Username")
        self.entry(register, self.reg_username)
        self.text(register, "Email (optional)")
        self.entry(register, self.reg_email)
        self.text(register, "Password (8+ characters)")
        self.entry(register, self.reg_password, show="•")
        self.text(register, "License key (optional in free mode)")
        self.entry(register, self.reg_license)
        register_actions = self.row(register)
        self.button(register_actions, "Create account", self.register, primary=True, width=32, busy=True)

        self.text(
            license_page,
            "Sign in with only a license key. The first use creates a key-only account; afterward the same key signs you in.",
            muted=True,
            wrap=420,
        )
        self.text(license_page, "License key")
        self.entry(license_page, self.license_key)
        license_actions = self.row(license_page)
        self.button(license_actions, "Continue with key", self.license_login, primary=True, width=32, busy=True)

        footer = ttk.Frame(self, style="Surface.TFrame", padding=(20, 9, 20, 10))
        footer.pack(fill="x")
        ttk.Label(
            footer,
            text="Try the demo (shared accounts, read-only):",
            style="SurfaceMuted.TLabel",
            font=("Segoe UI Semibold", 9),
        ).pack(anchor="w")
        demo_row = ttk.Frame(footer, style="Surface.TFrame")
        demo_row.pack(fill="x")
        member_button = ttk.Button(
            demo_row,
            text="Sign in as demo member",
            command=lambda: self.demo_login(*config.DEMO_MEMBER),
        )
        member_button.pack(side="left", padx=(0, 8), pady=5)
        admin_button = ttk.Button(
            demo_row,
            text="Sign in as demo admin",
            command=lambda: self.demo_login(*config.DEMO_ADMIN),
        )
        admin_button.pack(side="left", pady=5)
        self._busy.extend((member_button, admin_button))
        self.status_label = ttk.Label(footer, textvariable=self.status, style="SurfaceMuted.TLabel", wraplength=450)
        self.status_label.pack(fill="x")
        self.set_busy(True)

    def initialize(self):
        self.run_task(self.auth.init, self.initialized, "Connecting to StackWorkShop Auth…")

    def initialized(self, data):
        self.app_data = data["app"]
        self.login_title.configure(text=self.app_data.get("name", "StackWorkShop Auth"))
        self.login_subtitle.configure(
            text=f"Version {config.VERSION} · server version {self.app_data.get('version', '—')}"
        )
        self.announcement_label.configure(text=self.app_data.get("announcement") or "No announcement.")
        try:
            if not self.app_data.get("registration_open", True):
                self.login_notebook.tab(1, state="disabled")
        except tk.TclError:
            pass
        if self.app_data.get("outdated"):
            self.set_status(
                f"A newer version ({self.app_data.get('version')}) is available.",
                COLORS["warning"],
            )
        else:
            self.set_status("Ready. Sign in, register, or use a license key.", COLORS["success"])

    def require(self, *values):
        if any(not value.strip() for value in values):
            raise ValueError("Complete the required fields.")

    def login(self):
        username, password = self.username.get().strip(), self.password.get()
        try:
            self.require(username, password)
        except ValueError as error:
            self.finish_error(error)
            return

        def handle(error):
            if not isinstance(error, StackAuthError) or error.code != "TOTP_REQUIRED":
                return False
            code = simpledialog.askstring(
                "Two-step verification",
                "Enter the 6-digit code from your authenticator app:",
                parent=self,
            )
            if code:
                self.run_task(
                    lambda: (self.auth.init(), self.auth.login(username, password, totp=code))[1],
                    self.signed_in,
                    "Checking the verification code…",
                )
            return True

        self.run_task(
            lambda: self.auth.login(username, password),
            self.signed_in,
            "Signing in…",
            handle,
        )

    def demo_login(self, username, password):
        self.username.set(username)
        self.password.set(password)
        self.login()

    def register(self):
        username = self.reg_username.get().strip()
        password = self.reg_password.get()
        try:
            self.require(username, password)
        except ValueError as error:
            self.finish_error(error)
            return
        self.run_task(
            lambda: self.auth.register(
                username,
                password,
                license=self.reg_license.get().strip() or None,
                email=self.reg_email.get().strip() or None,
            ),
            self.signed_in,
            "Creating your account…",
        )

    def license_login(self):
        key = self.license_key.get().strip()
        if not key:
            self.finish_error(ValueErro…3942 tokens truncated…eparate from sessions. Decrypting requires the account credentials and an active license. Ship the ciphertext in your tool and decrypt it at runtime.",
            muted=True,
        )
        credentials = self.row(page)
        self.vault_username = tk.StringVar(value=self.member.get("username", ""))
        self.vault_password = tk.StringVar()
        ttk.Entry(credentials, textvariable=self.vault_username, width=24).pack(side="left", padx=(0, 8), pady=4)
        ttk.Entry(credentials, textvariable=self.vault_password, show="•", width=24).pack(
            side="left", padx=(0, 8), pady=4
        )
        self.text(page, "Plain text")
        self.vault_plain = self.output(page, 4)
        self.vault_plain.configure(state="normal")
        self.vault_plain.insert("1.0", "My secret config string")
        vault_actions = self.row(page)
        self.button(vault_actions, "Encrypt", self.vault_encrypt, busy=True)
        self.text(page, "Ciphertext")
        self.vault_cipher = self.output(page, 5)
        self.vault_cipher.configure(state="normal")
        decrypt_actions = self.row(page)
        self.button(decrypt_actions, "Decrypt", self.vault_decrypt, busy=True)
        self.text(page, "Result")
        self.vault_result = self.output(page, 4)

    def vault_credentials(self):
        username = self.vault_username.get().strip()
        password = self.vault_password.get()
        self.require(username, password)
        return username, password

    def vault_encrypt(self):
        try:
            username, password = self.vault_credentials()
        except ValueError as error:
            self.finish_error(error)
            return
        plain = self.vault_plain.get("1.0", "end-1c")
        self.run_task(
            lambda: self.with_fresh_init(lambda: self.auth.encrypt(username, password, plain)),
            lambda value: self.set_output(self.vault_cipher, value),
            "Encrypting…",
        )

    def vault_decrypt(self):
        try:
            username, password = self.vault_credentials()
        except ValueError as error:
            self.finish_error(error)
            return
        cipher = self.vault_cipher.get("1.0", "end-1c").strip()
        self.run_task(
            lambda: self.with_fresh_init(lambda: self.auth.decrypt(username, password, cipher)),
            lambda value: self.set_output(self.vault_result, f"Decrypted: {value}"),
            "Decrypting…",
        )

    # ------------------------------------------------------------------ account

    def build_account_tab(self):
        page = self.page(self.dashboard_tabs, "Account")
        self.account_output = self.output(page, 5)

        self.section(page, "Redeem a license key")
        self.text(page, "Adds the key's days to your account and raises your level to the key level.", muted=True)
        redeem = self.row(page)
        self.redeem_key = tk.StringVar()
        ttk.Entry(redeem, textvariable=self.redeem_key, width=34).pack(side="left", padx=(0, 8), pady=4)
        self.button(redeem, "Redeem", self.redeem, busy=True)

        self.section(page, "Change password")
        passwords = self.row(page)
        self.current_password = tk.StringVar()
        self.new_password = tk.StringVar()
        ttk.Entry(passwords, textvariable=self.current_password, show="•", width=24).pack(
            side="left", padx=(0, 8), pady=4
        )
        ttk.Entry(passwords, textvariable=self.new_password, show="•", width=24).pack(
            side="left", padx=(0, 8), pady=4
        )
        self.button(passwords, "Change", self.change_password, busy=True)

        self.section(page, "Two-step verification (authenticator app)")
        two_factor = self.row(page)
        self.button(two_factor, "Turn on 2FA…", self.enable_2fa, busy=True)
        self.button(two_factor, "Turn off 2FA…", self.disable_2fa, busy=True)

        self.section(page, "Self-service HWID reset")
        self.text(
            page,
            "Moved to a new PC? Release the device lock with your username and password (rate-limited).",
            muted=True,
        )
        hwid = self.row(page)
        self.hwid_username = tk.StringVar(value=self.member.get("username", ""))
        self.hwid_password = tk.StringVar()
        ttk.Entry(hwid, textvariable=self.hwid_username, width=24).pack(side="left", padx=(0, 8), pady=4)
        ttk.Entry(hwid, textvariable=self.hwid_password, show="•", width=24).pack(
            side="left", padx=(0, 8), pady=4
        )
        self.button(hwid, "Reset HWID", self.reset_hwid, busy=True)

        self.section(page, "Devices (sessions)")
        session_columns = (
            ("device", "Device", 150),
            ("ip", "IP", 100),
            ("method", "Method", 90),
            ("created_at", "Signed in", 120),
            ("last_seen_at", "Last seen", 120),
            ("current", "This one", 70),
            ("id", "Id", 70),
        )
        self.sessions_table = self.make_table(page, session_columns, 5)
        sessions = self.row(page)
        self.button(sessions, "Reload", self.load_sessions, busy=True)
        self.button(sessions, "Sign out selected device", self.revoke_session, busy=True)
        self.button(sessions, "Sign out all other devices", self.revoke_other_sessions, busy=True)

        self.section(page, "Reporting")
        reporting = self.row(page)
        self.report_message = tk.StringVar(value="Hello from the Python example")
        ttk.Entry(reporting, textvariable=self.report_message, width=44).pack(side="left", padx=(0, 8), pady=4)
        self.button(reporting, "Write to app log", self.send_log, busy=True)
        self.button(reporting, "Send to Discord", self.send_webhook, busy=True)
        self.text(
            page,
            "The Discord relay is off in the public demo app. Turn it on in your own app settings.",
            muted=True,
        )
        self.after(100, self.load_sessions)

    def account_message(self, text):
        self.set_output(self.account_output, text)

    def redeem(self):
        key = self.redeem_key.get().strip()
        if not key:
            self.finish_error(ValueError("Enter a license key."))
            return

        def complete(data):
            self.member = data.get("member", self.auth.member or self.member)
            self.render_profile()
            self.account_message(f"Redeemed. Level {self.member.get('level')}, access {expiry_text(self.member)}.")

        self.run_task(lambda: self.auth.redeem(key), complete, "Redeeming the key…")

    def change_password(self):
        self.run_task(
            lambda: self.auth.reset_password(self.current_password.get(), self.new_password.get()),
            lambda _data: self.account_message("Password changed. Your other devices were signed out."),
            "Changing the password…",
        )

    def enable_2fa(self):
        def setup_ready(data):
            secret = data.get("secret", "")
            code = simpledialog.askstring(
                "Turn on 2FA",
                f"Add this key to your authenticator app, then enter the code:\n\n{secret}",
                parent=self,
            )
            if code:
                self.run_task(
                    lambda: self.auth.enable_2fa(code),
                    lambda _result: self.two_factor_changed("2FA is on. You'll need a code at every sign-in."),
                    "Enabling 2FA…",
                )

        self.run_task(self.auth.setup_2fa, setup_ready, "Preparing 2FA…")

    def disable_2fa(self):
        password = simpledialog.askstring("Turn off 2FA", "Your password:", show="•", parent=self)
        if password is None:
            return
        code = simpledialog.askstring(
            "Turn off 2FA",
            "A code from your authenticator app:",
            parent=self,
        )
        if code:
            self.run_task(
                lambda: self.auth.disable_2fa(password, code),
                lambda _result: self.two_factor_changed("2FA is off."),
                "Disabling 2FA…",
            )

    def two_factor_changed(self, message):
        self.account_message(message)
        self.refresh_profile()

    def reset_hwid(self):
        username, password = self.hwid_username.get().strip(), self.hwid_password.get()
        self.run_task(
            lambda: self.with_fresh_init(lambda: self.auth.reset_hwid(username, password)),
            lambda data: self.account_message(
                f"HWID released. Resets left this window: {data.get('resets_remaining', '—')}."
            ),
            "Resetting the HWID…",
        )

    def load_sessions(self):
        if not getattr(self, "sessions_table", None):
            return
        self.run_task(
            self.auth.sessions,
            lambda rows: self.fill_table(
                self.sessions_table,
                rows,
                ("device", "ip", "method", "created_at", "last_seen_at", "current", "id"),
            ),
            "Loading devices…",
        )

    def selected_session_id(self):
        selected = self.sessions_table.selection()
        if not selected:
            raise ValueError("Pick a device in the list first.")
        values = self.sessions_table.item(selected[0], "values")
        return values[-1]

    def revoke_session(self):
        try:
            session_id = self.selected_session_id()
        except ValueError as error:
            self.finish_error(error)
            return
        self.run_task(
            lambda: self.auth.revoke_session(session_id),
            lambda _data: (self.account_message("The selected device was signed out."), self.load_sessions()),
            "Signing out the selected device…",
        )

    def revoke_other_sessions(self):
        self.run_task(
            self.auth.revoke_other_sessions,
            lambda data: (
                self.account_message(f"Signed out {data.get('revoked', 0)} other device(s)."),
                self.load_sessions(),
            ),
            "Signing out other devices…",
        )

    def send_log(self):
        self.run_task(
            lambda: self.auth.log(self.report_message.get()),
            lambda _data: self.account_message("Logged."),
            "Writing the app log…",
        )

    def send_webhook(self):
        self.run_task(
            lambda: self.with_fresh_init(
                lambda: self.auth.send_webhook(self.report_message.get(), "python-example")
            ),
            lambda _data: self.account_message("Sent to the app Discord webhook."),
            "Sending to Discord…",
        )

    # ------------------------------------------------------------------ staff panel

    def build_admin_tab(self):
        page = self.page(self.dashboard_tabs, "Admin")
        self.section(page, "Overview")
        if self.member.get("demo"):
            self.text(
                page,
                "Demo admin: you can see the panel, but changes are disabled and emails and keys are masked. A staff account in your own app can make these changes.",
                color=COLORS["warning"],
            )
        self.admin_stats = self.text(page, "Loading…")
        admin_reload = self.row(page)
        self.button(admin_reload, "Reload everything", self.load_admin, busy=True)

        self.section(page, "Members")
        filters = self.row(page)
        self.member_search = tk.StringVar()
        self.member_status = tk.StringVar(value="all")
        ttk.Entry(filters, textvariable=self.member_search, width=25).pack(side="left", padx=(0, 8), pady=4)
        ttk.Combobox(
            filters,
            textvariable=self.member_status,
            values=("all", "active", "banned", "expired"),
            state="readonly",
            width=11,
        ).pack(side="left", padx=(0, 8), pady=4)
        self.button(filters, "Search", self.load_admin_members, busy=True)
        member_columns = (
            ("username", "Username", 110),
            ("email", "Email", 130),
            ("level", "Level", 50),
            ("expires_at", "Expires", 110),
            ("banned", "Banned", 60),
            ("staff", "Staff", 55),
            ("totp_enabled", "2FA", 50),
            ("last_login_at", "Last sign-in", 110),
        )
        self.admin_members = self.make_table(page, member_columns, 6)
        actions = self.row(page)
        self.admin_reason = tk.StringVar()
        self.admin_days = tk.IntVar(value=7)
        self.button(actions, "Ban", lambda: self.update_member("ban"), busy=True)
        ttk.Entry(actions, textvariable=self.admin_reason, width=20).pack(side="left", padx=(0, 8), pady=4)
        self.button(actions, "Unban", lambda: self.update_member("unban"), busy=True)
        self.button(actions, "Reset HWID", lambda: self.update_member("reset_hwid"), busy=True)
        ttk.Spinbox(actions, from_=1, to=3650, textvariable=self.admin_days, width=6).pack(
            side="left", padx=(0, 8), pady=4
        )
        self.button(actions, "Add days", lambda: self.update_member("add_days"), busy=True)

        self.section(page, "License keys")
        license_filters = self.row(page)
        self.license_status = tk.StringVar(value="all")
        ttk.Combobox(
            license_filters,
            textvariable=self.license_status,
            values=("all", "unused", "used", "banned"),
            state="readonly",
            width=11,
        ).pack(side="left", padx=(0, 8), pady=4)
        self.button(license_filters, "Show", self.load_admin_licenses, busy=True)
        license_columns = (
            ("key", "Key", 180),
            ("level", "Level", 50),
            ("days", "Days", 50),
            ("status", "Status", 70),
            ("used_by", "Used by", 100),
            ("created_at", "Created", 110),
        )
        self.admin_licenses = self.make_table(page, license_columns, 5)
        create = self.row(page)
        self.key_count = tk.IntVar(value=5)
        self.key_level = tk.IntVar(value=1)
        self.key_days = tk.IntVar(value=30)
        self.text_inline(create, "Create")
        ttk.Spinbox(create, from_=1, to=25, textvariable=self.key_count, width=5).pack(
            side="left", padx=(0, 6), pady=4
        )
        self.text_inline(create, "keys, level")
        ttk.Spinbox(create, from_=0, to=1000, textvariable=self.key_level, width=5).pack(
            side="left", padx=(0, 6), pady=4
        )
        self.text_inline(create, "days")
        ttk.Spinbox(create, from_=0, to=3650, textvariable=self.key_days, width=6).pack(
            side="left", padx=(0, 6), pady=4
        )
        self.button(create, "Create", self.create_licenses, primary=True, busy=True)
        self.admin_output = self.output(page, 5)

        self.section(page, "Recent activity")
        log_columns = (
            ("at", "Time", 120),
            ("kind", "Event", 100),
            ("actor", "Who", 100),
            ("message", "Details", 270),
        )
        self.admin_logs = self.make_table(page, log_columns, 6)
        self.after(100, self.load_admin)

    @staticmethod
    def text_inline(parent, value):
        ttk.Label(parent, text=value).pack(side="left", padx=(0, 6), pady=4)

    def load_admin(self):
        def complete(data):
            stats = data.get("stats", {})
            members = stats.get("members", {})
            licenses = stats.get("licenses", {})
            self.admin_stats.configure(
                text=(
                    f"Members: {members.get('total', 0)} total · {members.get('active', 0)} active · "
                    f"{members.get('banned', 0)} banned     Online now: {stats.get('online_members', 0)}     "
                    f"Logins (24 h): {stats.get('logins_24h', 0)}\n"
                    f"License keys: {licenses.get('total', 0)} total · {licenses.get('unused', 0)} unused · "
                    f"{licenses.get('used', 0)} used     Staff level: {data.get('staff_level', '—')}"
                )
            )
            self.load_admin_members()
            self.load_admin_licenses()
            self.run_task(
                self.auth.staff_logs,
                lambda logs: self.fill_table(
                    self.admin_logs,
                    logs.get("logs", []),
                    ("at", "kind", "actor", "message"),
                ),
                "Loading recent activity…",
            )

        self.run_task(self.auth.staff_overview, complete, "Loading staff overview…")

    def load_admin_members(self):
        status = self.member_status.get()
        self.run_task(
            lambda: self.auth.staff_members(
                1,
                self.member_search.get().strip() or None,
                None if status == "all" else status,
            ),
            lambda data: self.fill_table(
                self.admin_members,
                data.get("members", []),
                ("username", "email", "level", "expires_at", "banned", "staff", "totp_enabled", "last_login_at"),
            ),
            "Loading members…",
        )

    def load_admin_licenses(self):
        status = self.license_status.get()
        self.run_task(
            lambda: self.auth.staff_licenses(1, None, None if status == "all" else status),
            lambda data: self.fill_table(
                self.admin_licenses,
                data.get("licenses", []),
                ("key", "level", "days", "status", "used_by", "created_at"),
            ),
            "Loading license keys…",
        )

    def selected_admin_username(self):
        selected = self.admin_members.selection()
        if not selected:
            raise ValueError("Pick a member in the list first.")
        return self.admin_members.item(selected[0], "values")[0]

    def update_member(self, action):
        try:
            username = self.selected_admin_username()
        except ValueError as error:
            self.finish_error(error)
            return
        self.run_task(
            lambda: self.auth.staff_update_member(
                username,
                action,
                reason=self.admin_reason.get().strip() or None,
                days=self.admin_days.get() if action == "add_days" else None,
            ),
            lambda data: (
                self.set_output(
                    self.admin_output,
                    f"{username}: {action.replace('_', ' ')} done. Access {expiry_text(data.get('member', {}))}.",
                ),
                self.load_admin_members(),
            ),
            f"Updating {username}…",
        )

    def create_licenses(self):
        self.run_task(
            lambda: self.auth.staff_create_licenses(
                self.key_count.get(),
                self.key_level.get(),
                self.key_days.get(),
            ),
            lambda data: (
                self.set_output(self.admin_output, "New keys:\n" + "\n".join(data.get("keys", []))),
                self.load_admin_licenses(),
            ),
            "Creating license keys…",
        )

    # ------------------------------------------------------------------ lifecycle

    def logout(self):
        self.run_task(self.auth.logout, lambda _data: self.show_login_again(), "Signing out…")

    def show_login_again(self):
        self.auth.session_token = None
        self.auth.refresh_token = None
        self.auth.member = None
        self.member = {}
        self.status.set("Ready. Sign in, register, or use a license key.")
        self.build_login()
        self.initialized({"app": self.app_data})

    def close_app(self):
        if self.auth.session_token and not self.remember.get():
            threading.Thread(target=self._safe_logout, daemon=True).start()
        self.destroy()

    def _safe_logout(self):
        try:
            self.auth.logout()
        except Exception:
            pass


if __name__ == "__main__":
    StackAuthExample().mainloop()
