"""StackWorkShop Auth Python desktop example (Python 3.8+, standard library only)."""

import hashlib
import json
import os
import platform
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

import config
from stackauth import StackAuth, StackAuthError


def machine_id():
    """Stable, privacy-preserving example HWID."""
    raw = "|".join((platform.node(), platform.system(), platform.machine(), os.getenv("USERNAME", "")))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class StackAuthExample(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("StackWorkShop Auth · Python Example")
        self.geometry("1020x700")
        self.minsize(850, 610)
        self.configure(bg="#090f1c")
        self.auth = StackAuth(
            config.APP_ID,
            config.APP_SECRET,
            version=config.VERSION,
            hwid=machine_id(),
            device=f"{platform.system()} · Python {platform.python_version()}",
            base_url=config.BASE_URL,
        )
        self.status = tk.StringVar(value="Connecting to StackWorkShop Auth…")
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.license_key = tk.StringVar()
        self.email = tk.StringVar()
        self.totp = tk.StringVar()
        self._style()
        self._build()
        self.after(100, lambda: self.run_task(self.auth.init, self.on_initialized))

    def _style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background="#0c1424", foreground="#dce7ff", fieldbackground="#111d31")
        style.configure("TFrame", background="#0c1424")
        style.configure("Card.TFrame", background="#101b2e")
        style.configure("TLabel", background="#0c1424", foreground="#dce7ff", font=("Segoe UI", 10))
        style.configure("Title.TLabel", font=("Segoe UI Semibold", 24), foreground="#ffffff")
        style.configure("Muted.TLabel", foreground="#94a3b8")
        style.configure("TButton", font=("Segoe UI Semibold", 10), padding=(12, 8), background="#2563eb")
        style.map("TButton", background=[("active", "#3b82f6")])
        style.configure("Secondary.TButton", background="#1f2a44")
        style.configure("Danger.TButton", background="#7f1d1d")
        style.configure("TEntry", padding=8)
        style.configure("TNotebook", background="#0c1424", borderwidth=0)
        style.configure("TNotebook.Tab", padding=(16, 9), background="#111d31", foreground="#94a3b8")
        style.map("TNotebook.Tab", background=[("selected", "#2563eb")], foreground=[("selected", "#ffffff")])
        style.configure("Treeview", rowheight=28, background="#0d1728", fieldbackground="#0d1728")
        style.configure("Treeview.Heading", font=("Segoe UI Semibold", 10), background="#17233a")

    def _build(self):
        header = ttk.Frame(self, padding=(28, 22))
        header.pack(fill="x")
        ttk.Label(header, text="StackWorkShop Auth", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text="Python example", style="Muted.TLabel").pack(side="left", padx=14)
        ttk.Label(header, textvariable=self.status, style="Muted.TLabel").pack(side="right")

        self.pages = ttk.Notebook(self)
        self.pages.pack(fill="both", expand=True, padx=28, pady=(0, 20))
        self.signin_page = ttk.Frame(self.pages, padding=24)
        self.dashboard_page = ttk.Frame(self.pages, padding=24)
        self.pages.add(self.signin_page, text="Sign in")
        self.pages.add(self.dashboard_page, text="Member dashboard")
        self.pages.tab(1, state="disabled")
        self._build_signin()
        self._build_dashboard()

        self.log = tk.Text(self, height=7, bg="#070c16", fg="#a7f3d0", insertbackground="white",
                           relief="flat", font=("Cascadia Mono", 9), padx=12, pady=10)
        self.log.pack(fill="x", padx=28, pady=(0, 20))
        self.write_log("Starting the signed Auth client…")

    def _build_signin(self):
        intro = ttk.Frame(self.signin_page)
        intro.pack(fill="x", pady=(0, 18))
        ttk.Label(intro, text="Try a complete signed authentication flow", font=("Segoe UI Semibold", 16)).pack(anchor="w")
        ttk.Label(intro, text="Use either public demo account or connect this project to your own app in config.py.",
                  style="Muted.TLabel").pack(anchor="w", pady=(5, 0))

        demo = ttk.Frame(self.signin_page)
        demo.pack(fill="x", pady=(0, 18))
        ttk.Button(demo, text="Use demo member", command=lambda: self.fill_demo(*config.DEMO_MEMBER)).pack(side="left")
        ttk.Button(demo, text="Use demo admin", style="Secondary.TButton",
                   command=lambda: self.fill_demo(*config.DEMO_ADMIN)).pack(side="left", padx=10)

        form = ttk.Frame(self.signin_page, style="Card.TFrame", padding=22)
        form.pack(fill="x")
        for col in range(4):
            form.columnconfigure(col, weight=1)

        self.field(form, "Username", self.username, 0, 0)
        self.field(form, "Password", self.password, 0, 1, show="•")
        self.field(form, "Email (register)", self.email, 1, 0)
        self.field(form, "License key", self.license_key, 1, 1)
        self.field(form, "TOTP (optional)", self.totp, 2, 0)

        actions = ttk.Frame(form, style="Card.TFrame")
        actions.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(18, 0))
        ttk.Button(actions, text="Sign in", command=self.login).pack(side="left")
        ttk.Button(actions, text="Register", style="Secondary.TButton", command=self.register).pack(side="left", padx=8)
        ttk.Button(actions, text="License login", style="Secondary.TButton", command=self.license_login).pack(side="left")
        ttk.Button(actions, text="Reset HWID", style="Secondary.TButton", command=self.reset_hwid).pack(side="left", padx=8)

    def field(self, parent, label, variable, row, column, show=None):
        box = ttk.Frame(parent, style="Card.TFrame")
        box.grid(row=row, column=column * 2, columnspan=2, sticky="ew", padx=(0 if column == 0 else 8, 8), pady=6)
        ttk.Label(box, text=label, background="#101b2e").pack(anchor="w")
        ttk.Entry(box, textvariable=variable, show=show).pack(fill="x", pady=(4, 0))

    def _build_dashboard(self):
        self.profile = ttk.Label(self.dashboard_page, text="Not signed in", font=("Segoe UI Semibold", 17))
        self.profile.pack(anchor="w")
        self.profile_detail = ttk.Label(self.dashboard_page, text="", style="Muted.TLabel")
        self.profile_detail.pack(anchor="w", pady=(4, 18))

        grid = ttk.Frame(self.dashboard_page)
        grid.pack(fill="both", expand=True)
        buttons = [
            ("Read variable", self.read_variable),
            ("Read custom script", self.read_script),
            ("View protected file in memory", self.view_file),
            ("Download protected file", self.download_file),
            ("Check subscription", self.check_subscription),
            ("List sessions/devices", self.list_sessions),
            ("Check update", self.check_update),
            ("Staff overview", self.staff_overview),
            ("Redeem license", self.redeem),
            ("Send app log", self.send_log),
        ]
        for index, (label, callback) in enumerate(buttons):
            ttk.Button(grid, text=label, command=callback).grid(
                row=index // 2, column=index % 2, sticky="ew", padx=6, pady=6
            )
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)
        ttk.Button(self.dashboard_page, text="Sign out", style="Danger.TButton", command=self.logout).pack(anchor="e", pady=(14, 0))

    def write_log(self, message):
        self.log.insert("end", f"{message}\n")
        self.log.see("end")

    def run_task(self, operation, on_success=None):
        self.status.set("Working…")

        def worker():
            try:
                result = operation()
            except Exception as error:
                self.after(0, lambda current=error: self.on_error(current))
            else:
                self.after(0, lambda: self.on_success(result, on_success))

        threading.Thread(target=worker, daemon=True).start()

    def on_success(self, result, callback):
        self.status.set("Connected · signed responses verified")
        if callback:
            callback(result)

    def on_error(self, error):
        self.status.set("Request failed")
        if isinstance(error, StackAuthError):
            text = f"{error.code}: {error.message}"
        else:
            text = str(error)
        self.write_log("ERROR · " + text)
        messagebox.showerror("StackWorkShop Auth", text)

    def on_initialized(self, data):
        app = data["app"]
        self.status.set(f"Connected to {app['name']} · v{app['version']}")
        self.write_log(f"INIT OK · {app['name']} v{app['version']} · signed response verified")

    def fill_demo(self, username, password):
        self.username.set(username)
        self.password.set(password)
        self.write_log(f"Filled shared demo login: {username}")

    def credentials(self):
        username, password = self.username.get().strip(), self.password.get()
        if not username or not password:
            raise ValueError("Enter a username and password.")
        return username, password

    def login(self):
        try:
            username, password = self.credentials()
        except ValueError as error:
            return self.on_error(error)
        self.run_task(lambda: self.auth.login(username, password, totp=self.totp.get().strip() or None), self.show_member)

    def register(self):
        try:
            username, password = self.credentials()
        except ValueError as error:
            return self.on_error(error)
        self.run_task(
            lambda: self.auth.register(username, password, license=self.license_key.get().strip() or None,
                                       email=self.email.get().strip() or None),
            self.show_member,
        )

    def license_login(self):
        key = self.license_key.get().strip()
        if not key:
            return self.on_error(ValueError("Enter a license key."))
        self.run_task(lambda: self.auth.license(key, totp=self.totp.get().strip() or None), self.show_member)

    def reset_hwid(self):
        try:
            username, password = self.credentials()
        except ValueError as error:
            return self.on_error(error)
        self.run_task(lambda: self.auth.reset_hwid(username, password, self.totp.get().strip() or None),
                      lambda _data: messagebox.showinfo("HWID reset", "The member HWID was reset."))

    def show_member(self, data):
        member = data.get("member", self.auth.member) or {}
        expires = member.get("expires_at") or "Lifetime"
        role = "Staff/admin" if member.get("staff") else "Member"
        self.profile.config(text=f"{member.get('username', 'Member')} · {role}")
        self.profile_detail.config(
            text=f"Level {member.get('level', 0)} · Expires: {expires} · Session: {self.auth.session_id or 'active'}"
        )
        self.pages.tab(1, state="normal")
        self.pages.select(1)
        self.write_log(f"LOGIN OK · {member.get('username')} · level {member.get('level')} · {expires}")

    def read_variable(self):
        name = simpledialog.askstring("Variable", "Variable name:", initialvalue=config.VARIABLES[0], parent=self)
        if name:
            self.run_task(lambda: self.auth.variable(name), lambda value: self.show_text(f"Variable · {name}", value))

    def read_script(self):
        script_id = simpledialog.askstring("Custom script", "Script ID:", initialvalue=config.MEMBER_SCRIPT, parent=self)
        if script_id:
            params = "url" if script_id == config.PUBLIC_SCRIPT else "headers"
            self.run_task(lambda: self.auth.script(script_id, method="GET", params_in=params),
                          lambda value: self.show_text(f"Script · {script_id}", value))

    def view_file(self):
        self.run_task(lambda: self.auth.file_bytes(config.PROTECTED_FILE),
                      lambda data: self.show_text(f"File in memory · {config.PROTECTED_FILE}",
                                                  data.decode("utf-8", errors="replace")))

    def download_file(self):
        destination = filedialog.asksaveasfilename(parent=self, initialfile=config.PROTECTED_FILE)
        if destination:
            self.run_task(lambda: self.auth.download_file(config.PROTECTED_FILE, destination),
                          lambda info: messagebox.showinfo("Downloaded", json.dumps(info, indent=2)))

    def check_subscription(self):
        self.run_task(self.auth.check, lambda data: self.show_member(data))

    def list_sessions(self):
        self.run_task(self.auth.sessions, lambda data: self.show_text("Sessions/devices", json.dumps(data, indent=2)))

    def check_update(self):
        self.run_task(self.auth.update, lambda data: self.show_text("Version & update", json.dumps(data, indent=2)))

    def staff_overview(self):
        self.run_task(self.auth.staff_overview,
                      lambda data: self.show_text("Staff overview", json.dumps(data, indent=2)))

    def redeem(self):
        key = simpledialog.askstring("Redeem", "License key:", parent=self)
        if key:
            self.run_task(lambda: self.auth.redeem(key), self.show_member)

    def send_log(self):
        text = simpledialog.askstring("App log", "Message:", initialvalue="Hello from the Python example", parent=self)
        if text:
            self.run_task(lambda: self.auth.log(text),
                          lambda _data: messagebox.showinfo("App log", "The signed log event was recorded."))

    def show_text(self, title, text):
        window = tk.Toplevel(self)
        window.title(title)
        window.geometry("720x470")
        viewer = tk.Text(window, wrap="word", bg="#070c16", fg="#dce7ff", insertbackground="white",
                         font=("Cascadia Mono", 10), padx=15, pady=15)
        viewer.pack(fill="both", expand=True)
        viewer.insert("1.0", str(text))
        viewer.config(state="disabled")
        self.write_log(title + " · OK")

    def logout(self):
        self.run_task(self.auth.logout, self.on_logout)

    def on_logout(self, _data):
        self.pages.select(0)
        self.pages.tab(1, state="disabled")
        self.profile.config(text="Not signed in")
        self.profile_detail.config(text="")
        self.write_log("LOGOUT OK")


if __name__ == "__main__":
    StackAuthExample().mainloop()
