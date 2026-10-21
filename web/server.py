#!/usr/bin/env python3
"""Local bridge for the Samsung debloat picker.

Serves web/index.html and runs adb on the machine that owns the USB cable.
Browsers cannot call adb directly, so this process does it for them.

    python3 web/server.py            # real run
    python3 web/server.py --dry-run  # print commands, change nothing

Only listens on 127.0.0.1. Every POST needs the token printed at startup.
"""

import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

WEB = Path(__file__).resolve().parent
TOKEN_FILE = WEB / ".token"


def load_token():
    """Keep one token across restarts so an open tab stays valid."""
    env = os.environ.get("DEBLOAT_TOKEN", "").strip()
    if env:
        return env
    if TOKEN_FILE.exists():
        saved = TOKEN_FILE.read_text().strip()
        if saved:
            return saved
    fresh = secrets.token_urlsafe(18)
    TOKEN_FILE.write_text(fresh)
    TOKEN_FILE.chmod(0o600)
    return fresh


TOKEN = load_token()
MAX_PACKAGES = 200
PKG = re.compile(r"^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$")

# Never removable through the web UI, even if a request tries.
DENY = {
    "com.samsung.sec.android.application.csc",
    "com.samsung.android.app.omcagent",
    "com.samsung.android.ese",
    "com.sec.android.app.SecSetupWizard",
    "com.sec.android.app.billing",
    "com.osp.app.signin",
    "com.android.providers.calendar",
    "com.google.android.syncadapters.calendar",
    "com.google.android.googlequicksearchbox",
    "com.google.android.partnersetup",
    "com.google.android.safetycenter.resources",
    "com.sec.android.app.safetyassurance",
    "com.monotype.android.font.samsungone",
    "com.touchtype.swiftkey",
    "com.google.android.gms",
    "com.google.android.gsf",
    "com.android.vending",
    "com.android.nfc",
    "com.samsung.android.nfc",
    "com.google.android.apps.walletnfcrel",
}

LOCK = threading.Lock()
ARGS = None


def adb(*args, serial=None):
    cmd = ["adb"] + (["-s", serial] if serial else []) + list(args)
    if ARGS.dry_run:
        return 0, "DRY-RUN: " + " ".join(cmd)
    return run(cmd)


def run(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, "adb not found in PATH"
    except subprocess.TimeoutExpired:
        return 124, "adb timed out"


def authorised_device():
    code, out = run(["adb", "devices"])
    if code != 0:
        return None
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            return parts[0]
    return None


def device_info():
    serial = authorised_device()
    if not serial:
        return {"connected": False}
    info = {"connected": True, "serial": serial}
    for prop, key in (
        ("ro.product.model", "model"),
        ("ro.build.version.release", "android"),
        ("ro.build.version.sdk", "sdk"),
        ("ro.build.PDA", "build"),
    ):
        _, out = run(["adb", "-s", serial, "shell", "getprop", prop])
        info[key] = out.strip()
    return info


def apply_one(serial, action, pkg):
    if ARGS.dry_run:
        return True, "dry-run"
    if action == "remove":
        code, out = adb("shell", "pm", "uninstall", "-k", "--user", "0", pkg, serial=serial)
        ok = "Success" in out
        return ok, ("removed" if ok else "not removable") if not ARGS.dry_run else out
    if action == "disable":
        code, out = adb("shell", "pm", "disable-user", "--user", "0", pkg, serial=serial)
        ok = "disabled" in out.lower()
        return ok, "disabled" if ok else "not disableable"
    if action == "enable":
        code, out = adb("shell", "pm", "enable", "--user", "0", pkg, serial=serial)
        ok = "enabled" in out.lower()
        return ok, "enabled" if ok else "not enabled"
    code, out = adb("shell", "cmd", "package", "install-existing", pkg, serial=serial)
    ok = "installed for user" in out.lower()
    return ok, ("restored" if ok else "no factory copy") if not ARGS.dry_run else out


class Handler(BaseHTTPRequestHandler):
    server_version = "DebloatBridge/1.0"

    def log_message(self, fmt, *args):
        if ARGS.verbose:
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            if parse_qs(u.query).get("t", [""])[0] != TOKEN:
                self.send_response(302)
                self.send_header("Location", "/?t=" + TOKEN)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            page = (WEB / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(page)
            return
        if u.path == "/installed":
            serial = authorised_device()
            if not serial:
                self.send_json({"ok": False, "error": "no authorised device"}, 409)
                return
            _, out = run(["adb", "-s", serial, "shell", "pm", "list", "packages"])
            pkgs = sorted({ln.strip()[8:] for ln in out.splitlines() if ln.startswith("package:")})
            _, dout = run(["adb", "-s", serial, "shell", "pm", "list", "packages", "-d"])
            disabled = sorted({ln.strip()[8:] for ln in dout.splitlines() if ln.startswith("package:")})
            self.send_json({"ok": True, "count": len(pkgs), "packages": pkgs, "disabled": disabled})
            return
        if u.path == "/health":
            tok = parse_qs(u.query).get("t", [""])[0]
            self.send_json({"ok": True, "token_ok": tok == TOKEN, "dry_run": ARGS.dry_run,
                            "device": device_info()})
            return
        self.send_json({"ok": False, "error": "not found"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        if u.path != "/apply":
            self.send_json({"ok": False, "error": "not found"}, 404)
            return
        if parse_qs(u.query).get("t", [""])[0] != TOKEN:
            self.send_json({"ok": False, "error": "bad token"}, 403)
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self.send_json({"ok": False, "error": "bad json"}, 400)
            return
        action = payload.get("action")
        pkgs = payload.get("packages") or []
        if action not in ("remove", "restore", "disable", "enable"):
            self.send_json({"ok": False, "error": "action must be remove, restore, disable or enable"}, 400)
            return
        if not isinstance(pkgs, list) or not pkgs or len(pkgs) > MAX_PACKAGES:
            self.send_json({"ok": False, "error": "1..%d packages required" % MAX_PACKAGES}, 400)
            return
        with LOCK:
            serial = authorised_device()
            if not serial:
                self.send_json({"ok": False, "error": "no authorised device"}, 409)
                return
            results = []
            for pkg in pkgs:
                if not isinstance(pkg, str) or not PKG.match(pkg):
                    results.append({"pkg": str(pkg), "ok": False, "msg": "invalid package name"})
                    continue
                if action in ("remove", "disable") and pkg in DENY:
                    results.append({"pkg": pkg, "ok": False, "msg": "protected by the bridge"})
                    continue
                ok, msg = apply_one(serial, action, pkg)
                results.append({"pkg": pkg, "ok": ok, "msg": msg})
        self.send_json({"ok": True, "serial": serial, "dry_run": ARGS.dry_run, "results": results})


def main():
    global ARGS
    ap = argparse.ArgumentParser(description="Local adb bridge for the debloat picker")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--dry-run", action="store_true", help="print adb commands instead of running them")
    ap.add_argument("--verbose", action="store_true")
    ARGS = ap.parse_args()

    if not shutil.which("adb"):
        print("ERROR: adb is not in PATH. Install Android platform-tools first.", file=sys.stderr)
        return 1
    if not ARGS.dry_run and not authorised_device():
        print("WARNING: no authorised device yet. Connect the phone and accept the USB debugging prompt.", file=sys.stderr)

    url = "http://127.0.0.1:%d/?t=%s" % (ARGS.port, TOKEN)
    print("Debloat bridge %s" % ("(DRY RUN)" if ARGS.dry_run else ""), flush=True)
    print("Open this URL:  %s" % url, flush=True)
    print("Press Ctrl-C to stop.", flush=True)
    ThreadingHTTPServer(("127.0.0.1", ARGS.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
