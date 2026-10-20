#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import argparse
import ctypes
import fnmatch
import getpass
import hashlib
import hmac
import json
import os
import secrets
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time

# --------------------------------------------------------------- paths ---
SELF = os.path.abspath(__file__)
BASE_DIR = os.path.dirname(SELF)
TEMPLATE = os.path.join(BASE_DIR, "template.tbl")
STATE = os.path.join(BASE_DIR, ".guard_state.json")
LOG = os.path.join(BASE_DIR, "guard.log")

# service files are never touched by masks
SERVICE_FILES = {os.path.basename(p) for p in (SELF, TEMPLATE, STATE, LOG)}

SERVICE_NAME = "fileguard.service"
SERVICE_PATH = "/etc/systemd/system/" + SERVICE_NAME

PBKDF2_ITER = 300_000
WRONG_PASS_DELAY = 2  # seconds; slows down online password guessing


# ============================================================ helpers ===
def die(msg, code=1):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)


def log(msg):
    """Append a line to guard.log (the file is append-only)."""
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {msg}\n"
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass


def require_root():
    if os.geteuid() != 0:
        die("Root privileges required (chattr, template.tbl protection). "
            "Run: sudo python3 fileguard.py ...")


# ------------------------------------------------- chattr attributes ---
def chattr(path, flag):
    """flag: '+i', '-i', '+a', '-a'."""
    r = subprocess.run(["chattr", flag, path], capture_output=True, text=True)
    if r.returncode != 0:
        raise OSError(r.stderr.strip() or f"chattr {flag} {path} failed")


def get_attrs(path):
    r = subprocess.run(["lsattr", "-d", path], capture_output=True, text=True)
    if r.returncode != 0:
        return ""
    return r.stdout.split()[0]


def is_immutable(path):
    return "i" in get_attrs(path)


# --------------------------------------------------------- password ---
def hash_password(password):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITER)
    return f"pbkdf2_sha256${PBKDF2_ITER}${salt.hex()}${dk.hex()}"


def verify_password(password, stored):
    try:
        algo, iters, salt_hex, hash_hex = stored.strip().split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 bytes.fromhex(salt_hex), int(iters))
        # constant-time comparison protects against timing attacks
        return hmac.compare_digest(dk.hex(), hash_hex)
    except ValueError:
        return False


def ask_new_password():
    while True:
        p1 = getpass.getpass("New password: ")
        if len(p1) < 4:
            print("Password too short (minimum 4 characters).")
            continue
        p2 = getpass.getpass("Repeat password: ")
        if p1 != p2:
            print("Passwords do not match.")
            continue
        return p1


def check_password():
    stored, _ = read_template()
    password = getpass.getpass("Password: ")
    if not verify_password(password, stored):
        log(f"WRONG PASSWORD (uid={os.getuid()}, sudo_user={os.environ.get('SUDO_USER', '-')})")
        time.sleep(WRONG_PASS_DELAY)
        die("Wrong password.")


# --------------------------------------------------- template.tbl ---
# Format: first line = password hash, remaining lines = file name masks.
def read_template():
    if not os.path.exists(TEMPLATE):
        die("template.tbl not found. Run first: sudo python3 fileguard.py init")
    with open(TEMPLATE, encoding="utf-8") as f:
        lines = f.read().splitlines()
    if not lines:
        die("template.tbl is empty or corrupted.")
    masks = [l.strip() for l in lines[1:] if l.strip() and not l.strip().startswith("#")]
    return lines[0], masks


def write_template(hash_line, masks):
    """Rewrite template.tbl: drop +i -> write -> root:root 600 -> set +i."""
    if os.path.exists(TEMPLATE) and is_immutable(TEMPLATE):
        chattr(TEMPLATE, "-i")
    with open(TEMPLATE, "w", encoding="utf-8") as f:
        f.write(hash_line + "\n")
        for m in masks:
            f.write(m + "\n")
    os.chown(TEMPLATE, 0, 0)
    os.chmod(TEMPLATE, 0o600)
    chattr(TEMPLATE, "+i")


# ----------------------------------------------------------- state ---
def read_state():
    if not os.path.exists(STATE):
        return {"enabled": False, "pid": None, "modes": {}}
    with open(STATE, encoding="utf-8") as f:
        return json.load(f)


def write_state(state):
    if os.path.exists(STATE) and is_immutable(STATE):
        chattr(STATE, "-i")
    with open(STATE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    os.chown(STATE, 0, 0)
    os.chmod(STATE, 0o600)
    if state["enabled"]:
        chattr(STATE, "+i")


# ------------------------------------------------------ file ops ---
def matches(name, masks):
    if name in SERVICE_FILES:
        return False
    return any(fnmatch.fnmatchcase(name, m) for m in masks)


def matching_files(masks):
    result = []
    for name in os.listdir(BASE_DIR):
        path = os.path.join(BASE_DIR, name)
        if matches(name, masks) and os.path.isfile(path) and not os.path.islink(path):
            result.append(name)
    return sorted(result)


def lock_file(name, state):
    path = os.path.join(BASE_DIR, name)
    if is_immutable(path):
        chattr(path, "-i")
    state["modes"][name] = stat.S_IMODE(os.lstat(path).st_mode)
    os.chmod(path, 0)        # unreadable -> cannot be copied by regular users
    chattr(path, "+i")       # cannot be deleted/renamed/modified/chmod'ed
    print(f"  [+] locked: {name}")


def unlock_file(name, state):
    path = os.path.join(BASE_DIR, name)
    mode = state["modes"].pop(name, 0o644)
    if not os.path.exists(path):
        return
    if is_immutable(path):
        chattr(path, "-i")
    os.chmod(path, mode)
    print(f"  [-] unlocked: {name}")


def reconcile(state, masks):
    """Bring the set of locked files in line with the current masks."""
    desired = set(matching_files(masks))
    for name in list(state["modes"]):
        if name not in desired:
            unlock_file(name, state)
    for name in sorted(desired):
        if name not in state["modes"]:
            lock_file(name, state)


# ------------------------------------------------ background watcher ---
def daemon_alive(pid):
    if not pid:
        return False
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmd = f.read().split(b"\0")
        return b"_daemon" in cmd and any(SELF.encode() == c for c in cmd)
    except OSError:
        return False


# --- optional systemd supervision: restarts the watcher if it is killed ---
def systemctl(*args):
    return subprocess.run(["systemctl", *args], capture_output=True, text=True)


def service_installed():
    return os.path.exists(SERVICE_PATH)


def watcher_alive(state):
    """Is the watcher running (as a systemd service or as a plain process)?"""
    if service_installed():
        return systemctl("is-active", "--quiet", SERVICE_NAME).returncode == 0
    return daemon_alive(state.get("pid"))


def service_cmd(*args):
    r = systemctl(*args)
    if r.returncode != 0:
        raise OSError(r.stderr.strip() or f"systemctl {' '.join(args)} failed")


def start_daemon():
    p = subprocess.Popen([sys.executable, SELF, "_daemon"],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True,
                         cwd=BASE_DIR)
    time.sleep(0.3)
    if p.poll() is not None:
        raise OSError("watcher failed to start (see guard.log)")
    return p.pid


def stop_daemon(pid):
    if daemon_alive(pid):
        os.kill(pid, signal.SIGTERM)
        for _ in range(20):
            if not daemon_alive(pid):
                break
            time.sleep(0.1)


IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_ISDIR = 0x40000000
EVENT_HDR = struct.Struct("iIII")  # wd, mask, cookie, len


def remove_path(path):
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path, ignore_errors=True)
    else:
        os.unlink(path)


def sweep():
    """Remove protected names that appeared while the watcher was not running.

    At this point every legitimately protected file is already recorded in
    state["modes"], so any other name matching a mask was created during the gap.
    """
    try:
        _, masks = read_template()
    except SystemExit:
        return
    locked = read_state().get("modes", {})
    for name in os.listdir(BASE_DIR):
        if matches(name, masks) and name not in locked:
            try:
                remove_path(os.path.join(BASE_DIR, name))
                log(f"DENIED: '{name}' appeared while the watcher was down - removed")
            except OSError as e:
                log(f"error while sweeping '{name}': {e}")


def run_daemon():
    """Watch the directory via inotify and remove any forbidden names as they appear."""
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    fd = libc.inotify_init1(0)
    if fd < 0:
        log(f"inotify_init1: errno={ctypes.get_errno()}")
        sys.exit(1)
    wd = libc.inotify_add_watch(fd, BASE_DIR.encode(),
                                IN_CREATE | IN_MOVED_FROM | IN_MOVED_TO)
    if wd < 0:
        log(f"inotify_add_watch: errno={ctypes.get_errno()}")
        sys.exit(1)

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    log(f"watcher started (pid={os.getpid()})")
    sweep()  # watch is already active, so nothing can slip through the gap
    moved_from = {}  # cookie -> old name (used to roll back renames)

    while True:
        data = os.read(fd, 64 * 1024)
        off = 0
        while off < len(data):
            _, mask, cookie, length = EVENT_HDR.unpack_from(data, off)
            raw = data[off + EVENT_HDR.size: off + EVENT_HDR.size + length]
            off += EVENT_HDR.size + length
            name = raw.rstrip(b"\0").decode("utf-8", "surrogateescape")

            if mask & IN_MOVED_FROM:
                moved_from[cookie] = name
                if len(moved_from) > 1000:
                    moved_from.clear()
                continue

            try:
                _, masks = read_template()
            except SystemExit:
                continue
            if not matches(name, masks):
                continue

            path = os.path.join(BASE_DIR, name)
            kind = "directory" if mask & IN_ISDIR else "file"
            try:
                if mask & IN_MOVED_TO and cookie in moved_from:
                    old = moved_from.pop(cookie)
                    old_path = os.path.join(BASE_DIR, old)
                    if not os.path.exists(old_path):
                        os.rename(path, old_path)
                        log(f"DENIED: rename '{old}' -> '{name}' reverted")
                        continue
                remove_path(path)
                action = "move into directory" if mask & IN_MOVED_TO else "creation"
                log(f"DENIED: {action} ({kind}) '{name}' - removed")
            except FileNotFoundError:
                pass
            except OSError as e:
                log(f"error while handling '{name}': {e}")


# =========================================================== commands ===
def cmd_init(args):
    if os.path.exists(TEMPLATE):
        die("template.tbl already exists. To change the password use: passwd; "
            "to edit masks use: add / remove.")
    print(f"Protected directory: {BASE_DIR}")
    password = ask_new_password()
    masks = list(args.masks)
    if not masks:
        print("Enter file name masks (one per line, empty line to finish).")
        print("Examples: secret.txt   *.key   report_??.doc")
        while True:
            m = input("mask> ").strip()
            if not m:
                break
            masks.append(m)
    try:
        write_template(hash_password(password), masks)
        if not os.path.exists(LOG):
            open(LOG, "w").close()
        os.chown(LOG, 0, 0)
        os.chmod(LOG, 0o644)
        chattr(LOG, "+a")
    except OSError as e:
        die(f"Failed to set file attributes: {e}\n"
            "    The filesystem does not support chattr. On WSL, work in the Linux\n"
            "    home directory (~/...), not under /mnt/c/...")
    write_state({"enabled": False, "pid": None, "modes": {}})
    log(f"initialized: {len(masks)} masks")
    print(f"[ok] template.tbl created ({len(masks)} masks) and protected (root, 600, +i).")
    print("     Enable protection: sudo python3 fileguard.py on")


def cmd_on(args):
    _, masks = read_template()
    state = read_state()
    if state["enabled"] and watcher_alive(state):
        print("Protection is already enabled.")
        return
    print("Enabling protection...")
    reconcile(state, masks)
    write_state(state)  # the watcher's startup sweep reads the locked-file list from here
    if service_installed():
        service_cmd("enable", "--now", SERVICE_NAME)  # also starts at boot
        state["pid"] = None
        how = "systemd service"
    else:
        state["pid"] = start_daemon()
        how = f"pid={state['pid']}"
    state["enabled"] = True
    chattr(SELF, "+i")  # the program itself cannot be deleted or replaced either
    write_state(state)
    log(f"PROTECTION ENABLED (files: {len(state['modes'])}, watcher: {how})")
    print(f"[ok] Protection enabled. Locked files: {len(state['modes'])}, "
          f"watcher: {how}")


def cmd_off(args):
    state = read_state()
    if not state["enabled"]:
        print("Protection is already disabled.")
        return
    check_password()
    print("Disabling protection...")
    if service_installed():
        service_cmd("disable", "--now", SERVICE_NAME)
    else:
        stop_daemon(state["pid"])
    for name in list(state["modes"]):
        unlock_file(name, state)
    if is_immutable(SELF):
        chattr(SELF, "-i")
    state.update(enabled=False, pid=None)
    write_state(state)
    log("PROTECTION DISABLED")
    print("[ok] Protection disabled.")


def cmd_status(args):
    state = read_state()
    alive = watcher_alive(state)
    _, masks = read_template()
    if alive and service_installed():
        watcher = "running (systemd service, auto-restart)"
    elif alive:
        watcher = f"running, pid={state['pid']} (no auto-restart)"
    else:
        watcher = "not running"
    print(f"Directory:    {BASE_DIR}")
    print(f"Protection:   {'ENABLED' if state['enabled'] else 'disabled'}")
    print(f"Watcher:      {watcher}")
    print(f"Masks:        {len(masks)} (view with: list, password required)")
    print(f"template.tbl: attributes {get_attrs(TEMPLATE)}, "
          f"mode {oct(stat.S_IMODE(os.stat(TEMPLATE).st_mode))}")
    if state["enabled"] and not alive:
        print("[!] Protection is enabled but the watcher is not running: run off, then on")
    if state["modes"]:
        print("Locked files:")
        for name in sorted(state["modes"]):
            path = os.path.join(BASE_DIR, name)
            if os.path.exists(path):
                print(f"   {get_attrs(path)}  {name}")


def cmd_list(args):
    check_password()
    _, masks = read_template()
    print("Protected file masks:")
    for m in masks:
        print(f"   {m}")
    if not masks:
        print("   (empty)")


def _edit_masks(add=None, remove=None):
    check_password()
    hash_line, masks = read_template()
    if add:
        if add in masks:
            die(f"Mask '{add}' already exists.")
        masks.append(add)
    if remove:
        if remove not in masks:
            die(f"Mask '{remove}' not found.")
        masks.remove(remove)
    write_template(hash_line, masks)
    state = read_state()
    if state["enabled"]:
        reconcile(state, masks)
        write_state(state)
    log(f"mask {'added' if add else 'removed'}: {add or remove}")
    print("[ok] Mask list updated.")


def cmd_add(args):
    _edit_masks(add=args.mask)


def cmd_remove(args):
    _edit_masks(remove=args.mask)


def cmd_passwd(args):
    print("Current password.")
    check_password()
    _, masks = read_template()
    new = ask_new_password()
    write_template(hash_password(new), masks)
    log("password changed")
    print("[ok] Password changed.")


UNIT_TEMPLATE = """[Unit]
Description=fileguard watcher ({base})
After=local-fs.target

[Service]
Type=simple
WorkingDirectory={base}
ExecStart="{python}" "{script}" _daemon
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
"""


def cmd_install_service(args):
    """Run the watcher under systemd so that kill -9 only restarts it."""
    check_password()
    if service_installed():
        die("Service is already installed.")
    with open(SERVICE_PATH, "w", encoding="utf-8") as f:
        f.write(UNIT_TEMPLATE.format(base=BASE_DIR, python=sys.executable, script=SELF))
    os.chmod(SERVICE_PATH, 0o644)
    state = read_state()
    try:
        service_cmd("daemon-reload")
        if state["enabled"]:  # switch the already running plain process to systemd
            stop_daemon(state["pid"])
            service_cmd("enable", "--now", SERVICE_NAME)
            state["pid"] = None
            write_state(state)
    except OSError:
        os.remove(SERVICE_PATH)  # roll back, do not leave a half-installed unit
        raise
    log("systemd service installed")
    print("[ok] Service installed. It starts with 'on' and restarts the watcher "
          "within ~1 s if it is killed.")


def cmd_remove_service(args):
    check_password()
    if not service_installed():
        die("Service is not installed.")
    service_cmd("disable", "--now", SERVICE_NAME)
    os.remove(SERVICE_PATH)
    service_cmd("daemon-reload")
    state = read_state()
    if state["enabled"]:  # keep protection running as a plain process
        state["pid"] = start_daemon()
        write_state(state)
    log("systemd service removed")
    print("[ok] Service removed.")


def cmd_uninstall(args):
    check_password()
    state = read_state()
    if state["enabled"]:
        if service_installed():
            service_cmd("disable", "--now", SERVICE_NAME)
        else:
            stop_daemon(state["pid"])
        for name in list(state["modes"]):
            unlock_file(name, state)
    if service_installed():
        os.remove(SERVICE_PATH)
        systemctl("daemon-reload")
    for p in (SELF, TEMPLATE, STATE):
        if os.path.exists(p) and is_immutable(p):
            chattr(p, "-i")
    if os.path.exists(LOG):
        chattr(LOG, "-a")
    if os.path.exists(STATE):
        os.remove(STATE)
    log("protection fully removed (uninstall)")
    print("[ok] Protection removed from all files. template.tbl can now be deleted (sudo rm).")


def main():
    parser = argparse.ArgumentParser(
        description="Protect files in the program's directory using masks from template.tbl")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="initial setup")
    p.add_argument("masks", nargs="*", help="masks (prompted interactively if omitted)")
    sub.add_parser("on", help="enable protection")
    sub.add_parser("off", help="disable protection (password)")
    sub.add_parser("status", help="show status")
    sub.add_parser("list", help="show masks (password)")
    p = sub.add_parser("add", help="add a mask (password)")
    p.add_argument("mask")
    p = sub.add_parser("remove", help="remove a mask (password)")
    p.add_argument("mask")
    sub.add_parser("passwd", help="change password")
    sub.add_parser("install-service",
                   help="run the watcher under systemd with auto-restart (password)")
    sub.add_parser("remove-service", help="remove the systemd service (password)")
    sub.add_parser("uninstall", help="remove all protection")
    sub.add_parser("_daemon", help=argparse.SUPPRESS)
    args = parser.parse_args()

    require_root()
    if args.cmd == "_daemon":
        run_daemon()
        return
    handlers = {
        "init": cmd_init, "on": cmd_on, "off": cmd_off, "status": cmd_status,
        "list": cmd_list, "add": cmd_add, "remove": cmd_remove,
        "passwd": cmd_passwd, "uninstall": cmd_uninstall,
        "install-service": cmd_install_service, "remove-service": cmd_remove_service,
    }
    try:
        handlers[args.cmd](args)
    except KeyboardInterrupt:
        die("Interrupted.")
    except OSError as e:
        die(f"Error: {e}")


if __name__ == "__main__":
    main()
