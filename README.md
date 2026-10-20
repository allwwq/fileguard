# fileguard

Mask-based file protection for a single Linux directory.

`fileguard` locks every file whose name matches a protected mask so that it can be neither read, copied, modified, renamed nor deleted by regular users, and runs a background watcher that removes any new file or directory that tries to appear under a protected name. All management commands are guarded by a password stored as a salted PBKDF2 hash.

It is a small, dependency-free tool (Python standard library only) built to demonstrate how several Linux security primitives combine into one protection scheme: extended file attributes, file permissions, inotify, password hashing and tamper-evident logging.

## Features

- **Immutable locking** – protected files get mode `000` and the `chattr +i` attribute. Even the owner cannot modify, rename, delete or `chmod` them.
- **Real-time watcher** – an inotify-based daemon watches the directory and removes newly created (or moved-in) files and directories whose names match a protected mask. Renames that would produce a protected name are reverted.
- **Self-healing watcher** – optionally runs as a systemd service (`Restart=always`): if the watcher is killed with `kill -9`, it is back within ~1 second, and a startup sweep removes any protected name created during the gap.
- **Password-protected administration** – disabling protection, listing or editing masks, changing the password and uninstalling all require the password.
- **Safe password storage** – PBKDF2-HMAC-SHA256, 300 000 iterations, 16-byte random salt, constant-time comparison (`hmac.compare_digest`) and a delay after each failed attempt.
- **Self-protection** – `template.tbl` (hash + masks), the state file and the script itself are made `root:root`, mode `600`/immutable while protection is on.
- **Append-only audit log** – `guard.log` has `chattr +a`; every event (enable/disable, denied operations, wrong passwords with the invoking uid and `SUDO_USER`) is recorded and cannot be rewritten.
- **Masks** use shell-style wildcards (`fnmatch`): `secret.txt`, `*.key`, `report_??.doc`.

## Requirements

- Linux with a filesystem that supports `chattr` / `lsattr` (ext4, xfs, btrfs, ...).
- Python 3.7+
- systemd (optional, only for `install-service`)
- Root privileges (`sudo`).

> **WSL note:** `chattr` does not work on `/mnt/c/...`. Keep the directory inside the Linux filesystem (e.g. `~/fileguard-demo`).

## Quick start

```bash
mkdir -p ~/demo && cp fileguard.py ~/demo && cd ~/demo
touch secret.txt passwords.key

# 1. one-time setup: choose a password and the masks to protect
sudo python3 fileguard.py init "secret.txt" "*.key"

# 2. enable protection
sudo python3 fileguard.py on

# 3. try to attack the protected files (all of these must fail)
rm secret.txt                 # Operation not permitted
mv secret.txt other.txt       # Operation not permitted
cat passwords.key             # Permission denied
touch new.key                 # file is created, then removed by the watcher

# 4. inspect
sudo python3 fileguard.py status
sudo cat guard.log
```

## Commands

| Command | Password | Description |
|---|:---:|---|
| `init [mask ...]` | – | First-time setup: set the password, define masks, create the protected `template.tbl` and log. |
| `on` | – | Lock matching files, start the watcher, make the script immutable. |
| `off` | yes | Stop the watcher and restore the original mode of every locked file. |
| `status` | – | Show protection state, watcher PID, mask count and locked files with their attributes. |
| `list` | yes | Print the protected masks. |
| `add <mask>` | yes | Add a mask; matching files are locked immediately if protection is on. |
| `remove <mask>` | yes | Remove a mask; files no longer matched are unlocked. |
| `passwd` | yes | Change the password. |
| `install-service` | yes | Run the watcher as a systemd service with auto-restart and start at boot. |
| `remove-service` | yes | Remove the systemd service (the watcher continues as a plain process if protection is on). |
| `uninstall` | yes | Remove every protection attribute so the files can be deleted. |

All commands require root, because they change file attributes.

## How it works

```
init  ─►  template.tbl   line 1: pbkdf2_sha256$iterations$salt$hash
                         line 2…: masks            (root:root, 600, chattr +i)

on    ─►  for each file matching a mask:
              remember original mode → chmod 000 → chattr +i
          start watcher (new session, detached)
          chattr +i on fileguard.py and .guard_state.json

watcher:  startup sweep: remove protected names that are not in the locked-file list
          inotify on the directory (IN_CREATE | IN_MOVED_FROM | IN_MOVED_TO)
              name matches a mask?
                 ├─ file/dir created or moved in  → delete it
                 └─ rename onto a protected name  → rename back
              every denied operation → guard.log
```

Design notes:

- **`chmod 000` + `chattr +i`** – the first blocks reading (and therefore copying) by non-root users, the second blocks every modification of the inode and of the directory entry (delete, rename, `chmod`).
- **Watcher identity check** – the stored PID is validated by reading `/proc/<pid>/cmdline` (it must contain `_daemon` and the script path), so a reused PID is never mistaken for the watcher.
- **Mask changes take effect live** – the watcher re-reads `template.tbl` on every event.
- **Original modes are stored** in `.guard_state.json` and restored on `off`, `remove` and `uninstall`.

## Threat model and limitations

This tool is meant to stop **accidental or unprivileged tampering**, not a determined attacker with root. Known limits:

| Limitation | Why it matters |
|---|---|
| `root` can run `chattr -i` or edit the filesystem offline | Immutable flags are a barrier for normal users only. A real deployment would add a MAC policy (SELinux/AppArmor) or a `CAP_LINUX_IMMUTABLE` restriction. |
| Without `install-service`, killing the watcher (`kill -9`) disables protection against **new** files | Already locked files stay locked, but new files with protected names stay until `off` → `on`; `status` reports "not running". With the systemd service the watcher restarts in ~1 s and the startup sweep deletes files created in the gap, but root can still `systemctl stop` it (the action is visible in the journal). |
| Removal of new files is **reactive** | The file exists for a short moment before the watcher deletes it (race window). |
| Only the top-level directory is watched | inotify is not recursive; subdirectories are neither watched nor locked. |
| Only regular, non-symlink files are locked | Pre-existing directories and symlinks matching a mask are not locked, only removed if they appear later. |
| Password is only checked by the script | Anyone with root can bypass the script entirely; the password protects the *tool*, not the kernel. |
| Minimum password length is 4 | Acceptable for a demo; raise it for real use. |

## Surviving `kill -9`

```bash
sudo python3 fileguard.py install-service   # once, password required
sudo python3 fileguard.py on
sudo kill -9 $(systemctl show -p MainPID --value fileguard.service)
systemctl status fileguard.service           # restarted ~1 s later
```

A process that is supervised by the same script cannot survive a root `kill`, so the supervision is delegated to PID 1 (systemd). Every restart is logged in `guard.log` ("watcher started") and in the systemd journal.

### Demo

Protected mask: `test.txt`. The watcher is killed with `kill -9` and a protected name is created in the same command line, while no watcher is running:

```console
$ sudo kill -9 $(systemctl show -p MainPID --value fileguard.service); touch test.txt; sleep 2; ls
fileguard  fileguard.py  guard.log  template.tbl
$ tail -5 guard.log
2026-10-20 18:51:38  DENIED: creation (file) 'test.txt' - removed
2026-10-20 18:51:46  watcher started (pid=2175)
2026-10-20 18:52:05  DENIED: creation (file) 'test.txt' - removed
2026-10-20 18:52:43  watcher started (pid=2227)
2026-10-20 18:52:43  DENIED: 'test.txt' appeared while the watcher was down - removed
```

- Lines 1 and 3: the running watcher removes a newly created protected file.
- Line 4: systemd has restarted the killed watcher (new PID).
- Line 5: the startup sweep removes the file that was created while the watcher was down.

## Possible improvements

- recursive watching via `inotify_add_watch` on subdirectories (or `fanotify`)
- `fanotify` permission events to deny access synchronously instead of reacting after the fact
- configurable password policy and lockout after repeated failures
- unit tests that run inside a throw-away loopback ext4 image

## License

MIT – see [LICENSE](LICENSE).
