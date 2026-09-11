#!/usr/bin/python3 -I
"""Lockbox helper: descriptor-based wrapper around gocryptfs, used by Panel.qml.

  lockbox.py status <cipherDir> <mountPoint>
  lockbox.py init   <cipherDir> <mountPoint>            password on stdin; prints master key
  lockbox.py unlock <cipherDir> <mountPoint> [idleMin]  password on stdin
  lockbox.py lock   <cipherDir> <mountPoint>
  lockbox.py open   <cipherDir> <mountPoint>

Identity model
  * Both paths must be absolute, inside $HOME, contain no "." or "..", and
    must not overlap.
  * Every component is opened with O_NOFOLLOW | O_DIRECTORY relative to the
    previous component's descriptor, so a symlink anywhere fails with ELOOP
    instead of being followed. The final directories are then verified on the
    retained descriptors: owned by this uid, not group/other writable.
  * A missing final component is created with mkdirat() on the verified parent
    descriptor (mode 700) and reopened the same way.
  * gocryptfs -init, gocryptfs-xray, and directory listings operate on those
    retained descriptors through /proc/self/fd/N.
  * The mount itself cannot take a descriptor: fusermount3 is a separate setuid
    process and needs a pathname. The path is read from the verified
    descriptor immediately before mounting, and after mounting the entry in
    /proc/self/mountinfo is checked to be a fuse.gocryptfs mount on exactly
    that path; otherwise it is unmounted again. Unmount uses the same
    mountinfo-verified path. That is the residual window, and it lies inside a
    directory only this uid can write.

Process model
  * Panel.qml starts this helper under setsid, so it is a session and process
    group leader. Its children stay in that group. The panel's watchdog kills
    the whole group; this helper also enforces its own per-tool deadlines and,
    on a gocryptfs timeout, kills the detached child gocryptfs forks.
  * The password is read from stdin (capped), handed to tools on stdin only,
    and never written anywhere.
"""

import json
import os
import signal
import stat
import subprocess
import sys
import time

GOCRYPTFS = "/usr/bin/gocryptfs"
XRAY = "/usr/bin/gocryptfs-xray"
FUSERMOUNT = "/usr/bin/fusermount3"
XDG_OPEN = "/usr/bin/xdg-open"

MAX_PASSWORD = 1024
MAX_OUTPUT = 4096
T_INIT = 90
T_UNLOCK = 60
T_LOCK = 20
T_XRAY = 30

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
UID = os.getuid()
ELOOP = getattr(os, "ELOOP", 40)
ENOTDIR = 20


def fail(msg, code=1):
    sys.stderr.write(msg + "\n")
    sys.exit(code)


# ---------- descriptor-based path handling ----------

def home_dir():
    h = os.environ.get("HOME", "")
    if not h.startswith("/"):
        fail("HOME is not set to an absolute path")
    return h.rstrip("/") or "/"


def check_string(path, home):
    if not path.startswith("/"):
        fail(f"{path} is not an absolute path")
    if not path.startswith(home + "/"):
        fail(f"{path} is outside your home directory")
    parts = [p for p in path.split("/") if p != ""]
    for p in parts:
        if p in (".", ".."):
            fail(f"{path} contains . or ..")
    return parts


def open_component(parent_fd, name, path_so_far):
    try:
        return os.open(name, DIR_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    except OSError as e:
        if e.errno in (ELOOP, ENOTDIR):
            fail(f"{path_so_far} is a symbolic link or not a directory; refusing")
        fail(f"cannot open {path_so_far}: {e.strerror}")


def is_private_dir(fd):
    st = os.fstat(fd)
    return stat.S_ISDIR(st.st_mode) and st.st_uid == UID and (st.st_mode & 0o022) == 0


def traverse(path, home, create=False):
    """Walk every component with O_NOFOLLOW. Returns the final directory fd,
    or None if the last component is missing and create is False. With
    create=True a missing last component is created on the verified parent."""
    parts = check_string(path, home)
    fd = os.open("/", DIR_FLAGS)
    so_far = ""
    for i, name in enumerate(parts):
        so_far += "/" + name
        nxt = open_component(fd, name, so_far)
        last = i == len(parts) - 1
        if nxt is None:
            if not last:
                fail(f"{so_far} does not exist")
            if not create:
                os.close(fd)
                return None
            if not is_private_dir(fd):
                fail(f"{os.path.dirname(so_far)} must be owned by you and writable only by you")
            try:
                os.mkdir(name, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            nxt = open_component(fd, name, so_far)
            if nxt is None:
                fail(f"could not create {so_far}")
        os.close(fd)
        fd = nxt
    return fd


def require_private(fd, path):
    if not is_private_dir(fd):
        fail(f"{path} must be a directory you own that only you can write")


def fd_path(fd):
    return f"/proc/self/fd/{fd}"


def fd_realpath(fd):
    return os.readlink(fd_path(fd))


def listdir_fd(fd):
    d = os.dup(fd)
    try:
        return os.listdir(d)
    finally:
        os.close(d)


def conf_stat(cfd):
    try:
        st = os.stat("gocryptfs.conf", dir_fd=cfd, follow_symlinks=False)
    except OSError:
        return None
    return st if stat.S_ISREG(st.st_mode) else None


# ---------- mounts ----------

def unescape_mountinfo(s):
    return s.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")


def gocryptfs_mount_at(path):
    """True if /proc/self/mountinfo has a fuse.gocryptfs mount on exactly path."""
    try:
        with open("/proc/self/mountinfo", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                fields = line.split()
                if len(fields) < 10 or "-" not in fields:
                    continue
                sep = fields.index("-")
                fstype = fields[sep + 1] if sep + 1 < len(fields) else ""
                if unescape_mountinfo(fields[4]) == path and fstype == "fuse.gocryptfs":
                    return True
    except OSError:
        pass
    return False


# ---------- bounded subprocesses ----------

def kill_gocryptfs_children(parent_pid):
    """gocryptfs forks a child carrying -notifypid=<parent>; on timeout end it too."""
    marker = f"-notifypid={parent_pid}".encode()
    try:
        entries = os.listdir("/proc")
    except OSError:
        return
    for pid in entries:
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = f.read().split(b"\0")
        except OSError:
            continue
        if cmd and cmd[0].endswith(b"gocryptfs") and marker in cmd:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.kill(int(pid), sig)
                except OSError:
                    break
                time.sleep(0.5)


def run(cmd, timeout, stdin_bytes=None, pass_fds=()):
    """Run cmd with a deadline; returns (rc, capped output). rc 124 = timed out."""
    try:
        p = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            pass_fds=tuple(pass_fds), close_fds=True,
        )
    except OSError as e:
        return 127, str(e)
    try:
        out, _ = p.communicate(stdin_bytes, timeout=timeout)
        return p.returncode, out[:MAX_OUTPUT].decode("utf-8", "replace").strip()
    except subprocess.TimeoutExpired:
        p.kill()
        try:
            p.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        if os.path.basename(cmd[0]) == "gocryptfs":
            kill_gocryptfs_children(p.pid)
        return 124, "timed out"


def read_password():
    data = sys.stdin.buffer.readline(MAX_PASSWORD + 2)
    pw = data.rstrip(b"\r\n")
    if len(pw) > MAX_PASSWORD:
        fail("password is too long")
    if not pw:
        fail("no password given")
    return pw


# ---------- commands ----------

def main(argv):
    if len(argv) < 4:
        fail("usage: lockbox.py <status|init|unlock|lock|open> <cipherDir> <mountPoint> [idleMin]", 2)
    cmd, cipher, mount = argv[1], argv[2], argv[3]
    home = home_dir()
    check_string(cipher, home)
    check_string(mount, home)
    if cipher == mount or cipher.startswith(mount + "/") or mount.startswith(cipher + "/"):
        fail("encrypted folder and unlocked folder must not overlap")

    if cmd == "status":
        cfd = traverse(cipher, home)
        exists = False
        if cfd is not None:
            exists = conf_stat(cfd) is not None
            os.close(cfd)
        print(json.dumps({
            "installed": os.access(GOCRYPTFS, os.X_OK),
            "exists": exists,
            "mounted": gocryptfs_mount_at(mount),
            "cipherDir": cipher,
            "mountPoint": mount,
            "ownSession": os.getsid(0) == os.getpid(),
        }))
        return

    if cmd == "lock":
        if not gocryptfs_mount_at(mount):
            return
        rc, out = run([FUSERMOUNT, "-u", "--", mount], T_LOCK)
        if rc != 0:
            if "busy" in out:
                fail("Something is still using the folder. Close it and try again.")
            fail("unmount failed: " + out.replace("\n", " "))
        if gocryptfs_mount_at(mount):
            fail("still mounted after unmount")
        return

    if cmd == "open":
        if not gocryptfs_mount_at(mount):
            fail("vault is locked")
        # xdg-open rejects "--"; the mount point is absolute so it cannot read as an option.
        subprocess.Popen([XDG_OPEN, mount], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        return

    if not os.access(GOCRYPTFS, os.X_OK):
        fail("gocryptfs is not installed (install the gocryptfs package)")

    if cmd == "init":
        cfd = traverse(cipher, home, create=True)
        require_private(cfd, cipher)
        mfd = traverse(mount, home, create=True)
        require_private(mfd, mount)
        if listdir_fd(cfd):
            fail(f"a vault already exists in {cipher}" if conf_stat(cfd) else f"{cipher} is not empty")
        pw = read_password()
        rc, out = run([GOCRYPTFS, "-init", "-q", "-passfile", "/dev/stdin", "--", fd_path(cfd)],
                      T_INIT, pw + b"\n", pass_fds=(cfd,))
        if rc != 0:
            fail("gocryptfs init timed out" if rc == 124 else "gocryptfs init failed: " + out.replace("\n", " "))
        key = ""
        if os.access(XRAY, os.X_OK):
            try:
                conf_fd = os.open("gocryptfs.conf", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=cfd)
            except OSError:
                conf_fd = None
            if conf_fd is not None:
                st = os.fstat(conf_fd)
                if stat.S_ISREG(st.st_mode) and st.st_uid == UID:
                    rc, out = run([XRAY, "-dumpmasterkey", "--", fd_path(conf_fd)], T_XRAY, pw + b"\n", pass_fds=(conf_fd,))
                    if rc == 0:
                        for line in out.splitlines():
                            line = line.strip()
                            if len(line) == 64 and all(c in "0123456789abcdef" for c in line):
                                key = "-".join(line[i:i + 8] for i in range(0, 64, 8))
                                break
                os.close(conf_fd)
        pw = b""
        if key:
            print(key)
        return

    if cmd == "unlock":
        cfd = traverse(cipher, home)
        if cfd is None or conf_stat(cfd) is None:
            fail(f"no vault in {cipher}")
        require_private(cfd, cipher)
        if gocryptfs_mount_at(mount):
            return
        mfd = traverse(mount, home, create=True)
        require_private(mfd, mount)
        if listdir_fd(mfd):
            fail(f"{mount} is not empty")
        idle = argv[4] if len(argv) > 4 else "0"
        args = ["-q", "-passfile", "/dev/stdin"]
        if idle.isdigit() and int(idle) > 0:
            args += ["-idle", f"{int(idle)}m"]
        pw = read_password()
        # fusermount3 needs a pathname: take it from the verified descriptor now.
        mount_path = fd_realpath(mfd)
        if mount_path != mount:
            fail("mount point moved during validation; refusing")
        rc, out = run([GOCRYPTFS] + args + ["--", fd_path(cfd), mount_path], T_UNLOCK, pw + b"\n", pass_fds=(cfd,))
        pw = b""
        if rc != 0:
            if rc == 124:
                fail("unlock timed out")
            if "assword incorrect" in out:
                fail("Wrong password")
            fail("gocryptfs: " + out.replace("\n", " "))
        if not gocryptfs_mount_at(mount):
            run([FUSERMOUNT, "-u", "--", mount_path], T_LOCK)
            fail("mount did not appear on the verified path; rolled back")
        return

    fail(f"unknown command: {cmd}", 2)


if __name__ == "__main__":
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        sys.exit(130)
