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
    instead of being followed. Directories are verified on the retained
    descriptors: owned by this uid, not group/other writable.
  * A missing final component is created with mkdirat() on the verified parent
    descriptor (mode 700) and reopened the same way.
  * gocryptfs -init, gocryptfs-xray and directory listings operate on retained
    descriptors through /proc/self/fd/N.
  * Mount state is never judged by pathname. "Is the vault mounted?" means:
    open the mount point through its verified parent descriptor, read that
    descriptor's mount id from /proc/self/fdinfo, and check that
    /proc/self/mountinfo lists that mount id as fuse.gocryptfs. That binds
    the answer to the directory identity reached through the verified chain.
  * Mounting: gocryptfs runs in the foreground (-fg) as a process this helper
    starts and records (pid + kernel start time) in $XDG_RUNTIME_DIR/lockbox.
    fusermount3 is setuid and needs a pathname, so gocryptfs receives the
    name read from the verified descriptor; the result is then verified by
    mount identity as above, and if the mount is not attached to the verified
    directory the daemon is killed, which tears the mount down. Fail closed.
  * Unmounting never resolves a pathname: the recorded daemon is validated by
    pid, start time and executable, then signalled; gocryptfs unmounts itself
    on SIGTERM. If the folder is busy nothing else is touched.

Process model
  * Panel.qml starts this helper under setsid; the panel's watchdog kills the
    helper's whole process group. The gocryptfs daemon is deliberately started
    in its own session so it outlives the helper; it is the vault itself.
  * Every tool call has a deadline and a byte budget enforced while reading;
    exceeding either kills that tool's process group.
  * The password is read from stdin (capped), handed to tools on stdin only,
    and never written anywhere.
"""

import errno
import json
import os
import secrets
import select
import signal
import stat
import subprocess
import sys
import time

GOCRYPTFS = "/usr/bin/gocryptfs"
XRAY = "/usr/bin/gocryptfs-xray"
XDG_OPEN = "/usr/bin/xdg-open"

MAX_PASSWORD = 1024
MAX_OUTPUT = 4096
T_INIT = 90
T_UNLOCK = 60
T_LOCK = 20
T_XRAY = 30
EXIT_PASSWORD_INCORRECT = 12   # gocryptfs exit code

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
UID = os.getuid()
ELOOP = getattr(errno, "ELOOP", 40)
ENOTDIR = errno.ENOTDIR


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


def traverse_parent(path, home):
    """Walk every component but the last with O_NOFOLLOW.
    Returns (parent_fd, last_name)."""
    parts = check_string(path, home)
    fd = os.open("/", DIR_FLAGS)
    so_far = ""
    for name in parts[:-1]:
        so_far += "/" + name
        nxt = open_component(fd, name, so_far)
        if nxt is None:
            fail(f"{so_far} does not exist")
        os.close(fd)
        fd = nxt
    return fd, parts[-1]


def open_last(parent_fd, name, path, create=False):
    """Open the final component on the verified parent. Returns an fd, or
    None when it is missing and create is False."""
    fd = open_component(parent_fd, name, path)
    if fd is not None or not create:
        return fd
    if not is_private_dir(parent_fd):
        fail(f"{os.path.dirname(path)} must be owned by you and writable only by you")
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    fd = open_component(parent_fd, name, path)
    if fd is None:
        fail(f"could not create {path}")
    return fd


def traverse(path, home, create=False):
    """Final directory fd for path (or None if missing and not create)."""
    pfd, name = traverse_parent(path, home)
    try:
        return open_last(pfd, name, path, create)
    finally:
        os.close(pfd)


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


# ---------- mount identity ----------

def mount_id_of(fd):
    """Kernel mount id of the mount that fd's inode lives on."""
    try:
        with open(f"/proc/self/fdinfo/{fd}", "r", encoding="ascii", errors="replace") as f:
            for line in f:
                if line.startswith("mnt_id:"):
                    return int(line.split(":", 1)[1].strip())
    except (OSError, ValueError):
        pass
    return None


def mountinfo_fstype(mount_id):
    """Filesystem type recorded in /proc/self/mountinfo for a mount id."""
    try:
        with open("/proc/self/mountinfo", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                fields = line.split()
                if len(fields) < 10 or "-" not in fields:
                    continue
                try:
                    if int(fields[0]) != mount_id:
                        continue
                except ValueError:
                    continue
                sep = fields.index("-")
                return fields[sep + 1] if sep + 1 < len(fields) else ""
    except OSError:
        pass
    return None


def gocryptfs_mount_via(parent_fd, name):
    """(mounted, mount_id): open the mount point through its verified parent
    (lookup follows the mount, so this reaches the mounted root if there is
    one) and check that its mount is fuse.gocryptfs."""
    try:
        fd = os.open(name, DIR_FLAGS, dir_fd=parent_fd)
    except OSError:
        return False, None
    try:
        mid = mount_id_of(fd)
    finally:
        os.close(fd)
    if mid is None:
        return False, None
    return mountinfo_fstype(mid) == "fuse.gocryptfs", mid


# ---------- daemon record ----------

def runtime_dir():
    base = os.environ.get("XDG_RUNTIME_DIR", "")
    if not base.startswith("/"):
        base = f"/run/user/{UID}"
    try:
        bfd = os.open(base, DIR_FLAGS)
    except OSError:
        return None
    try:
        if not is_private_dir(bfd):
            return None
        try:
            os.mkdir("lockbox", 0o700, dir_fd=bfd)
        except FileExistsError:
            pass
        fd = open_component(bfd, "lockbox", base + "/lockbox")
        if fd is None or not is_private_dir(fd):
            if fd is not None:
                os.close(fd)
            return None
        return fd
    finally:
        os.close(bfd)


def record_name(mount_id):
    return f"mount-{mount_id}.json"


def proc_start_time(pid):
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            data = f.read(4096)
    except OSError:
        return None
    # comm can contain spaces/parens; fields after the last ')' are stable.
    tail = data[data.rfind(b")") + 2:].split()
    try:
        return int(tail[19])   # field 22 overall = starttime
    except (IndexError, ValueError):
        return None


def proc_exe(pid):
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""


def write_record(rfd, mount_id, pid):
    rec = {"pid": pid, "starttime": proc_start_time(pid), "mountId": mount_id}
    tmp = "." + secrets.token_hex(8) + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=rfd)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(rec, f)
        f.flush()
        os.fsync(f.fileno())
    os.rename(tmp, record_name(mount_id), src_dir_fd=rfd, dst_dir_fd=rfd)


def read_record(rfd, mount_id):
    try:
        fd = os.open(record_name(mount_id), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=rfd)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != UID:
            return None
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            fd = -1
            rec = json.load(f)
        if not isinstance(rec, dict):
            return None
        return rec
    except (OSError, ValueError):
        return None
    finally:
        if fd >= 0:
            os.close(fd)


def remove_record(rfd, mount_id):
    try:
        os.unlink(record_name(mount_id), dir_fd=rfd)
    except OSError:
        pass


def adopt_daemon(mount_realpath):
    """Fallback for a mount without a record (started before this version,
    or by the user by hand): the gocryptfs process whose executable is the
    real gocryptfs and whose argv names this mount point. The kill is by pid
    and the result is verified by mount identity, so a wrong guess can only
    end a same-uid gocryptfs process and never unmount anything else."""
    target = mount_realpath.encode()
    try:
        entries = os.listdir("/proc")
    except OSError:
        return None
    for ent in entries:
        if not ent.isdigit():
            continue
        pid = int(ent)
        if proc_exe(pid) != GOCRYPTFS:
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                argv = f.read(65536).split(b"\0")
        except OSError:
            continue
        argv = [a for a in argv if a]
        if len(argv) >= 2 and argv[-1].rstrip(b"/") == target.rstrip(b"/"):
            return pid
    return None


def owned_daemon(rec):
    """The recorded pid, if it is still the same gocryptfs process."""
    try:
        pid = int(rec.get("pid"))
        start = int(rec.get("starttime"))
    except (TypeError, ValueError):
        return None
    if pid <= 1 or proc_start_time(pid) != start:
        return None
    exe = proc_exe(pid)
    if exe != GOCRYPTFS and not exe.startswith(GOCRYPTFS + " "):
        return None
    return pid


# ---------- bounded subprocesses ----------

def kill_group(pid):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pid, sig)
        except OSError:
            return
        time.sleep(0.3)


def run(cmd, timeout, stdin_bytes=None, pass_fds=()):
    """Run cmd in its own process group with a deadline and an output budget
    enforced while reading. Returns (rc, output). rc 124 = timed out,
    rc 125 = output budget exceeded; both kill the group."""
    try:
        p = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            pass_fds=tuple(pass_fds), close_fds=True, process_group=0,
        )
    except OSError as e:
        return 127, str(e)
    try:
        if stdin_bytes:
            p.stdin.write(stdin_bytes)
        p.stdin.close()
    except OSError:
        pass
    out = bytearray()
    fd = p.stdout.fileno()
    deadline = time.monotonic() + timeout
    status = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            status = 124
            break
        ready, _, _ = select.select([fd], [], [], min(remaining, 0.5))
        if not ready:
            continue
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        out += chunk
        if len(out) > MAX_OUTPUT:
            status = 125
            break
    if status is not None:
        kill_group(p.pid)
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        return status, "timed out" if status == 124 else "output limit exceeded"
    try:
        rc = p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        kill_group(p.pid)
        rc = 124
    return rc, bytes(out[:MAX_OUTPUT]).decode("utf-8", "replace").strip()


def read_password():
    data = sys.stdin.buffer.readline(MAX_PASSWORD + 2)
    pw = data.rstrip(b"\r\n")
    if len(pw) > MAX_PASSWORD:
        fail("password is too long")
    if not pw:
        fail("no password given")
    return pw


# ---------- commands ----------

def cmd_status(cipher, mount, home):
    cfd = traverse(cipher, home)
    exists = False
    if cfd is not None:
        exists = conf_stat(cfd) is not None
        os.close(cfd)
    mounted = False
    try:
        pfd, name = traverse_parent(mount, home)
        mounted, _ = gocryptfs_mount_via(pfd, name)
        os.close(pfd)
    except SystemExit:
        mounted = False
    print(json.dumps({
        "installed": os.access(GOCRYPTFS, os.X_OK),
        "exists": exists,
        "mounted": mounted,
        "cipherDir": cipher,
        "mountPoint": mount,
        "ownSession": os.getsid(0) == os.getpid(),
    }))


def cmd_lock(mount, home):
    pfd, name = traverse_parent(mount, home)
    mounted, mid = gocryptfs_mount_via(pfd, name)
    if not mounted:
        os.close(pfd)
        return
    rfd = runtime_dir()
    rec = read_record(rfd, mid) if rfd is not None else None
    pid = owned_daemon(rec) if rec else None
    if pid is None:
        mfd = os.open(name, DIR_FLAGS, dir_fd=pfd)
        try:
            pid = adopt_daemon(fd_realpath(mfd))
        finally:
            os.close(mfd)
    if pid is None:
        fail("No gocryptfs process serves this folder; unmount it with fusermount3 -u yourself.")
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as e:
        fail(f"could not signal gocryptfs: {e.strerror}")
    deadline = time.monotonic() + T_LOCK
    while time.monotonic() < deadline:
        still, _ = gocryptfs_mount_via(pfd, name)
        if not still:
            if rfd is not None:
                remove_record(rfd, mid)
                os.close(rfd)
            os.close(pfd)
            return
        time.sleep(0.2)
    fail("Something is still using the folder. Close it and try again.")


def cmd_open(mount, home):
    pfd, name = traverse_parent(mount, home)
    mounted, _ = gocryptfs_mount_via(pfd, name)
    if not mounted:
        fail("vault is locked")
    mfd = os.open(name, DIR_FLAGS, dir_fd=pfd)
    # The file manager needs a pathname; it only displays the folder.
    target = fd_realpath(mfd)
    os.close(mfd)
    os.close(pfd)
    subprocess.Popen([XDG_OPEN, target], stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


def cmd_init(cipher, mount, home):
    cfd = traverse(cipher, home, create=True)
    require_private(cfd, cipher)
    mfd = traverse(mount, home, create=True)
    require_private(mfd, mount)
    os.close(mfd)
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


def cmd_unlock(cipher, mount, home, idle):
    cfd = traverse(cipher, home)
    if cfd is None or conf_stat(cfd) is None:
        fail(f"no vault in {cipher}")
    require_private(cfd, cipher)
    pfd, name = traverse_parent(mount, home)
    mounted, _ = gocryptfs_mount_via(pfd, name)
    if mounted:
        return
    mfd = open_last(pfd, name, mount, create=True)
    require_private(mfd, mount)
    if listdir_fd(mfd):
        fail(f"{mount} is not empty")
    rfd = runtime_dir()
    if rfd is None:
        fail("no private runtime directory (XDG_RUNTIME_DIR) to record the mount in")
    args = ["-fg", "-q", "-passfile", "/dev/stdin"]
    if idle.isdigit() and int(idle) > 0:
        args += ["-idle", f"{int(idle)}m"]
    pw = read_password()
    # fusermount3 is setuid and needs a pathname: take it from the verified
    # descriptor now; the outcome is checked by mount identity below.
    mount_path = fd_realpath(mfd)
    if mount_path != mount:
        fail("mount point moved during validation; refusing")
    try:
        daemon = subprocess.Popen(
            [GOCRYPTFS] + args + ["--", fd_path(cfd), mount_path],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            pass_fds=(cfd,), close_fds=True, start_new_session=True,
        )
    except OSError as e:
        fail(f"could not start gocryptfs: {e.strerror}")
    try:
        daemon.stdin.write(pw + b"\n")
        daemon.stdin.close()
    except OSError:
        pass
    pw = b""
    deadline = time.monotonic() + T_UNLOCK
    while time.monotonic() < deadline:
        rc = daemon.poll()
        if rc is not None:
            if rc == EXIT_PASSWORD_INCORRECT:
                fail("Wrong password")
            fail(f"gocryptfs exited with code {rc}")
        mounted, mid = gocryptfs_mount_via(pfd, name)
        if mounted:
            # Bind the record to this exact process and mount identity.
            write_record(rfd, mid, daemon.pid)
            return
        time.sleep(0.1)
    # Nothing attached to the verified directory in time: fail closed.
    try:
        daemon.terminate()
        daemon.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        try:
            daemon.kill()
        except OSError:
            pass
    fail("the vault did not mount on the verified folder; rolled back")


def main(argv):
    os.umask(0o077)
    if len(argv) < 4:
        fail("usage: lockbox.py <status|init|unlock|lock|open> <cipherDir> <mountPoint> [idleMin]", 2)
    cmd, cipher, mount = argv[1], argv[2], argv[3]
    home = home_dir()
    check_string(cipher, home)
    check_string(mount, home)
    if cipher == mount or cipher.startswith(mount + "/") or mount.startswith(cipher + "/"):
        fail("encrypted folder and unlocked folder must not overlap")

    if cmd == "status":
        cmd_status(cipher, mount, home)
    elif cmd == "lock":
        cmd_lock(mount, home)
    elif cmd == "open":
        cmd_open(mount, home)
    elif cmd in ("init", "unlock"):
        if not os.access(GOCRYPTFS, os.X_OK):
            fail("gocryptfs is not installed (install the gocryptfs package)")
        if cmd == "init":
            cmd_init(cipher, mount, home)
        else:
            cmd_unlock(cipher, mount, home, argv[4] if len(argv) > 4 else "0")
    else:
        fail(f"unknown command: {cmd}", 2)


if __name__ == "__main__":
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        sys.exit(130)
