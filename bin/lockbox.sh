#!/usr/bin/bash
# Lockbox helper: thin wrapper around gocryptfs used by Panel.qml.
#
#   lockbox.sh status <cipherDir> <mountPoint>
#   lockbox.sh init   <cipherDir> <mountPoint>            (password on stdin, prints master key)
#   lockbox.sh unlock <cipherDir> <mountPoint> [idleMin]  (password on stdin)
#   lockbox.sh lock   <cipherDir> <mountPoint>
#   lockbox.sh open   <cipherDir> <mountPoint>
#
# Rules this script enforces:
#   * Both paths must be absolute, inside $HOME, free of "." / ".." and of
#     symlinks in every component, and must not overlap each other.
#   * A path that exists must be a directory owned by the current user and not
#     writable by group or others; a path that does not exist is created only
#     when its parent passes the same test. The final components therefore
#     live in directories only this user can write, which is the strongest
#     guarantee a shell wrapper can give against swapped links.
#   * The password arrives on stdin (never argv, never disk), is capped in
#     length, and is handed to gocryptfs on stdin only.
#   * Every external call runs under a hard timeout; captured output is capped.
#   * Every tool is called by absolute path.
set -euo pipefail

GOCRYPTFS=/usr/bin/gocryptfs
XRAY=/usr/bin/gocryptfs-xray
FUSERMOUNT=/usr/bin/fusermount3
FINDMNT=/usr/bin/findmnt
MKDIR=/usr/bin/mkdir
CHMOD=/usr/bin/chmod
STAT=/usr/bin/stat
XDG_OPEN=/usr/bin/xdg-open
TIMEOUT=/usr/bin/timeout
HEAD=/usr/bin/head
GREP=/usr/bin/grep
SED=/usr/bin/sed
TR=/usr/bin/tr
ID=/usr/bin/id
LS=/usr/bin/ls

MAX_PASSWORD=1024      # bytes read from stdin
MAX_OUTPUT=4096        # bytes of tool output kept
T_INIT=90              # seconds; scrypt key derivation can take a few
T_UNLOCK=60
T_LOCK=20
T_XRAY=30

cmd="${1:-status}"
cipher="${2:?cipherDir required}"
mount="${3:?mountPoint required}"

fail() { printf '%s\n' "$*" >&2; exit 1; }
json_escape() { printf '%s' "$1" | $SED -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

uid="$($ID -u)"
home="${HOME:-}"
[[ -n "$home" && "$home" == /* && -d "$home" && ! -L "$home" ]] || fail "HOME is not a usable directory"

# ---------- path validation ----------

# Absolute, inside $HOME, no "." or "..", no symlink in any component.
check_components() {
  local p="$1" cur="" part
  [[ "$p" == /* ]] || fail "$p is not an absolute path"
  [[ "$p" == "$home"/* ]] || fail "$p is outside your home directory"
  IFS=/ read -ra parts <<<"${p#/}"
  for part in "${parts[@]}"; do
    [[ -n "$part" ]] || continue
    [[ "$part" != "." && "$part" != ".." ]] || fail "$p contains . or .."
    cur="$cur/$part"
    [[ ! -L "$cur" ]] || fail "$cur is a symbolic link; refusing"
  done
}

# Existing directory owned by us and not writable by group/others.
private_dir() {
  local d="$1" st
  [[ -d "$d" && ! -L "$d" ]] || return 1
  st="$($STAT -c '%u %a' -- "$d" 2>/dev/null)" || return 1
  [[ "${st%% *}" == "$uid" ]] || return 1
  (( (8#${st##* } & 8#022) == 0 ))
}

# Ensure $1 is a private directory, creating it (mode 700) if its parent is one.
ensure_private_dir() {
  local d="$1"
  if [[ -e "$d" || -L "$d" ]]; then
    private_dir "$d" || fail "$d must be a directory you own that only you can write"
    return
  fi
  private_dir "${d%/*}" || fail "${d%/*} must exist, be owned by you, and be writable only by you"
  $MKDIR -- "$d"
  $CHMOD 700 -- "$d"
  private_dir "$d" || fail "could not create $d safely"
}

check_components "$cipher"
check_components "$mount"
[[ "$cipher" != "$mount" && "$cipher" != "$mount"/* && "$mount" != "$cipher"/* ]] \
  || fail "encrypted folder and unlocked folder must not overlap"

is_mounted() { [[ "$($TIMEOUT 5 $FINDMNT -n -o FSTYPE -- "$mount" 2>/dev/null)" == "fuse.gocryptfs" ]]; }
vault_exists() { [[ -f "$cipher/gocryptfs.conf" && ! -L "$cipher/gocryptfs.conf" ]]; }

read_password() {
  local pw
  IFS= read -r -n "$MAX_PASSWORD" pw || pw=""
  [[ -n "$pw" ]] || fail "no password given"
  printf '%s' "$pw"
}

# Run a tool under a deadline, keep at most MAX_OUTPUT bytes of its output.
# Usage: run_bounded <seconds> <cmd...>   (stdin is passed through)
run_bounded() {
  local secs="$1"; shift
  $TIMEOUT --kill-after=5 -- "$secs" "$@" 2>&1 | $HEAD -c "$MAX_OUTPUT"
}

case "$cmd" in
  status)
    installed=false; [[ -x "$GOCRYPTFS" ]] && installed=true
    exists=false; vault_exists && exists=true
    mounted=false; is_mounted && mounted=true
    printf '{"installed":%s,"exists":%s,"mounted":%s,"cipherDir":"%s","mountPoint":"%s"}\n' \
      "$installed" "$exists" "$mounted" "$(json_escape "$cipher")" "$(json_escape "$mount")"
    ;;

  init)
    [[ -x "$GOCRYPTFS" ]] || fail "gocryptfs is not installed (install the gocryptfs package)"
    vault_exists && fail "a vault already exists in $cipher"
    ensure_private_dir "$cipher"
    ensure_private_dir "$mount"
    [[ -z "$($LS -A -- "$cipher")" ]] || fail "$cipher is not empty"
    pw="$(read_password)"
    set +e
    out="$(printf '%s\n' "$pw" | run_bounded "$T_INIT" $GOCRYPTFS -init -q -passfile /dev/stdin -- "$cipher")"
    rc=${PIPESTATUS[0]:-$?}
    set -e
    if (( rc != 0 )); then
      pw=""
      (( rc == 124 || rc == 137 )) && fail "gocryptfs init timed out"
      fail "gocryptfs init failed: $(printf '%s' "$out" | $TR '\n' ' ')"
    fi
    key=""
    if [[ -x "$XRAY" ]]; then
      key="$(printf '%s\n' "$pw" | run_bounded "$T_XRAY" $XRAY -dumpmasterkey -- "$cipher/gocryptfs.conf" \
             | $GREP -oE '^[0-9a-f]{64}$' | $HEAD -n1 || true)"
    fi
    pw=""
    [[ -z "$key" ]] || printf '%s\n' "$key" | $SED -E 's/([0-9a-f]{8})/\1-/g; s/-$//'
    ;;

  unlock)
    [[ -x "$GOCRYPTFS" ]] || fail "gocryptfs is not installed (install the gocryptfs package)"
    private_dir "$cipher" || fail "$cipher must be a directory you own that only you can write"
    vault_exists || fail "no vault in $cipher"
    is_mounted && exit 0
    ensure_private_dir "$mount"
    [[ -z "$($LS -A -- "$mount")" ]] || fail "$mount is not empty"
    idle="${4:-0}"
    args=(-q -passfile /dev/stdin)
    if [[ "$idle" =~ ^[0-9]+$ ]] && (( idle > 0 )); then args+=(-idle "${idle}m"); fi
    pw="$(read_password)"
    set +e
    # gocryptfs forks its long-lived server into its own session after the
    # mount succeeds; the deadline bounds only the foreground setup.
    out="$(printf '%s\n' "$pw" | run_bounded "$T_UNLOCK" $GOCRYPTFS "${args[@]}" -- "$cipher" "$mount")"
    rc=${PIPESTATUS[0]:-$?}
    set -e
    pw=""
    if (( rc != 0 )); then
      (( rc == 124 || rc == 137 )) && fail "unlock timed out"
      case "$out" in
        *"assword incorrect"*) fail "Wrong password" ;;
        *) fail "gocryptfs: $(printf '%s' "$out" | $TR '\n' ' ')" ;;
      esac
    fi
    is_mounted || fail "mount did not appear"
    ;;

  lock)
    is_mounted || exit 0
    set +e
    out="$(run_bounded "$T_LOCK" $FUSERMOUNT -u -- "$mount")"
    rc=${PIPESTATUS[0]:-$?}
    set -e
    if (( rc != 0 )); then
      case "$out" in
        *busy*) fail "Something is still using the folder. Close it and try again." ;;
        *) fail "unmount failed: $(printf '%s' "$out" | $TR '\n' ' ')" ;;
      esac
    fi
    ! is_mounted || fail "still mounted after unmount"
    ;;

  open)
    is_mounted || fail "vault is locked"
    $XDG_OPEN -- "$mount" >/dev/null 2>&1 &
    ;;

  *)
    fail "unknown command: $cmd"
    ;;
esac
