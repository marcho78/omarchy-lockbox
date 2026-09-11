#!/usr/bin/bash
# Lockbox helper: thin wrapper around gocryptfs used by Panel.qml.
#
#   lockbox.sh status <cipherDir> <mountPoint>
#   lockbox.sh init   <cipherDir> <mountPoint>            (password on stdin, prints master key)
#   lockbox.sh unlock <cipherDir> <mountPoint> [idleMin]  (password on stdin)
#   lockbox.sh lock   <cipherDir> <mountPoint>
#   lockbox.sh open   <cipherDir> <mountPoint>
#
# The password is only ever passed to gocryptfs on stdin, never on the command
# line, and is never written to disk. Every tool is called by absolute path.
set -euo pipefail

GOCRYPTFS=/usr/bin/gocryptfs
FUSERMOUNT=/usr/bin/fusermount3
FINDMNT=/usr/bin/findmnt
MKDIR=/usr/bin/mkdir
CHMOD=/usr/bin/chmod
XDG_OPEN=/usr/bin/xdg-open
LS=/usr/bin/ls
GREP=/usr/bin/grep
HEAD=/usr/bin/head
TR=/usr/bin/tr

cmd="${1:-status}"
cipher="${2:?cipherDir required}"
mount="${3:?mountPoint required}"

fail() { printf '%s\n' "$*" >&2; exit 1; }

json_escape() { printf '%s' "$1" | /usr/bin/sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

is_mounted() { [[ "$($FINDMNT -n -o FSTYPE -- "$mount" 2>/dev/null)" == "fuse.gocryptfs" ]]; }
vault_exists() { [[ -f "$cipher/gocryptfs.conf" ]]; }

case "$cmd" in
  status)
    installed=false; [[ -x "$GOCRYPTFS" ]] && installed=true
    exists=false; vault_exists && exists=true
    mounted=false; is_mounted && mounted=true
    printf '{"installed":%s,"exists":%s,"mounted":%s,"cipherDir":"%s","mountPoint":"%s"}\n' \
      "$installed" "$exists" "$mounted" "$(json_escape "$cipher")" "$(json_escape "$mount")"
    ;;
  init)
    [[ -x "$GOCRYPTFS" ]] || fail "gocryptfs is not installed (sudo pacman -S gocryptfs)"
    vault_exists && fail "a vault already exists in $cipher"
    $MKDIR -p -- "$cipher" "$mount"
    $CHMOD 700 -- "$cipher"
    [[ -z "$($LS -A -- "$cipher")" ]] || fail "$cipher is not empty"
    # -passfile /dev/stdin reads exactly one line: the password we are piped.
    out="$($GOCRYPTFS -init -q -passfile /dev/stdin -- "$cipher" 2>&1)" || fail "gocryptfs init failed: $out"
    key="$(printf '%s\n' "$out" | $GREP -oE '[0-9a-f]{8}(-[0-9a-f]{8}){7}' | $HEAD -n1 || true)"
    printf '%s\n' "$key"
    ;;
  unlock)
    [[ -x "$GOCRYPTFS" ]] || fail "gocryptfs is not installed (sudo pacman -S gocryptfs)"
    vault_exists || fail "no vault in $cipher"
    is_mounted && exit 0
    $MKDIR -p -- "$mount"
    [[ -z "$($LS -A -- "$mount")" ]] || fail "$mount is not empty"
    idle="${4:-0}"
    args=(-q -passfile /dev/stdin)
    if [[ "$idle" =~ ^[0-9]+$ ]] && (( idle > 0 )); then args+=(-idle "${idle}m"); fi
    out="$($GOCRYPTFS "${args[@]}" -- "$cipher" "$mount" 2>&1)" || {
      case "$out" in
        *"Password incorrect"*|*"password incorrect"*) fail "Wrong password" ;;
        *) fail "gocryptfs: $(printf '%s' "$out" | $TR '\n' ' ')" ;;
      esac
    }
    ;;
  lock)
    is_mounted || exit 0
    out="$($FUSERMOUNT -u -- "$mount" 2>&1)" || {
      case "$out" in
        *busy*) fail "Something is still using the folder. Close it and try again." ;;
        *) fail "unmount failed: $out" ;;
      esac
    }
    ;;
  open)
    is_mounted || fail "vault is locked"
    $XDG_OPEN "$mount" >/dev/null 2>&1 &
    ;;
  *)
    fail "unknown command: $cmd"
    ;;
esac
