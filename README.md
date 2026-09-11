# Lockbox for Omarchy

An encrypted folder you unlock from the bar and that locks itself again.

Lockbox wraps [gocryptfs](https://nuetzlich.net/gocryptfs/): files you drop
into `~/Lockbox` are stored encrypted, file by file, in `~/.lockbox`. No root,
no block devices, and the encrypted folder syncs and backs up like any other.

* Bar icon shows locked or unlocked. Left click opens the panel, right click
  locks, middle click opens the folder.
* Create a vault from the panel. The gocryptfs master key is shown once for
  recovery and never stored by the plugin.
* Auto-locks after a configurable idle time (gocryptfs's own idle timer) and
  when the Omarchy screen lock engages.
* The password only ever goes to gocryptfs on stdin. It is never written to
  disk, never placed on a command line, and cleared from memory as soon as it
  is sent.

## Install

```bash
sudo pacman -S gocryptfs
omarchy plugin add https://github.com/marcho78/omarchy-lockbox.git --enable
```

Then click the lock icon in the bar and choose **Create vault**.

## Settings

Bar widget settings (right-click the widget or edit `~/.config/omarchy/shell.json`):

| Setting | Default | Meaning |
|---|---|---|
| `cipherDir` | `~/.lockbox` | Where encrypted files live. Sync or back up this folder. |
| `mountPoint` | `~/Lockbox` | Where the decrypted view appears while unlocked. |
| `autoLockMinutes` | `15` | Lock after this many idle minutes. `0` disables. |
| `lockOnScreenLock` | `true` | Lock when the screen locks. |
| `openAfterUnlock` | `true` | Open the folder in your file manager after unlocking. |

To use an existing gocryptfs directory, point `cipherDir` at it.

## IPC

```bash
omarchy-shell marcho78.lockbox status
omarchy-shell marcho78.lockbox lock
omarchy-shell marcho78.lockbox openFolder
omarchy-shell marcho78.lockbox toggle
```

## Recovery

If you forget the password, gocryptfs can open the vault with the master key
shown at creation:

```bash
gocryptfs -masterkey <key> ~/.lockbox ~/Lockbox
```

## Remove

```bash
omarchy plugin remove marcho78.lockbox
```

Your encrypted files stay in `cipherDir`. Delete that folder yourself if you
no longer want them.

## Dependencies

* `gocryptfs` and `fuse3` (Arch repos)
* `util-linux` for `findmnt`, `xdg-utils` for opening the folder, `wl-clipboard`
  for the copy buttons. All ship with Omarchy except gocryptfs.

The plugin makes no network requests and writes only to the two folders you
configure.

## License

MIT

## Author

[@devsec_ai](https://x.com/devsec_ai) on X
