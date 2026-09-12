import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// Lockbox: an encrypted folder (gocryptfs) you unlock from the bar and that
// locks itself again. The password only ever travels to gocryptfs on stdin
// through bin/lockbox.sh and is cleared from memory as soon as it is sent.
Panel {
  id: root
  moduleName: "marcho78.lockbox"
  ipcTarget: "marcho78.lockbox"
  manageIpc: false

  readonly property string home: Quickshell.env("HOME")
  readonly property string pluginDir: Qt.resolvedUrl(".").toString().replace(/^file:\/\//, "").replace(/\/$/, "")
  readonly property string helper: pluginDir + "/bin/lockbox.py"
  // The helper runs under setsid so it leads its own session and process
  // group; the watchdog can then end the whole group, children included.
  readonly property var helperPrefix: ["/usr/bin/setsid", "-w", "/usr/bin/python3", "-I", helper]

  function expand(p) {
    p = String(p || "")
    if (p === "~") return home
    if (p.indexOf("~/") === 0) return home + p.substring(1)
    return p
  }

  readonly property string cipherDir: expand(setting("cipherDir", "~/.lockbox"))
  readonly property string mountPoint: expand(setting("mountPoint", "~/Lockbox"))
  readonly property int autoLockMinutes: Math.max(0, Number(setting("autoLockMinutes", 15)) || 0)
  readonly property bool lockOnScreenLock: setting("lockOnScreenLock", true) !== false
  readonly property bool openAfterUnlock: setting("openAfterUnlock", true) !== false

  property bool installed: true
  property bool exists: false
  property bool mounted: false
  property bool statusLoaded: false
  property bool busy: false
  property string errorText: ""
  property string masterKey: ""
  property string pendingAction: ""
  property string pendingPassword: ""
  property string chainPassword: ""
  property var lockService: null
  property bool screenLocked: false
  property bool pendingLock: false
  readonly property int maxOutput: 4096

  readonly property string glyph: mounted ? "󰌿" : "󰌾"
  readonly property string stateText: !statusLoaded ? "Checking…"
    : !installed ? "gocryptfs not installed"
    : !exists ? "No vault yet"
    : mounted ? "Unlocked" : "Locked"
  readonly property string autoLockText: autoLockMinutes > 0
    ? "Locks after " + autoLockMinutes + " min idle" + (lockOnScreenLock ? " and when the screen locks" : "")
    : (lockOnScreenLock ? "Locks when the screen locks" : "Stays unlocked until you lock it")

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  // ---------- status ----------

  function refresh() {
    if (!statusProc.running) statusProc.running = true
  }

  function applyStatus(text) {
    try {
      var s = JSON.parse(String(text).trim())
      root.installed = s.installed === true
      root.exists = s.exists === true
      var wasMounted = root.mounted
      root.mounted = s.mounted === true
      root.statusLoaded = true
      if (wasMounted && !root.mounted && root.errorText === "") root.errorText = ""
    } catch (e) {
      console.warn("[lockbox] bad status: " + text)
    }
  }

  // Output from the helper is read in chunks against a byte budget. Exceeding
  // it ends the helper's whole process group at once; nothing beyond the
  // budget is ever held in the shell.
  function collect(proc, which, chunk) {
    var s = String(chunk)
    var cur = which === "out" ? proc.outBuf : proc.errBuf
    var room = root.maxOutput - cur.length
    if (s.length > room) {
      if (which === "out") proc.outBuf = cur + s.slice(0, Math.max(0, room)); else proc.errBuf = cur + s.slice(0, Math.max(0, room))
      if (!proc.overflowed) {
        proc.overflowed = true
        console.warn("[lockbox] helper output exceeded " + root.maxOutput + " bytes; killing its process group")
        root.killGroupOf(proc, "KILL")
      }
      return
    }
    if (which === "out") proc.outBuf = cur + s; else proc.errBuf = cur + s
  }

  function killGroupOf(proc, sig) {
    var pid = proc.processId
    if (!pid) return
    Quickshell.execDetached(["/usr/bin/kill", "-" + sig, "--", "-" + String(pid)])
  }

  Process {
    id: statusProc
    property string outBuf: ""
    property string errBuf: ""
    property bool overflowed: false
    command: root.helperPrefix.concat(["status", root.cipherDir, root.mountPoint])
    onStarted: { outBuf = ""; errBuf = ""; overflowed = false }
    stdout: SplitParser { splitMarker: ""; onRead: function(d) { root.collect(statusProc, "out", d) } }
    stderr: SplitParser { splitMarker: ""; onRead: function(d) { root.collect(statusProc, "err", d) } }
    onExited: function(code) {
      if (!statusProc.overflowed && code === 0) root.applyStatus(statusProc.outBuf)
      statusProc.outBuf = ""; statusProc.errBuf = ""
    }
  }

  // ---------- actions ----------

  function run(action, password) {
    if (actionProc.running) {
      if (action === "lock") root.pendingLock = true
      return
    }
    root.errorText = ""
    root.busy = true
    root.pendingAction = action
    root.pendingPassword = password || ""
    var args = root.helperPrefix.concat([action, root.cipherDir, root.mountPoint])
    if (action === "unlock") args.push(String(root.autoLockMinutes))
    actionProc.command = args
    actionProc.running = true
    watchdog.restart()
  }

  // Backstop: the helper bounds every tool with its own timeout; if the
  // helper itself hangs, end its entire process group (TERM, then KILL).
  function killGroup(sig) { root.killGroupOf(actionProc, sig) }
  Timer {
    id: watchdog
    interval: 120000
    repeat: false
    onTriggered: {
      if (!actionProc.running) return
      console.warn("[lockbox] helper exceeded deadline; terminating its process group")
      root.killGroup("TERM")
      killTimer.restart()
    }
  }
  Timer {
    id: killTimer
    interval: 5000
    repeat: false
    onTriggered: if (actionProc.running) root.killGroup("KILL")
  }

  function unlock(password) {
    if (!password) { root.errorText = "Enter the vault password."; return }
    run("unlock", password)
  }

  function lock() { run("lock") }
  function openFolder() { run("open") }

  function create(password, confirm) {
    if (!password) { root.errorText = "Choose a password."; return }
    if (password.length < 8) { root.errorText = "Use at least 8 characters."; return }
    if (password !== confirm) { root.errorText = "Passwords do not match."; return }
    root.chainPassword = password
    run("init", password)
  }

  function onActionDone(code, out, err) {
    root.busy = false
    watchdog.stop()
    var action = root.pendingAction
    root.pendingAction = ""
    out = String(out || "").slice(0, root.maxOutput)
    var message = String(err || "").slice(0, root.maxOutput).trim()
    if (action === "init") {
      if (code === 0) {
        root.masterKey = String(out || "").trim()
        root.exists = true
        newPwField.text = ""
        confirmPwField.text = ""
        var pw = root.chainPassword
        root.chainPassword = ""
        if (pw) unlock(pw)
        return
      }
      root.chainPassword = ""
      root.errorText = message || "Could not create the vault."
    } else if (action === "unlock") {
      if (code === 0) {
        root.mounted = true
        pwField.text = ""
        // Deferred: this runs inside the unlock process's exit handler, and
        // run() refuses to start while that process still counts as running.
        if (root.openAfterUnlock && !root.screenLocked && !root.pendingLock) Qt.callLater(root.openFolder)
      } else {
        root.errorText = message || "Unlock failed."
      }
    } else if (action === "lock") {
      if (code === 0) root.mounted = false
      else root.errorText = message || "Lock failed."
    }
    if (root.pendingLock) {
      root.pendingLock = false
      if (root.mounted || action === "unlock") { run("lock"); return }
    }
    refresh()
  }

  Process {
    id: actionProc
    stdinEnabled: true
    property string outBuf: ""
    property string errBuf: ""
    property bool overflowed: false
    stdout: SplitParser { splitMarker: ""; onRead: function(d) { root.collect(actionProc, "out", d) } }
    stderr: SplitParser { splitMarker: ""; onRead: function(d) { root.collect(actionProc, "err", d) } }
    onStarted: {
      actionProc.outBuf = ""; actionProc.errBuf = ""; actionProc.overflowed = false
      if (root.pendingPassword !== "") {
        actionProc.write(root.pendingPassword + "\n")
        root.pendingPassword = ""
      }
    }
    onExited: function(code) {
      var o = actionProc.outBuf, e = actionProc.overflowed ? "The helper produced too much output and was stopped." : actionProc.errBuf
      actionProc.outBuf = ""; actionProc.errBuf = ""
      root.onActionDone(actionProc.overflowed ? 1 : code, o, e)
      actionProc.overflowed = false
    }
  }

  Process {
    id: copyProc
    stdinEnabled: true
    command: ["/usr/bin/wl-copy"]
    onStarted: { copyProc.write(root._copyPayload); root._copyPayload = "" }
  }
  property string _copyPayload: ""
  function copyText(s) {
    if (copyProc.running) return
    root._copyPayload = String(s)
    copyProc.running = true
  }

  // ---------- lock when the screen locks ----------

  function findLockService() {
    if (root.lockService) return
    var shell = root.bar ? root.bar.shell : null
    if (shell && typeof shell.serviceFor === "function") {
      var s = shell.serviceFor("omarchy.lock")
      if (s) { root.lockService = s; root.screenLocked = s.locked === true }
    }
  }

  Connections {
    target: root.lockService
    ignoreUnknownSignals: true
    function onLockedChanged() {
      if (!root.lockService) return
      root.screenLocked = root.lockService.locked === true
      if (!root.screenLocked || !root.lockOnScreenLock) return
      if (actionProc.running) {
        console.log("[lockbox] screen locked during an action; vault will lock when it finishes")
        root.pendingLock = true
      } else if (root.mounted) {
        console.log("[lockbox] screen locked; locking vault")
        root.lock()
      }
    }
  }

  Timer {
    interval: 5000
    repeat: true
    running: root.lockService === null
    triggeredOnStart: true
    onTriggered: root.findLockService()
  }

  // gocryptfs unmounts itself on idle; poll so the icon follows.
  Timer {
    interval: root.opened ? 5000 : 30000
    repeat: true
    running: true
    onTriggered: root.refresh()
  }

  Component.onCompleted: refresh()

  onOpenedChanged: {
    if (opened) {
      root.errorText = ""
      refresh()
      Qt.callLater(function() {
        if (pwField.visible) pwField.forceActiveFocus()
        else if (newPwField.visible) newPwField.forceActiveFocus()
      })
    } else {
      pwField.text = ""
      newPwField.text = ""
      confirmPwField.text = ""
    }
  }

  IpcHandler {
    target: root.ipcTarget
    function open(): void { root.open() }
    function close(): void { root.close() }
    function toggle(): void { root.toggle() }
    function status(): string {
      return JSON.stringify({ installed: root.installed, exists: root.exists, mounted: root.mounted, mountPoint: root.mountPoint, lockServiceFound: root.lockService !== null, screenLocked: root.screenLocked, pendingLock: root.pendingLock, opened: root.opened })
    }
    function lock(): string { root.lock(); return "locking" }
    function openFolder(): string { root.openFolder(); return "opening" }
  }

  // ---------- bar button ----------

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.glyph
    dimmed: root.statusLoaded && (!root.installed || !root.exists)
    tooltipText: "Lockbox: " + root.stateText
    onPressed: function(b) {
      if (b === Qt.RightButton) { if (root.mounted) root.lock(); else root.open() }
      else if (b === Qt.MiddleButton) { if (root.mounted) root.openFolder() }
      else root.toggle()
    }
  }

  // ---------- popup ----------

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(360))
    contentHeight: panel.fittedContentHeight(panelColumn.implicitHeight, Style.space(520))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      blocked: pwField.activeFocus || newPwField.activeFocus || confirmPwField.activeFocus
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }

      Column {
        id: panelColumn
        width: parent.width
        spacing: Style.space(12)

        // Hero
        Item {
          width: parent.width
          implicitHeight: Math.max(heroIcon.implicitHeight, heroLabels.implicitHeight)

          Text {
            id: heroIcon
            text: root.glyph
            color: root.mounted ? Color.accent : root.bar.foreground
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.display
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
          }

          Column {
            id: heroLabels
            anchors.left: heroIcon.right
            anchors.leftMargin: Style.space(14)
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            spacing: Style.space(2)

            Text {
              text: "Lockbox"
              color: root.bar.foreground
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
              elide: Text.ElideRight
              width: parent.width
            }
            Text {
              text: root.stateText
              color: root.bar.foreground
              opacity: 0.7
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.caption
              elide: Text.ElideRight
              width: parent.width
            }
          }
        }

        PanelSeparator { width: parent.width }

        // gocryptfs missing
        Column {
          width: parent.width
          spacing: Style.space(8)
          visible: root.statusLoaded && !root.installed

          Text {
            width: parent.width
            wrapMode: Text.WordWrap
            text: "Lockbox needs the gocryptfs package from the Arch repos. Install it as root, then reopen this panel."
            color: root.bar.foreground
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.body
          }
          Text {
            width: parent.width
            text: "pacman -S gocryptfs"
            color: Color.accent
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.body
          }
          Button {
            text: "Copy command"
            bordered: true
            onClicked: root.copyText("pacman -S gocryptfs")
          }
        }

        // No vault yet
        Column {
          width: parent.width
          spacing: Style.space(8)
          visible: root.statusLoaded && root.installed && !root.exists

          Text {
            width: parent.width
            wrapMode: Text.WordWrap
            text: "Create an encrypted folder. Files you put in " + root.mountPoint + " are stored encrypted in " + root.cipherDir + "."
            color: root.bar.foreground
            opacity: 0.85
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.body
          }
          TextField {
            id: newPwField
            width: parent.width
            maximumLength: 1024
            password: true
            placeholderText: "Vault password (8+ characters)"
            onAccepted: confirmPwField.forceActiveFocus()
          }
          TextField {
            id: confirmPwField
            width: parent.width
            maximumLength: 1024
            password: true
            placeholderText: "Confirm password"
            onAccepted: root.create(newPwField.text, confirmPwField.text)
          }
          Button {
            text: root.busy ? "Creating…" : "Create vault"
            iconText: "󰐕"
            bordered: true
            enabled: !root.busy
            onClicked: root.create(newPwField.text, confirmPwField.text)
          }
        }

        // Master key, shown once after creation
        Column {
          width: parent.width
          spacing: Style.space(6)
          visible: root.masterKey !== ""

          PanelSectionHeader { text: "Recovery master key" }
          Text {
            width: parent.width
            wrapMode: Text.WordWrap
            text: "Shown once. Store it somewhere safe; it can open the vault if you forget the password."
            color: root.bar.foreground
            opacity: 0.85
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.caption
          }
          Text {
            width: parent.width
            wrapMode: Text.WrapAnywhere
            text: root.masterKey
            color: Color.accent
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.caption
          }
          Row {
            spacing: Style.spacing.controlGap
            Button { text: "Copy"; bordered: true; onClicked: root.copyText(root.masterKey) }
            Button { text: "I saved it"; onClicked: root.masterKey = "" }
          }
        }

        // Locked: unlock form
        Column {
          width: parent.width
          spacing: Style.space(8)
          visible: root.statusLoaded && root.installed && root.exists && !root.mounted

          TextField {
            id: pwField
            width: parent.width
            maximumLength: 1024
            password: true
            placeholderText: "Vault password"
            enabled: !root.busy
            onAccepted: root.unlock(pwField.text)
          }
          Button {
            text: root.busy ? "Unlocking…" : "Unlock"
            iconText: "󰌿"
            bordered: true
            enabled: !root.busy
            onClicked: root.unlock(pwField.text)
          }
          Text {
            width: parent.width
            wrapMode: Text.WordWrap
            text: root.autoLockText
            color: root.bar.foreground
            opacity: 0.6
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.caption
          }
        }

        // Unlocked
        Column {
          width: parent.width
          spacing: Style.space(8)
          visible: root.statusLoaded && root.mounted

          Row {
            spacing: Style.spacing.controlGap
            Button {
              text: "Open folder"
              iconText: "󰉋"
              bordered: true
              onClicked: root.openFolder()
            }
            Button {
              text: root.busy ? "Locking…" : "Lock now"
              iconText: "󰌾"
              bordered: true
              enabled: !root.busy
              onClicked: root.lock()
            }
          }
          Text {
            width: parent.width
            wrapMode: Text.WordWrap
            text: root.mountPoint + "\n" + root.autoLockText
            color: root.bar.foreground
            opacity: 0.6
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.caption
          }
        }

        // Error
        Text {
          width: parent.width
          wrapMode: Text.WordWrap
          visible: root.errorText !== ""
          text: root.errorText
          color: Color.urgent
          font.family: root.bar.fontFamily
          font.pixelSize: Style.font.caption
        }

        PanelSeparator { width: parent.width; visible: root.statusLoaded && root.installed }

        Text {
          width: parent.width
          visible: root.statusLoaded && root.installed
          wrapMode: Text.WrapAnywhere
          text: "Encrypted storage: " + root.cipherDir
          color: root.bar.foreground
          opacity: 0.45
          font.family: root.bar.fontFamily
          font.pixelSize: Style.font.caption
        }
      }
    }
  }
}
