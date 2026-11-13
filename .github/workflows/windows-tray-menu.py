"""Check that the Tailscale Windows tray menu lists an exit node.

The Windows GUI is closed source, so its menu is the only view of what it
shows. The menu is opened by posting the notify-icon callback straight to the
GUI's sink window, so no taskbar or mouse is needed, and is then read with
GetMenuString, which works across processes because menus live in the desktop
heap rather than in the GUI's memory.
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import json
import pathlib
import sys
import time

u = ctypes.WinDLL("user32", use_last_error=True)
u.FindWindowW.argtypes = [wt.LPCWSTR, wt.LPCWSTR]
u.FindWindowW.restype = wt.HWND
u.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
u.SendMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
u.SendMessageW.restype = wt.HMENU
u.IsWindowVisible.argtypes = [wt.HWND]
u.GetMenuItemCount.argtypes = [wt.HMENU]
u.GetMenuStringW.argtypes = [wt.HMENU, wt.UINT, wt.LPWSTR, ctypes.c_int, wt.UINT]
u.GetMenuState.argtypes = [wt.HMENU, wt.UINT, wt.UINT]
u.GetMenuState.restype = wt.UINT
u.GetSubMenu.argtypes = [wt.HMENU, ctypes.c_int]
u.GetSubMenu.restype = wt.HMENU

# github.com/tailscale/walk: notifyIconWindowClass, and the first message it
# allocates per window class (WM_USER+3) as the notify-icon callback.
SINK_CLASS = "WalkNotifyIconSink"
CALLBACK = 0x0400 + 3
WM_CONTEXTMENU = 0x007B
WM_KEYDOWN, VK_ESCAPE = 0x0100, 0x1B
MN_GETHMENU = 0x01E1
POPUP_CLASS = "#32768"
MF_BYPOSITION = 0x400
MF_GRAYED, MF_DISABLED, MF_CHECKED = 0x1, 0x2, 0x8


def read(hmenu):
    items = []
    for i in range(u.GetMenuItemCount(hmenu)):
        buf = ctypes.create_unicode_buffer(512)
        u.GetMenuStringW(hmenu, i, buf, len(buf), MF_BYPOSITION)
        sub = u.GetSubMenu(hmenu, i)
        state = u.GetMenuState(hmenu, i, MF_BYPOSITION)
        if sub:
            state &= 0xFF  # the high byte of a submenu's state is its item count
        items.append(
            {
                "text": buf.value.replace("&", ""),
                "disabled": bool(state & (MF_GRAYED | MF_DISABLED)),
                "checked": bool(state & MF_CHECKED),
                "children": read(sub) if sub else [],
            }
        )
    return items


def wait_popup(visible):
    for _ in range(20):
        popup = u.FindWindowW(POPUP_CLASS, None)
        if bool(popup and u.IsWindowVisible(popup)) == visible:
            return popup or True
        time.sleep(0.1)
    return None


def open_menu(sink):
    # The icon id rides in the high word; a GUID icon ignores it, so try a few.
    for uid in range(4):
        u.PostMessageW(sink, CALLBACK, 0, (uid << 16) | WM_CONTEXTMENU)
        popup = wait_popup(True)
        if popup:
            return popup, uid
    return None, None


def close_menu(sink, popup, uid):
    # walk cancels a shown menu on a second WM_CONTEXTMENU.
    u.PostMessageW(sink, CALLBACK, 0, (uid << 16) | WM_CONTEXTMENU)
    if not wait_popup(False):
        u.PostMessageW(popup, WM_KEYDOWN, VK_ESCAPE, 0)
        wait_popup(False)


def render(items, depth=0):
    out = []
    for it in items:
        flags = "".join(f for f, on in (("[x]", it["checked"]), ("(disabled)", it["disabled"])) if on)
        out.append("  " * depth + (it["text"] or "----") + (" " + flags if flags else ""))
        out += render(it["children"], depth + 1)
    return out


def usable_exit_node(items, name):
    for it in items:
        if "exit node" in it["text"].lower() and it["children"]:
            for c in it["children"]:
                if c["text"].startswith(name) and not c["disabled"] and "(offline)" not in c["text"]:
                    return True
        if usable_exit_node(it["children"], name):
            return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--expect", required=True, help="exit node hostname that must be selectable")
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--timeout", type=float, default=120)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    tree = []
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        sink = u.FindWindowW(SINK_CLASS, None)
        popup, uid = open_menu(sink) if sink else (None, None)
        if popup:
            tree = read(u.SendMessageW(popup, MN_GETHMENU, 0, 0))
            close_menu(sink, popup, uid)
            if usable_exit_node(tree, args.expect):
                break
        time.sleep(3)

    (args.out / "menu.json").write_text(json.dumps(tree, indent=2))
    print("\n".join(render(tree)) or "no tray menu found")
    if not usable_exit_node(tree, args.expect):
        print(f"FAIL: {args.expect!r} is not a selectable exit node in the tray menu", file=sys.stderr)
        return 1
    print(f"OK: {args.expect!r} is a selectable exit node")
    return 0


if __name__ == "__main__":
    sys.exit(main())
