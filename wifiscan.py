#!/usr/bin/env python3
"""
wifiscan - list nearby Wi-Fi networks and flag weak security.

Uses the operating system's own Wi-Fi tools (netsh on Windows, nmcli on
Linux, system_profiler on macOS) to list nearby access points with
SSID, BSSID, channel, band and signal, then flags open and WEP networks,
legacy WPA / TKIP, hidden SSIDs, and the same network name advertised
with different security, a common sign of an evil-twin access point.

Passive: it only reads what the Wi-Fi adapter already hears.

Standard library only. Python 3.8+.
"""

import argparse
import csv
import json
import platform
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone

__version__ = "1.0.0"

PASS, WARN, FAIL, INFO = "PASS", "WARN", "FAIL", "INFO"


def run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                           encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as err:
        raise RuntimeError(str(err))
    return r.returncode, r.stdout + r.stderr


def band_for(channel):
    try:
        ch = int(channel)
    except (TypeError, ValueError):
        return ""
    if ch <= 14:
        return "2.4 GHz"
    if ch <= 177:
        return "5 GHz"
    return "6 GHz"


# ---- Windows -----------------------------------------------------------------

def scan_windows():
    code, out = run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    if code != 0 or "SSID" not in out:
        if "location" in out.lower():
            raise RuntimeError("Windows blocked the scan: turn on Location services "
                               "(Settings > Privacy & security > Location) and allow desktop apps.")
        raise RuntimeError(out.strip() or "netsh wlan failed (is Wi-Fi on?)")
    nets = []
    ssid = auth = enc = None
    current = None
    for raw in out.splitlines():
        line = raw.strip()
        m = re.match(r"^SSID \d+\s*:\s?(.*)$", line)
        if m:
            ssid, auth, enc = m.group(1), "", ""
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key.startswith("authentication"):
            auth = value
        elif key.startswith("encryption"):
            enc = value
        elif key.startswith("bssid"):
            current = {"ssid": ssid, "bssid": value.lower(), "auth": auth, "cipher": enc,
                       "signal": None, "channel": None, "band": "", "radio": ""}
            nets.append(current)
        elif current is not None:
            if key.startswith("signal"):
                current["signal"] = int(re.sub(r"\D", "", value) or 0)
            elif key.startswith("channel") and not key.startswith("channel util"):
                current["channel"] = value.split()[0]
            elif key.startswith("band"):
                current["band"] = value
            elif key.startswith("radio type"):
                current["radio"] = value
    for n in nets:
        n["band"] = n["band"] or band_for(n["channel"])
        n["security"] = f"{n['auth']} {n['cipher']}".strip()
    return nets


# ---- Linux -------------------------------------------------------------------

def split_nmcli(line):
    return [p.replace("\\:", ":") for p in re.split(r"(?<!\\):", line)]


def scan_linux():
    if not shutil.which("nmcli"):
        raise RuntimeError("nmcli not found; install NetworkManager or run on a desktop distro")
    code, out = run(["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi", "list",
                     "--rescan", "auto"])
    if code != 0:
        raise RuntimeError(out.strip() or "nmcli failed (is there a Wi-Fi adapter?)")
    nets = []
    for line in out.splitlines():
        parts = split_nmcli(line)
        if len(parts) < 5:
            continue
        ssid, bssid, chan, signal, sec = parts[:5]
        nets.append({"ssid": ssid, "bssid": bssid.lower(), "channel": chan, "band": band_for(chan),
                     "signal": int(signal) if signal.isdigit() else None,
                     "security": sec if sec and sec != "--" else "Open",
                     "auth": sec, "cipher": "", "radio": ""})
    return nets


# ---- macOS -------------------------------------------------------------------

def scan_mac():
    code, out = run(["system_profiler", "SPAirPortDataType", "-json"])
    if code != 0 or "{" not in out:
        raise RuntimeError("system_profiler failed")
    data = json.loads(out[out.index("{"):])
    nets = []
    redacted = 0
    for block in data.get("SPAirPortDataType", []):
        for iface in block.get("spairport_airport_interfaces", []):
            cur = iface.get("spairport_current_network_information")
            others = iface.get("spairport_airport_other_local_wireless_networks", [])
            for n in ([cur] if isinstance(cur, dict) else []) + list(others):
                chan_raw = str(n.get("spairport_network_channel", ""))
                chan = (re.match(r"\d+", chan_raw) or [""])[0]
                sec = str(n.get("spairport_security_mode", "")).replace("spairport_security_mode_", "")
                sec = sec.replace("pairport_security_mode_", "").replace("_", " ").strip()
                sig = re.match(r"(-?\d+)", str(n.get("spairport_signal_noise", "")))
                ssid = n.get("_name", "")
                if ssid in ("<redacted>", ""):
                    redacted += 1
                nets.append({"ssid": "" if ssid == "<redacted>" else ssid, "redacted": ssid == "<redacted>", "bssid": "", "channel": chan,
                             "band": band_for(chan), "signal": int(sig.group(1)) if sig else None,
                             "security": sec or "unknown", "auth": sec, "cipher": "", "radio": ""})
    if nets and redacted == len(nets):
        print("[!] macOS hid the network names. Give your terminal app Location access "
              "(System Settings > Privacy & Security > Location Services) to see them.", file=sys.stderr)
    return nets


# ---- Analysis ----------------------------------------------------------------

def rate(security):
    s = security.lower()
    if s in ("", "none", "--") or s.startswith("open") or s.startswith("none"):
        return FAIL, "Open network; traffic is unencrypted"
    if "wep" in s:
        return FAIL, "WEP can be cracked in minutes"
    if "wpa3" in s or "sae" in s or "owe" in s:
        return PASS, "WPA3"
    if "enterprise" in s or "802.1x" in s or "eap" in s:
        return PASS, "Enterprise (802.1X)"
    if "wpa2" in s:
        if "tkip" in s and "ccmp" not in s and "aes" not in s:
            return WARN, "WPA2 with TKIP only; switch to AES/CCMP"
        return PASS, "WPA2"
    if "wpa" in s:
        return WARN, "WPA (v1) is outdated; use WPA2 or WPA3"
    return INFO, "Unrecognized security"


def analyze(nets):
    by_ssid = defaultdict(set)
    for n in nets:
        n["status"], n["note"] = rate(n["security"])
        if n.get("redacted"):
            pass  # macOS withheld the name; it isn't actually hidden
        elif not n["ssid"]:
            n["note"] += "; hidden SSID"
        elif not n.get("redacted"):
            by_ssid[n["ssid"]].add(n["status"] if n["status"] == FAIL else "secure")
    twins = {s for s, kinds in by_ssid.items() if len(kinds) > 1}
    for n in nets:
        if n["ssid"] in twins:
            n["status"] = FAIL if n["status"] == FAIL else WARN
            n["note"] += "; same name advertised with different security (possible evil twin)"
    return sorted(nets, key=lambda n: (n["signal"] is None, -(n["signal"] or 0)))


def color(status, on):
    return f"\033[{ {PASS: '32', WARN: '33', FAIL: '31', INFO: '36'}[status] }m{status}\033[0m" if on else status


def label(n):
    if n.get("redacted"):
        return "(name withheld)"
    return n["ssid"] or "(hidden)"


def signal_text(v, os_name):
    if v is None:
        return "-"
    return f"{v} dBm" if os_name == "Darwin" else f"{v}%"


def parse_args(argv):
    p = argparse.ArgumentParser(prog="wifiscan", description="List nearby Wi-Fi networks and flag weak security.")
    p.add_argument("-a", "--issues", action="store_true", help="only show networks with problems")
    p.add_argument("-f", "--format", choices=("table", "csv", "json"), default="table", help="output format")
    p.add_argument("-o", "--output", metavar="FILE", help="write results to a file")
    p.add_argument("--no-color", action="store_true", help="plain output without colors")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    system = platform.system()
    scanners = {"Windows": scan_windows, "Linux": scan_linux, "Darwin": scan_mac}
    if system not in scanners:
        print(f"[!] Unsupported OS: {system}", file=sys.stderr)
        return 2
    try:
        nets = analyze(scanners[system]())
    except (RuntimeError, ValueError) as err:
        print(f"[!] {err}", file=sys.stderr)
        return 2
    if args.issues:
        nets = [n for n in nets if n["status"] in (WARN, FAIL)]

    fields = ["ssid", "bssid", "channel", "band", "signal", "security", "status", "note"]
    if args.format == "table" and not args.output:
        use_color = sys.stdout.isatty() and not args.no_color
        print(f"  {'STATUS':<6} {'SSID':<28} {'BSSID':<18} {'CH':>4} {'BAND':<8} {'SIGNAL':>7}  SECURITY")
        for n in nets:
            pad = " " * (6 - len(n["status"]))
            print(f"  {color(n['status'], use_color)}{pad} {label(n)[:28]:<28} "
                  f"{n['bssid'] or '-':<18} {n['channel'] or '-':>4} {n['band']:<8} "
                  f"{signal_text(n['signal'], system):>7}  {n['security']}")
        problems = [n for n in nets if n["status"] in (WARN, FAIL)]
        if problems:
            print()
            for n in problems:
                where = f" ({n['bssid']})" if n["bssid"] else ""
                print(f"  [{color(n['status'], use_color)}] {label(n)}{where}: {n['note']}")
        ssids = {n["ssid"] for n in nets if not n.get("redacted")}
        names = f", {len(ssids)} network name(s)" if ssids else ""
        print(f"\n[*] {len(nets)} access point(s){names}, {len(problems)} with issues")
    elif args.format == "csv":
        fh = open(args.output, "w", newline="", encoding="utf-8") if args.output else sys.stdout
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(nets)
        if args.output:
            fh.close()
    else:
        data = json.dumps({"scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                           "os": system, "networks": [{k: n.get(k) for k in fields} for n in nets]}, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(data + "\n")
        else:
            print(data)
    if args.output:
        print(f"[*] Wrote {args.output}", file=sys.stderr)
    return 1 if any(n["status"] in (WARN, FAIL) for n in nets) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:  # e.g. piped into `head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
