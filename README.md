# wifiscan

A small, dependency-free command-line tool that lists nearby Wi-Fi networks and flags the ones with weak or suspicious security.

- Every visible access point: **SSID, BSSID, channel, band, signal and security**
- Flags **open networks, WEP, WPA (v1) and TKIP-only** WPA2
- Spots the **same network name advertised with different security**, a classic evil-twin sign
- Notes **hidden SSIDs**
- Uses the OS's own Wi-Fi tools (**netsh, nmcli, system_profiler**), so nothing to install

Python 3.8+, standard library only. Windows, macOS and Linux.

## Usage

```bash
# Everything in range
python wifiscan.py

# Only networks with problems
python wifiscan.py --issues

# Save for a site survey
python wifiscan.py -f csv -o office-wifi.csv
```

### Example output

```
PS C:\> python wifiscan.py
  STATUS SSID                         BSSID                CH BAND      SIGNAL  SECURITY
  WARN   HomeNet                      aa:bb:cc:11:22:33    36 5 GHz        92%  WPA2-Personal CCMP
  WARN   HomeNet                      aa:bb:cc:11:22:34     6 2.4 GHz      70%  WPA2-Personal CCMP
  FAIL   HomeNet                      de:ad:be:ef:00:01     1 2.4 GHz      55%  Open None
  FAIL   CoffeeShop                   10:20:30:40:50:60    11 2.4 GHz      40%  Open None
  WARN   (hidden)                     00:00:00:00:00:09   149 5 GHz        20%  WPA-Personal TKIP

  [WARN] HomeNet (aa:bb:cc:11:22:33): WPA2; same name advertised with different security (possible evil twin)
  [WARN] HomeNet (aa:bb:cc:11:22:34): WPA2; same name advertised with different security (possible evil twin)
  [FAIL] HomeNet (de:ad:be:ef:00:01): Open network; traffic is unencrypted; same name advertised with different security (possible evil twin)
  [FAIL] CoffeeShop (10:20:30:40:50:60): Open network; traffic is unencrypted
  [WARN] (hidden) (00:00:00:00:00:09): WPA (v1) is outdated; use WPA2 or WPA3; hidden SSID

[*] 5 access point(s), 3 network name(s), 5 with issues
```

## Options

| Flag | Description |
|---|---|
| `-a, --issues` | Only show networks with problems |
| `-f, --format` | Output format (`table` / `csv` / `json`) |
| `-o, --output FILE` | Write results to a file |
| `--no-color` | Plain output without colors |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No issues found |
| `1` | At least one network has an issue |
| `2` | Unsupported OS or the Wi-Fi scan failed |

## Notes

It's passive: it reads what your Wi-Fi adapter already hears and never connects to or sends anything to the networks.

**Windows 11:** `netsh wlan` needs Location services turned on (Settings > Privacy & security > Location, and allow desktop apps). wifiscan tells you if that's what's blocking it. Output labels are parsed in English.

**Linux** needs NetworkManager (`nmcli`). Windows reports signal as a percentage, macOS in dBm.

An evil-twin warning isn't proof of an attack: some venues really do run an open guest SSID with the same name. It's a prompt to check which access points you actually own.

**Status:** tested on macOS and Linux. The Windows code path follows Microsoft's documented output but hasn't been field-tested yet; please open an issue if anything looks off.

## License

MIT, see [LICENSE](LICENSE).

---

Part of [Landull](https://github.com/Landull)'s scankit.
