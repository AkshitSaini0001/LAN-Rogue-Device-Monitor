#!/usr/bin/env python3
"""
LAN Device Discovery & Rogue Device Monitor  (CSL-G34)
Cyber Security Lab (7CS4-22) - Exp 6: ARP Poisoning / LAN Attacks

Scans the LAN periodically (ping sweep + ARP table), compares devices against an
approved list (MAC / vendor) and raises alerts when:
  1. an UNKNOWN device joins the network (rogue device)
  2. an IP address suddenly maps to a different MAC (possible ARP spoofing)
  3. an approved device goes offline (optional info)

Use ONLY on your own lab network / VMs.  Standard library only (no installs).

Usage:
  python lan_monitor.py scan                   # one scan, print table
  python lan_monitor.py learn                  # mark all currently seen devices as approved
  python lan_monitor.py approve AA:BB:.. "Name"# approve a single MAC
  python lan_monitor.py monitor -i 30          # scan every 30 s, alert on rogue devices
  python lan_monitor.py monitor --simulate     # demo without a real network
  python lan_monitor.py list                   # show approved list
"""
import argparse, csv, ipaddress, json, os, platform, re, socket
import subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

APPROVED_FILE = "approved_devices.json"
ALERT_LOG = "alerts.log"
HISTORY_CSV = "scan_history.csv"

# Small built-in OUI table (first 3 bytes of MAC -> vendor). Extend as needed.
OUI = {
    "00:50:56": "VMware", "00:0C:29": "VMware", "08:00:27": "VirtualBox",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "24:0A:C4": "Espressif (ESP32)", "30:AE:A4": "Espressif (ESP32)", "A4:CF:12": "Espressif",
    "3C:5A:B4": "Google", "F4:F5:D8": "Google", "AC:BC:32": "Apple", "F0:18:98": "Apple",
    "00:1A:11": "Google", "FC:FB:FB": "Cisco", "00:1B:63": "Apple", "D8:BB:C1": "Micro-Star",
    "9C:B6:D0": "Rivet Networks", "18:C0:4D": "Giga-Byte", "50:E5:49": "Giga-Byte",
    "E8:DE:27": "TP-Link", "50:C7:BF": "TP-Link", "C0:25:E9": "TP-Link",
}

RED, GREEN, YELLOW, RESET = "\033[91m", "\033[92m", "\033[93m", "\033[0m"


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def norm_mac(m):
    return m.upper().replace("-", ":")


def vendor_of(mac):
    return OUI.get(norm_mac(mac)[:8], "Unknown vendor")


# ---------------------------------------------------------------- scanning
def local_subnet():
    """Find own IP via UDP trick and assume /24."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    except OSError:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ipaddress.ip_network(ip + "/24", strict=False), ip


def ping(ip):
    flag = "-n" if platform.system() == "Windows" else "-c"
    wait = ["-w", "700"] if platform.system() == "Windows" else ["-W", "1"]
    try:
        subprocess.run(["ping", flag, "1", *wait, str(ip)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
    except Exception:
        pass


def read_arp_table():
    """Return {ip: mac} from the OS ARP cache."""
    table = {}
    if os.path.exists("/proc/net/arp"):                       # Linux
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                p = line.split()
                if len(p) >= 4 and p[3] != "00:00:00:00:00:00" and p[2] != "0x0":
                    table[p[0]] = norm_mac(p[3])
        return table
    out = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout   # Win/Mac
    for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)\D+?([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})", out):
        mac = ":".join(x.zfill(2) for x in re.split(r"[:-]", m.group(2)))
        if not mac.upper().startswith(("FF:FF", "01:00:5E")):
            table[m.group(1)] = norm_mac(mac)
    return table


def hostname_of(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "-"


def real_scan():
    net, my_ip = local_subnet()
    with ThreadPoolExecutor(max_workers=64) as ex:
        list(ex.map(ping, net.hosts()))
    arp = read_arp_table()
    devices = {}
    for ip, mac in arp.items():
        if ipaddress.ip_address(ip) in net:
            devices[mac] = {"ip": ip, "vendor": vendor_of(mac), "host": hostname_of(ip)}
    return devices


# ------------------------------------------------------- simulation (demo)
SIM_ROUNDS = [
    {"AA:BB:CC:00:00:01": ("192.168.1.1", "TP-Link router"),
     "08:00:27:11:22:33": ("192.168.1.10", "Kali VM"),
     "B8:27:EB:44:55:66": ("192.168.1.20", "Raspberry Pi")},
    {"AA:BB:CC:00:00:01": ("192.168.1.1", "TP-Link router"),
     "08:00:27:11:22:33": ("192.168.1.10", "Kali VM"),
     "B8:27:EB:44:55:66": ("192.168.1.20", "Raspberry Pi"),
     "DE:AD:BE:EF:00:99": ("192.168.1.77", "unknown-phone")},           # rogue joins
    {"AA:BB:CC:00:00:01": ("192.168.1.1", "TP-Link router"),
     "08:00:27:11:22:33": ("192.168.1.10", "Kali VM"),
     "DE:AD:BE:EF:00:99": ("192.168.1.20", "attacker-box"),             # takes Pi's IP -> spoof
     "DE:AD:BE:EF:00:99_": ("192.168.1.77", "x")},
]


def sim_scan(round_no):
    data = SIM_ROUNDS[min(round_no, len(SIM_ROUNDS) - 1)]
    return {m.rstrip("_"): {"ip": ip, "vendor": vendor_of(m), "host": h}
            for m, (ip, h) in data.items() if not m.endswith("_")}


# ------------------------------------------------------------ persistence
def load_approved():
    if os.path.exists(APPROVED_FILE):
        with open(APPROVED_FILE) as f:
            return json.load(f)
    return {}


def save_approved(a):
    with open(APPROVED_FILE, "w") as f:
        json.dump(a, f, indent=2)


def alert(level, msg):
    color = RED if level in ("ROGUE", "SPOOF?") else YELLOW
    line = f"[{now()}] [{level}] {msg}"
    print(color + line + RESET)
    with open(ALERT_LOG, "a") as f:
        f.write(line + "\n")


def log_history(devices):
    new = not os.path.exists(HISTORY_CSV)
    with open(HISTORY_CSV, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["time", "mac", "ip", "vendor", "hostname", "status"])
        approved = load_approved()
        for mac, d in devices.items():
            w.writerow([now(), mac, d["ip"], d["vendor"], d["host"],
                        "approved" if mac in approved else "UNKNOWN"])


def print_table(devices):
    approved = load_approved()
    print(f"\n{'IP':<16}{'MAC':<19}{'Vendor':<20}{'Hostname':<18}Status")
    print("-" * 80)
    for mac, d in sorted(devices.items(), key=lambda x: ipaddress.ip_address(x[1]["ip"])):
        ok = mac in approved
        st = (GREEN + "approved" if ok else RED + "UNKNOWN") + RESET
        print(f"{d['ip']:<16}{mac:<19}{d['vendor']:<20}{d['host'][:17]:<18}{st}")
    print()


# ---------------------------------------------------------------- monitor
def check(devices, prev, approved):
    """Compare current scan with approved list and previous scan; raise alerts."""
    for mac, d in devices.items():
        if mac not in approved:
            if prev is None or mac not in prev:
                alert("ROGUE", f"Unknown device joined: MAC={mac} IP={d['ip']} vendor={d['vendor']}")
    if prev is not None:
        ip_prev = {d["ip"]: m for m, d in prev.items()}
        for mac, d in devices.items():
            old = ip_prev.get(d["ip"])
            if old and old != mac:
                alert("SPOOF?", f"IP {d['ip']} changed MAC {old} -> {mac} (possible ARP poisoning)")
        for mac in prev:
            if mac in approved and mac not in devices:
                alert("INFO", f"Approved device offline: {approved[mac]['name']} ({mac})")


def monitor(interval, simulate):
    approved = load_approved()
    if not approved:
        print("Approved list is empty - run `learn` first on a clean network.")
        if not simulate:
            return
    prev, rnd = None, 0
    print(f"Monitoring every {interval}s. Ctrl+C to stop.")
    try:
        while True:
            devices = sim_scan(rnd) if simulate else real_scan()
            print(f"[{now()}] scan #{rnd + 1}: {len(devices)} device(s)")
            check(devices, prev, approved)
            log_history(devices)
            print_table(devices)
            prev, rnd = devices, rnd + 1
            if simulate and rnd >= len(SIM_ROUNDS):
                break
            time.sleep(0 if simulate else interval)
    except KeyboardInterrupt:
        print("\nStopped.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["scan", "learn", "approve", "monitor", "list"])
    ap.add_argument("mac", nargs="?")
    ap.add_argument("name", nargs="?", default="device")
    ap.add_argument("-i", "--interval", type=int, default=60)
    ap.add_argument("--simulate", action="store_true", help="use fake devices (demo/testing)")
    a = ap.parse_args()

    if a.cmd == "scan":
        print_table(sim_scan(1) if a.simulate else real_scan())
    elif a.cmd == "learn":
        devs = sim_scan(0) if a.simulate else real_scan()
        ap_ = load_approved()
        for mac, d in devs.items():
            ap_[mac] = {"name": d["host"] if d["host"] != "-" else d["vendor"],
                        "ip": d["ip"], "vendor": d["vendor"], "added": now()}
        save_approved(ap_)
        print(f"Approved {len(devs)} device(s) -> {APPROVED_FILE}")
    elif a.cmd == "approve":
        if not a.mac:
            sys.exit("give a MAC address")
        ap_ = load_approved()
        ap_[norm_mac(a.mac)] = {"name": a.name, "vendor": vendor_of(a.mac), "added": now()}
        save_approved(ap_)
        print("Approved", norm_mac(a.mac))
    elif a.cmd == "list":
        for m, d in load_approved().items():
            print(f"{m}  {d['name']:<20} {d.get('vendor', '')}")
    elif a.cmd == "monitor":
        monitor(a.interval, a.simulate)


if __name__ == "__main__":
    main()
