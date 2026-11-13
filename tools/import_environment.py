#!/usr/bin/env python3
"""Import only VPN credentials and permitted targets; never copy SSH/BMC passwords."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile


def cells(path):
    ns = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    with zipfile.ZipFile(path) as z:
        strings = []
        if "xl/sharedStrings.xml" in z.namelist():
            strings = ["".join(e.itertext()) for e in ET.fromstring(z.read("xl/sharedStrings.xml")).findall("s:si", ns)]
        doc = ET.fromstring(z.read("xl/worksheets/sheet1.xml"))
        out = {}
        for c in doc.findall(".//s:c", ns):
            v = c.find("s:v", ns)
            text = v.text if v is not None else ""
            if c.get("t") == "s":
                text = strings[int(text)]
            elif c.get("t") == "inlineStr":
                text = "".join(c.find("s:is", ns).itertext())
            if text:
                out[c.get("r")] = text
        return out


def private_write(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(content)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("xlsx", type=Path)
    p.add_argument("--output", type=Path, default=Path(".private/hidevlab.json"))
    p.add_argument("--row", type=int, default=3)
    a = p.parse_args()
    c = cells(a.xlsx)
    # Validate the attached HiDevLab schema instead of silently using wrong columns.
    expected = {"I1": "SSL VPN", "I2": "IP", "J2": "端口", "K2": "用户名", "L2": "密码", "M2": "BMC IP", "P2": "业务系统 IP"}
    if any(c.get(k, "").strip() != v for k, v in expected.items()):
        raise SystemExit("Unsupported spreadsheet schema; inspect column labels locally.")
    row = str(a.row)
    gateway = str(ipaddress.IPv4Address(c["I" + row].strip()))
    port = int(float(c["J" + row]))
    if not 0 < port < 65536:
        raise SystemExit("Invalid VPN port")
    hosts = {}
    for col, name in (("P", "atlas.internal"), ("M", "bmc.internal")):
        if c.get(col + row):
            hosts[name] = str(ipaddress.IPv4Address(c[col + row].strip()))
    if not hosts:
        raise SystemExit("No permitted target found")
    parent = a.output.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if parent.stat().st_mode & 0o077:
        raise SystemExit("Output directory must be private (chmod 700)")
    password_path = parent / "vpn-password"
    if a.output.exists() or password_path.exists():
        raise SystemExit("Output already exists; refusing to overwrite secrets/configuration")
    config = {
        "gateway": gateway + ":" + str(port),
        "username": c["K" + row],
        "password_file": password_path.name,
        "listen": "127.0.0.1:7890",
        "allow_cidrs": [ip + "/32" for ip in dict.fromkeys(hosts.values())],
        "hosts": hosts,
        "mtu": 1400,
        "max_connections": 256,
    }
    private_write(password_path, c["L" + row].encode())
    try:
        private_write(a.output, (json.dumps(config, ensure_ascii=False, indent=2) + "\n").encode())
    except Exception:
        password_path.unlink()
        raise
    print("Created private config and VPN password file; imported", len(hosts), "permitted targets.")
    print("No SSH/BMC passwords copied. TLS verification remains enabled; MFA is interactive.")


if __name__ == "__main__":
    main()
