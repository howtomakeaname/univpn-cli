#!/usr/bin/env python3
"""Build an explicit release allowlist; never package the working directory."""
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import zipfile


def main():
    version = os.environ.get("UVPN_VERSION", "dev")
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?|dev|main", version):
        raise SystemExit("Unsupported release version")
    goos, arch = os.environ["GOOS"], os.environ["GOARCH"]
    if goos not in ("linux", "darwin", "windows") or arch not in ("amd64", "arm64"):
        raise SystemExit("Unsupported release platform")
    name = "uvpn_" + version + "_" + goos + "_" + arch
    dist = Path("dist")
    dist.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / ("uvpn.exe" if goos == "windows" else "uvpn")
        subprocess.run(["go", "build", "-trimpath", "-ldflags", "-s -w -X main.version=" + version, "-o", str(binary), "./cmd/uvpn"], check=True)
        entries = [(binary, binary.name)]
        entries += [(Path(p), p) for p in ("README.md", "README.zh-CN.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "config.example.json")]
        entries += [(p, p.as_posix()) for p in sorted(Path("third_party/licenses").glob("*.txt"))]
        if goos == "windows":
            target = dist / (name + ".zip")
            with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
                for path, dest in entries:
                    z.write(path, name + "/" + dest)
        else:
            target = dist / (name + ".tar.gz")
            with tarfile.open(target, "w:gz") as t:
                for path, dest in entries:
                    t.add(path, arcname=name + "/" + dest)
        print(target)


if __name__ == "__main__":
    main()
