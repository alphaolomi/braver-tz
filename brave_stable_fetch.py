#!/usr/bin/env python3
"""
brave_stable_fetch.py

Cross-platform downloader (and optional installer) for the latest *stable* Brave release
from GitHub Releases: brave/brave-browser.

- Detects OS + CPU arch
- Chooses best-matching asset (.dmg, .exe, .deb, .rpm)
- Downloads it
- Optional install step: --install (prompts before doing anything destructive)

Notes:
- GitHub API is rate-limited. If you hit limits, set env var GITHUB_TOKEN to a personal token.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

GITHUB_API_LATEST = "https://api.github.com/repos/brave/brave-browser/releases/latest"


@dataclass
class SystemInfo:
    os_name: str          # "macos" | "windows" | "linux"
    arch: str             # "arm64" | "x64" | "x86" | "unknown"
    linux_family: str     # "debian" | "rhel" | "arch" | "unknown" (only used on linux)


def log(msg: str) -> None:
    print(msg, flush=True)


def http_get_json(url: str) -> Dict[str, Any]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "brave-stable-fetch/1.0",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req) as resp:
        data = resp.read().decode("utf-8")
    return json.loads(data)


def detect_linux_family() -> str:
    # Best-effort detection using /etc/os-release
    osr = Path("/etc/os-release")
    if not osr.exists():
        return "unknown"

    text = osr.read_text(errors="ignore")
    # Parse like KEY=VALUE
    vals = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        vals[k.strip()] = v.strip().strip('"')

    distro_id = (vals.get("ID") or "").lower()
    like = (vals.get("ID_LIKE") or "").lower()

    def has_any(s: str, words: List[str]) -> bool:
        return any(w in s for w in words)

    if has_any(distro_id, ["debian", "ubuntu", "linuxmint", "pop"]) or has_any(like, ["debian", "ubuntu"]):
        return "debian"
    if has_any(distro_id, ["fedora", "rhel", "centos", "rocky", "almalinux", "opensuse", "sles"]) or has_any(like, ["rhel", "fedora", "suse"]):
        return "rhel"
    if has_any(distro_id, ["arch", "manjaro", "endeavouros"]) or has_any(like, ["arch"]):
        return "arch"

    return "unknown"


def detect_system() -> SystemInfo:
    sys_plat = sys.platform.lower()
    machine = platform.machine().lower()

    # OS
    if sys_plat.startswith("darwin"):
        os_name = "macos"
    elif sys_plat.startswith("win"):
        os_name = "windows"
    elif sys_plat.startswith("linux"):
        os_name = "linux"
    else:
        os_name = "unknown"

    # Arch
    # Normalize common values
    if machine in ("arm64", "aarch64"):
        arch = "arm64"
    elif machine in ("x86_64", "amd64"):
        arch = "x64"
    elif machine in ("i386", "i686", "x86"):
        arch = "x86"
    else:
        arch = "unknown"

    linux_family = detect_linux_family() if os_name == "linux" else "unknown"
    return SystemInfo(os_name=os_name, arch=arch, linux_family=linux_family)


def pick_asset(assets: List[Dict[str, Any]], si: SystemInfo) -> Tuple[Dict[str, Any], str]:
    """
    Returns (asset, reason).
    Picks conservatively and robustly by filename patterns.
    """
    names = [a.get("name", "") for a in assets]

    def find_by_pred(pred) -> Optional[Dict[str, Any]]:
        for a in assets:
            n = (a.get("name") or "").lower()
            if pred(n):
                return a
        return None

    # macOS: prefer universal dmg, then arch-specific dmg, then pkg
    if si.os_name == "macos":
        # Brave commonly uses "Brave-Browser-universal.dmg" in releases. :contentReference[oaicite:2]{index=2}
        a = find_by_pred(lambda n: n.endswith(".dmg") and "universal" in n)
        if a:
            return a, "macOS: chose universal .dmg"
        if si.arch == "arm64":
            a = find_by_pred(lambda n: n.endswith(".dmg") and ("arm64" in n or "aarch64" in n))
            if a:
                return a, "macOS ARM: chose arm64 .dmg"
        if si.arch == "x64":
            a = find_by_pred(lambda n: n.endswith(".dmg") and ("x64" in n or "amd64" in n or "x86_64" in n))
            if a:
                return a, "macOS Intel: chose x64 .dmg"
        a = find_by_pred(lambda n: n.endswith(".dmg"))
        if a:
            return a, "macOS: chose first available .dmg"
        a = find_by_pred(lambda n: n.endswith(".pkg"))
        if a:
            return a, "macOS: chose .pkg (no .dmg found)"

    # Windows: prefer StandaloneSetup (offline installer), then any .exe
    if si.os_name == "windows":
        a = find_by_pred(lambda n: n.endswith(".exe") and "standalone" in n and "setup" in n)
        if a:
            return a, "Windows: chose StandaloneSetup.exe (offline installer)"
        a = find_by_pred(lambda n: n.endswith(".exe") and "setup" in n)
        if a:
            return a, "Windows: chose Setup.exe"
        a = find_by_pred(lambda n: n.endswith(".exe"))
        if a:
            return a, "Windows: chose first available .exe"

    # Linux: prefer .deb for Debian-like, .rpm for RHEL-like; try to match arch
    if si.os_name == "linux":
        arch_tokens = []
        if si.arch == "x64":
            arch_tokens = ["amd64", "x86_64"]
        elif si.arch == "arm64":
            arch_tokens = ["arm64", "aarch64"]

        if si.linux_family == "debian":
            # Prefer matching arch if present in filename
            for tok in arch_tokens:
                a = find_by_pred(lambda n, t=tok: n.endswith(".deb") and t in n)
                if a:
                    return a, f"Linux Debian-like: chose .deb matching {tok}"
            a = find_by_pred(lambda n: n.endswith(".deb"))
            if a:
                return a, "Linux Debian-like: chose first available .deb"

        if si.linux_family == "rhel":
            for tok in arch_tokens:
                a = find_by_pred(lambda n, t=tok: n.endswith(".rpm") and t in n)
                if a:
                    return a, f"Linux RHEL-like: chose .rpm matching {tok}"
            a = find_by_pred(lambda n: n.endswith(".rpm"))
            if a:
                return a, "Linux RHEL-like: chose first available .rpm"

        # Fallbacks: try .deb then .rpm then .tar.gz/.zip
        a = find_by_pred(lambda n: n.endswith(".deb"))
        if a:
            return a, "Linux: fallback to .deb"
        a = find_by_pred(lambda n: n.endswith(".rpm"))
        if a:
            return a, "Linux: fallback to .rpm"
        a = find_by_pred(lambda n: n.endswith(".tar.gz") or n.endswith(".zip"))
        if a:
            return a, "Linux: fallback to archive"

    raise RuntimeError(
        "Could not find a suitable asset in this release.\n"
        f"Detected system: {si}\n"
        f"Assets seen (first 30): {names[:30]}"
    )


def download_file(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    log(f"Downloading:\n  {url}\n→ {dest}")
    with urllib.request.urlopen(url) as resp, open(dest, "wb") as f:
        total = resp.length or 0
        read = 0
        chunk = 1024 * 256
        while True:
            b = resp.read(chunk)
            if not b:
                break
            f.write(b)
            read += len(b)
            if total:
                pct = (read / total) * 100
                print(f"\r{pct:6.2f}% ({read}/{total} bytes)", end="", flush=True)
        if total:
            print()
    log("Download complete.")


def prompt_yes_no(question: str, default_no: bool = True) -> bool:
    suffix = " [y/N]: " if default_no else " [Y/n]: "
    ans = input(question + suffix).strip().lower()
    if not ans:
        return not default_no
    return ans in ("y", "yes")


def install_macos(pkg_or_dmg: Path) -> None:
    # Handles DMG by mounting and copying app to /Applications.
    # Handles PKG by running installer.
    if pkg_or_dmg.suffix.lower() == ".pkg":
        log("Installing .pkg via macOS installer (will prompt for admin password if needed)...")
        subprocess.check_call(["sudo", "installer", "-pkg", str(pkg_or_dmg), "-target", "/"])
        log("Install finished.")
        return

    if pkg_or_dmg.suffix.lower() != ".dmg":
        raise RuntimeError("macOS install expects .dmg or .pkg")

    mountpoint = Path("/Volumes/BraveTmpMount")
    mountpoint.mkdir(parents=True, exist_ok=True)

    log("Mounting DMG...")
    subprocess.check_call(["hdiutil", "attach", str(pkg_or_dmg), "-mountpoint", str(mountpoint), "-nobrowse", "-quiet"])

    try:
        app = mountpoint / "Brave Browser.app"
        if not app.exists():
            # Sometimes app bundle name differs; try to find any *.app
            apps = list(mountpoint.glob("*.app"))
            if apps:
                app = apps[0]
            else:
                raise RuntimeError("Could not find .app inside the DMG.")

        target = Path("/Applications") / app.name
        log(f"Copying {app.name} to /Applications ...")
        # Remove old app if present
        if target.exists():
            subprocess.check_call(["sudo", "rm", "-rf", str(target)])
        subprocess.check_call(["sudo", "cp", "-R", str(app), str(target)])
        log("Brave copied to /Applications.")
    finally:
        log("Unmounting DMG...")
        subprocess.call(["hdiutil", "detach", str(mountpoint), "-quiet"])


def install_windows(exe_path: Path) -> None:
    # Runs the installer normally. Silent flags differ by installer type; keep it simple.
    log("Launching installer...")
    os.startfile(str(exe_path))  # type: ignore[attr-defined]


def install_linux(pkg: Path, family: str) -> None:
    if pkg.suffix.lower() == ".deb":
        log("Installing .deb (will prompt for sudo password if needed)...")
        subprocess.check_call(["sudo", "dpkg", "-i", str(pkg)])
        log("Install finished. (If dependencies failed, run: sudo apt -f install)")
        return
    if pkg.suffix.lower() == ".rpm":
        log("Installing .rpm (will prompt for sudo password if needed)...")
        # dnf is preferred if available; otherwise rpm
        if shutil.which("dnf"):
            subprocess.check_call(["sudo", "dnf", "install", "-y", str(pkg)])
        elif shutil.which("yum"):
            subprocess.check_call(["sudo", "yum", "install", "-y", str(pkg)])
        else:
            subprocess.check_call(["sudo", "rpm", "-Uvh", str(pkg)])
        log("Install finished.")
        return

    raise RuntimeError(f"Don't know how to install {pkg.name} on Linux (family={family}).")


def main() -> int:
    ap = argparse.ArgumentParser(description="Download latest stable Brave from GitHub Releases (and optionally install).")
    ap.add_argument("--dir", default=str(Path.home() / "Downloads"), help="Download directory (default: ~/Downloads)")
    ap.add_argument("--install", action="store_true", help="After download, prompt and attempt to install")
    ap.add_argument("--print-only", action="store_true", help="Only print chosen version and asset URL; do not download")
    args = ap.parse_args()

    si = detect_system()
    log(f"Detected system: os={si.os_name}, arch={si.arch}, linux_family={si.linux_family}")

    rel = http_get_json(GITHUB_API_LATEST)
    tag = rel.get("tag_name", "")
    name = rel.get("name", "")
    body = rel.get("body", "")
    assets = rel.get("assets", [])

    if not assets:
        log("Release has no assets. Exiting.")
        return 2

    asset, reason = pick_asset(assets, si)
    asset_name = asset.get("name", "unknown")
    url = asset.get("browser_download_url", "")

    log(f"Latest stable release: {tag}  ({name})")
    log(f"Chosen asset: {asset_name}")
    log(f"Reason: {reason}")
    if body:
        # Optional extra: show Chromium base version if present (often included in release text)
        m = re.search(r"Chromium:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", body)
        if m:
            log(f"Chromium base: {m.group(1)}")

    if not url:
        log("No download URL found for chosen asset. Exiting.")
        return 3

    if args.print_only:
        print(url)
        return 0

    dest_dir = Path(args.dir).expanduser().resolve()
    dest = dest_dir / asset_name
    download_file(url, dest)

    if args.install:
        if not prompt_yes_no(f"Install {asset_name} now?", default_no=True):
            log("Install skipped.")
            return 0

        if si.os_name == "macos":
            install_macos(dest)
        elif si.os_name == "windows":
            install_windows(dest)
        elif si.os_name == "linux":
            install_linux(dest, si.linux_family)
        else:
            log("Unknown OS; cannot install automatically.")
            return 4

        log("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
