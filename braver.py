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
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import URLError, HTTPError

GITHUB_API_LATEST = "https://api.github.com/repos/brave/brave-browser/releases/latest"
ALLOWED_DOMAINS = {"github.com", "githubusercontent.com"}


@dataclass
class SystemInfo:
    os_name: str          # "macos" | "windows" | "linux"
    arch: str             # "arm64" | "x64" | "x86" | "unknown"
    linux_family: str     # "debian" | "rhel" | "arch" | "unknown" (only used on linux)


# Global flag to control log output destination
_PRINT_ONLY_MODE = False

def log(msg: str) -> None:
    """Log message to stdout (or stderr if in print-only mode)."""
    if _PRINT_ONLY_MODE:
        print(msg, file=sys.stderr, flush=True)
    else:
        print(msg, flush=True)


def validate_url(url: str) -> bool:
    """Validate that URL is from allowed domain."""
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]
        return any(domain.endswith(f".{allowed}") or domain == allowed for allowed in ALLOWED_DOMAINS)
    except Exception:
        return False


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal."""
    # Remove path components
    filename = os.path.basename(filename)
    # Remove dangerous characters
    dangerous = ["..", "/", "\\", "\x00"]
    for d in dangerous:
        filename = filename.replace(d, "")
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:255-len(ext)] + ext
    return filename


def verify_file_hash(file_path: Path, expected_hash: str) -> bool:
    """Verify file SHA256 hash."""
    if not expected_hash:
        return False
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)
        computed = sha256.hexdigest().lower()
        expected = expected_hash.lower().strip()
        return computed == expected
    except Exception as e:
        log(f"Error computing hash: {e}")
        return False


def http_get_json(url: str, timeout: int = 30, max_retries: int = 3) -> Dict[str, Any]:
    """Fetch JSON with retry logic and timeout."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "brave-stable-fetch/1.0",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        # Basic validation - token should not contain spaces or newlines
        token = token.strip()
        if not token or "\n" in token or " " in token:
            log("Warning: GITHUB_TOKEN appears invalid, ignoring.")
        else:
            headers["Authorization"] = f"Bearer {token}"

    last_error = None
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    raise URLError(f"HTTP {resp.status}: {resp.reason}")
                data = resp.read().decode("utf-8")
                result = json.loads(data)
                # Validate response structure
                if not isinstance(result, dict):
                    raise ValueError("API response is not a JSON object")
                return result
        except (URLError, socket.timeout, socket.error, json.JSONDecodeError, ValueError) as e:
            last_error = e
            if attempt < max_retries - 1:
                wait = 2 ** attempt  # Exponential backoff
                log(f"Attempt {attempt + 1} failed: {e}. Retrying in {wait}s...")
                time.sleep(wait)
            else:
                log(f"All {max_retries} attempts failed.")
    
    raise RuntimeError(f"Failed to fetch {url} after {max_retries} attempts: {last_error}")


def validate_release_data(rel: Dict[str, Any]) -> None:
    """Validate GitHub release API response structure."""
    required_fields = ["tag_name", "assets"]
    for field in required_fields:
        if field not in rel:
            raise ValueError(f"Invalid API response: missing field '{field}'")
    
    if not isinstance(rel["assets"], list):
        raise ValueError("Invalid API response: 'assets' must be a list")
    
    for asset in rel["assets"]:
        if not isinstance(asset, dict):
            raise ValueError("Invalid API response: asset must be a dict")
        if "name" not in asset or "browser_download_url" not in asset:
            raise ValueError("Invalid API response: asset missing required fields")


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
        # Brave commonly uses "Brave-Browser-universal.dmg" in releases.
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


def download_file(url: str, dest: Path, expected_hash: Optional[str] = None, 
                  timeout: int = 60, max_retries: int = 3) -> None:
    """Download file with retry, resume, and integrity verification."""
    if not validate_url(url):
        raise ValueError(f"URL not from allowed domain: {url}")
    
    dest.parent.mkdir(parents=True, exist_ok=True)
    
    # Check disk space (rough estimate - need at least 500MB free)
    try:
        stat = shutil.disk_usage(dest.parent)
        free_mb = stat.free / (1024 * 1024)
        if free_mb < 500:
            raise RuntimeError(f"Insufficient disk space: {free_mb:.0f}MB free (need at least 500MB)")
    except Exception as e:
        log(f"Warning: Could not check disk space: {e}")
    
    # Resume partial download
    resume_pos = 0
    if dest.exists():
        resume_pos = dest.stat().st_size
        if resume_pos > 0:
            log(f"Resuming download from byte {resume_pos}...")
    
    last_error = None
    for attempt in range(max_retries):
        try:
            headers = {}
            if resume_pos > 0:
                headers["Range"] = f"bytes={resume_pos}-"
            
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                # Check if server supports resume
                if resume_pos > 0 and resp.status not in (206, 200):
                    log("Server doesn't support resume, starting from beginning...")
                    resume_pos = 0
                    dest.unlink()
                    headers.pop("Range", None)
                    req = urllib.request.Request(url, headers=headers)
                    resp = urllib.request.urlopen(req, timeout=timeout)
                
                total = int(resp.headers.get("Content-Length", 0)) or (resp.length or 0)
                if resume_pos > 0 and total > 0:
                    total += resume_pos
                
                mode = "ab" if resume_pos > 0 else "wb"
                log(f"Downloading:\n  {url}\n-> {dest}")
                with open(dest, mode) as f:
                    read = resume_pos
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
                
                # Verify file size if Content-Length was provided
                actual_size = dest.stat().st_size
                if total > 0 and actual_size != total:
                    raise RuntimeError(f"Size mismatch: expected {total}, got {actual_size}")
                
                # Verify hash if provided
                if expected_hash:
                    log("Verifying download integrity...")
                    if not verify_file_hash(dest, expected_hash):
                        raise RuntimeError("Download integrity check failed! File may be corrupted.")
                    log("Integrity check passed.")
                
                log("Download complete.")
                return
                
        except HTTPError as e:
            # Handle 416 Range Not Satisfiable - file may have changed or range invalid
            if e.code == 416:
                log(f"Range request failed (416), deleting partial file and restarting...")
                if dest.exists():
                    dest.unlink()
                resume_pos = 0
                last_error = e
                if attempt < max_retries - 1:
                    wait = 2 ** attempt
                    log(f"Download attempt {attempt + 1} failed: {e}. Retrying in {wait}s...")
                    time.sleep(wait)
                continue
            else:
                last_error = e
                if attempt < max_retries - 1:
                    wait = 2 ** attempt
                    log(f"Download attempt {attempt + 1} failed: {e}. Retrying in {wait}s...")
                    time.sleep(wait)
                else:
                    # Clean up partial download on final failure if empty
                    if dest.exists() and dest.stat().st_size == 0:
                        dest.unlink()
        except (URLError, socket.timeout, socket.error, OSError) as e:
            last_error = e
            if attempt < max_retries - 1:
                wait = 2 ** attempt
                log(f"Download attempt {attempt + 1} failed: {e}. Retrying in {wait}s...")
                time.sleep(wait)
            else:
                # Clean up partial download on final failure if empty
                if dest.exists() and dest.stat().st_size == 0:
                    dest.unlink()
    
    raise RuntimeError(f"Failed to download {url} after {max_retries} attempts: {last_error}")


def prompt_yes_no(question: str, default_no: bool = True) -> bool:
    # Check if stdin is available (interactive terminal)
    if not sys.stdin.isatty():
        # Non-interactive environment (CI, pipes, etc.) - return default
        return not default_no
    suffix = " [y/N]: " if default_no else " [Y/n]: "
    ans = input(question + suffix).strip().lower()
    if not ans:
        return not default_no
    return ans in ("y", "yes")


def install_macos(pkg_or_dmg: Path) -> None:
    """Install with better error handling and cleanup."""
    if not pkg_or_dmg.exists():
        raise FileNotFoundError(f"Install file not found: {pkg_or_dmg}")
    
    if pkg_or_dmg.suffix.lower() == ".pkg":
        log("Installing .pkg via macOS installer (will prompt for admin password if needed)...")
        try:
            subprocess.check_call(
                ["sudo", "installer", "-pkg", str(pkg_or_dmg), "-target", "/"],
                timeout=600  # 10 minute timeout
            )
            log("Install finished.")
            return
        except subprocess.TimeoutExpired:
            raise RuntimeError("Installation timed out after 10 minutes")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Installation failed with exit code {e.returncode}")

    if pkg_or_dmg.suffix.lower() != ".dmg":
        raise RuntimeError("macOS install expects .dmg or .pkg")

    mountpoint = Path("/Volumes/BraveTmpMount")
    mounted = False
    
    try:
        # Clean up any existing mount
        if mountpoint.exists():
            try:
                subprocess.run(["hdiutil", "detach", str(mountpoint), "-quiet"], 
                             capture_output=True, timeout=5)
            except Exception:
                pass
        
        mountpoint.mkdir(parents=True, exist_ok=True)
        log("Mounting DMG...")
        subprocess.check_call(
            ["hdiutil", "attach", str(pkg_or_dmg), "-mountpoint", str(mountpoint), 
             "-nobrowse", "-quiet"],
            timeout=60
        )
        mounted = True

        app = mountpoint / "Brave Browser.app"
        if not app.exists():
            apps = list(mountpoint.glob("*.app"))
            if apps:
                app = apps[0]
            else:
                raise RuntimeError("Could not find .app inside the DMG.")

        target = Path("/Applications") / app.name
        log(f"Copying {app.name} to /Applications ...")
        
        if target.exists():
            subprocess.check_call(
                ["sudo", "rm", "-rf", str(target)],
                timeout=30
            )
        
        subprocess.check_call(
            ["sudo", "cp", "-R", str(app), str(target)],
            timeout=300
        )
        log("Brave copied to /Applications.")
        
    except subprocess.TimeoutExpired:
        raise RuntimeError("Operation timed out")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Installation command failed: {e}")
    finally:
        if mounted:
            log("Unmounting DMG...")
            for _ in range(3):  # Try up to 3 times
                try:
                    subprocess.run(
                        ["hdiutil", "detach", str(mountpoint), "-quiet"],
                        timeout=10,
                        capture_output=True
                    )
                    break
                except Exception as e:
                    if _ == 2:
                        log(f"Warning: Could not unmount DMG: {e}")
                    else:
                        time.sleep(1)


def install_windows(exe_path: Path) -> None:
    """Runs the installer normally."""
    if not exe_path.exists():
        raise FileNotFoundError(f"Install file not found: {exe_path}")
    log("Launching installer...")
    os.startfile(str(exe_path))  # type: ignore[attr-defined]


def install_linux(pkg: Path, family: str) -> None:
    """Install Linux package with better error handling."""
    if not pkg.exists():
        raise FileNotFoundError(f"Install file not found: {pkg}")
    
    if pkg.suffix.lower() == ".deb":
        log("Installing .deb (will prompt for sudo password if needed)...")
        try:
            subprocess.check_call(
                ["sudo", "dpkg", "-i", str(pkg)],
                timeout=600
            )
            log("Install finished. (If dependencies failed, run: sudo apt -f install)")
            return
        except subprocess.TimeoutExpired:
            raise RuntimeError("Installation timed out after 10 minutes")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Installation failed with exit code {e.returncode}")
    
    if pkg.suffix.lower() == ".rpm":
        log("Installing .rpm (will prompt for sudo password if needed)...")
        # dnf is preferred if available; otherwise rpm
        try:
            if shutil.which("dnf"):
                subprocess.check_call(
                    ["sudo", "dnf", "install", "-y", str(pkg)],
                    timeout=600
                )
            elif shutil.which("yum"):
                subprocess.check_call(
                    ["sudo", "yum", "install", "-y", str(pkg)],
                    timeout=600
                )
            else:
                subprocess.check_call(
                    ["sudo", "rpm", "-Uvh", str(pkg)],
                    timeout=600
                )
            log("Install finished.")
            return
        except subprocess.TimeoutExpired:
            raise RuntimeError("Installation timed out after 10 minutes")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Installation failed with exit code {e.returncode}")

    raise RuntimeError(f"Don't know how to install {pkg.name} on Linux (family={family}).")


def main() -> int:
    global _PRINT_ONLY_MODE
    ap = argparse.ArgumentParser(description="Download latest stable Brave from GitHub Releases (and optionally install).")
    ap.add_argument("--dir", default=str(Path.home() / "Downloads"), help="Download directory (default: ~/Downloads)")
    ap.add_argument("--install", action="store_true", help="After download, prompt and attempt to install")
    ap.add_argument("--print-only", action="store_true", help="Only print chosen version and asset URL; do not download")
    ap.add_argument("--skip-verify", action="store_true", help="Skip integrity verification (not recommended)")
    args = ap.parse_args()

    # Set global flag for log output redirection
    _PRINT_ONLY_MODE = args.print_only

    try:
        si = detect_system()
        log(f"Detected system: os={si.os_name}, arch={si.arch}, linux_family={si.linux_family}")

        rel = http_get_json(GITHUB_API_LATEST)
        validate_release_data(rel)
        
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
        
        # Get hash if available from asset's digest field
        expected_hash = None
        if not args.skip_verify:
            # Extract SHA256 from asset's digest field (format: "sha256:hash")
            digest = asset.get("digest", "")
            if digest and digest.startswith("sha256:"):
                expected_hash = digest[7:]  # Remove "sha256:" prefix
                log(f"Found SHA256 hash for verification: {expected_hash[:16]}...")
            else:
                # Fallback: Look for checksums file in release assets
                for a in assets:
                    name_lower = a.get("name", "").lower()
                    if "checksum" in name_lower or "sha256" in name_lower:
                        # Could download and parse checksums file here if needed
                        pass

        # Sanitize filename
        asset_name = sanitize_filename(asset_name)

        log(f"Latest stable release: {tag}  ({name})")
        log(f"Chosen asset: {asset_name}")
        log(f"Reason: {reason}")
        if body:
            m = re.search(r"Chromium:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", body)
            if m:
                log(f"Chromium base: {m.group(1)}")

        if not url:
            log("No download URL found for chosen asset. Exiting.")
            return 3
        
        if not validate_url(url):
            log(f"ERROR: Download URL failed validation: {url}")
            return 5

        if args.print_only:
            print(url)
            return 0

        dest_dir = Path(args.dir).expanduser().resolve()
        # Ensure destination is within user's home, current working directory, or explicitly allowed absolute path
        cwd = Path.cwd()
        is_in_home = str(dest_dir).startswith(str(Path.home()))
        is_in_cwd = str(dest_dir).startswith(str(cwd))
        is_absolute_allowed = args.dir.startswith("/") or (os.name == "nt" and len(args.dir) > 1 and args.dir[1] == ":")
        
        if not (is_in_home or is_in_cwd or is_absolute_allowed):
            log(f"Warning: Download directory is outside home and current directory: {dest_dir}")
            if not prompt_yes_no("Continue anyway?", default_no=True):
                return 1
        
        dest = dest_dir / asset_name
        download_file(url, dest, expected_hash=expected_hash if not args.skip_verify else None)

        if args.install:
            if not prompt_yes_no(f"Install {asset_name} now?", default_no=True):
                log("Install skipped.")
                return 0

            try:
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
            except Exception as e:
                log(f"Installation failed: {e}")
                return 6
        
        return 0
    except KeyboardInterrupt:
        log("\nInterrupted by user.")
        return 130
    except Exception as e:
        log(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())