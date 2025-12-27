# Braver-tz

<p align="center">
  <img src="braver-tz-banner.png" alt="braver-tz banner showing Brave shield, network nodes, and clock" width="100%">
</p>

A cross-platform Python script that automatically downloads the **latest stable release of Brave Browser** directly from **GitHub Releases**, without relying on brave.com.

This project is useful in environments where the official Brave website is blocked or inaccessible, but GitHub remains reachable.

---

## ✨ Features

- Fetches the **latest stable Brave release** from the official GitHub repository
- Automatically detects:
  - Operating system (macOS, Windows, Linux)
  - CPU architecture (x64, ARM64, etc.)
  - Linux distribution family (Debian-based, RHEL-based when possible)
- Selects the most appropriate installer:
  - `.dmg` / `.pkg` for macOS
  - `.exe` for Windows
  - `.deb` or `.rpm` for Linux
- Downloads the installer automatically
- Optional interactive installation step
- Uses only Python standard library (no external dependencies)

---

## 🖥️ Platform Support Status

| Platform | Status |
|--------|--------|
| macOS | ✅ Tested |
| Windows | ✅ Tested |
| Linux | ⚠️ Untested |

> **Important:**  
> This script has currently been tested **macOS and Windows**.  
> Linux users are strongly encouraged to test it and report results.

Please open an issue if you encounter:
- Incorrect installer selection
- Architecture mismatches
- Installation failures
- Any unexpected behavior

---

## 🔧 Requirements

- Python **3.8+**
- Internet access to `api.github.com`
- Administrator privileges **only if installing** (platform-dependent)

No third-party Python packages are required.

---

## 🚀 Usage

Download the script:

```bash
git clone https://github.com/maotora/braver-tz.git
cd braver-tz
```

Run to download only:

```bash
python3 braver.py
```

Download **and** install (you will be prompted):

```bash
python3 braver.py --install
```

Print the direct download URL only (useful for automation):

```bash
python3 braver.py --print-only
```

Specify a custom download directory:

```bash
python3 braver.py --dir /path/to/downloads
```

---

## 🧠 How It Works

1. Detects the local system OS and CPU architecture
2. Queries the GitHub Releases API for:
   ```
   brave/brave-browser
   ```
3. Selects the **latest stable release**
4. Chooses the best-matching installer asset
5. Downloads the installer
6. Optionally runs the installer using native OS mechanisms

The script intentionally avoids:
- Beta releases
- Nightly releases
- Release candidates

---

## 🔐 GitHub API Rate Limits

GitHub enforces unauthenticated rate limits.

If you hit a rate limit, set a token:

```bash
export GITHUB_TOKEN=your_token_here
python3 braver.py
```

---

## 🤝 Contributing

Contributions are welcome!

Especially needed:
- Windows testing
- Linux distro compatibility testing
- Installer selection improvements
- Error handling improvements

Please:
1. Open an issue describing the problem
2. Include OS, architecture, and installer name
3. Attach logs or error output when possible

---

## 📄 License

This project is licensed under the **MIT License**.  
See the `LICENSE` file for details.
