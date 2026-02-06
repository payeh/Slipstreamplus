# Slipstream Plus 🚀

**فارسی | English**: `README-fa.md` | `README.md`

A Windows desktop app for managing Slipstream-based proxies, scanning DNS endpoints, and routing traffic through `sing-box` with an easy GUI.

## ✨ Key Features
- 🧩 Proxy manager with import, add, copy, and remove actions
- ⚡ Fast DNS scan with CIDR support and optional real ping test
- 🌍 Global or IR‑Direct routing modes (using geo rule sets)
- 🧭 One‑click system proxy enable/disable
- 📶 LAN mode for sharing proxy with phones on the same network
- 🔄 Auto reconnect
- 📊 Live traffic stats (optional `websocket-client`)

## ✅ Requirements
- Windows 10/11
- `bin/sing-box.exe`
- `bin/slipstream-client-windows-amd64.exe`
- Python 3.10+ if running from source
- Python packages: `PySide6` (required), `websocket-client` (optional)

## 🚀 Quick Start (Windows Binary)
1. Make sure the `bin/` folder is present and contains:
   - `sing-box.exe`
   - `slipstream-client-windows-amd64.exe`
   - `libcrypto-3-x64.dll` and `libssl-3-x64.dll`
2. Run `Slipstreamplus.exe`.
3. Add a Slipstream proxy and click **CONNECT**.

## 🧑‍💻 Run From Source
```bash
python -m pip install -U PySide6 websocket-client
python Slipstreamplus.py
```

## 🧭 Using The App

### 1) Proxy Tab
- **Import Links**: paste one or more links
- **Add Config**: add a single proxy manually
- **Copy Link**: copy selected proxy
- **Remove Selected**: delete selected proxies

**Slipstream link format**
```
SLIPSTREAM://<DNS_IP>@<DOMAIN>:53#<REMARKS>
```
Example:
```
SLIPSTREAM://1.2.3.4@example.com:53#My%20Server
```

**Modes**
- **Global**: all traffic goes through proxy
- **IR‑Direct**: Iran traffic goes direct (requires geo rule files in `geo/srss/`)

**System Proxy**
Use **Set System Proxy** / **Clear System Proxy** to control Windows proxy settings.

### 2) Scanner Tab
- Load IPs/CIDRs from a file or paste them
- Set timeout, threads, and domain
- Start scan to find working DNS IPs
- Add results directly to the proxy list

**Real Ping Test**
Runs a deeper check on scan results to estimate real latency.

### 3) LAN Mode
Enable **LAN Mode (Hotspot)** to share your proxy with devices on the same Wi‑Fi.

## ⚙️ Configuration & Data
- The app auto‑creates config files in `config/` on first run.
- **Important:** `config/` is ignored by Git because it may contain sensitive data.
- To reset the app, close it and delete the `config/` folder.

## 📂 Project Structure
- `Slipstreamplus.py` — main application
- `bin/` — runtime binaries (`sing-box`, `slipstream-client`, DLLs)
- `geo/` — geo rule sets
- `cidrs/` — CIDR lists
- `asset/` — UI assets
- `icon.ico` — app icon

## 🧱 Build (PyInstaller)
```bash
pyinstaller Slipstreamplus.spec
```

## 🛠️ Troubleshooting
- **sing-box.exe not found**: place it in `bin/` or add it to your PATH.
- **No traffic stats**: install `websocket-client`.
- **App already running**: close the tray icon instance and try again.

## 🔐 Security Notes
- Do not commit `config/` to version control.
- If sensitive data leaked, rotate keys/tokens immediately.

## 📄 License
No license is specified yet.
