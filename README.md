# KJAGU // Defensive Endpoint Threat Hunter & Browser Shield

```
  _  ______   _    ____ _   _ 
 | |/ /___ \ / \  / ___| | | |
 | ' /  __) / _ \| |  _| | | |
 | . \ / __/ ___ \ |_| | |_| |
 |_|\_\_____/_/   \_\____|\___/ 
 DEFENSIVE ENDPOINT THREAT HUNTER
 Version 4.0 -- Absolute Immortal Inc.
```

Kjagu is a hybrid defensive endpoint security system and anti-spyware suite designed to audit, triage, and neutralize infostealers, memory injections, unauthorized browser surveillance, and persistence hooks.

Built around a **Zero-API-Key philosophy**: **100% free, requiring zero paid external LLM API tokens**. Kjagu offers two complementary operational modes:
1. **Standalone Claude-Style CLI Shell:** Zero-overhead, 100% local heuristic correlation engine running entirely inside your terminal.
2. **Browser Shield Extension & Native Messaging Bridge:** Manifest V3 browser extension and IPC bridge integrating free browser-based AI analysis (DeepSeek / Kimi chat) without API keys.

---

## Architecture Overview

```
+-----------------------------------------------------------------------------------+
|                                 KJAGU ECOSYSTEM                                   |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [MODE 1: STANDALONE CLI ENGINE]                  [MODE 2: BROWSER SHIELD & BRIDGE]  |
|                                                                                   |
|  +-----------------------------+                  +----------------------------+  |
|  |       kjagu_core.py         |                  |    Manifest V3 Extension   |  |
|  |  * Claude-Style Terminal UI |                  |  * Chrome / Brave / Edge   |  |
|  |  * Local Heuristic Matrix   |                  |  * Injected Chat HUD       |  |
|  |  * Zero Cloud / Zero Keys   |                  |  * Cookie & Storage Shield |  |
|  +-----------------------------+                  +----------------------------+  |
|                 |                                                |                |
|                 v                                                v                |
|  +-----------------------------+                  +----------------------------+  |
|  |     Endpoint Subsystems     |                  |   Native Messaging Bridge  |  |
|  |  * Process Memory Auditing  |                  |  * com.kjagu.ridit         |  |
|  |  * C2 Socket Correlation    |                  |  * kjagu_bridge.py / .bat  |  |
|  |  * Registry Persistence     |                  +----------------------------+  |
|  |  * Safe Quarantine Vault    |                                 |                |
|  +-----------------------------+                                 v                |
|                                                   +----------------------------+  |
|                                                   |   Modular Scanner Core     |  |
|                                                   |  * Recon Module (Telemetry)|  |
|                                                   |  * Reverse Engineer (PE)   |  |
|                                                   |  * Kernel Access Hooks     |  |
|                                                   |  * Approval Action System  |  |
|                                                   +----------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## Key Capabilities

- **Zero Paid API Requirement:** No OpenAI, Anthropic, or DeepSeek API subscription required. Use local standalone heuristics or free browser chat bridges.
- **Claude-Style Terminal UI:** Modern terminal interface featuring ANSI palettes, box drawing, real-time stage progression indicators (`●`, `✔`, `▲`), and structured threat incident cards.
- **Browser Shield Extension (v4.0 Prototype):** Manifest V3 extension for Chrome, Brave, and Edge with an in-browser HUD on `chat.deepseek.com` and `kimi.moonshot.cn` for zero-cost AI triage.
- **Chrome Native Messaging Bridge:** 32-bit length-prefixed JSON protocol over stdin/stdout connecting browser security controls to the local Python engine.
- **Multi-Vector Telemetry:** Concurrent auditing of processes, unbacked memory regions (`PAGE_EXECUTE_READWRITE`), network sockets, browser extensions, registry hooks, and startup artifacts.
- **Static PE Reverse Engineering:** Automated entropy calculation, PE header parsing, import table extraction, and packer detection (`scanner/reverse_engineer.py`).
- **Safe Isolation & Quarantine Vault:** Isolated file containment with AES-256-GCM metadata tracking and full rollback capability. Files are never irreversibly deleted without administrator intent.
- **Hardware-Bound Cookie Vault:** Transparent AES-256-GCM encryption of Chromium and Gecko credential databases keyed to hardware identifiers (CPU, BIOS, and disk serials).

---

## Quickstart

### Option 1: Standalone CLI (Recommended for Fast Triage)

Single-click launcher for Windows:

```cmd
start.bat
```

For Linux / WSL:

```bash
chmod +x start.sh
./start.sh
```

Or run directly with Python:

```bash
pip install -r requirements.txt
python kjagu_core.py
```

#### Interactive Terminal Commands

```
kjagu ❯ /help

  Commands:
    /scan         Run deep endpoint threat audit
    /quick        Run quick scan (processes & memory only)
    /vault        Encrypt browser cookie stores (AES-256-GCM)
    /quarantine   List quarantined files and restore options
    /restore <id> Restore quarantined artifact by ID
    /status       Show system telemetry and engine status
    /help         Display this help message
    /exit         Exit Kjagu
```

---

### Option 2: Browser Extension & Free AI Bridge

The v4 prototype pairs a Chrome/Brave/Edge extension with the Python native bridge to provide free AI-assisted threat triage through web chat interfaces.

#### Step 1: Install Native Messaging Host

Run the bridge setup script as Administrator:

```cmd
run_bridge.bat
```

This automatically:
1. Updates `bridge/host_manifest.json` with your local installation path.
2. Registers `com.kjagu.ridit` in the Windows Registry for Google Chrome, Brave Browser, Microsoft Edge, and Chromium.
3. Prepares the desktop report destination (`%USERPROFILE%\Desktop\KjaguReports`).

#### Step 2: Load the Extension

1. Open your browser (**Chrome**, **Brave**, or **Edge**).
2. Navigate to extensions management:
   - Chrome: `chrome://extensions`
   - Brave: `brave://extensions`
   - Edge: `edge://extensions`
3. Turn on **Developer mode** (toggle in the top-right corner).
4. Click **Load unpacked**.
5. Select the `extension/` folder inside this repository:
   ```
   C:\Users\USER\kjagu\extension
   ```
6. The extension with ID `afedgicomnmflgadegkmlemcipmpebce` will appear in your toolbar.

#### Step 3: Launch Free AI Web Chat

1. Open [chat.deepseek.com](https://chat.deepseek.com) or [kimi.moonshot.cn](https://kimi.moonshot.cn).
2. The **KJAGU // AI SHIELD** floating panel will appear on the page.
3. Click **START AI SCAN** or use the extension toolbar popup.
4. Review threat cards, reverse engineering reports, and approve or dismiss neutralization actions directly inside your browser window.

---

## Directory Structure

```
kjagu/
├── kjagu_core.py              # v3.1 Standalone Claude-Style CLI Engine
├── start.bat                  # One-click Windows CLI launcher
├── start.sh                   # Linux / WSL CLI launcher
├── run_bridge.bat             # One-click Windows Bridge & Extension installer
├── requirements.txt           # Python dependencies (psutil, cryptography, pywin32)
├── README.md                  # Complete architectural documentation
├── extension/                 # Manifest V3 Browser Extension
│   ├── manifest.json          # Extension manifest with deterministic RSA public key
│   ├── background.js          # Service worker managing Native Messaging port
│   ├── content_script.js      # HUD injected into DeepSeek and Kimi chat
│   ├── popup.html             # Toolbar popup interface
│   ├── popup.js               # Popup event handler and status polling
│   ├── popup.css              # Cyberpunk dark theme stylesheet
│   └── icons/                 # Shield icons (16x16, 48x48, 128x128)
├── bridge/                    # Native Messaging Host
│   ├── host_manifest.json     # Chrome native host manifest
│   ├── install_host.bat       # Multi-browser Windows registry installer
│   ├── kjagu_bridge.bat       # Win32 batch launcher for Chrome CreateProcess
│   └── kjagu_bridge.py        # 32-bit length-prefixed stdin/stdout IPC conduit
└── scanner/                   # Modular v4 Scanning Core
    ├── __init__.py            # Package export
    ├── kjagu_engine.py        # Central orchestrator
    ├── recon_module.py        # Process, memory, network & persistence collector
    ├── reverse_engineer.py    # PE parser, entropy calculator & string extractor
    ├── kernel_access.py       # Driver signature verification & privilege checks
    ├── approval_system.py     # Interactive action gating (terminate / isolate)
    ├── policy_manager.py      # Action authorization policies
    └── report_generator.py    # JSON forensic report compiler
```

---

## CLI Flags Reference

For headless execution in scripts, scheduled tasks, or incident response workflows:

| Flag | Description |
|------|-------------|
| `--scan` | Execute a complete multi-vector endpoint threat audit. |
| `--quick` | Rapid triage scanning active processes and memory allocations only. |
| `--aggressive`, `--kill` | Automatically neutralize and quarantine verified threats without prompts. |
| `--vault` | Lock and encrypt Chromium and Gecko cookie databases with hardware keys. |
| `--quarantine-list` | Display all currently quarantined files, hashes, and isolation timestamps. |
| `--restore <ID>` | Revert and restore a quarantined artifact back to its original path. |
| `--json <PATH>` | Output machine-readable JSON forensic telemetry to a designated file path. |
| `-h`, `--help` | Display command usage and option reference. |

---

## Responsible Security Disclaimer

Kjagu is developed for defensive research, system auditing, and incident response. It is designed to assist administrators and security researchers in identifying indicators of compromise (IoCs).

While the correlation engine incorporates aggressive heuristic detection, defensive tools may produce false positives on game anti-cheat software, kernel debugging tools, or enterprise EDR agents. Always verify incident cards before executing aggressive file isolation.

---

## Author & Research

Developed by **demonala** // **Hendry**  
Chief Architect & Security Researcher  
**Absolute Immortal Inc.**
