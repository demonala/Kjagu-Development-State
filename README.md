# KJAGU // Defensive Endpoint Threat Hunter

```
  _  ______   _    ____ _   _ 
 | |/ /___ \ / \  / ___| | | |
 | ' /  __) / _ \| |  _| | | |
 | . \ / __/ ___ \ |_| | |_| |
 |_|\_\_____/_/   \_\____|\___/ 
 DEFENSIVE ENDPOINT THREAT HUNTER
 Version 3.1 -- Absolute Immortal Inc.
```

Kjagu is an autonomous, standalone endpoint threat hunter and anti-spyware engine designed to audit, triage, and neutralize infostealers, memory injections, unauthorized browser surveillance, and persistence hooks.

Built with a ZeroScript architecture model: **100% free, fully local, and requiring zero external LLM API keys**. All threat correlation, scoring, and classification runs locally through heuristic analysis pipelines and cross-validation matrices.

---

## Key Highlights

- **Zero API Dependency:** No OpenAI, Anthropic, DeepSeek, or Ollama requirements. Zero telemetry sent off-box.
- **Claude-Style Terminal UI:** Modern terminal interface featuring ANSI palettes, box drawing, real-time stage progression indicators (`●`, `✔`, `▲`), and structured threat incident cards.
- **One-Click Launchers:** Zero-friction setup via `start.bat` (Windows) and `start.sh` (Linux) with automated virtual terminal configuration and dependency verification.
- **Multi-Vector Telemetry:** Concurrent auditing of processes, unbacked memory regions, network sockets, browser extensions, registry hooks, and startup artifacts.
- **Safe Isolation & Quarantine Vault:** Isolated file containment with AES-256-GCM metadata tracking and full rollback capability. Files are never irreversibly deleted without administrator intent.
- **Hardware-Bound Cookie Vault:** Transparent AES-256-GCM encryption of Chromium and Gecko credential databases keyed to hardware identifiers (CPU, BIOS, and disk serials).

---

## Threat Detection Vectors

Kjagu correlates low-level endpoint telemetry across 7 distinct investigative phases:

```
+-------------------------------------------------------------------------+
|                         RECON TELEMETRY GATHERING                       |
|   Processes  |  Memory RWX  |  Sockets  |  Registry  |  Extensions      |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                       HEURISTIC CORRELATION MATRIX                      |
|   Rule Matching  |  Behavioral Scoring  |  Masquerade Classification    |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                          CONSENSUS VALIDATION                           |
|   False-Positive Suppression  |  Known Vendor Whitelisting              |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                          MITIGATION PIPELINE                            |
|   Interactive Confirmation  |  Quarantine Staging  |  Cookie Protection |
+-------------------------------------------------------------------------+
```

1. **Process Masquerading:** Identifies binaries impersonating core system executables (`svchost.exe`, `lsass.exe`, `explorer.exe`) executing out of non-standard directories (`AppData`, `Temp`, `Users/Public`).
2. **Memory Injections:** Flags unbacked executable memory allocations (`PAGE_EXECUTE_READWRITE`), hollowed process memory spaces, and injected threads.
3. **Network Beaconing:** Correlates active sockets against known malicious C2 ports, non-standard outbound HTTP/S tunnels, and ephemeral socket spikes.
4. **Persistence Hooks:** Scans Windows Run/RunOnce registry hives, Winlogon keys, user startup folders, and scheduled tasks for unauthorized autorun entries.
5. **Browser Extension Auditing:** Detects unpacked extensions, sideloaded CRX manifests requesting excessive permissions (`debugger`, `webRequestBlocking`, `<all_urls>`), and telemetry scrapers.
6. **Infostealer Fingerprints:** Hunts for active grabbers targeting Telegram sessions, Discord tokens, crypto wallet keys, and developer credential stores.
7. **Safe Quarantine System:** Quarantined binaries are neutralized, stamped with SHA-256 checksums, and safely isolated inside `.kjagu_vault/` with instant restoration support.

---

## Quickstart

### Windows (Single-Click Launch)

Simply double-click `start.bat` or run from PowerShell / Command Prompt:

```cmd
start.bat
```

The launcher automatically configures UTF-8 console output, checks for Python 3.10+, installs required dependencies from `requirements.txt`, and boots the interactive Claude-style shell.

### Linux / WSL

```bash
chmod +x start.sh
./start.sh
```

### Manual Execution

```bash
pip install -r requirements.txt
python kjagu_core.py
```

---

## Interactive Shell

When launched without arguments, Kjagu enters an interactive terminal shell:

```
╭──────────────────────────────────────────────────────────────────╮
│  ● KJAGU // Defensive Endpoint Threat Hunter                     │
│    Zero API Keys · Local Heuristic Engine · v3.1 · Ready          │
╰──────────────────────────────────────────────────────────────────╯

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

### Incident Card Preview

When an endpoint anomaly is detected, Kjagu renders an actionable card:

```
┌──────────────────────────────────────────────────────────────────┐
│ THREAT: INJECTED_PROCESS [CRITICAL]                              │
├──────────────────────────────────────────────────────────────────┤
│ PID:         4812                                                │
│ Binary:      C:\Users\Public\svchost.exe                         │
│ Hash:        e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca49 │
│ Confidence:  94%                                                 │
│ Vectors:     Parent: explorer.exe, RWX memory allocation         │
│ Recommended: Terminate process and isolate binary                │
└──────────────────────────────────────────────────────────────────┘
```

---

## Command Line Flags

Kjagu can be automated in scripts, scheduled tasks, and CI/CD pipelines using command-line arguments:

| Flag | Description |
|------|-------------|
| `--scan` | Execute a complete multi-vector endpoint threat audit. |
| `--quick` | Rapid triage scanning active processes and memory allocations only. |
| `--aggressive`, `--kill` | Automatically neutralize and quarantine verified threats without interactive prompts. |
| `--vault` | Lock and encrypt Chromium and Gecko cookie databases with hardware keys. |
| `--quarantine-list` | Display all currently quarantined files, hashes, and isolation timestamps. |
| `--restore <ID>` | Revert and restore a quarantined artifact back to its original path. |
| `--json <PATH>` | Output machine-readable JSON forensic telemetry to a designated file path. |
| `-h`, `--help` | Display command usage and option reference. |

### CLI Usage Examples

```bash
# Perform non-interactive deep audit and output report to desktop
python kjagu_core.py --scan --json C:\Users\USER\Desktop\audit.json

# Rapid process and memory triage
python kjagu_core.py --quick

# Auto-neutralize confirmed infostealers and injectors
python kjagu_core.py --scan --aggressive

# Encrypt browser cookies against off-line dumping
python kjagu_core.py --vault

# View quarantine vault
python kjagu_core.py --quarantine-list

# Restore a false-positive file
python kjagu_core.py --restore a1b2c3d4
```

---

## Quarantine Vault & Restoration

Unlike basic cleanup scripts that permanently delete files, Kjagu employs a defensive quarantine architecture:

- Quarantined binaries are stripped of execute permissions and relocated to `.kjagu_vault/`.
- File content is encoded and tracked in an encrypted metadata registry with original path, SHA-256 hash, and detection context.
- Files can be inspected or reverted at any time using `--restore <ID>` or via the interactive `/quarantine` menu.

---

## Cookie Vault Protection

Modern infostealers (RedLine, Lumma, Vidar, Stealc) target SQLite database files containing session cookies:

- `Google\Chrome\User Data\Default\Network\Cookies`
- `Microsoft\Edge\User Data\Default\Network\Cookies`
- `BraveSoftware\Brave-Browser\User Data\Default\Network\Cookies`

Kjagu's cookie vault locks these database files using AES-256-GCM. The encryption key is derived through PBKDF2 from hardware parameters unique to the machine (Motherboard UUID, CPU ID, Disk Volume serial). If an infostealer exfiltrates the encrypted database file, the contents cannot be decrypted on adversary infrastructure.

---

## System Requirements

- **Operating System:** Windows 10/11 (x64) or Linux (Kernel 5.4+)
- **Python:** Version 3.10 or higher
- **Privileges:** Administrator / Root required for deep memory scanning, driver verification, and process termination.
- **Dependencies:**
  - `psutil` (Process and system telemetry)
  - `cryptography` (AES-256-GCM vault encryption)
  - `pywin32` (Windows API bindings, optional on Linux)
  - `wmi` (Windows Management Instrumentation, optional on Linux)

---

## Responsible Security Disclaimer

Kjagu is developed for defensive research, system auditing, and incident response. It is designed to assist administrators and security researchers in identifying indicators of compromise (IoCs).

While the correlation engine incorporates aggressive heuristic detection, defensive tools may produce false positives on game anti-cheat software, kernel debugging tools, or enterprise EDR agents. Always verify incident cards before executing aggressive file isolation.

---

## Author & Research

Developed by **demonala** // **Hendry**  
Chief Architect & Security Researcher  
**Absolute Immortal Inc.**
