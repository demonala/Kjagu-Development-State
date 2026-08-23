# KJAGU VIRUS ATTACKER v2.1

## ⚠️ HONEST DISCLAIMER — READ THIS FIRST

**This is early development software. Not production-ready. Not battle-tested. Use at your own risk.**

I built this in a few hours while running on caffeine and spite. It works for basic detection, but if you're dealing with actual nation-state spyware or a properly written rootkit, this tool might miss it, crash, or in rare cases, f*** up your system. You've been warned.

---

## What Kjagu Actually Does

Kjagu is a **defensive anti-spyware scanner** that hunts for:

- Suspicious processes and memory injections
- Browser cookie theft protection (AES-256-GCM encryption)
- Registry persistence mechanisms
- Unsigned/suspicious kernel drivers (Windows)
- LKM rootkit indicators (Linux)
- Hidden files and alternate data streams

## What Kjagu DOES NOT Do (Yet)

| Feature | Status | Why |
|---------|--------|-----|
| Real-time protection | ❌ Not implemented | Would need a kernel driver or service running 24/7 |
| Full SSDT hook repair | ❌ Detection only | Fixing kernel hooks from usermode is impossible without a driver |
| Behavioral AI analysis | ❌ Not implemented | Would need ML models and training data |
| Automatic quarantine | ❌ Partial | Kills processes and deletes files, but no "restore from quarantine" |
| Cross-browser cookie sync | ❌ Not implemented | Each browser is encrypted separately |
| macOS support | ❌ Not implemented | I don't own a Mac, sue me |

## Known Limitations

### Windows
- **Memory scanning** requires Administrator privileges. Without it, Kjagu skips deep memory checks.
- **Kernel callback scanning** uses `driverquery` and signature verification — it can detect suspicious drivers but cannot unload them from usermode.
- **API hook detection** compares disk vs memory addresses. This is a simplified PE parser; it might false-positive on legit security software (AV, EDR) that also hooks APIs.
- **DLL unloading** via `CreateRemoteThread` + `FreeLibrary` is dirty and might crash the target process. Use with caution.

### Linux
- **Syscall table verification** needs root + ideally a kernel module (`kjagu_kmod.ko`). The usermode scanner can read `/proc/kallsyms` but cannot verify actual hook addresses without kernel access.
- **Hidden process detection** compares `/proc` vs `ps` output. Sophisticated rootkits hook both, making this check useless against them.
- **Kprobe detection** reads debugfs — if the rootkit hides its own kprobes, Kjagu won't see them.

### Cookie Vault
- **Hardware-bound keys** use CPU ID, BIOS serial, and disk serial. If you swap hardware (new motherboard, new disk), your vault becomes unreadable. **Back up your cookies before encrypting.**
- **Browser must be closed** during encryption. If Chrome/Edge/Firefox is running, the cookie files are locked and Kjagu will skip them.
- **No auto-decrypt on browser launch** — you'd need to manually decrypt or build a launcher script.

## False Positives

Kjagu WILL flag legitimate software as suspicious. Examples:
- **Game overlays** (Discord, Steam, NVIDIA) — inject DLLs into games, look like spyware
- **Password managers** — hook keyboard input, look like keyloggers
- **Development tools** — debuggers use `CreateRemoteThread`, look like injectors
- **Corporate EDR/AV** — hook syscalls, hide processes, look like rootkits

**Always review the scan results before hitting "purge."** Kjagu is aggressive by design — it assumes everything is guilty until proven innocent.

## What "Early Development" Means

- Code is **not optimized** — some scans are slow, single-threaded where they should be parallel
- Error handling is **minimal** — if a scan fails, it might just print an error and move on
- The **kernel driver** (`kjagu_kmod.c`) is a template. It compiles but the SSDT finding logic is incomplete for x64. You'd need to implement pattern scanning or use a different hooking detection method.
- **No installer, no GUI, no auto-update.** It's a Python script. Run it from terminal like a caveman.

## How to Actually Use This

### 1. Install
```bash
pip install -r requirements.txt
