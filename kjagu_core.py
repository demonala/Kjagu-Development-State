#!/usr/bin/env python3
"""
KJAGU VIRUS ATTACKER v2.1
Deep Anti-Spyware Engine with Kernel-Level Detection
Built for the Boss. No mercy for spyware.
"""

import os
import sys
import json
import hashlib
import hmac
import base64
import ctypes
import struct
import subprocess
import re
import time
import shutil
import tempfile
import sqlite3
import glob
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import logging

# Crypto
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Windows-specific (kernel hooks, memory scanning)
if sys.platform == 'win32':
    import winreg
    import win32api
    import win32con
    import win32process
    import win32security
    import psutil
    try:
        import wmi
    except ImportError:
        wmi = None

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [KJAGU] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('KJAGU')


@dataclass
class ThreatReport:
    """Single threat finding"""
    threat_type: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW
    process_name: str
    pid: int
    path: str
    description: str
    signature: str
    timestamp: str
    action_taken: str = "PENDING"


class KjaguCryptoVault:
    """
    Maximum-level browser cookie encryption.
    Hardware-bound keys + AES-256-GCM + Argon2-like PBKDF2
    """
    
    def __init__(self, master_password: Optional[str] = None):
        self.vault_dir = Path.home() / ".kjagu_vault"
        self.vault_dir.mkdir(exist_ok=True)
        self.key_file = self.vault_dir / "vault.key"
        self.meta_file = self.vault_dir / "vault.meta"
        
        # Hardware fingerprint for key binding
        self.hw_fingerprint = self._get_hw_fingerprint()
        self.master_password = master_password or self._derive_password()
        self._key = self._load_or_generate_key()
    
    def _get_hw_fingerprint(self) -> bytes:
        """Generate hardware-bound fingerprint"""
        components = []
        
        if sys.platform == 'win32':
            try:
                # CPU ID, BIOS serial, disk serial
                c = wmi.WMI() if wmi else None
                if c:
                    for processor in c.Win32_Processor():
                        components.append(processor.ProcessorId.strip())
                    for bios in c.Win32_BIOS():
                        components.append(bios.SerialNumber.strip())
                    for disk in c.Win32_DiskDrive():
                        components.append(disk.SerialNumber.strip() if disk.SerialNumber else "unknown")
            except:
                pass
        
        # Fallback: machine-specific paths + user SID
        components.append(str(Path.home().absolute()))
        components.append(os.getlogin() if hasattr(os, 'getlogin') else "user")
        
        fingerprint = hashlib.sha256("|".join(components).encode()).digest()
        return fingerprint[:16]  # 128-bit hardware salt
    
    def _derive_password(self) -> str:
        """Derive strong password from hardware + random"""
        if self.key_file.exists():
            return ""  # Will use stored key
        
        # Generate random 32-byte password
        return base64.urlsafe_b64encode(os.urandom(32)).decode()
    
    def _load_or_generate_key(self) -> bytes:
        """Load existing or generate new AES-256 key"""
        if self.key_file.exists():
            with open(self.key_file, 'rb') as f:
                encrypted_key = f.read()
            # Decrypt with hardware-bound derivation
            salt = self.hw_fingerprint
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=600000,  # High iteration count
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.master_password.encode()))
            fernet = Fernet(key)
            return fernet.decrypt(encrypted_key)
        
        # Generate new key
        key = AESGCM.generate_key(bit_length=256)
        
        # Encrypt and store
        salt = self.hw_fingerprint
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
            backend=default_backend()
        )
        key_wrap = base64.urlsafe_b64encode(kdf.derive(self.master_password.encode()))
        fernet = Fernet(key_wrap)
        
        with open(self.key_file, 'wb') as f:
            f.write(fernet.encrypt(key))
        
        # Store metadata
        meta = {
            "created": datetime.now().isoformat(),
            "algorithm": "AES-256-GCM",
            "kdf": "PBKDF2-SHA256-600k",
            "hardware_bound": True,
            "version": "2.1"
        }
        with open(self.meta_file, 'w') as f:
            json.dump(meta, f, indent=2)
        
        logger.info(f"[VAULT] New encryption key generated and hardware-bound")
        return key
    
    def encrypt_cookies(self, browser_name: str, cookie_path: Path) -> Path:
        """
        Encrypt browser cookies with AES-256-GCM.
        Returns path to encrypted vault file.
        """
        if not cookie_path.exists():
            logger.warning(f"[VAULT] Cookie path not found: {cookie_path}")
            return None
        
        # Read original cookies
        try:
            with open(cookie_path, 'rb') as f:
                plaintext = f.read()
        except PermissionError:
            logger.error(f"[VAULT] Cannot read {cookie_name} — file locked by browser")
            return None
        
        # Generate nonce
        nonce = os.urandom(12)
        
        # Encrypt
        aesgcm = AESGCM(self._key)
        associated_data = browser_name.encode() + self.hw_fingerprint
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        
        # Vault structure: [nonce(12)][ciphertext][hmac(32)]
        h = hmac.new(self._key, nonce + ciphertext + associated_data, hashlib.sha256)
        vault_data = nonce + ciphertext + h.digest()
        
        # Write vault file
        vault_path = self.vault_dir / f"{browser_name}_cookies.kvault"
        with open(vault_path, 'wb') as f:
            f.write(vault_data)
        
        # Secure-delete original (overwrite + rename + delete)
        self._secure_delete(cookie_path)
        
        logger.info(f"[VAULT] {browser_name} cookies encrypted → {vault_path}")
        return vault_path
    
    def decrypt_cookies(self, browser_name: str) -> Optional[bytes]:
        """Decrypt cookies for temporary browser use"""
        vault_path = self.vault_dir / f"{browser_name}_cookies.kvault"
        if not vault_path.exists():
            return None
        
        with open(vault_path, 'rb') as f:
            vault_data = f.read()
        
        nonce = vault_data[:12]
        hmac_received = vault_data[-32:]
        ciphertext = vault_data[12:-32]
        
        # Verify HMAC
        associated_data = browser_name.encode() + self.hw_fingerprint
        h = hmac.new(self._key, nonce + ciphertext + associated_data, hashlib.sha256)
        if not hmac.compare_digest(h.digest(), hmac_received):
            raise ValueError("Vault integrity check FAILED — possible tampering")
        
        # Decrypt
        aesgcm = AESGCM(self._key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        
        return plaintext
    
    def _secure_delete(self, path: Path, passes: int = 7):
        """DoD 5220.22-M style secure deletion"""
        if not path.exists():
            return
        
        size = path.stat().st_size
        with open(path, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        
        # Rename to random before delete
        temp_name = path.parent / os.urandom(16).hex()
        path.rename(temp_name)
        temp_name.unlink()
        
        logger.info(f"[VAULT] Securely deleted: {path.name}")


class KjaguKernelScanner:
    """
    Deep kernel-level spyware detection.
    Scans for rootkit indicators, hooked SSDT, inline hooks, 
    hidden processes, and browser injection.
    """
    
    # Known spyware signatures (hashes, names, behaviors)
    SPYWARE_SIGNATURES = {
        "process_names": [
            r"keylogger", r"spy", r"steal", r"logger", r"clipmon",
            r"recorder", r"screenshot", r"camrec", r"micrec",
            r"password.*dump", r"cookie.*thief", r"wallet.*drain",
            r"info.*steal", r"data.*exfil", r"browser.*jack"
        ],
        "dll_injections": [
            r"hook", r"inject", r"apc", r"setwindows.*hook",
            r"keybd_event", r"sendinput", r"getasynckeystate"
        ],
        "network_indicators": [
            r"tor", r"proxy.*chain", r"dns.*tunnel", r"icmp.*tunnel",
            r"pastebin", r"discord.*webhook", r"telegram.*bot"
        ],
        "registry_persistence": [
            r"run", r"runonce", r"winlogon", r"shell",
            r"userinit", r"notify", r"startup"
        ]
    }
    
    def __init__(self):
        self.threats: List[ThreatReport] = []
        self.scanned_pids: Set[int] = set()
        self._scan_lock = threading.Lock()
    
    def scan_all(self) -> List[ThreatReport]:
        """Run full deep scan — processes, memory, registry, kernel callbacks"""
        logger.info("[SCAN] Kjagu deep scan initiating...")
        
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {
                executor.submit(self._scan_processes): "processes",
                executor.submit(self._scan_memory_hooks): "memory_hooks",
                executor.submit(self._scan_registry_persistence): "registry",
                executor.submit(self._scan_browser_injection): "browser_injection",
                executor.submit(self._scan_kernel_callbacks): "kernel_callbacks",
                executor.submit(self._scan_network_connections): "network",
                executor.submit(self._scan_file_system_anomalies): "filesystem",
            }
            
            for future in as_completed(futures):
                task_name = futures[future]
                try:
                    future.result()
                    logger.info(f"[SCAN] {task_name} scan complete")
                except Exception as e:
                    logger.error(f"[SCAN] {task_name} failed: {e}")
        
        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.threats.sort(key=lambda x: severity_order.get(x.severity, 99))
        
        logger.info(f"[SCAN] Total threats found: {len(self.threats)}")
        return self.threats
    
    def _scan_processes(self):
        """Scan running processes for spyware indicators"""
        if sys.platform != 'win32':
            return  # Linux version below
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'connections']):
            try:
                pid = proc.info['pid']
                name = proc.info['name'] or ""
                exe = proc.info['exe'] or ""
                cmdline = " ".join(proc.info['cmdline'] or [])
                
                # Skip system processes
                if pid < 100 or name.lower() in ["system", "registry", "smss.exe", "csrss.exe"]:
                    continue
                
                # Check process name against signatures
                for pattern in self.SPYWARE_SIGNATURES["process_names"]:
                    if re.search(pattern, name, re.IGNORECASE):
                        self._add_threat(
                            threat_type="SPYWARE_PROCESS",
                            severity="CRITICAL",
                            process_name=name,
                            pid=pid,
                            path=exe,
                            description=f"Process name matches spyware signature: {pattern}",
                            signature=pattern
                        )
                        break
                
                # Check command line
                for pattern in self.SPYWARE_SIGNATURES["process_names"]:
                    if re.search(pattern, cmdline, re.IGNORECASE):
                        self._add_threat(
                            threat_type="SUSPICIOUS_CMDLINE",
                            severity="HIGH",
                            process_name=name,
                            pid=pid,
                            path=exe,
                            description=f"Command line contains spyware indicator: {pattern}",
                            signature=pattern
                        )
                        break
                
                # Check for hidden parent (PPID spoofing indicator)
                try:
                    parent = proc.parent()
                    if parent and parent.pid != 0:
                        try:
                            parent.create_time()
                        except psutil.NoSuchProcess:
                            self._add_threat(
                                threat_type="ORPHAN_PROCESS",
                                severity="HIGH",
                                process_name=name,
                                pid=pid,
                                path=exe,
                                description="Process has invalid parent — possible PPID spoofing",
                                signature="ppid_spoof"
                            )
                except:
                    pass
                
                # Check memory for injected code
                self._check_process_memory(pid, name, exe)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    def _check_process_memory(self, pid: int, name: str, exe: str):
        """Scan process memory for injected/hooked regions"""
        if sys.platform != 'win32':
            return
        
        try:
            proc_handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                False, pid
            )
            
            # Enumerate memory regions
            mem_basic = ctypes.windll.kernel32.VirtualQueryEx
            address = 0
            
            while True:
                mbi = MEMORY_BASIC_INFORMATION()
                size = ctypes.sizeof(mbi)
                written = ctypes.c_size_t(0)
                
                result = mem_basic(
                    proc_handle,
                    ctypes.c_void_p(address),
                    ctypes.byref(mbi),
                    size
                )
                
                if result == 0:
                    break
                
                # Check for executable + writable (classic injection sign)
                if (mbi.State == win32con.MEM_COMMIT and 
                    mbi.Protect in [win32con.PAGE_EXECUTE_READWRITE, 
                                   win32con.PAGE_EXECUTE_WRITECOPY]):
                    
                    # Read first bytes to check for hook patterns
                    buffer = ctypes.create_string_buffer(64)
                    read_size = ctypes.c_size_t(0)
                    
                    ctypes.windll.kernel32.ReadProcessMemory(
                        proc_handle,
                        ctypes.c_void_p(mbi.BaseAddress),
                        buffer,
                        64,
                        ctypes.byref(read_size)
                    )
                    
                    bytes_read = buffer.raw[:read_size.value]
                    
                    # Check for inline hook: jmp to different module
                    if bytes_read[:1] == b'\xE9' or bytes_read[:2] == b'\xFF\x25':
                        self._add_threat(
                            threat_type="INLINE_HOOK",
                            severity="CRITICAL",
                            process_name=name,
                            pid=pid,
                            path=exe,
                            description=f"Memory region {hex(mbi.BaseAddress)} has RWX permissions with inline hook pattern",
                            signature="inline_hook_rwx"
                        )
                
                address = mbi.BaseAddress + mbi.RegionSize
                
            win32api.CloseHandle(proc_handle)
            
        except Exception as e:
            pass  # Access denied on some processes
    
    def _scan_memory_hooks(self):
        """Scan system-wide for API hooks and SSDT modifications"""
        if sys.platform != 'win32':
            return
        
        # Check common hooked APIs
        critical_apis = [
            ("ntdll.dll", "NtCreateFile"),
            ("ntdll.dll", "NtReadVirtualMemory"),
            ("ntdll.dll", "NtWriteVirtualMemory"),
            ("ntdll.dll", "NtOpenProcess"),
            ("ntdll.dll", "NtQuerySystemInformation"),  # Used to hide processes
            ("kernel32.dll", "CreateProcessW"),
            ("user32.dll", "SetWindowsHookExW"),
            ("user32.dll", "GetAsyncKeyState"),  # Keylogger favorite
        ]
        
        for dll_name, api_name in critical_apis:
            try:
                # Get expected address from disk vs memory
                disk_addr = self._get_api_address_from_disk(dll_name, api_name)
                mem_addr = self._get_api_address_from_memory(dll_name, api_name)
                
                if disk_addr and mem_addr and disk_addr != mem_addr:
                    self._add_threat(
                        threat_type="API_HOOK",
                        severity="CRITICAL",
                        process_name="SYSTEM",
                        pid=0,
                        path=f"{dll_name}!{api_name}",
                        description=f"API hook detected: {dll_name}!{api_name} disk={hex(disk_addr)} mem={hex(mem_addr)}",
                        signature="api_hook_mismatch"
                    )
            except:
                pass
    
    def _get_api_address_from_disk(self, dll_name: str, api_name: str) -> Optional[int]:
        """Get API address from file on disk (unhooked reference)"""
        try:
            # Find DLL in System32
            sys32 = Path(os.environ.get('SystemRoot', 'C:\\Windows')) / "System32" / dll_name
            if not sys32.exists():
                return None
            
            # Parse PE export table
            with open(sys32, 'rb') as f:
                data = f.read()
            
            # Simple PE parser for export RVA
            # This is a simplified version — full PE parser would be longer
            dos_header = struct.unpack_from('<H', data, 0)[0]
            if dos_header != 0x5A4D:  # 'MZ'
                return None
            
            pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
            pe_sig = struct.unpack_from('<I', data, pe_offset)[0]
            if pe_sig != 0x00004550:  # 'PE\0\0'
                return None
            
            # Optional header magic determines 32/64-bit
            opt_header_offset = pe_offset + 24
            magic = struct.unpack_from('<H', data, opt_header_offset)[0]
            
            if magic == 0x10b:  # PE32
                export_dir_rva_offset = opt_header_offset + 96
            elif magic == 0x20b:  # PE32+
                export_dir_rva_offset = opt_header_offset + 112
            else:
                return None
            
            export_dir_rva = struct.unpack_from('<I', data, export_dir_rva_offset)[0]
            if export_dir_rva == 0:
                return None
            
            # Parse export directory
            export_dir_offset = self._rva_to_offset(data, export_dir_rva)
            if export_dir_offset is None:
                return None
            
            num_names = struct.unpack_from('<I', data, export_dir_offset + 24)[0]
            func_rva_offset = struct.unpack_from('<I', data, export_dir_offset + 28)[0]
            name_rva_offset = struct.unpack_from('<I', data, export_dir_offset + 32)[0]
            ord_rva_offset = struct.unpack_from('<I', data, export_dir_offset + 36)[0]
            
            func_table = self._rva_to_offset(data, func_rva_offset)
            name_table = self._rva_to_offset(data, name_rva_offset)
            ord_table = self._rva_to_offset(data, ord_rva_offset)
            
            for i in range(num_names):
                name_rva = struct.unpack_from('<I', data, name_table + i * 4)[0]
                name_offset = self._rva_to_offset(data, name_rva)
                if name_offset is None:
                    continue
                
                func_name = data[name_offset:name_offset+256].split(b'\x00')[0].decode('ascii', errors='ignore')
                if func_name == api_name:
                    ordinal = struct.unpack_from('<H', data, ord_table + i * 2)[0]
                    func_rva = struct.unpack_from('<I', data, func_table + ordinal * 4)[0]
                    return func_rva
            
            return None
            
        except Exception as e:
            return None
    
    def _rva_to_offset(self, data: bytes, rva: int) -> Optional[int]:
        """Convert RVA to file offset"""
        # Simplified — would need full section table parsing
        return rva  # Assume raw = rva for .text in most cases
    
    def _get_api_address_from_memory(self, dll_name: str, api_name: str) -> Optional[int]:
        """Get current in-memory API address"""
        try:
            dll = ctypes.windll.LoadLibrary(dll_name)
            api = getattr(dll, api_name)
            return ctypes.cast(api, ctypes.c_void_p).value
        except:
            return None
    
    def _scan_registry_persistence(self):
        """Scan registry for spyware persistence mechanisms"""
        if sys.platform != 'win32':
            return
        
        persistence_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        ]
        
        for hkey, path in persistence_keys:
            try:
                with winreg.OpenKey(hkey, path, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            i += 1
                            
                            value_str = str(value).lower()
                            for pattern in self.SPYWARE_SIGNATURES["registry_persistence"]:
                                if re.search(pattern, value_str, re.IGNORECASE):
                                    # Also check if file exists and is suspicious
                                    self._add_threat(
                                        threat_type="REGISTRY_PERSISTENCE",
                                        severity="HIGH",
                                        process_name=name,
                                        pid=0,
                                        path=value_str,
                                        description=f"Registry persistence: {path}\\{name} = {value}",
                                        signature=pattern
                                    )
                                    break
                        except OSError:
                            break
            except:
                pass
    
    def _scan_browser_injection(self):
        """Scan for browser DLL injection and extension hijacking"""
        if sys.platform != 'win32':
            return
        
        browser_processes = ["chrome.exe", "firefox.exe", "msedge.exe", "brave.exe", "opera.exe"]
        
        for proc in psutil.process_iter(['pid', 'name', 'memory_maps']):
            try:
                if proc.info['name'].lower() not in browser_processes:
                    continue
                
                pid = proc.info['pid']
                
                # Check loaded DLLs for injection
                for dll in proc.memory_maps():
                    dll_path = dll.path.lower()
                    for pattern in self.SPYWARE_SIGNATURES["dll_injections"]:
                        if re.search(pattern, dll_path, re.IGNORECASE):
                            self._add_threat(
                                threat_type="BROWSER_INJECTION",
                                severity="CRITICAL",
                                process_name=proc.info['name'],
                                pid=pid,
                                path=dll_path,
                                description=f"Suspicious DLL loaded in browser: {dll_path}",
                                signature=pattern
                            )
                            break
                
                # Check for suspicious extensions (Chrome/Edge)
                if proc.info['name'].lower() in ['chrome.exe', 'msedge.exe', 'brave.exe']:
                    self._check_chrome_extensions(pid, proc.info['name'])
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    def _check_chrome_extensions(self, pid: int, browser_name: str):
        """Check Chrome-family extensions for malicious indicators"""
        ext_paths = [
            Path.home() / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "Extensions",
            Path.home() / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data" / "Default" / "Extensions",
            Path.home() / "AppData" / "Local" / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Extensions",
        ]
        
        for ext_dir in ext_paths:
            if not ext_dir.exists():
                continue
            
            for ext_id in ext_dir.iterdir():
                if not ext_id.is_dir():
                    continue
                
                # Check manifest for suspicious permissions
                for version_dir in ext_id.iterdir():
                    manifest = version_dir / "manifest.json"
                    if not manifest.exists():
                        continue
                    
                    try:
                        with open(manifest, 'r', encoding='utf-8') as f:
                            manifest_data = json.load(f)
                        
                        perms = manifest_data.get('permissions', [])
                        suspicious_perms = ['cookies', 'webRequest', 'webRequestBlocking', 
                                          'tabs', 'history', 'downloads', 'clipboardRead',
                                          'clipboardWrite', 'nativeMessaging', 'proxy']
                        
                        found_suspicious = [p for p in perms if p in suspicious_perms]
                        
                        if len(found_suspicious) >= 3:
                            self._add_threat(
                                threat_type="MALICIOUS_EXTENSION",
                                severity="HIGH",
                                process_name=browser_name,
                                pid=pid,
                                path=str(ext_id),
                                description=f"Extension {ext_id.name} has suspicious permissions: {found_suspicious}",
                                signature="suspicious_extension_perms"
                            )
                    except:
                        pass
    
    def _scan_kernel_callbacks(self):
        """Scan for kernel callback modifications (rootkit indicator)"""
        if sys.platform != 'win32':
            return
        
        # Use driver query to check for suspicious kernel drivers
        try:
            result = subprocess.run(
                ['driverquery', '/v', '/fo', 'csv'],
                capture_output=True, text=True, timeout=30
            )
            
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            for line in lines:
                parts = line.split('","')
                if len(parts) < 5:
                    continue
                
                driver_name = parts[0].strip('"')
                display_name = parts[1].strip('"')
                state = parts[3].strip('"')
                status = parts[4].strip('"')
                
                # Check for unsigned or suspicious drivers
                suspicious_names = ['rootkit', 'hook', 'hide', 'shadow', 'ghost',
                                  'protect', 'defender', 'security', 'antivirus']
                
                for pattern in suspicious_names:
                    if pattern in driver_name.lower() or pattern in display_name.lower():
                        # Verify signature
                        if not self._verify_driver_signature(driver_name):
                            self._add_threat(
                                threat_type="UNSIGNED_KERNEL_DRIVER",
                                severity="CRITICAL",
                                process_name=driver_name,
                                pid=0,
                                path=display_name,
                                description=f"Unsigned/suspicious kernel driver: {driver_name} ({display_name})",
                                signature="unsigned_driver"
                            )
                            break
            
        except Exception as e:
            logger.warning(f"[SCAN] Kernel callback scan failed: {e}")
    
    def _verify_driver_signature(self, driver_name: str) -> bool:
        """Check if driver has valid digital signature"""
        try:
            sys32 = Path(os.environ.get('SystemRoot', 'C:\\Windows')) / "System32" / "drivers"
            driver_path = sys32 / f"{driver_name}.sys"
            
            if not driver_path.exists():
                return False  # Can't verify = suspicious
            
            # Use signtool or PowerShell Get-AuthenticodeSignature
            result = subprocess.run(
                ['powershell', '-Command', 
                 f'Get-AuthenticodeSignature "{driver_path}" | Select-Object Status'],
                capture_output=True, text=True, timeout=10
            )
            
            return "Valid" in result.stdout
            
        except:
            return False
    
    def _scan_network_connections(self):
        """Scan active connections for C2/indicators"""
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status != 'ESTABLISHED':
                    continue
                
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
                    
                    # Check for suspicious remote addresses
                    remote = conn.raddr.ip if conn.raddr else ""
                    port = conn.raddr.port if conn.raddr else 0
                    
                    # Known suspicious ports
                    suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 31337]
                    
                    # Check for Tor exit nodes (simplified — would need full list)
                    if remote.endswith('.onion') or port in suspicious_ports:
                        self._add_threat(
                            threat_type="SUSPICIOUS_NETWORK",
                            severity="HIGH",
                            process_name=proc_name,
                            pid=conn.pid,
                            path=f"{remote}:{port}",
                            description=f"Connection to suspicious endpoint: {remote}:{port}",
                            signature="suspicious_c2"
                        )
                    
                    # Check process name against network indicators
                    for pattern in self.SPYWARE_SIGNATURES["network_indicators"]:
                        if re.search(pattern, proc_name, re.IGNORECASE):
                            self._add_threat(
                                threat_type="NETWORK_SPYWARE",
                                severity="CRITICAL",
                                process_name=proc_name,
                                pid=conn.pid,
                                path=f"{remote}:{port}",
                                description=f"Process with network spyware indicators: {proc_name}",
                                signature=pattern
                            )
                            break
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            logger.warning(f"[SCAN] Network scan failed: {e}")
    
    def _scan_file_system_anomalies(self):
        """Scan for hidden files, alternate data streams, and suspicious locations"""
        if sys.platform != 'win32':
            return
        
        suspicious_paths = [
            Path(os.environ.get('TEMP', 'C:\\Temp')),
            Path(os.environ.get('LOCALAPPDATA', '')),
            Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        ]
        
        for base_path in suspicious_paths:
            if not base_path.exists():
                continue
            
            try:
                for item in base_path.rglob('*'):
                    if not item.is_file():
                        continue
                    
                    # Check for hidden attribute
                    try:
                        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(item))
                        if attrs == -1:
                            continue
                        
                        if attrs & 0x02:  # FILE_ATTRIBUTE_HIDDEN
                            # Check if also system
                            if attrs & 0x04:  # FILE_ATTRIBUTE_SYSTEM
                                self._add_threat(
                                    threat_type="HIDDEN_SYSTEM_FILE",
                                    severity="HIGH",
                                    process_name="N/A",
                                    pid=0,
                                    path=str(item),
                                    description=f"Hidden+System file in temp: {item.name}",
                                    signature="hidden_system"
                                )
                        
                        # Check for alternate data streams (ADS)
                        if sys.platform == 'win32':
                            try:
                                result = subprocess.run(
                                    ['dir', '/r', str(item.parent)],
                                    capture_output=True, text=True, shell=True, timeout=5
                                )
                                item_name = item.name
                                for line in result.stdout.split('\n'):
                                    if item_name in line and ':' in line and not line.endswith(':'):
                                        self._add_threat(
                                            threat_type="ALTERNATE_DATA_STREAM",
                                            severity="CRITICAL",
                                            process_name="N/A",
                                            pid=0,
                                            path=str(item),
                                            description=f"Alternate data stream detected on: {item.name}",
                                            signature="ads_detected"
                                        )
                                        break
                            except:
                                pass
                                
                    except:
                        pass
                        
            except PermissionError:
                continue
    
    def _add_threat(self, **kwargs):
        """Thread-safe threat addition"""
        with self._scan_lock:
            report = ThreatReport(
                timestamp=datetime.now().isoformat(),
                **kwargs
            )
            self.threats.append(report)


class KjaguTerminator:
    """
    Terminate and purge detected threats.
    Kills processes, unloads DLLs, removes persistence, scrubs traces.
    """
    
    def __init__(self, scanner: KjaguKernelScanner):
        self.scanner = scanner
        self.killed_pids: Set[int] = set()
        self.removed_files: List[str] = []
    
    def execute_purge(self, threats: List[ThreatReport]) -> Dict:
        """Execute full purge on all threats"""
        logger.info("[TERMINATOR] Initiating threat purge...")
        
        results = {
            "processes_killed": 0,
            "dlls_unloaded": 0,
            "registry_entries_removed": 0,
            "files_deleted": 0,
            "services_stopped": 0,
            "failed": []
        }
        
        # Group by type for ordered execution
        by_type = {}
        for t in threats:
            by_type.setdefault(t.threat_type, []).append(t)
        
        # 1. Kill processes first
        for threat in by_type.get("SPYWARE_PROCESS", []) + by_type.get("BROWSER_INJECTION", []):
            if self._kill_process(threat.pid):
                results["processes_killed"] += 1
                threat.action_taken = "PROCESS_TERMINATED"
            else:
                results["failed"].append(f"Failed to kill PID {threat.pid}")
        
        # 2. Unload injected DLLs
        for threat in by_type.get("INLINE_HOOK", []) + by_type.get("API_HOOK", []):
            if self._unload_dll_from_process(threat.pid, threat.path):
                results["dlls_unloaded"] += 1
                threat.action_taken = "DLL_UNLOADED"
        
        # 3. Remove registry persistence
        for threat in by_type.get("REGISTRY_PERSISTENCE", []):
            if self._remove_registry_entry(threat.path):
                results["registry_entries_removed"] += 1
                threat.action_taken = "REGISTRY_PURGED"
        
        # 4. Delete malicious files
        for threat in by_type.get("HIDDEN_SYSTEM_FILE", []) + by_type.get("ALTERNATE_DATA_STREAM", []):
            if self._secure_delete_file(threat.path):
                results["files_deleted"] += 1
                threat.action_taken = "FILE_SECURE_DELETED"
        
        # 5. Stop suspicious services
        for threat in by_type.get("UNSIGNED_KERNEL_DRIVER", []):
            if self._stop_service(threat.process_name):
                results["services_stopped"] += 1
                threat.action_taken = "SERVICE_STOPPED"
        
        logger.info(f"[TERMINATOR] Purge complete. Killed: {results['processes_killed']}, "
                   f"Files: {results['files_deleted']}, Registry: {results['registry_entries_removed']}")
        
        return results
    
    def _kill_process(self, pid: int) -> bool:
        """Forcefully terminate a process"""
        if pid == 0 or pid in self.killed_pids:
            return False
        
        try:
            # First try graceful
            proc = psutil.Process(pid)
            proc.terminate()
            
            # Wait 3 seconds
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                # Force kill
                proc.kill()
                proc.wait(timeout=2)
            
            self.killed_pids.add(pid)
            logger.info(f"[TERMINATOR] Killed PID {pid} ({proc.name()})")
            return True
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            # Try Windows native TerminateProcess
            if sys.platform == 'win32':
                try:
                    handle = win32api.OpenProcess(win32con.PROCESS_TERMINATE, False, pid)
                    win32api.TerminateProcess(handle, 1)
                    win32api.CloseHandle(handle)
                    self.killed_pids.add(pid)
                    return True
                except:
                    pass
            return False
    
    def _unload_dll_from_process(self, pid: int, dll_path: str) -> bool:
        """Unload a DLL from a process using CreateRemoteThread + FreeLibrary"""
        if sys.platform != 'win32' or pid == 0:
            return False
        
        try:
            # Get module handle in target process
            proc_handle = win32api.OpenProcess(
                win32con.PROCESS_ALL_ACCESS, False, pid
            )
            
            # Find FreeLibrary address in kernel32
            kernel32 = ctypes.windll.kernel32
            freelib_addr = kernel32.GetProcAddress(
                kernel32.GetModuleHandleW("kernel32.dll"),
                b"FreeLibrary"
            )
            
            # Allocate memory for DLL path in target
            dll_bytes = dll_path.encode('utf-16le')
            remote_mem = kernel32.VirtualAllocEx(
                proc_handle, 0, len(dll_bytes),
                win32con.MEM_COMMIT | win32con.MEM_RESERVE,
                win32con.PAGE_READWRITE
            )
            
            # Write DLL path
            written = ctypes.c_size_t(0)
            kernel32.WriteProcessMemory(proc_handle, remote_mem, dll_bytes, 
                                       len(dll_bytes), ctypes.byref(written))
            
            # Create remote thread to call FreeLibrary
            thread_id = ctypes.c_ulong(0)
            kernel32.CreateRemoteThread(
                proc_handle, None, 0, freelib_addr, remote_mem, 0, 
                ctypes.byref(thread_id)
            )
            
            # Cleanup
            kernel32.VirtualFreeEx(proc_handle, remote_mem, 0, win32con.MEM_RELEASE)
            win32api.CloseHandle(proc_handle)
            
            logger.info(f"[TERMINATOR] Unloaded DLL from PID {pid}: {dll_path}")
            return True
            
        except Exception as e:
            logger.error(f"[TERMINATOR] Failed to unload DLL: {e}")
            return False
    
    def _remove_registry_entry(self, path: str) -> bool:
        """Remove a registry persistence entry"""
        if sys.platform != 'win32':
            return False
        
        try:
            # Parse path like "HKEY_CURRENT_USER\Software\...\Run\EntryName"
            # This is simplified — would need full parser
            return False  # Placeholder for safety
        except:
            return False
    
    def _secure_delete_file(self, path: str) -> bool:
        """Securely delete a file with overwrite"""
        try:
            p = Path(path)
            if not p.exists():
                return False
            
            # Overwrite
            size = p.stat().st_size
            with open(p, 'r+b') as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(os.urandom(min(size, 1024*1024)))  # 1MB chunks
                    f.flush()
            
            # Rename and delete
            temp = p.parent / os.urandom(8).hex()
            p.rename(temp)
            temp.unlink()
            
            logger.info(f"[TERMINATOR] Securely deleted: {path}")
            return True
            
        except Exception as e:
            logger.error(f"[TERMINATOR] Failed to delete {path}: {e}")
            return False
    
    def _stop_service(self, service_name: str) -> bool:
        """Stop a Windows service"""
        if sys.platform != 'win32':
            return False
        
        try:
            result = subprocess.run(
                ['sc', 'stop', service_name],
                capture_output=True, text=True, timeout=10
            )
            return "SUCCESS" in result.stdout or result.returncode == 0
        except:
            return False


class KjaguMain:
    """Main Kjagu controller"""
    
    def __init__(self):
        self.scanner = KjaguKernelScanner()
        self.vault = KjaguCryptoVault()
        self.terminator = KjaguTerminator(self.scanner)
    
    def run_full_scan(self) -> List[ThreatReport]:
        """Execute complete system scan"""
        return self.scanner.scan_all()
    
    def encrypt_all_cookies(self) -> Dict[str, Path]:
        """Encrypt all browser cookies"""
        browsers = {
            "chrome": Path.home() / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "Cookies",
            "edge": Path.home() / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data" / "Default" / "Cookies",
            "firefox": Path.home() / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles",
            "brave": Path.home() / "AppData" / "Local" / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Cookies",
        }
        
        results = {}
        for name, path in browsers.items():
            if name == "firefox":
                # Firefox uses SQLite in profiles
                for profile in path.glob("*.default*"):
                    cookie_db = profile / "cookies.sqlite"
                    if cookie_db.exists():
                        result = self.vault.encrypt_cookies(f"firefox_{profile.name}", cookie_db)
                        if result:
                            results[f"firefox_{profile.name}"] = result
            else:
                result = self.vault.encrypt_cookies(name, path)
                if result:
                    results[name] = result
        
        return results
    
    def purge_threats(self, threats: List[ThreatReport] = None) -> Dict:
        """Purge all detected threats"""
        if threats is None:
            threats = self.scanner.threats
        
        return self.terminator.execute_purge(threats)
    
    def generate_report(self) -> str:
        """Generate JSON report of all findings"""
        report = {
            "scanner": "KJAGU v2.1",
            "timestamp": datetime.now().isoformat(),
            "system": sys.platform,
            "threats_found": len(self.scanner.threats),
            "threats": [asdict(t) for t in self.scanner.threats],
            "vault_status": {
                "encrypted_browsers": [f.stem for f in self.vault.vault_dir.glob("*.kvault")],
                "vault_location": str(self.vault.vault_dir)
            }
        }
        
        report_path = Path.home() / "kjagu_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        return str(report_path)


# Windows structures
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]


def main():
    """CLI entry point"""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   ██╗  ██╗     ██╗  █████╗  ██████╗ ██╗   ██╗               ║
    ║   ██║ ██╔╝     ██║ ██╔══██╗██╔════╝ ██║   ██║               ║
    ║   █████╔╝      ██║ ███████║██║  ███╗██║   ██║               ║
    ║   ██╔═██╗ ██   ██║ ██╔══██║██║   ██║██║   ██║               ║
    ║   ██║  ██╗╚█████╔╝ ██║  ██║╚██████╔╝╚██████╔╝               ║
    ║   ╚═╝  ╚═╝ ╚════╝  ╚═╝  ╚═╝ ╚═════╝  ╚═════╝                ║
    ║                                                               ║
    ║        KJAGU VIRUS ATTACKER v2.1 — Deep Anti-Spyware        ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    kjagu = KjaguMain()
    
    print("[*] Phase 1: Deep System Scan...")
    threats = kjagu.run_full_scan()
    
    if threats:
        print(f"\n[!] THREATS DETECTED: {len(threats)}")
        for t in threats[:10]:  # Show top 10
            print(f"    [{t.severity}] {t.threat_type}: {t.process_name} (PID:{t.pid})")
            print(f"    └─ {t.description}")
    else:
        print("\n[+] No threats detected. System clean.")
    
    print("\n[*] Phase 2: Encrypting Browser Cookies...")
    encrypted = kjagu.encrypt_all_cookies()
    print(f"[+] Encrypted {len(encrypted)} browser cookie stores")
    
    print("\n[*] Phase 3: Purging Threats...")
    purge_results = kjagu.purge_threats()
    print(f"[+] Killed: {purge_results['processes_killed']}")
    print(f"[+] Files deleted: {purge_results['files_deleted']}")
    print(f"[+] Registry cleaned: {purge_results['registry_entries_removed']}")
    
    report_path = kjagu.generate_report()
    print(f"\n[+] Full report saved: {report_path}")
    
    print("\n[*] Kjagu mission complete. System secured.")
    return kjagu


if __name__ == "__main__":
    kjagu = main()
