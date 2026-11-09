"""
KJAGU Recon Module
Deep system evidence collection — processes, memory, network, registry, files.
"""

import os
import sys
import psutil
import struct
import ctypes
import subprocess
import re
import json
import hashlib
import threading
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Set
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class Evidence:
    evidence_id: str
    category: str  # process, memory, network, registry, file, service, dll
    source: str
    data: Dict[str, Any]
    raw_value: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    hash: str = ""

    def __post_init__(self):
        if not self.hash:
            self.hash = hashlib.sha256(
                json.dumps(self.data, sort_keys=True).encode()
            ).hexdigest()[:16]

    def to_dict(self):
        return {
            "evidence_id": self.evidence_id,
            "category": self.category,
            "source": self.source,
            "data": self.data,
            "timestamp": self.timestamp,
            "hash": self.hash
        }


class ReconModule:
    """Collects comprehensive system evidence for AI analysis"""

    # Known spyware indicators
    SUSPICIOUS_PROCESS_NAMES = [
        r"keylogger", r"spy", r"steal", r"logger", r"clipmon",
        r"recorder", r"screenshot", r"camrec", r"micrec",
        r"password.*dump", r"cookie.*thief", r"wallet.*drain",
        r"info.*steal", r"data.*exfil", r"browser.*jack",
        r"rat", r"remote.*admin", r"trojan", r"backdoor"
    ]

    SUSPICIOUS_PORTS = [4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 54321]

    def __init__(self):
        self.evidence: List[Evidence] = []
        self._lock = threading.Lock()
        self._counter = 0

    def _add(self, category: str, source: str, data: Dict, raw: str = ""):
        with self._lock:
            self._counter += 1
            ev = Evidence(
                evidence_id=f"{category}_{self._counter:04d}",
                category=category,
                source=source,
                data=data,
                raw_value=raw[:500]
            )
            self.evidence.append(ev)
            return ev

    def collect_all(self) -> List[Evidence]:
        """Run full evidence collection"""
        self.evidence = []

        collectors = [
            ("processes", self._collect_processes),
            ("network", self._collect_network),
            ("services", self._collect_services),
            ("startup", self._collect_startup),
            ("browser_extensions", self._collect_browser_extensions),
            ("loaded_dlls", self._collect_loaded_dlls),
            ("memory_regions", self._collect_memory_regions),
            ("suspicious_files", self._collect_suspicious_files),
        ]

        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = {executor.submit(fn): name for name, fn in collectors}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    future.result()
                except Exception as e:
                    self._add("error", "exception", {"collector": name, "error": str(e)})

        return self.evidence

    def _collect_processes(self):
        for proc in psutil.process_iter([
            'pid', 'name', 'exe', 'cmdline', 'cpu_percent',
            'memory_percent', 'connections', 'ppid', 'create_time', 'num_threads'
        ]):
            try:
                info = proc.info
                pid = info['pid']
                if pid < 10:
                    continue

                parent_name = ""
                try:
                    parent = proc.parent()
                    if parent:
                        parent_name = parent.name()
                except:
                    pass

                cmdline = " ".join(info['cmdline'] or [])

                # Check for suspicious names
                threat_indicators = []
                for pattern in self.SUSPICIOUS_PROCESS_NAMES:
                    if re.search(pattern, info['name'] or "", re.IGNORECASE):
                        threat_indicators.append(f"name_match:{pattern}")
                    if re.search(pattern, cmdline, re.IGNORECASE):
                        threat_indicators.append(f"cmdline_match:{pattern}")

                # Check for orphan process (PPID spoofing indicator)
                orphan = False
                try:
                    parent = proc.parent()
                    if parent and parent.pid != 0:
                        parent.create_time()
                except psutil.NoSuchProcess:
                    orphan = True
                    threat_indicators.append("orphan_process")

                self._add("process", "psutil", {
                    "pid": pid,
                    "name": info['name'],
                    "exe": info['exe'] or "",
                    "cmdline": cmdline[:500],
                    "ppid": info['ppid'],
                    "parent_name": parent_name,
                    "cpu_percent": info['cpu_percent'],
                    "memory_percent": info['memory_percent'],
                    "num_threads": info['num_threads'],
                    "num_connections": len(info['connections'] or []),
                    "create_time": info['create_time'],
                    "orphan": orphan,
                    "threat_indicators": threat_indicators,
                    "suspicious": len(threat_indicators) > 0
                })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _collect_network(self):
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                    except:
                        proc_name = "unknown"

                    remote_port = conn.raddr.port
                    suspicious = remote_port in self.SUSPICIOUS_PORTS

                    self._add("network", "psutil", {
                        "pid": conn.pid,
                        "process_name": proc_name,
                        "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}",
                        "remote_ip": conn.raddr.ip,
                        "remote_port": remote_port,
                        "status": conn.status,
                        "suspicious_port": suspicious
                    })
        except Exception as e:
            self._add("error", "network", {"error": str(e)})

    def _collect_services(self):
        if sys.platform == 'win32':
            try:
                result = subprocess.run(
                    ['sc', 'query', 'type=', 'service', 'state=', 'all'],
                    capture_output=True, text=True, timeout=30
                )
                for line in result.stdout.split('\n'):
                    if 'SERVICE_NAME:' in line:
                        name = line.split(':')[1].strip()
                        self._add("service", "sc", {"service_name": name})
            except Exception as e:
                self._add("error", "services", {"error": str(e)})

    def _collect_startup(self):
        if sys.platform == 'win32':
            paths = [
                Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
                Path("C:/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp"),
            ]
            for path in paths:
                if path.exists():
                    for item in path.iterdir():
                        self._add("startup", "filesystem", {
                            "path": str(item),
                            "name": item.name,
                            "type": "file" if item.is_file() else "dir"
                        })

            # Registry startup
            try:
                import winreg
                keys = [
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                ]
                for hkey, path in keys:
                    try:
                        with winreg.OpenKey(hkey, path, 0, winreg.KEY_READ) as key:
                            i = 0
                            while True:
                                try:
                                    name, value, _ = winreg.EnumValue(key, i)
                                    i += 1
                                    self._add("registry", "winreg", {
                                        "hive": "HKCU" if hkey == winreg.HKEY_CURRENT_USER else "HKLM",
                                        "path": path,
                                        "entry_name": name,
                                        "value": str(value)[:300]
                                    })
                                except OSError:
                                    break
                    except:
                        pass
            except:
                pass

    def _collect_browser_extensions(self):
        ext_paths = []
        if sys.platform == 'win32':
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
                for version_dir in ext_id.iterdir():
                    manifest = version_dir / "manifest.json"
                    if manifest.exists():
                        try:
                            with open(manifest, 'r', encoding='utf-8') as f:
                                data = json.load(f)
                            perms = data.get("permissions", [])
                            suspicious = ['cookies', 'webRequest', 'webRequestBlocking', 
                                         'tabs', 'history', 'downloads', 'clipboardRead',
                                         'clipboardWrite', 'nativeMessaging', 'proxy']
                            sus_count = sum(1 for p in perms if p in suspicious)

                            self._add("browser_extension", "filesystem", {
                                "browser": "chrome" if "Chrome" in str(ext_dir) else "edge" if "Edge" in str(ext_dir) else "brave",
                                "extension_id": ext_id.name,
                                "name": data.get("name", "unknown"),
                                "permissions": perms,
                                "suspicious_permissions": [p for p in perms if p in suspicious],
                                "suspicious_count": sus_count,
                                "high_risk": sus_count >= 3
                            })
                        except:
                            pass

    def _collect_loaded_dlls(self):
        browser_names = ['chrome.exe', 'firefox.exe', 'msedge.exe', 'brave.exe']
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'].lower() not in browser_names:
                    continue
                for dll in proc.memory_maps():
                    dll_path = dll.path.lower()
                    if any(x in dll_path for x in ['\\windows\\', '\\program files\\']):
                        continue
                    if dll_path.endswith('.dll') or dll_path.endswith('.exe'):
                        self._add("loaded_dll", "psutil", {
                            "pid": proc.info['pid'],
                            "process_name": proc.info['name'],
                            "dll_path": dll.path,
                            "rss": dll.rss
                        })
            except:
                pass

    def _collect_memory_regions(self):
        if sys.platform != 'win32':
            return

        try:
            import win32api
            import win32con
        except:
            return

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                if pid < 100:
                    continue

                handle = win32api.OpenProcess(
                    win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                    False, pid
                )

                rwx_count = 0
                address = 0
                while True:
                    mbi = MEMORY_BASIC_INFORMATION()
                    result = ctypes.windll.kernel32.VirtualQueryEx(
                        handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
                    )
                    if result == 0:
                        break

                    if (mbi.State == win32con.MEM_COMMIT and 
                        mbi.Protect == win32con.PAGE_EXECUTE_READWRITE):
                        rwx_count += 1

                    address = mbi.BaseAddress + mbi.RegionSize

                win32api.CloseHandle(handle)

                if rwx_count > 0:
                    self._add("memory_region", "win32api", {
                        "pid": pid,
                        "process_name": name,
                        "rwx_region_count": rwx_count,
                        "note": "Executable+Writable memory regions detected"
                    })

            except:
                pass

    def _collect_suspicious_files(self):
        """Check temp and appdata for suspicious files"""
        check_paths = [
            Path(os.environ.get('TEMP', 'C:/Temp')),
            Path.home() / "AppData" / "Local" / "Temp",
        ]

        for base_path in check_paths:
            if not base_path.exists():
                continue
            try:
                for item in base_path.iterdir():
                    if not item.is_file():
                        continue

                    # Check hidden attribute on Windows
                    hidden = False
                    if sys.platform == 'win32':
                        try:
                            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(item))
                            if attrs != -1 and (attrs & 0x02):
                                hidden = True
                        except:
                            pass

                    # Check for suspicious extensions
                    sus_ext = item.suffix.lower() in ['.scr', '.pif', '.com', '.bat', '.ps1', '.vbs', '.js']

                    if hidden or sus_ext:
                        self._add("suspicious_file", "filesystem", {
                            "path": str(item),
                            "name": item.name,
                            "size": item.stat().st_size,
                            "hidden": hidden,
                            "suspicious_extension": sus_ext,
                            "modified": item.stat().st_mtime
                        })

                    # Limit to prevent overload
                    if len(self.evidence) > 5000:
                        break

            except PermissionError:
                continue


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
