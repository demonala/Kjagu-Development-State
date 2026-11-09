"""
KJAGU Kernel Access Module
Elevated system scanning — drivers, kernel callbacks, deep memory.
ONLY runs after policy acceptance and admin verification.
"""

import os
import sys
import ctypes
import subprocess
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class KernelFinding:
    finding_type: str
    severity: str
    target: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        return {
            "finding_type": self.finding_type,
            "severity": self.severity,
            "target": self.target,
            "description": self.description,
            "details": self.details,
            "timestamp": self.timestamp
        }


class KernelAccess:
    """
    Kernel-level threat detection.
    Requires Administrator privileges.
    """

    def __init__(self, policy_manager):
        self.policy = policy_manager
        self.findings: List[KernelFinding] = []
        self._has_access = False

    def check_privileges(self) -> bool:
        """Check if running with elevated privileges"""
        if sys.platform == 'win32':
            try:
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False
        else:
            return os.geteuid() == 0

    def scan(self) -> List[KernelFinding]:
        """Run full kernel scan if authorized"""
        self.findings = []

        if not self.policy.is_accepted():
            self.findings.append(KernelFinding(
                finding_type="POLICY_BLOCK",
                severity="INFO",
                target="kernel_access",
                description="Kernel scan skipped — policy not accepted. Accept policy to enable deep scanning."
            ))
            return self.findings

        if not self.check_privileges():
            self.findings.append(KernelFinding(
                finding_type="PRIVILEGE_INSUFFICIENT",
                severity="INFO",
                target="kernel_access",
                description="Kernel scan skipped — not running as Administrator. Run run.bat as Administrator."
            ))
            return self.findings

        self._has_access = True

        # Run kernel-level checks
        self._scan_drivers()
        self._scan_system_modules()
        self._scan_callback_routines()
        self._scan_hidden_processes()
        self._scan_kernel_hooks()

        return self.findings

    def _scan_drivers(self):
        """Scan loaded kernel drivers for suspicious signatures"""
        if sys.platform != 'win32':
            return

        try:
            result = subprocess.run(
                ['driverquery', '/v', '/fo', 'csv'],
                capture_output=True, text=True, timeout=30
            )

            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            suspicious_keywords = [
                'rootkit', 'hook', 'hide', 'shadow', 'ghost', 'protector',
                'defender', 'security', 'unknown', 'unverified'
            ]

            for line in lines:
                parts = line.split('","')
                if len(parts) < 5:
                    continue

                driver_name = parts[0].strip('"')
                display_name = parts[1].strip('"')
                state = parts[3].strip('"')
                status = parts[4].strip('"')

                combined = f"{driver_name} {display_name}".lower()

                for keyword in suspicious_keywords:
                    if keyword in combined:
                        self.findings.append(KernelFinding(
                            finding_type="SUSPICIOUS_DRIVER",
                            severity="CRITICAL",
                            target=driver_name,
                            description=f"Driver name contains suspicious keyword: '{keyword}'",
                            details={
                                "display_name": display_name,
                                "state": state,
                                "status": status,
                                "keyword_matched": keyword
                            }
                        ))
                        break

                # Check for unsigned drivers
                if 'not' in status.lower() or 'unsigned' in status.lower():
                    self.findings.append(KernelFinding(
                        finding_type="UNSIGNED_DRIVER",
                        severity="HIGH",
                        target=driver_name,
                        description="Driver appears to be unsigned or has signature issues",
                        details={
                            "display_name": display_name,
                            "status": status
                        }
                    ))

        except Exception as e:
            self.findings.append(KernelFinding(
                finding_type="SCAN_ERROR",
                severity="INFO",
                target="driver_scan",
                description=f"Failed to scan drivers: {e}"
            ))

    def _scan_system_modules(self):
        """Enumerate system modules via NTDLL"""
        if sys.platform != 'win32':
            return

        try:
            # Use Windows API to enumerate modules
            ntdll = ctypes.windll.ntdll

            # NtQuerySystemInformation with SystemModuleInformation (11)
            SystemModuleInformation = 11

            # First call to get size
            size = ctypes.c_ulong(0)
            ntdll.NtQuerySystemInformation(SystemModuleInformation, None, 0, ctypes.byref(size))

            if size.value == 0:
                return

            # Allocate buffer and query
            buffer = ctypes.create_string_buffer(size.value)
            status = ntdll.NtQuerySystemInformation(SystemModuleInformation, buffer, size, None)

            if status != 0:
                return

            # Parse module list
            num_modules = struct.unpack_from('<I', buffer.raw)[0]
            offset = 4  # Skip count

            for i in range(min(num_modules, 200)):  # Limit for safety
                # RTL_PROCESS_MODULE_INFORMATION structure
                # Section, MappedBase, ImageBase, ImageSize, Flags, LoadOrderIndex, InitOrderIndex, LoadCount, OffsetToFileName, FullPathName[256]
                try:
                    image_base = struct.unpack_from('<P', buffer.raw, offset + 8)[0]
                    image_size = struct.unpack_from('<I', buffer.raw, offset + 16)[0]
                    flags = struct.unpack_from('<H', buffer.raw, offset + 20)[0]
                    path_offset = offset + 24
                    full_path = buffer.raw[path_offset:path_offset+256].split(b'\x00')[0].decode('ascii', errors='ignore')

                    # Check for suspicious paths
                    if full_path and not any(x in full_path.lower() for x in ['\\windows\\', '\\system32\\']):
                        self.findings.append(KernelFinding(
                            finding_type="NON_STANDARD_MODULE",
                            severity="MEDIUM",
                            target=full_path.split('\\')[-1] if '\\' in full_path else full_path,
                            description="Kernel module loaded from non-standard path",
                            details={
                                "full_path": full_path,
                                "image_base": hex(image_base),
                                "image_size": image_size
                            }
                        ))

                    offset += 284  # Size of RTL_PROCESS_MODULE_INFORMATION
                except:
                    break

        except Exception as e:
            self.findings.append(KernelFinding(
                finding_type="SCAN_ERROR",
                severity="INFO",
                target="module_scan",
                description=f"Failed to enumerate system modules: {e}"
            ))

    def _scan_callback_routines(self):
        """Detect suspicious kernel callback registrations"""
        # This requires a kernel driver for full detection
        # We use heuristics based on visible symptoms

        if sys.platform != 'win32':
            return

        try:
            # Check for processes that should exist but don't (hidden by callback hook)
            expected_system = ['csrss.exe', 'smss.exe', 'services.exe', 'lsass.exe']
            found_system = []

            for proc in __import__('psutil').process_iter(['name']):
                try:
                    if proc.info['name']:
                        found_system.append(proc.info['name'].lower())
                except:
                    pass

            for expected in expected_system:
                if expected not in found_system:
                    self.findings.append(KernelFinding(
                        finding_type="HIDDEN_SYSTEM_PROCESS",
                        severity="CRITICAL",
                        target=expected,
                        description="Critical system process not visible — possible rootkit process hiding",
                        details={
                            "expected": expected,
                            "visible_processes": list(set(found_system))[:20]
                        }
                    ))
        except Exception as e:
            pass

    def _scan_hidden_processes(self):
        """Cross-reference multiple methods to find hidden processes"""
        try:
            import psutil

            # Method 1: psutil process list
            psutil_pids = set()
            for proc in psutil.process_iter(['pid']):
                try:
                    psutil_pids.add(proc.info['pid'])
                except:
                    pass

            # Method 2: WMI process list (Windows)
            if sys.platform == 'win32':
                try:
                    import wmi
                    c = wmi.WMI()
                    wmi_pids = set()
                    for p in c.Win32_Process():
                        wmi_pids.add(p.ProcessId)

                    hidden = wmi_pids - psutil_pids
                    for pid in hidden:
                        self.findings.append(KernelFinding(
                            finding_type="HIDDEN_PROCESS",
                            severity="CRITICAL",
                            target=f"PID:{pid}",
                            description="Process visible to WMI but hidden from standard APIs — rootkit indicator",
                            details={
                                "pid": pid,
                                "detection_method": "wmi_vs_psutil"
                            }
                        ))
                except:
                    pass

            # Method 3: Check /proc on Linux
            elif sys.platform == 'linux':
                proc_pids = set()
                for entry in Path('/proc').iterdir():
                    if entry.name.isdigit():
                        proc_pids.add(int(entry.name))

                hidden = proc_pids - psutil_pids
                for pid in hidden:
                    self.findings.append(KernelFinding(
                        finding_type="HIDDEN_PROCESS",
                        severity="CRITICAL",
                        target=f"PID:{pid}",
                        description="Process in /proc but not visible to psutil — possible rootkit",
                        details={"pid": pid}
                    ))

        except Exception as e:
            self.findings.append(KernelFinding(
                finding_type="SCAN_ERROR",
                severity="INFO",
                target="hidden_process_scan",
                description=f"Failed hidden process check: {e}"
            ))

    def _scan_kernel_hooks(self):
        """Detect inline hooks in critical system DLLs"""
        if sys.platform != 'win32':
            return

        critical_dlls = ['ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'user32.dll']

        for dll_name in critical_dlls:
            try:
                dll = ctypes.windll.LoadLibrary(dll_name)
                base_addr = ctypes.cast(dll._handle, ctypes.c_void_p).value

                # Read first bytes of common exports
                exports_to_check = [
                    'NtCreateFile', 'NtReadVirtualMemory', 'NtWriteVirtualMemory',
                    'NtOpenProcess', 'NtQuerySystemInformation'
                ]

                for export in exports_to_check:
                    try:
                        proc_addr = ctypes.windll.kernel32.GetProcAddress(dll._handle, export.encode())
                        if not proc_addr:
                            continue

                        # Read first 16 bytes
                        buf = (ctypes.c_ubyte * 16).from_address(proc_addr)
                        bytes_data = bytes(buf)

                        # Check for hook patterns
                        # JMP rel32 (E9 xx xx xx xx)
                        # JMP [mem] (FF 25 xx xx xx xx)
                        # PUSH + RET (68 xx xx xx xx C3)
                        if bytes_data[0:1] == b'\xE9':
                            self.findings.append(KernelFinding(
                                finding_type="INLINE_HOOK",
                                severity="CRITICAL",
                                target=f"{dll_name}!{export}",
                                description="Inline hook detected: JMP instruction at function entry",
                                details={
                                    "dll": dll_name,
                                    "function": export,
                                    "address": hex(proc_addr),
                                    "first_bytes": bytes_data[:8].hex()
                                }
                            ))
                        elif bytes_data[0:2] == b'\xFF\x25':
                            self.findings.append(KernelFinding(
                                finding_type="INLINE_HOOK",
                                severity="CRITICAL",
                                target=f"{dll_name}!{export}",
                                description="Inline hook detected: JMP [mem] instruction at function entry",
                                details={
                                    "dll": dll_name,
                                    "function": export,
                                    "address": hex(proc_addr),
                                    "first_bytes": bytes_data[:8].hex()
                                }
                            ))
                    except:
                        pass

            except Exception as e:
                pass
