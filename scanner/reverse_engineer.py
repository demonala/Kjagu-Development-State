"""
KJAGU Reverse Engineering Module
Static analysis of suspicious files before any destructive action.
Extracts strings, imports, entropy, and behavioral indicators.
"""

import os
import re
import math
import hashlib
import struct
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class REReport:
    """Reverse Engineering analysis report"""
    file_path: str
    file_hash_md5: str
    file_hash_sha256: str
    file_size: int
    entropy: float
    file_type: str
    is_pe: bool
    is_dll: bool
    is_packed: bool
    imported_dlls: List[str] = field(default_factory=list)
    imported_functions: List[str] = field(default_factory=list)
    suspicious_strings: List[str] = field(default_factory=list)
    suspicious_apis: List[str] = field(default_factory=list)
    network_indicators: List[str] = field(default_factory=list)
    crypto_indicators: List[str] = field(default_factory=list)
    persistence_indicators: List[str] = field(default_factory=list)
    injection_indicators: List[str] = field(default_factory=list)
    risk_score: float = 0.0  # 0.0 - 1.0
    analysis_notes: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "file_hash_md5": self.file_hash_md5,
            "file_hash_sha256": self.file_hash_sha256,
            "file_size": self.file_size,
            "entropy": round(self.entropy, 4),
            "file_type": self.file_type,
            "is_pe": self.is_pe,
            "is_dll": self.is_dll,
            "is_packed": self.is_packed,
            "imported_dlls": self.imported_dlls[:50],
            "imported_functions": self.imported_functions[:100],
            "suspicious_strings": self.suspicious_strings[:50],
            "suspicious_apis": self.suspicious_apis,
            "network_indicators": self.network_indicators,
            "crypto_indicators": self.crypto_indicators,
            "persistence_indicators": self.persistence_indicators,
            "injection_indicators": self.injection_indicators,
            "risk_score": round(self.risk_score, 4),
            "analysis_notes": self.analysis_notes,
            "timestamp": self.timestamp
        }


class ReverseEngineer:
    """Static analysis engine for suspicious binaries"""

    # Suspicious API imports
    SUSPICIOUS_APIS = {
        "keylogging": [
            "GetAsyncKeyState", "GetKeyState", "SetWindowsHookEx", "CallNextHookEx",
            "GetKeyboardState", "GetRawInputData", "RegisterRawInputDevices"
        ],
        "injection": [
            "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory",
            "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext", "NtUnmapViewOfSection"
        ],
        "process_manipulation": [
            "OpenProcess", "TerminateProcess", "SuspendThread", "ResumeThread",
            "DebugActiveProcess", "NtSuspendProcess", "NtResumeProcess"
        ],
        "persistence": [
            "RegCreateKeyEx", "RegSetValueEx", "CreateService", "StartService",
            "WritePrivateProfileString", "CreateShortcut"
        ],
        "network": [
            "socket", "connect", "send", "recv", "InternetOpen", "InternetConnect",
            "HttpSendRequest", "URLDownloadToFile", "WinHttpOpen", "WSAStartup"
        ],
        "stealth": [
            "NtSetInformationProcess", "NtQuerySystemInformation", "NtAdjustPrivilegesToken",
            "LookupPrivilegeValue", "AdjustTokenPrivileges"
        ],
        "crypto": [
            "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptExportKey",
            "BCryptEncrypt", "NCryptEncrypt", "CryptStringToBinary"
        ],
        "screen_capture": [
            "BitBlt", "GetDC", "CreateCompatibleDC", "GetForegroundWindow",
            "PrintWindow", "DwmGetWindowAttribute"
        ],
        "file_operations": [
            "DeleteFile", "MoveFileEx", "CopyFile", "CreateFile", "WriteFile",
            "SetFileAttributes", "FindFirstFile", "GetFileSize"
        ]
    }

    # Suspicious strings to search for
    SUSPICIOUS_STRINGS = [
        r"password", r"passwd", r"credential", r"login", r"token",
        r"cookie", r"session", r"wallet", r"private.?key", r"seed.?phrase",
        r"discord.*webhook", r"telegram.*bot", r"pastebin", r"ghostbin",
        r"smtp", r"imap", r"pop3", r"ftp", r"ssh",
        r"base64", r"encrypt", r"decrypt", r"xor", r"aes",
        r"keylogger", r"stealer", r"grabber", r"clipper",
        r"screenshot", r"webcam", r"microphone", r"desktop",
        r"chrome.*cookie", r"firefox.*cookie", r"edge.*cookie",
        r"credit.?card", r"cvv", r"iban", r"bitcoin", r"ethereum",
        r"\b[A-Za-z0-9]{32,64}\b",  # Potential hashes/keys
    ]

    def analyze_file(self, file_path: str) -> REReport:
        """Perform full static analysis on a file"""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        report = REReport(file_path=file_path)

        # Basic file info
        report.file_size = path.stat().st_size
        report.file_hash_md5 = self._hash_file(path, "md5")
        report.file_hash_sha256 = self._hash_file(path, "sha256")

        # Read file data
        with open(path, 'rb') as f:
            data = f.read()

        # Entropy analysis
        report.entropy = self._calculate_entropy(data)
        report.is_packed = report.entropy > 7.2  # High entropy = likely packed/encrypted

        # File type detection
        report.file_type = self._detect_file_type(data)
        report.is_pe = data[:2] == b'MZ'
        report.is_dll = False

        # PE analysis
        if report.is_pe:
            report.is_dll = self._is_dll(data)
            pe_info = self._parse_pe_imports(data)
            report.imported_dlls = pe_info.get("dlls", [])
            report.imported_functions = pe_info.get("functions", [])

            # Check imports against suspicious APIs
            all_imports = " ".join(report.imported_functions).lower()
            for category, apis in self.SUSPICIOUS_APIS.items():
                found = [api for api in apis if api.lower() in all_imports]
                if found:
                    if category == "keylogging":
                        report.suspicious_apis.extend(found)
                    elif category == "injection":
                        report.injection_indicators.extend(found)
                    elif category == "persistence":
                        report.persistence_indicators.extend(found)
                    elif category == "network":
                        report.network_indicators.extend(found)
                    elif category == "crypto":
                        report.crypto_indicators.extend(found)

        # String extraction
        strings = self._extract_strings(data)
        report.suspicious_strings = self._find_suspicious_strings(strings)

        # Calculate risk score
        report.risk_score = self._calculate_risk(report)

        # Analysis notes
        report.analysis_notes = self._generate_notes(report)

        return report

    def _hash_file(self, path: Path, algo: str) -> str:
        h = hashlib.new(algo)
        with open(path, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()

    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def _detect_file_type(self, data: bytes) -> str:
        if data[:2] == b'MZ':
            return "PE/Windows Executable"
        elif data[:4] == b'\x7fELF':
            return "ELF/Linux Executable"
        elif data[:4] == b'\xca\xfe\xba\xbe':
            return "Mach-O/macOS Executable"
        elif data[:2] == b'PK':
            return "ZIP/Archive"
        elif data[:4] == b'%PDF':
            return "PDF Document"
        else:
            return "Unknown"

    def _is_dll(self, data: bytes) -> bool:
        try:
            pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
            characteristics = struct.unpack_from('<H', data, pe_offset + 24 + 22)[0]
            return bool(characteristics & 0x2000)
        except:
            return False

    def _parse_pe_imports(self, data: bytes) -> dict:
        """Simplified PE import parser"""
        result = {"dlls": [], "functions": []}
        try:
            pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
            pe_sig = struct.unpack_from('<I', data, pe_offset)[0]
            if pe_sig != 0x00004550:
                return result

            is_64 = struct.unpack_from('<H', data, pe_offset + 24)[0] == 0x20b
            opt_header_size = 24 + (240 if is_64 else 224)
            data_dir_offset = pe_offset + 24 + (112 if is_64 else 96)

            import_dir_rva = struct.unpack_from('<I', data, data_dir_offset + 8)[0]
            if import_dir_rva == 0:
                return result

            # Find section containing imports
            num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
            section_table = pe_offset + 24 + (240 if is_64 else 224)

            import_offset = None
            for i in range(num_sections):
                sec_offset = section_table + i * 40
                sec_rva = struct.unpack_from('<I', data, sec_offset + 12)[0]
                sec_size = struct.unpack_from('<I', data, sec_offset + 16)[0]
                sec_raw = struct.unpack_from('<I', data, sec_offset + 20)[0]

                if sec_rva <= import_dir_rva < sec_rva + sec_size:
                    import_offset = sec_raw + (import_dir_rva - sec_rva)
                    break

            if import_offset is None:
                return result

            # Parse import descriptors
            idx = 0
            while True:
                desc_offset = import_offset + idx * 20
                if desc_offset + 20 > len(data):
                    break

                name_rva = struct.unpack_from('<I', data, desc_offset + 12)[0]
                if name_rva == 0:
                    break

                # Find DLL name
                dll_name_offset = None
                for i in range(num_sections):
                    sec_offset = section_table + i * 40
                    sec_rva = struct.unpack_from('<I', data, sec_offset + 12)[0]
                    sec_size = struct.unpack_from('<I', data, sec_offset + 16)[0]
                    sec_raw = struct.unpack_from('<I', data, sec_offset + 20)[0]
                    if sec_rva <= name_rva < sec_rva + sec_size:
                        dll_name_offset = sec_raw + (name_rva - sec_rva)
                        break

                if dll_name_offset and dll_name_offset < len(data):
                    dll_name = data[dll_name_offset:dll_name_offset+256].split(b'\x00')[0].decode('ascii', errors='ignore')
                    result["dlls"].append(dll_name)

                idx += 1
                if idx > 1000:
                    break

        except Exception as e:
            result["dlls"].append(f"parse_error: {str(e)}")

        return result

    def _extract_strings(self, data: bytes, min_len: int = 4) -> List[str]:
        """Extract ASCII and Unicode strings"""
        strings = []
        # ASCII strings
        ascii_pattern = re.compile(b'[\x20-\x7e]{' + str(min_len).encode() + b',}')
        strings.extend([s.decode('ascii', errors='ignore') for s in ascii_pattern.findall(data)])
        return strings

    def _find_suspicious_strings(self, strings: List[str]) -> List[str]:
        """Find suspicious patterns in extracted strings"""
        found = []
        seen = set()
        for s in strings:
            for pattern in self.SUSPICIOUS_STRINGS:
                try:
                    if re.search(pattern, s, re.IGNORECASE):
                        if s not in seen and len(s) < 200:
                            seen.add(s)
                            found.append(s)
                            if len(found) >= 50:
                                return found
                except:
                    pass
        return found

    def _calculate_risk(self, report: REReport) -> float:
        """Calculate overall risk score 0.0-1.0"""
        score = 0.0

        # Entropy (packed/encrypted)
        if report.entropy > 7.5:
            score += 0.15
        elif report.entropy > 7.0:
            score += 0.08

        # Suspicious APIs
        api_count = (len(report.suspicious_apis) + len(report.injection_indicators) +
                    len(report.persistence_indicators) + len(report.network_indicators) +
                    len(report.crypto_indicators))
        score += min(api_count * 0.05, 0.3)

        # Suspicious strings
        score += min(len(report.suspicious_strings) * 0.02, 0.2)

        # Network indicators
        score += min(len(report.network_indicators) * 0.05, 0.15)

        # Injection indicators (high weight)
        score += min(len(report.injection_indicators) * 0.08, 0.25)

        # Persistence indicators
        score += min(len(report.persistence_indicators) * 0.06, 0.15)

        return min(score, 1.0)

    def _generate_notes(self, report: REReport) -> List[str]:
        notes = []

        if report.is_packed:
            notes.append(f"High entropy ({report.entropy:.2f}) suggests packed/encrypted binary")

        if report.injection_indicators:
            notes.append(f"Process injection APIs detected: {', '.join(report.injection_indicators[:5])}")

        if report.suspicious_apis:
            notes.append(f"Keylogging APIs detected: {', '.join(report.suspicious_apis[:5])}")

        if report.network_indicators:
            notes.append(f"Network APIs detected: {', '.join(report.network_indicators[:5])}")

        if report.persistence_indicators:
            notes.append(f"Persistence APIs detected: {', '.join(report.persistence_indicators[:5])}")

        if report.suspicious_strings:
            notes.append(f"Found {len(report.suspicious_strings)} suspicious strings")

        if not notes:
            notes.append("No immediately suspicious indicators found in static analysis")

        return notes
