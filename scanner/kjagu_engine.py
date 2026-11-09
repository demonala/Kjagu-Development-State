"""
KJAGU RID IT EDITION - Main Engine
Orchestrates all scanner modules, AI analysis, approvals, and reporting.
"""

import os
import sys
import time
import json
import threading
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any

from policy_manager import PolicyManager
from approval_system import ApprovalSystem, ActionType
from recon_module import ReconModule
from reverse_engineer import ReverseEngineer
from kernel_access import KernelAccess
from report_generator import ReportGenerator


class KjaguEngine:
    """Central engine that ties all modules together"""

    def __init__(self, bridge=None):
        self.bridge = bridge
        self.scan_id = f"SCAN_{int(time.time())}"

        # Modules
        self.policy_manager = PolicyManager()
        self.approval_system = ApprovalSystem(bridge)
        self.recon = ReconModule()
        self.re_engineer = ReverseEngineer()
        self.kernel = KernelAccess(self.policy_manager)
        self.reports = ReportGenerator()

        # State
        self.status = "idle"
        self.evidence: List[dict] = []
        self.re_reports: List[dict] = []
        self.kernel_findings: List[dict] = []
        self.scan_metadata = {}

        # Threading
        self._scan_thread = None
        self._stop_event = threading.Event()

    def get_status(self) -> dict:
        """Return current engine status"""
        return {
            "status": self.status,
            "scan_id": self.scan_id,
            "policy_accepted": self.policy_manager.is_accepted(),
            "is_admin": self.kernel.check_privileges(),
            "pending_approvals": len(self.approval_system.get_pending()),
            "evidence_count": len(self.evidence),
            "re_reports_count": len(self.re_reports),
            "kernel_findings_count": len(self.kernel_findings)
        }

    def start_scan(self, scan_type: str = "full", request_id: str = ""):
        """Start a full system scan"""
        self.status = "scanning"
        self._stop_event.clear()

        try:
            self._emit("scan_phase", {"phase": "recon", "message": "Collecting system evidence..."})

            # Phase 1: Evidence Collection
            evidence_objs = self.recon.collect_all()
            self.evidence = [e.to_dict() for e in evidence_objs]

            self._emit("scan_phase", {
                "phase": "recon_complete",
                "evidence_count": len(self.evidence)
            })

            # Phase 2: Identify suspicious targets for RE
            suspicious_files = self._identify_suspicious_files()

            if suspicious_files:
                self._emit("scan_phase", {
                    "phase": "reverse_engineering",
                    "message": f"Analyzing {len(suspicious_files)} suspicious files...",
                    "files": suspicious_files
                })

                for file_path in suspicious_files[:10]:  # Limit RE to top 10
                    if self._stop_event.is_set():
                        break
                    try:
                        report = self.re_engineer.analyze_file(file_path)
                        self.re_reports.append(report.to_dict())
                        self._emit("re_complete", report.to_dict())
                    except Exception as e:
                        self._emit("re_error", {"file": file_path, "error": str(e)})

            # Phase 3: Kernel Scan (if authorized)
            self._emit("scan_phase", {
                "phase": "kernel",
                "message": "Scanning kernel-level indicators..."
            })

            kernel_results = self.kernel.scan()
            self.kernel_findings = [f.to_dict() for f in kernel_results]

            self._emit("scan_phase", {
                "phase": "kernel_complete",
                "findings_count": len(self.kernel_findings)
            })

            # Phase 4: Generate AI analysis and approval requests
            self._generate_approval_requests()

            # Phase 5: Save report
            report_path = self.reports.generate_full_report(
                self.scan_id,
                self.evidence,
                self.re_reports,
                self.kernel_findings,
                self.approval_system.get_pending(),
                self.approval_system.get_history(),
                {"scan_type": scan_type, "completed": True}
            )

            self.scan_metadata = {
                "scan_type": scan_type,
                "completed": True,
                "report_path": report_path,
                "evidence_count": len(self.evidence),
                "re_reports_count": len(self.re_reports),
                "kernel_findings_count": len(self.kernel_findings),
                "pending_approvals": len(self.approval_system.get_pending())
            }

            self.status = "complete"
            self._emit("scan_complete", self.scan_metadata)

        except Exception as e:
            self.status = "error"
            self._emit("scan_error", {"error": str(e)})

    def _identify_suspicious_files(self) -> List[str]:
        """Extract file paths from evidence that warrant reverse engineering"""
        files = []

        # From suspicious file evidence
        for ev in self.evidence:
            if ev.get("category") == "suspicious_file":
                path = ev.get("data", {}).get("path", "")
                if path and Path(path).exists():
                    files.append(path)

        # From process executables with threat indicators
        for ev in self.evidence:
            if ev.get("category") == "process":
                data = ev.get("data", {})
                if data.get("suspicious") or data.get("orphan"):
                    exe = data.get("exe", "")
                    if exe and Path(exe).exists() and exe not in files:
                        files.append(exe)

        # From loaded DLLs in browsers
        for ev in self.evidence:
            if ev.get("category") == "loaded_dll":
                path = ev.get("data", {}).get("dll_path", "")
                if path and Path(path).exists() and path not in files:
                    files.append(path)

        return files

    def _generate_approval_requests(self):
        """Create approval requests for all high-risk findings"""

        # Process-based threats
        for ev in self.evidence:
            if ev.get("category") != "process":
                continue
            data = ev.get("data", {})

            if not (data.get("suspicious") or data.get("orphan")):
                continue

            pid = data.get("pid", 0)
            name = data.get("name", "unknown")
            exe = data.get("exe", "")
            indicators = data.get("threat_indicators", [])

            # Build evidence summary
            evidence_summary = f"Process: {name} (PID {pid})\\n"
            evidence_summary += f"Path: {exe}\\n"
            evidence_summary += f"Indicators: {', '.join(indicators)}\\n"
            if data.get("orphan"):
                evidence_summary += "Orphan process (possible PPID spoofing)\\n"

            # Determine risk
            risk = "HIGH" if data.get("orphan") else "MEDIUM"
            if len(indicators) > 2:
                risk = "CRITICAL"

            # Find matching RE report
            re_note = ""
            for rep in self.re_reports:
                if exe and exe in rep.get("file_path", ""):
                    re_note = f"RE Analysis: Risk score {rep.get('risk_score', 0):.0%}. "
                    re_note += "; ".join(rep.get("analysis_notes", []))
                    if rep.get("risk_score", 0) > 0.7:
                        risk = "CRITICAL"
                    break

            ai_rec = f"{re_note} Recommend TERMINATE due to {len(indicators)} threat indicators."

            self.approval_system.request_approval(
                action_type=ActionType.TERMINATE_PROCESS,
                target=name,
                target_pid=pid,
                description=f"Terminate suspicious process: {name}",
                risk_level=risk,
                evidence_summary=evidence_summary,
                ai_recommendation=ai_rec,
                ai_confidence=min(0.5 + len(indicators) * 0.15, 0.95),
                callback=lambda action, p=pid, n=name: self._execute_terminate(p, n)
            )

        # Kernel-level findings
        for finding in self.kernel_findings:
            if finding.get("severity") not in ["CRITICAL", "HIGH"]:
                continue

            ftype = finding.get("finding_type", "")
            target = finding.get("target", "")
            desc = finding.get("description", "")

            if ftype == "INLINE_HOOK":
                self.approval_system.request_approval(
                    action_type=ActionType.KERNEL_SCAN,
                    target=target,
                    target_pid=0,
                    description=f"Kernel hook detected: {desc}",
                    risk_level="CRITICAL",
                    evidence_summary=json.dumps(finding.get("details", {})),
                    ai_recommendation="Kernel-level hook detected. Manual remediation required. Cannot auto-fix from usermode.",
                    ai_confidence=0.95,
                    callback=lambda action: "Kernel hooks require manual remediation. Report saved."
                )

        # High-risk files from RE
        for rep in self.re_reports:
            if rep.get("risk_score", 0) < 0.6:
                continue

            path = rep.get("file_path", "")
            score = rep.get("risk_score", 0)
            risk = "CRITICAL" if score > 0.8 else "HIGH"

            notes = "; ".join(rep.get("analysis_notes", []))

            self.approval_system.request_approval(
                action_type=ActionType.DELETE_FILE,
                target=Path(path).name,
                target_pid=0,
                description=f"Delete suspicious file: {Path(path).name}",
                risk_level=risk,
                evidence_summary=f"Path: {path}\\nEntropy: {rep.get('entropy')}\\nSuspicious strings: {len(rep.get('suspicious_strings', []))}",
                ai_recommendation=f"Static analysis indicates high risk. {notes}",
                ai_confidence=score,
                callback=lambda action, p=path: self._execute_delete_file(p)
            )

    def _execute_terminate(self, pid: int, name: str) -> str:
        """Execute process termination"""
        import psutil
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except:
                proc.kill()
                proc.wait(timeout=2)
            return f"Terminated {name} (PID {pid})"
        except Exception as e:
            return f"Failed to terminate {name}: {e}"

    def _execute_delete_file(self, path: str) -> str:
        """Securely delete a file"""
        try:
            p = Path(path)
            if not p.exists():
                return f"File not found: {path}"

            # Overwrite
            size = p.stat().st_size
            with open(p, 'r+b') as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(os.urandom(min(size, 1024*1024)))
                    f.flush()

            # Rename and delete
            temp = p.parent / os.urandom(16).hex()
            p.rename(temp)
            temp.unlink()
            return f"Securely deleted: {path}"
        except Exception as e:
            return f"Failed to delete {path}: {e}"

    def approve_action(self, action_id: str, approved: bool):
        """User approves or denies a pending action"""
        return self.approval_system.approve_action(action_id, approved)

    def reverse_engineer_file(self, file_path: str, request_id: str = ""):
        """On-demand reverse engineering of a specific file"""
        try:
            report = self.re_engineer.analyze_file(file_path)
            self._emit("re_complete", report.to_dict())
            return report.to_dict()
        except Exception as e:
            self._emit("re_error", {"file": file_path, "error": str(e)})
            return {"error": str(e)}

    def encrypt_cookies(self) -> dict:
        """Encrypt browser cookies"""
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        import base64

        results = {}
        vault_dir = Path.home() / ".kjagu_vault"
        vault_dir.mkdir(exist_ok=True)

        # Generate key
        key = AESGCM.generate_key(bit_length=256)

        browsers = {
            "chrome": Path.home() / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "Cookies",
            "edge": Path.home() / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data" / "Default" / "Cookies",
            "brave": Path.home() / "AppData" / "Local" / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Cookies",
        }

        for name, path in browsers.items():
            if not path.exists():
                continue
            try:
                with open(path, 'rb') as f:
                    plaintext = f.read()

                nonce = os.urandom(12)
                aesgcm = AESGCM(key)
                ciphertext = aesgcm.encrypt(nonce, plaintext, name.encode())

                vault_path = vault_dir / f"{name}_cookies.kvault"
                with open(vault_path, 'wb') as f:
                    f.write(nonce + ciphertext)

                # Secure delete original
                size = path.stat().st_size
                with open(path, 'r+b') as f:
                    for _ in range(3):
                        f.seek(0)
                        f.write(os.urandom(min(size, 1024*1024)))
                temp = path.parent / os.urandom(16).hex()
                path.rename(temp)
                temp.unlink()

                results[name] = str(vault_path)
            except Exception as e:
                results[name] = f"ERROR: {e}"

        return results

    def _emit(self, event_type: str, data: dict):
        """Send event to bridge/extension"""
        if self.bridge:
            self.bridge.emit_event(event_type, data)
