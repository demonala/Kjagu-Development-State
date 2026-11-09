"""
KJAGU Report Generator
Saves all scan results as JSON files to the Desktop.
"""

import os
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any


class ReportGenerator:
    """Generates comprehensive JSON reports saved to Desktop"""

    def __init__(self):
        self.reports_dir = Path.home() / "Desktop" / "KjaguReports"
        self.reports_dir.mkdir(exist_ok=True)

    def generate_full_report(self, scan_id: str, evidence: List[dict], 
                             re_reports: List[dict], kernel_findings: List[dict],
                             approvals: List[dict], history: List[dict],
                             scan_metadata: dict) -> str:
        """Generate and save the full scan report"""

        report = {
            "report_metadata": {
                "scanner": "KJAGU RID IT EDITION",
                "version": "4.0",
                "scan_id": scan_id,
                "timestamp": datetime.now().isoformat(),
                "hostname": os.environ.get('COMPUTERNAME', 'unknown'),
                "username": os.getlogin() if hasattr(os, 'getlogin') else 'unknown',
                "platform": os.name,
            },
            "scan_summary": scan_metadata,
            "evidence_collected": {
                "total_count": len(evidence),
                "by_category": self._categorize_evidence(evidence),
                "items": evidence[:500]  # Limit for file size
            },
            "reverse_engineering": {
                "files_analyzed": len(re_reports),
                "reports": re_reports
            },
            "kernel_findings": {
                "total_count": len(kernel_findings),
                "findings": kernel_findings
            },
            "approval_log": {
                "pending": [a for a in approvals if a.get("status") == "pending"],
                "resolved": history
            },
            "threat_summary": self._summarize_threats(evidence, kernel_findings, re_reports)
        }

        # Save to file
        filename = f"kjagu_report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.reports_dir / filename

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return str(filepath)

    def _categorize_evidence(self, evidence: List[dict]) -> Dict[str, int]:
        categories = {}
        for ev in evidence:
            cat = ev.get("category", "unknown")
            categories[cat] = categories.get(cat, 0) + 1
        return categories

    def _summarize_threats(self, evidence: List[dict], kernel: List[dict], 
                           re_reports: List[dict]) -> Dict[str, Any]:
        summary = {
            "total_threats": 0,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "top_processes": [],
            "top_files": [],
            "recommendations": []
        }

        # Count kernel findings by severity
        for finding in kernel:
            sev = finding.get("severity", "INFO")
            summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1
            summary["total_threats"] += 1

        # Count suspicious evidence
        for ev in evidence:
            data = ev.get("data", {})
            if data.get("suspicious") or data.get("high_risk") or data.get("orphan"):
                summary["by_severity"]["HIGH"] = summary["by_severity"].get("HIGH", 0) + 1
                summary["total_threats"] += 1

        # High-risk RE reports
        for rep in re_reports:
            if rep.get("risk_score", 0) > 0.7:
                summary["by_severity"]["CRITICAL"] = summary["by_severity"].get("CRITICAL", 0) + 1
                summary["total_threats"] += 1
                summary["top_files"].append({
                    "path": rep.get("file_path"),
                    "risk_score": rep.get("risk_score"),
                    "notes": rep.get("analysis_notes", [])[:3]
                })

        # Generate recommendations
        if summary["by_severity"].get("CRITICAL", 0) > 0:
            summary["recommendations"].append(
                "CRITICAL threats detected. Immediate action recommended. Review approval queue."
            )
        if summary["by_severity"].get("HIGH", 0) > 0:
            summary["recommendations"].append(
                "HIGH severity findings present. Investigate suspicious processes and files."
            )
        if any(r.get("is_packed") for r in re_reports):
            summary["recommendations"].append(
                "Packed/encrypted binaries detected. Consider sandbox analysis for full behavior."
            )
        if not summary["recommendations"]:
            summary["recommendations"].append(
                "No critical threats detected. System appears clean based on current scan."
            )

        return summary

    def generate_mini_report(self, scan_id: str, content: dict) -> str:
        """Generate a quick summary report"""
        filename = f"kjagu_quick_{scan_id}.json"
        filepath = self.reports_dir / filename
        with open(filepath, 'w') as f:
            json.dump(content, f, indent=2)
        return str(filepath)
