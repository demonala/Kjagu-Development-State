"""
KJAGU Policy Manager
Handles user acceptance of kernel access policy before granting elevated permissions.
"""

import os
import json
from pathlib import Path
from datetime import datetime


class PolicyManager:
    """
    Manages the KJAGU Security Policy acceptance.
    User must explicitly accept before kernel-level access is granted.
    """

    POLICY_TEXT = """
═══════════════════════════════════════════════════════════════════════════════
                        KJAGU RID IT EDITION
                     SECURITY POLICY AGREEMENT
═══════════════════════════════════════════════════════════════════════════════

BEFORE GRANTING KERNEL-LEVEL ACCESS, YOU MUST UNDERSTAND:

1. ELEVATED PRIVILEGES
   KJAGU will access kernel-level system services, drivers, and protected
   memory regions. This requires Administrator/root privileges.

2. SYSTEM MODIFICATIONS
   KJAGU may:
   - Terminate running processes
   - Quarantine (suspend) suspicious processes
   - Delete or overwrite malicious files
   - Modify registry entries related to persistence
   - Access and analyze kernel memory structures

3. RISK ACKNOWLEDGMENT
   - False positives are possible. Legitimate software may be flagged.
   - YOU control all destructive actions via the approval system.
   - KJAGU will NEVER auto-destroy without your explicit approval.
   - Kernel access carries inherent system stability risks.

4. DATA HANDLING
   - All scan data is processed LOCALLY on your machine.
   - No data is sent to external servers (unless you use cloud AI).
   - Reports are saved to your Desktop in JSON format.

5. USER RESPONSIBILITY
   - You are responsible for reviewing AI recommendations before approval.
   - KJAGU is a defensive tool. Misuse is your responsibility.
   - Always back up critical data before running security scans.

BY ACCEPTING, YOU ACKNOWLEDGE:
   ✓ You understand the risks of kernel-level access
   ✓ You will review all actions before approving destructive operations
   ✓ You accept full responsibility for system changes made by KJAGU

═══════════════════════════════════════════════════════════════════════════════
"""

    def __init__(self):
        self.policy_file = Path.home() / ".kjagu" / "policy_accepted.json"
        self.policy_file.parent.mkdir(exist_ok=True)
        self._accepted = False
        self._load_status()

    def _load_status(self):
        """Load previous acceptance status"""
        if self.policy_file.exists():
            try:
                with open(self.policy_file, 'r') as f:
                    data = json.load(f)
                self._accepted = data.get("accepted", False)
            except:
                self._accepted = False

    def is_accepted(self) -> bool:
        """Check if policy has been accepted"""
        return self._accepted

    def get_policy_text(self) -> str:
        """Return the full policy text"""
        return self.POLICY_TEXT

    def accept_policy(self):
        """Record policy acceptance"""
        self._accepted = True
        record = {
            "accepted": True,
            "timestamp": datetime.now().isoformat(),
            "user": os.getlogin() if hasattr(os, 'getlogin') else "unknown",
            "machine": os.environ.get('COMPUTERNAME', 'unknown'),
            "version": "4.0-ridit"
        }
        with open(self.policy_file, 'w') as f:
            json.dump(record, f, indent=2)

    def require_acceptance(self) -> dict:
        """Return status requiring acceptance"""
        return {
            "requires_acceptance": True,
            "policy_text": self.POLICY_TEXT,
            "accepted": self._accepted,
            "message": "Kernel access requires policy acceptance. Please review and accept the security policy."
        }
