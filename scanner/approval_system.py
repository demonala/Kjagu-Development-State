"""
KJAGU Approval System
Claude Code-style approval flow for all destructive actions.
No action executes without explicit user confirmation.
"""

import time
import threading
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Callable
from enum import Enum
import json


class ActionStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    EXECUTED = "executed"
    FAILED = "failed"


class ActionType(Enum):
    TERMINATE_PROCESS = "terminate_process"
    QUARANTINE_PROCESS = "quarantine_process"
    DELETE_FILE = "delete_file"
    DELETE_REGISTRY = "delete_registry"
    UNLOAD_DRIVER = "unload_driver"
    KERNEL_SCAN = "kernel_scan"
    ENCRYPT_COOKIES = "encrypt_cookies"


@dataclass
class PendingAction:
    action_id: str
    action_type: ActionType
    target: str
    target_pid: int
    description: str
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    evidence_summary: str
    ai_recommendation: str
    ai_confidence: float
    status: ActionStatus = ActionStatus.PENDING
    created_at: float = 0.0
    responded_at: Optional[float] = None
    result: Optional[str] = None

    def __post_init__(self):
        if self.created_at == 0.0:
            self.created_at = time.time()

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type.value,
            "target": self.target,
            "target_pid": self.target_pid,
            "description": self.description,
            "risk_level": self.risk_level,
            "evidence_summary": self.evidence_summary,
            "ai_recommendation": self.ai_recommendation,
            "ai_confidence": self.ai_confidence,
            "status": self.status.value,
            "created_at": self.created_at,
            "responded_at": self.responded_at,
            "result": self.result
        }


class ApprovalSystem:
    """
    Central approval queue for all destructive actions.
    Like Claude Code's tool approval — every dangerous action waits for user.
    """

    ACTION_TIMEOUT = 300  # 5 minutes to respond

    def __init__(self, bridge=None):
        self.bridge = bridge
        self.pending: Dict[str, PendingAction] = {}
        self.history: List[PendingAction] = []
        self._callbacks: Dict[str, Callable] = {}
        self._lock = threading.Lock()
        self._counter = 0

        # Start cleanup thread
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

    def _cleanup_loop(self):
        """Expire old pending actions"""
        while True:
            time.sleep(30)
            now = time.time()
            with self._lock:
                expired = [
                    aid for aid, action in self.pending.items()
                    if now - action.created_at > self.ACTION_TIMEOUT
                ]
                for aid in expired:
                    self.pending[aid].status = ActionStatus.EXPIRED
                    self.history.append(self.pending.pop(aid))
                    self._notify_expired(aid)

    def _notify_expired(self, action_id: str):
        """Notify extension that action expired"""
        if self.bridge:
            self.bridge.emit_event("action_expired", {
                "action_id": action_id,
                "message": "Action expired without user response. No changes were made."
            })

    def request_approval(self, action_type: ActionType, target: str, target_pid: int,
                         description: str, risk_level: str, evidence_summary: str,
                         ai_recommendation: str, ai_confidence: float,
                         callback: Optional[Callable] = None) -> str:
        """
        Queue a destructive action for user approval.
        Returns action_id. Action will NOT execute until approved.
        """
        with self._lock:
            self._counter += 1
            action_id = f"ACT_{int(time.time())}_{self._counter}"

            action = PendingAction(
                action_id=action_id,
                action_type=action_type,
                target=target,
                target_pid=target_pid,
                description=description,
                risk_level=risk_level,
                evidence_summary=evidence_summary,
                ai_recommendation=ai_recommendation,
                ai_confidence=ai_confidence
            )

            self.pending[action_id] = action
            if callback:
                self._callbacks[action_id] = callback

        # Notify extension to show approval UI
        if self.bridge:
            self.bridge.emit_event("approval_required", action.to_dict())

        return action_id

    def approve_action(self, action_id: str, approved: bool) -> dict:
        """User responds to approval request"""
        with self._lock:
            if action_id not in self.pending:
                return {"error": "Action not found or already processed"}

            action = self.pending[action_id]
            action.responded_at = time.time()

            if approved:
                action.status = ActionStatus.APPROVED
                # Execute the callback
                callback = self._callbacks.pop(action_id, None)
                if callback:
                    try:
                        result = callback(action)
                        action.result = str(result)
                        action.status = ActionStatus.EXECUTED
                    except Exception as e:
                        action.result = f"ERROR: {e}"
                        action.status = ActionStatus.FAILED
            else:
                action.status = ActionStatus.DENIED
                action.result = "User denied action"
                self._callbacks.pop(action_id, None)

            self.history.append(action)
            del self.pending[action_id]

        # Notify extension of result
        if self.bridge:
            self.bridge.emit_event("action_resolved", action.to_dict())

        return action.to_dict()

    def get_pending(self) -> List[dict]:
        """Get all pending actions"""
        with self._lock:
            return [a.to_dict() for a in self.pending.values()]

    def get_history(self) -> List[dict]:
        """Get all resolved actions"""
        with self._lock:
            return [a.to_dict() for a in self.history]
