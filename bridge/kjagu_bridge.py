#!/usr/bin/env python3
"""
KJAGU RID IT EDITION - Native Messaging Bridge
Handles Chrome Extension <-> Python Scanner communication
Protocol: 32-bit length-prefixed JSON over stdin/stdout
"""

import sys
import os
import struct
import json
import threading
import time
import traceback
from pathlib import Path

# Add scanner to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scanner'))

from kjagu_engine import KjaguEngine


class NativeMessagingBridge:
    """Chrome Native Messaging protocol handler"""

    def __init__(self):
        self.engine = KjaguEngine(self)
        self.running = True
        self.message_id = 0

    def read_message(self):
        """Read a message from Chrome (stdin)"""
        raw_length = sys.stdin.buffer.read(4)
        if not raw_length:
            return None
        length = struct.unpack('=I', raw_length)[0]
        if length > 10_000_000:  # Sanity check
            return None
        message = sys.stdin.buffer.read(length).decode('utf-8')
        return json.loads(message)

    def send_message(self, msg):
        """Send a message to Chrome (stdout)"""
        encoded = json.dumps(msg).encode('utf-8')
        sys.stdout.buffer.write(struct.pack('=I', len(encoded)))
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()

    def run(self):
        """Main loop"""
        self.send_message({
            "type": "bridge_ready",
            "version": "4.0-ridit",
            "timestamp": time.time()
        })

        while self.running:
            try:
                msg = self.read_message()
                if msg is None:
                    break

                self.handle_message(msg)

            except Exception as e:
                self.send_message({
                    "type": "error",
                    "error": str(e),
                    "traceback": traceback.format_exc()
                })

    def handle_message(self, msg):
        """Route messages to appropriate handler"""
        cmd = msg.get("command", "")
        req_id = msg.get("id", "")

        if cmd == "ping":
            self.send_message({"type": "pong", "id": req_id})

        elif cmd == "start_scan":
            scan_type = msg.get("scan_type", "full")
            threading.Thread(
                target=self.engine.start_scan,
                args=(scan_type, req_id),
                daemon=True
            ).start()
            self.send_message({
                "type": "scan_started",
                "id": req_id,
                "scan_type": scan_type
            })

        elif cmd == "get_status":
            status = self.engine.get_status()
            self.send_message({"type": "status", "id": req_id, **status})

        elif cmd == "approve_action":
            action_id = msg.get("action_id")
            approved = msg.get("approved", False)
            self.engine.approve_action(action_id, approved)
            self.send_message({
                "type": "action_response",
                "id": req_id,
                "action_id": action_id,
                "approved": approved
            })

        elif cmd == "accept_policy":
            self.engine.policy_manager.accept_policy()
            self.send_message({
                "type": "policy_accepted",
                "id": req_id
            })

        elif cmd == "reverse_engineer":
            file_path = msg.get("file_path", "")
            threading.Thread(
                target=self.engine.reverse_engineer_file,
                args=(file_path, req_id),
                daemon=True
            ).start()
            self.send_message({
                "type": "re_started",
                "id": req_id,
                "file_path": file_path
            })

        elif cmd == "encrypt_cookies":
            result = self.engine.encrypt_cookies()
            self.send_message({
                "type": "cookies_encrypted",
                "id": req_id,
                "result": result
            })

        else:
            self.send_message({
                "type": "error",
                "id": req_id,
                "error": f"Unknown command: {cmd}"
            })

    def emit_event(self, event_type, data):
        """Send async event to extension"""
        self.send_message({
            "type": "event",
            "event": event_type,
            "data": data,
            "timestamp": time.time()
        })


def main():
    bridge = NativeMessagingBridge()
    bridge.run()


if __name__ == "__main__":
    main()
