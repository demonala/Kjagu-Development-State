#!/usr/bin/env python3
"""
KJAGU VIRUS ATTACKER v3.0 — AGENTIC AI EDITION
Deep Anti-Spyware Engine with LLM-Powered Agentic Intelligence
Research-inspired architecture from:
  - mrphrazer/agentic-malware-analysis (multi-phase orchestration)
  - LAMPS multi-agent system (specialized agent roles)
  - SentinelOne adversarial consensus (cross-validation)
  - AiSOC/Vigil SOC (LangGraph autonomous investigation)

Boss drops an API key → Kjagu becomes an autonomous threat hunter.
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
import sqlite3
import glob
import traceback
import textwrap
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Tuple, Set, Callable, Any, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum
import threading
import logging
import urllib.request
import urllib.error

# Crypto
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Windows-specific
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
else:
    import psutil

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [KJAGU-AI] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('KJAGU-AI')


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION & API KEY MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

class AIProvider(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    DEEPSEEK = "deepseek"
    CUSTOM = "custom"


@dataclass
class KjaguConfig:
    """Kjagu configuration — API keys, preferences, tuning"""
    ai_provider: AIProvider = AIProvider.OLLAMA
    api_key: str = ""
    api_base: str = ""  # For custom/Ollama endpoints
    model: str = "qwen2.5:14b"  # Default local model
    temperature: float = 0.1  # Low temp for security analysis
    max_tokens: int = 4096
    enable_aggressive_mode: bool = False  # If True, AI can auto-kill without confirmation
    user_context: str = ""  # "gamer", "developer", "trader", etc. — reduces false positives
    evidence_limit: int = 50  # Max evidence items per analysis batch
    consensus_threshold: float = 0.75  # Heuristic + AI must agree above this

    @classmethod
    def load(cls) -> 'KjaguConfig':
        """Load from ~/.kjagu/config.json or env vars"""
        config_path = Path.home() / ".kjagu" / "config.json"
        config = cls()

        # Environment variables take precedence
        if os.environ.get("KJAGU_OPENAI_KEY"):
            config.ai_provider = AIProvider.OPENAI
            config.api_key = os.environ["KJAGU_OPENAI_KEY"]
            config.model = os.environ.get("KJAGU_MODEL", "gpt-4o-mini")
            config.api_base = "https://api.openai.com/v1"
        elif os.environ.get("KJAGU_ANTHROPIC_KEY"):
            config.ai_provider = AIProvider.ANTHROPIC
            config.api_key = os.environ["KJAGU_ANTHROPIC_KEY"]
            config.model = os.environ.get("KJAGU_MODEL", "claude-3-haiku-20240307")
            config.api_base = "https://api.anthropic.com"
        elif os.environ.get("KJAGU_DEEPSEEK_KEY"):
            config.ai_provider = AIProvider.DEEPSEEK
            config.api_key = os.environ["KJAGU_DEEPSEEK_KEY"]
            config.model = os.environ.get("KJAGU_MODEL", "deepseek-chat")
            config.api_base = "https://api.deepseek.com/v1"
        elif os.environ.get("KJAGU_OLLAMA_URL"):
            config.ai_provider = AIProvider.OLLAMA
            config.api_key = "ollama"  # Not used but required
            config.model = os.environ.get("KJAGU_MODEL", "qwen2.5:14b")
            config.api_base = os.environ["KJAGU_OLLAMA_URL"]

        # Load from file if exists
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    data = json.load(f)
                for k, v in data.items():
                    if hasattr(config, k):
                        setattr(config, k, v)
                if isinstance(config.ai_provider, str):
                    config.ai_provider = AIProvider(config.ai_provider)
            except Exception as e:
                logger.warning(f"[CONFIG] Failed to load config: {e}")

        return config

    def save(self):
        """Save to ~/.kjagu/config.json"""
        config_path = Path.home() / ".kjagu"
        config_path.mkdir(exist_ok=True)
        data = asdict(self)
        data['ai_provider'] = self.ai_provider.value
        with open(config_path / "config.json", 'w') as f:
            json.dump(data, f, indent=2)


# ═══════════════════════════════════════════════════════════════════════════════
# EVIDENCE & THREAT DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Evidence:
    """A single piece of evidence collected by ReconAgent"""
    evidence_id: str
    category: str  # process, memory, network, registry, file, kernel, browser
    source: str    # e.g., "psutil", "win32api", "registry"
    data: Dict[str, Any]
    raw_value: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    hash: str = ""  # SHA256 of raw evidence for deduplication

    def __post_init__(self):
        if not self.hash:
            self.hash = hashlib.sha256(
                json.dumps(self.data, sort_keys=True).encode()
            ).hexdigest()[:16]


@dataclass
class Hypothesis:
    """AI-generated hypothesis about a potential threat"""
    hypothesis_id: str
    description: str
    confidence: float  # 0.0 - 1.0
    evidence_refs: List[str]  # Evidence IDs that support this
    mitre_technique: str = ""  # e.g., "T1055" for Process Injection
    recommended_action: str = "INVESTIGATE"
    rationale: str = ""


@dataclass
class ThreatReport:
    """Final threat verdict"""
    threat_id: str
    threat_type: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    target_name: str
    target_pid: int
    target_path: str
    description: str
    heuristic_score: float  # 0.0 - 1.0 from traditional scanning
    ai_score: float  # 0.0 - 1.0 from LLM analysis
    consensus_score: float  # Combined score
    evidence: List[Evidence]
    hypotheses: List[Hypothesis]
    recommended_action: str
    action_taken: str = "PENDING"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# ═══════════════════════════════════════════════════════════════════════════════
# LLM CLIENT — Multi-Provider Support
# ═══════════════════════════════════════════════════════════════════════════════

class LLMClient:
    """Unified LLM client supporting OpenAI, Anthropic, DeepSeek, Ollama"""

    def __init__(self, config: KjaguConfig):
        self.config = config
        self._validate_setup()

    def _validate_setup(self):
        if self.config.ai_provider == AIProvider.OLLAMA:
            # Test Ollama connection
            try:
                req = urllib.request.Request(
                    f"{self.config.api_base}/api/tags",
                    method='GET'
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    pass
                logger.info(f"[LLM] Ollama connected at {self.config.api_base}")
            except Exception as e:
                logger.warning(f"[LLM] Ollama not reachable: {e}")
        elif not self.config.api_key:
            logger.error("[LLM] No API key configured! Set KJAGU_OPENAI_KEY or similar.")

    def chat(self, system_prompt: str, user_prompt: str, 
             tools: Optional[List[Dict]] = None) -> Dict:
        """
        Send chat completion request.
        Returns dict with: content, tool_calls, usage, model
        """
        if self.config.ai_provider == AIProvider.OPENAI:
            return self._chat_openai(system_prompt, user_prompt, tools)
        elif self.config.ai_provider == AIProvider.ANTHROPIC:
            return self._chat_anthropic(system_prompt, user_prompt, tools)
        elif self.config.ai_provider == AIProvider.DEEPSEEK:
            return self._chat_openai(system_prompt, user_prompt, tools)  # OpenAI-compatible
        elif self.config.ai_provider == AIProvider.OLLAMA:
            return self._chat_ollama(system_prompt, user_prompt, tools)
        else:
            raise ValueError(f"Unknown provider: {self.config.ai_provider}")

    def _chat_openai(self, system: str, user: str, tools: Optional[List[Dict]]) -> Dict:
        import urllib.request

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user}
        ]

        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        req = urllib.request.Request(
            f"{self.config.api_base}/chat/completions",
            data=json.dumps(payload).encode(),
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json"
            },
            method='POST'
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read().decode())

            choice = result["choices"][0]
            msg = choice["message"]

            return {
                "content": msg.get("content", ""),
                "tool_calls": msg.get("tool_calls", []),
                "usage": result.get("usage", {}),
                "model": result.get("model", self.config.model),
                "finish_reason": choice.get("finish_reason", "")
            }
        except Exception as e:
            logger.error(f"[LLM-OpenAI] Request failed: {e}")
            return {"content": f"ERROR: {e}", "tool_calls": [], "usage": {}}

    def _chat_anthropic(self, system: str, user: str, tools: Optional[List[Dict]]) -> Dict:
        import urllib.request

        payload = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "system": system,
            "messages": [{"role": "user", "content": user}]
        }
        if tools:
            payload["tools"] = tools

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(payload).encode(),
            headers={
                "x-api-key": self.config.api_key,
                "Content-Type": "application/json",
                "anthropic-version": "2023-06-01"
            },
            method='POST'
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read().decode())

            content = result.get("content", [])
            text = ""
            tool_calls = []

            for block in content:
                if block.get("type") == "text":
                    text += block.get("text", "")
                elif block.get("type") == "tool_use":
                    tool_calls.append({
                        "id": block.get("id"),
                        "function": {
                            "name": block.get("name"),
                            "arguments": json.dumps(block.get("input", {}))
                        }
                    })

            return {
                "content": text,
                "tool_calls": tool_calls,
                "usage": result.get("usage", {}),
                "model": result.get("model", self.config.model),
                "finish_reason": result.get("stop_reason", "")
            }
        except Exception as e:
            logger.error(f"[LLM-Anthropic] Request failed: {e}")
            return {"content": f"ERROR: {e}", "tool_calls": [], "usage": {}}

    def _chat_ollama(self, system: str, user: str, tools: Optional[List[Dict]]) -> Dict:
        import urllib.request

        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            "stream": False,
            "options": {"temperature": self.config.temperature}
        }

        req = urllib.request.Request(
            f"{self.config.api_base}/api/chat",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method='POST'
        )

        try:
            with urllib.request.urlopen(req, timeout=180) as resp:
                result = json.loads(resp.read().decode())

            msg = result.get("message", {})
            return {
                "content": msg.get("content", ""),
                "tool_calls": [],  # Ollama tool calling varies by version
                "usage": {"prompt_tokens": 0, "completion_tokens": 0},  # Not always provided
                "model": result.get("model", self.config.model),
                "finish_reason": "stop"
            }
        except Exception as e:
            logger.error(f"[LLM-Ollama] Request failed: {e}")
            return {"content": f"ERROR: {e}", "tool_calls": [], "usage": {}}


# ═══════════════════════════════════════════════════════════════════════════════
# AGENTIC AI ENGINE — The Brain of Kjagu
# ═══════════════════════════════════════════════════════════════════════════════

class ReconAgent:
    """
    Phase 1: Evidence Collection
    Collects raw system data — processes, memory, network, registry, files
    Inspired by: agentic-malware-analysis evidence collection pipeline
    """

    def __init__(self):
        self.evidence: List[Evidence] = []
        self._lock = threading.Lock()

    def collect_all(self) -> List[Evidence]:
        """Run full evidence collection across all categories"""
        logger.info("[RECON] Starting evidence collection...")
        self.evidence = []

        collectors = [
            ("processes", self._collect_processes),
            ("network", self._collect_network),
            ("memory_regions", self._collect_memory_regions),
            ("registry_persistence", self._collect_registry),
            ("browser_extensions", self._collect_browser_extensions),
            ("startup_items", self._collect_startup_items),
            ("services", self._collect_services),
            ("loaded_dlls", self._collect_loaded_dlls),
        ]

        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = {executor.submit(fn): name for name, fn in collectors}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    future.result()
                    logger.info(f"[RECON] {name} collected: {len([e for e in self.evidence if e.category == name])} items")
                except Exception as e:
                    logger.error(f"[RECON] {name} failed: {e}")

        logger.info(f"[RECON] Total evidence collected: {len(self.evidence)}")
        return self.evidence

    def _add_evidence(self, category: str, source: str, data: Dict, raw: str = ""):
        with self._lock:
            ev = Evidence(
                evidence_id=f"{category}_{len(self.evidence):04d}",
                category=category,
                source=source,
                data=data,
                raw_value=raw
            )
            self.evidence.append(ev)

    def _collect_processes(self):
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cpu_percent', 
                                          'memory_percent', 'connections', 'ppid', 'create_time']):
            try:
                info = proc.info
                pid = info['pid']
                if pid < 10:
                    continue

                # Get parent info
                parent_name = ""
                try:
                    parent = proc.parent()
                    if parent:
                        parent_name = parent.name()
                except:
                    pass

                # Check if process has suspicious characteristics
                cmdline = " ".join(info['cmdline'] or [])

                self._add_evidence("processes", "psutil", {
                    "pid": pid,
                    "name": info['name'],
                    "exe": info['exe'] or "",
                    "cmdline": cmdline[:500],
                    "ppid": info['ppid'],
                    "parent_name": parent_name,
                    "cpu_percent": info['cpu_percent'],
                    "memory_percent": info['memory_percent'],
                    "create_time": info['create_time'],
                    "num_threads": proc.num_threads(),
                    "num_connections": len(info['connections'] or []),
                    "username": proc.username() if hasattr(proc, 'username') else "",
                }, raw=cmdline)

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

                    self._add_evidence("network", "psutil", {
                        "pid": conn.pid,
                        "process_name": proc_name,
                        "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}",
                        "status": conn.status,
                        "family": str(conn.family),
                    })
        except Exception as e:
            logger.warning(f"[RECON] Network collection error: {e}")

    def _collect_memory_regions(self):
        """Collect suspicious memory regions per process"""
        if sys.platform != 'win32':
            return

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                if pid < 100:
                    continue

                # Use Windows API to check memory
                try:
                    handle = win32api.OpenProcess(
                        win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                        False, pid
                    )

                    # Quick check: count RWX regions
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
                        self._add_evidence("memory_regions", "win32api", {
                            "pid": pid,
                            "process_name": name,
                            "rwx_region_count": rwx_count,
                            "note": "Process has executable+writable memory regions"
                        })

                except Exception:
                    pass

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _collect_registry(self):
        if sys.platform != 'win32':
            return

        keys_to_check = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]

        for hkey, path in keys_to_check:
            try:
                with winreg.OpenKey(hkey, path, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            i += 1
                            self._add_evidence("registry_persistence", "winreg", {
                                "hive": "HKCU" if hkey == winreg.HKEY_CURRENT_USER else "HKLM",
                                "path": path,
                                "entry_name": name,
                                "value": str(value)[:300],
                            })
                        except OSError:
                            break
            except Exception:
                pass

    def _collect_browser_extensions(self):
        """Collect browser extension manifests"""
        ext_paths = []
        if sys.platform == 'win32':
            ext_paths = [
                Path.home() / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "Extensions",
                Path.home() / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data" / "Default" / "Extensions",
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
                            self._add_evidence("browser_extensions", "filesystem", {
                                "browser": "chrome" if "Chrome" in str(ext_dir) else "edge",
                                "extension_id": ext_id.name,
                                "name": data.get("name", "unknown"),
                                "permissions": data.get("permissions", []),
                                "host_permissions": data.get("host_permissions", []),
                                "content_scripts_count": len(data.get("content_scripts", [])),
                                "background_script": bool(data.get("background")),
                            })
                        except:
                            pass

    def _collect_startup_items(self):
        if sys.platform == 'win32':
            startup_paths = [
                Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
                Path("C:/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp"),
            ]
            for path in startup_paths:
                if path.exists():
                    for item in path.iterdir():
                        self._add_evidence("startup_items", "filesystem", {
                            "path": str(item),
                            "name": item.name,
                            "type": "file" if item.is_file() else "dir",
                        })

    def _collect_services(self):
        if sys.platform == 'win32':
            try:
                result = subprocess.run(['sc', 'query', 'type=', 'service', 'state=', 'all'], 
                                       capture_output=True, text=True, timeout=30)
                for line in result.stdout.split('\n'):
                    if 'SERVICE_NAME:' in line:
                        name = line.split(':')[1].strip()
                        self._add_evidence("services", "sc", {
                            "service_name": name,
                        })
            except:
                pass

    def _collect_loaded_dlls(self):
        """Collect DLLs loaded into browser processes"""
        browser_names = ['chrome.exe', 'firefox.exe', 'msedge.exe', 'brave.exe']
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'].lower() not in browser_names:
                    continue

                for dll in proc.memory_maps():
                    dll_path = dll.path.lower()
                    # Only collect non-system DLLs
                    if any(x in dll_path for x in ['\windows\', '\program files\']):
                        continue
                    if dll_path.endswith('.dll') or dll_path.endswith('.exe'):
                        self._add_evidence("loaded_dlls", "psutil", {
                            "pid": proc.info['pid'],
                            "process_name": proc.info['name'],
                            "dll_path": dll.path,
                            "rss": dll.rss,
                        })
            except:
                pass


class AnalyzerAgent:
    """
    Phase 2: AI-Powered Analysis
    Sends evidence to LLM for intelligent threat analysis
    Inspired by: LAMPS Classifier Agent + SentinelOne adversarial consensus
    """

    # System prompt for the AI security analyst
    SYSTEM_PROMPT = """You are Kjagu-AI, an elite cybersecurity threat analyst. Your job is to analyze system evidence and identify spyware, information stealers, keyloggers, and other malicious software.

You operate with surgical precision. For each piece of evidence, you must:
1. Evaluate if it exhibits malicious behavior patterns
2. Assign a confidence score (0.0-1.0)
3. Cite specific MITRE ATT&CK techniques if applicable
4. Recommend an action: INVESTIGATE, QUARANTINE, TERMINATE, or IGNORE

CONTEXT about the user: {user_context}

RULES:
- Be paranoid but accurate. False positives waste time.
- Look for: injection patterns, persistence mechanisms, data exfiltration, credential theft, keylogging, screen capture, browser hijacking
- Consider the user's context. A game overlay DLL in a gaming system is likely benign. The same DLL on a trading workstation is suspicious.
- Output STRICT JSON only. No markdown, no explanations outside JSON.

OUTPUT FORMAT:
{
  "findings": [
    {
      "evidence_ids": ["id1", "id2"],
      "threat_type": "KEYLOGGER|INFOSTEALER|ROOTKIT|ADWARE|MINER|RANSOMWARE|BENIGN",
      "confidence": 0.95,
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "mitre_technique": "T1055",
      "description": "Detailed explanation",
      "recommended_action": "TERMINATE|QUARANTINE|INVESTIGATE|IGNORE",
      "rationale": "Why this decision was made"
    }
  ],
  "summary": "Brief overall assessment"
}"""

    def __init__(self, llm: LLMClient, config: KjaguConfig):
        self.llm = llm
        self.config = config

    def analyze_evidence_batch(self, evidence_batch: List[Evidence]) -> List[Hypothesis]:
        """Analyze a batch of evidence using the LLM"""
        if not evidence_batch:
            return []

        # Format evidence for the LLM
        evidence_json = []
        for ev in evidence_batch:
            evidence_json.append({
                "id": ev.evidence_id,
                "category": ev.category,
                "data": ev.data
            })

        user_prompt = f"""Analyze the following system evidence and identify threats.

EVIDENCE BATCH ({len(evidence_batch)} items):
```json
{json.dumps(evidence_json, indent=2)[:8000]}
```

Provide your analysis in the required JSON format."""

        system = self.SYSTEM_PROMPT.format(user_context=self.config.user_context or "General user")

        response = self.llm.chat(system, user_prompt)
        content = response.get("content", "")

        # Extract JSON from response
        hypotheses = self._parse_analysis_response(content)

        logger.info(f"[ANALYZER] AI generated {len(hypotheses)} hypotheses for batch of {len(evidence_batch)}")
        return hypotheses

    def _parse_analysis_response(self, content: str) -> List[Hypothesis]:
        """Parse LLM JSON response into Hypothesis objects"""
        hypotheses = []

        try:
            # Try to find JSON in the response
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
            else:
                data = json.loads(content)

            for i, finding in enumerate(data.get("findings", [])):
                hyp = Hypothesis(
                    hypothesis_id=f"hyp_{int(time.time())}_{i}",
                    description=finding.get("description", ""),
                    confidence=finding.get("confidence", 0.5),
                    evidence_refs=finding.get("evidence_ids", []),
                    mitre_technique=finding.get("mitre_technique", ""),
                    recommended_action=finding.get("recommended_action", "INVESTIGATE"),
                    rationale=finding.get("rationale", "")
                )
                hypotheses.append(hyp)

        except json.JSONDecodeError as e:
            logger.error(f"[ANALYZER] Failed to parse AI response: {e}")
            logger.debug(f"[ANALYZER] Raw response: {content[:500]}")

        return hypotheses

    def deep_dive_process(self, pid: int, process_name: str, 
                          evidence_pool: List[Evidence]) -> Optional[Hypothesis]:
        """Request AI to perform deep analysis on a specific process"""
        # Gather all evidence related to this process
        related = [e for e in evidence_pool 
                   if e.data.get("pid") == pid or e.data.get("process_name") == process_name]

        if len(related) < 2:
            return None

        user_prompt = f"""Perform DEEP ANALYSIS on process {process_name} (PID {pid}).

This process has been flagged by initial scanning. Analyze all related evidence:

```json
{json.dumps([{"id": e.evidence_id, "cat": e.category, "data": e.data} for e in related], indent=2)[:6000]}
```

Is this process malicious? Provide detailed reasoning and confidence.
Output strict JSON with: threat_type, confidence (0-1), severity, mitre_technique, description, recommended_action, rationale."""

        system = self.SYSTEM_PROMPT.format(user_context=self.config.user_context or "General user")
        response = self.llm.chat(system, user_prompt)

        hypotheses = self._parse_analysis_response(response.get("content", ""))
        return hypotheses[0] if hypotheses else None


class VerifierAgent:
    """
    Phase 3: Cross-Validation & Consensus
    Reduces false positives by verifying AI findings against heuristics and known-good lists
    Inspired by: SentinelOne adversarial consensus engine
    """

    # Known-good patterns that frequently trigger false positives
    KNOWN_GOOD_SIGNATURES = [
        (r"nvidia.*overlay", "gaming", 0.9),
        (r"discord.*overlay", "gaming", 0.9),
        (r"steam.*overlay", "gaming", 0.9),
        (r"epicgames.*overlay", "gaming", 0.9),
        (r"msedge.*\browser_broker", "browser", 0.85),
        (r"chrome.*\chrome_.*\chrome.exe", "browser", 0.9),
        (r"vscode", "development", 0.9),
        (r"python.*\python.exe", "development", 0.8),
        (r"node.*\node.exe", "development", 0.8),
        (r"docker", "development", 0.85),
        (r"wsl", "development", 0.85),
        (r"spotify", "media", 0.9),
        (r"obs.*\obs", "streaming", 0.85),
        (r"1password", "security", 0.9),
        (r"bitwarden", "security", 0.9),
        (r"lastpass", "security", 0.9),
    ]

    def __init__(self, config: KjaguConfig):
        self.config = config

    def verify_hypothesis(self, hypothesis: Hypothesis, 
                         evidence_map: Dict[str, Evidence]) -> Tuple[bool, float, str]:
        """
        Verify an AI hypothesis. Returns: (is_valid, adjusted_confidence, reason)
        """
        # Gather evidence for this hypothesis
        related_evidence = []
        for ev_id in hypothesis.evidence_refs:
            if ev_id in evidence_map:
                related_evidence.append(evidence_map[ev_id])

        # Check 1: Known-good whitelist
        for ev in related_evidence:
            path = ev.data.get("exe", "") + ev.data.get("dll_path", "") + ev.data.get("path", "")
            name = ev.data.get("name", "") + ev.data.get("process_name", "")

            for pattern, category, confidence_boost in self.KNOWN_GOOD_SIGNATURES:
                if re.search(pattern, path, re.IGNORECASE) or re.search(pattern, name, re.IGNORECASE):
                    # Check if user context matches
                    if self.config.user_context and category in self.config.user_context.lower():
                        return False, 0.1, f"Known-good {category} software: {pattern}"
                    # Even without context, reduce confidence
                    hypothesis.confidence *= 0.3

        # Check 2: Heuristic validation
        heuristic_score = self._compute_heuristic_score(related_evidence)

        # Check 3: Confidence floor
        if hypothesis.confidence < 0.3:
            return False, hypothesis.confidence, "AI confidence below threshold"

        # Check 4: Consensus — AI and heuristics must somewhat agree
        consensus = (hypothesis.confidence + heuristic_score) / 2
        if consensus < self.config.consensus_threshold:
            return False, consensus, f"Consensus score {consensus:.2f} below threshold {self.config.consensus_threshold}"

        return True, consensus, "Verified by heuristic consensus"

    def _compute_heuristic_score(self, evidence_list: List[Evidence]) -> float:
        """Compute traditional heuristic threat score from evidence"""
        score = 0.0
        weights = {
            "rwx_region_count": 0.3,
            "suspicious_permissions": 0.25,
            "hidden_file": 0.2,
            "orphan_process": 0.25,
            "unknown_publisher": 0.15,
            "network_to_rare_port": 0.2,
        }

        for ev in evidence_list:
            data = ev.data

            if data.get("rwx_region_count", 0) > 0:
                score += weights["rwx_region_count"] * min(data["rwx_region_count"] / 3, 1.0)

            if ev.category == "browser_extensions":
                perms = data.get("permissions", [])
                suspicious = ['cookies', 'webRequest', 'webRequestBlocking', 'tabs', 
                             'history', 'downloads', 'clipboardRead', 'nativeMessaging']
                count = sum(1 for p in perms if p in suspicious)
                if count >= 3:
                    score += weights["suspicious_permissions"]

            if data.get("orphan_process"):
                score += weights["orphan_process"]

        return min(score, 1.0)


class VerdictAgent:
    """
    Phase 4: Final Verdict & Action Recommendation
    Aggregates all verified hypotheses into final threat reports
    Inspired by: LAMPS Verdict Agent
    """

    def __init__(self, config: KjaguConfig):
        self.config = config

    def render_verdicts(self, hypotheses: List[Hypothesis], 
                       evidence_pool: List[Evidence],
                       evidence_map: Dict[str, Evidence]) -> List[ThreatReport]:
        """Convert verified hypotheses into final threat reports"""
        reports = []
        verifier = VerifierAgent(self.config)

        # Group hypotheses by target process
        by_target: Dict[Tuple[str, int], List[Hypothesis]] = {}
        for hyp in hypotheses:
            # Find target from evidence refs
            target_name = "unknown"
            target_pid = 0
            target_path = ""

            for ev_id in hyp.evidence_refs:
                if ev_id in evidence_map:
                    ev = evidence_map[ev_id]
                    target_name = ev.data.get("process_name", ev.data.get("name", "unknown"))
                    target_pid = ev.data.get("pid", 0)
                    target_path = ev.data.get("exe", ev.data.get("path", ""))
                    break

            key = (target_name, target_pid)
            by_target.setdefault(key, []).append(hyp)

        # Generate report per target
        for (name, pid), hyps in by_target.items():
            # Verify each hypothesis
            valid_hyps = []
            for hyp in hyps:
                is_valid, consensus, reason = verifier.verify_hypothesis(hyp, evidence_map)
                if is_valid:
                    hyp.confidence = consensus  # Update with consensus score
                    valid_hyps.append(hyp)

            if not valid_hyps:
                continue

            # Aggregate
            max_conf = max(h.confidence for h in valid_hyps)
            avg_conf = sum(h.confidence for h in valid_hyps) / len(valid_hyps)

            # Determine severity
            if max_conf >= 0.9:
                severity = "CRITICAL"
            elif max_conf >= 0.75:
                severity = "HIGH"
            elif max_conf >= 0.5:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            # Collect all evidence
            all_ev_ids = set()
            for h in valid_hyps:
                all_ev_ids.update(h.evidence_refs)
            all_evidence = [evidence_map[eid] for eid in all_ev_ids if eid in evidence_map]

            # Determine action
            actions = [h.recommended_action for h in valid_hyps]
            if "TERMINATE" in actions:
                action = "TERMINATE"
            elif "QUARANTINE" in actions:
                action = "QUARANTINE"
            else:
                action = "INVESTIGATE"

            # Build description
            descriptions = [f"- {h.description} (conf: {h.confidence:.0%})" for h in valid_hyps]

            report = ThreatReport(
                threat_id=f"THREAT_{int(time.time())}_{pid}",
                threat_type=valid_hyps[0].threat_type if hasattr(valid_hyps[0], 'threat_type') else "UNKNOWN",
                severity=severity,
                target_name=name,
                target_pid=pid,
                target_path=target_path,
                description="\n".join(descriptions),
                heuristic_score=avg_conf,  # Simplified
                ai_score=max_conf,
                consensus_score=avg_conf,
                evidence=all_evidence,
                hypotheses=valid_hyps,
                recommended_action=action
            )
            reports.append(report)

        # Sort by consensus score descending
        reports.sort(key=lambda r: r.consensus_score, reverse=True)
        return reports


class ActorAgent:
    """
    Phase 5: Action Execution
    Executes approved actions: terminate, quarantine, encrypt cookies
    """

    def __init__(self, config: KjaguConfig):
        self.config = config
        self.executed_actions: List[Dict] = []

    def execute(self, reports: List[ThreatReport], vault) -> Dict:
        """Execute actions on verified threats"""
        results = {
            "terminated": [],
            "quarantined": [],
            "investigated": [],
            "failed": [],
            "cookies_encrypted": []
        }

        for report in reports:
            if report.recommended_action == "TERMINATE":
                if self.config.enable_aggressive_mode:
                    success = self._terminate_process(report.target_pid, report.target_name)
                    if success:
                        report.action_taken = "TERMINATED"
                        results["terminated"].append(report.target_name)
                    else:
                        results["failed"].append(f"{report.target_name} (PID {report.target_pid})")
                else:
                    report.action_taken = "PENDING_APPROVAL"
                    results["investigated"].append(report.target_name)
                    logger.info(f"[ACTOR] TERMINATE pending approval for {report.target_name} (aggressive_mode=False)")

            elif report.recommended_action == "QUARANTINE":
                success = self._quarantine_process(report.target_pid, report.target_name)
                if success:
                    report.action_taken = "QUARANTINED"
                    results["quarantined"].append(report.target_name)
                else:
                    results["failed"].append(report.target_name)

        # Encrypt cookies
        cookie_results = vault.encrypt_all_cookies() if vault else {}
        results["cookies_encrypted"] = list(cookie_results.keys())

        return results

    def _terminate_process(self, pid: int, name: str) -> bool:
        """Force terminate a process"""
        if pid <= 0:
            return False
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
            logger.info(f"[ACTOR] Terminated {name} (PID {pid})")
            return True
        except Exception as e:
            logger.error(f"[ACTOR] Failed to terminate {name}: {e}")
            return False

    def _quarantine_process(self, pid: int, name: str) -> bool:
        """Suspend process instead of killing (safer)"""
        try:
            proc = psutil.Process(pid)
            proc.suspend()
            logger.info(f"[ACTOR] Suspended {name} (PID {pid}) — quarantine mode")
            return True
        except Exception as e:
            logger.error(f"[ACTOR] Failed to suspend {name}: {e}")
            return False


# ═══════════════════════════════════════════════════════════════════════════════
# COOKIE VAULT (unchanged core, enhanced)
# ═══════════════════════════════════════════════════════════════════════════════

class KjaguCryptoVault:
    """Maximum-level browser cookie encryption with hardware binding"""

    def __init__(self, master_password: Optional[str] = None):
        self.vault_dir = Path.home() / ".kjagu_vault"
        self.vault_dir.mkdir(exist_ok=True)
        self.key_file = self.vault_dir / "vault.key"
        self.meta_file = self.vault_dir / "vault.meta"
        self.hw_fingerprint = self._get_hw_fingerprint()
        self.master_password = master_password or self._derive_password()
        self._key = self._load_or_generate_key()

    def _get_hw_fingerprint(self) -> bytes:
        components = []
        if sys.platform == 'win32' and wmi:
            try:
                c = wmi.WMI()
                for processor in c.Win32_Processor():
                    components.append(processor.ProcessorId.strip())
                for bios in c.Win32_BIOS():
                    components.append(bios.SerialNumber.strip())
            except:
                pass
        components.append(str(Path.home().absolute()))
        components.append(os.getlogin() if hasattr(os, 'getlogin') else "user")
        return hashlib.sha256("|".join(components).encode()).digest()[:16]

    def _derive_password(self) -> str:
        if self.key_file.exists():
            return ""
        return base64.urlsafe_b64encode(os.urandom(32)).decode()

    def _load_or_generate_key(self) -> bytes:
        if self.key_file.exists():
            with open(self.key_file, 'rb') as f:
                encrypted_key = f.read()
            salt = self.hw_fingerprint
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, 
                           iterations=600000, backend=default_backend())
            key = base64.urlsafe_b64encode(kdf.derive(self.master_password.encode()))
            fernet = Fernet(key)
            return fernet.decrypt(encrypted_key)

        key = AESGCM.generate_key(bit_length=256)
        salt = self.hw_fingerprint
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                        iterations=600000, backend=default_backend())
        key_wrap = base64.urlsafe_b64encode(kdf.derive(self.master_password.encode()))
        fernet = Fernet(key_wrap)
        with open(self.key_file, 'wb') as f:
            f.write(fernet.encrypt(key))
        meta = {"created": datetime.now().isoformat(), "algorithm": "AES-256-GCM",
                "kdf": "PBKDF2-SHA256-600k", "hardware_bound": True, "version": "3.0"}
        with open(self.meta_file, 'w') as f:
            json.dump(meta, f, indent=2)
        return key

    def encrypt_cookies(self, browser_name: str, cookie_path: Path) -> Optional[Path]:
        if not cookie_path.exists():
            return None
        try:
            with open(cookie_path, 'rb') as f:
                plaintext = f.read()
        except PermissionError:
            logger.warning(f"[VAULT] Cannot read {cookie_path} — browser running?")
            return None

        nonce = os.urandom(12)
        aesgcm = AESGCM(self._key)
        associated_data = browser_name.encode() + self.hw_fingerprint
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        h = hmac.new(self._key, nonce + ciphertext + associated_data, hashlib.sha256)
        vault_data = nonce + ciphertext + h.digest()

        vault_path = self.vault_dir / f"{browser_name}_cookies.kvault"
        with open(vault_path, 'wb') as f:
            f.write(vault_data)
        self._secure_delete(cookie_path)
        logger.info(f"[VAULT] {browser_name} cookies encrypted → {vault_path}")
        return vault_path

    def encrypt_all_cookies(self) -> Dict[str, Path]:
        browsers = {
            "chrome": Path.home() / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "Cookies",
            "edge": Path.home() / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data" / "Default" / "Cookies",
            "brave": Path.home() / "AppData" / "Local" / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Cookies",
        }
        results = {}
        for name, path in browsers.items():
            result = self.encrypt_cookies(name, path)
            if result:
                results[name] = result
        # Firefox
        ff_path = Path.home() / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles"
        if ff_path.exists():
            for profile in ff_path.glob("*.default*"):
                cookie_db = profile / "cookies.sqlite"
                if cookie_db.exists():
                    result = self.encrypt_cookies(f"firefox_{profile.name}", cookie_db)
                    if result:
                        results[f"firefox_{profile.name}"] = result
        return results

    def _secure_delete(self, path: Path, passes: int = 7):
        if not path.exists():
            return
        size = path.stat().st_size
        with open(path, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(min(size, 1024*1024)))
                f.flush()
                os.fsync(f.fileno())
        temp_name = path.parent / os.urandom(16).hex()
        path.rename(temp_name)
        temp_name.unlink()


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN CONTROLLER
# ═══════════════════════════════════════════════════════════════════════════════

class KjaguMain:
    """Main controller orchestrating the agentic pipeline"""

    def __init__(self, config: Optional[KjaguConfig] = None):
        self.config = config or KjaguConfig.load()
        self.llm = LLMClient(self.config)
        self.vault = KjaguCryptoVault()

        # Agents
        self.recon = ReconAgent()
        self.analyzer = AnalyzerAgent(self.llm, self.config)
        self.verdict = VerdictAgent(self.config)
        self.actor = ActorAgent(self.config)

        # Results
        self.evidence: List[Evidence] = []
        self.hypotheses: List[Hypothesis] = []
        self.reports: List[ThreatReport] = []

    def run(self, deep_dive: bool = True) -> Dict:
        """Run full agentic pipeline"""
        print("""
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                                                                       ║
    ║   ██╗  ██╗     ██╗  █████╗  ██████╗ ██╗   ██╗     █████╗ ██╗         ║
    ║   ██║ ██╔╝     ██║ ██╔══██╗██╔════╝ ██║   ██║    ██╔══██╗██║         ║
    ║   █████╔╝      ██║ ███████║██║  ███╗██║   ██║    ███████║██║         ║
    ║   ██╔═██╗ ██   ██║ ██╔══██║██║   ██║██║   ██║    ██╔══██║██║         ║
    ║   ██║  ██╗╚█████╔╝ ██║  ██║╚██████╔╝╚██████╔╝    ██║  ██║███████╗    ║
    ║   ╚═╝  ╚═╝ ╚════╝  ╚═╝  ╚═╝ ╚═════╝  ╚═════╝     ╚═╝  ╚═╝╚══════╝    ║
    ║                                                                       ║
    ║     KJAGU v3.0 — AGENTIC AI ANTI-SPYWARE ENGINE                     ║
    ║     LLM: {model}                                                    ║
    ║                                                                       ║
    ╚═══════════════════════════════════════════════════════════════════════╝
        """.format(model=self.config.model))

        # Phase 1: Recon
        print("\n[*] PHASE 1: RECON — Collecting system evidence...")
        self.evidence = self.recon.collect_all()

        # Phase 2: Analysis (batched)
        print("\n[*] PHASE 2: ANALYZER — AI analyzing evidence...")
        self.hypotheses = []
        batch_size = self.config.evidence_limit

        for i in range(0, len(self.evidence), batch_size):
            batch = self.evidence[i:i+batch_size]
            hyps = self.analyzer.analyze_evidence_batch(batch)
            self.hypotheses.extend(hyps)
            print(f"    Batch {i//batch_size + 1}: {len(hyps)} hypotheses")

        # Deep dive on high-confidence targets
        if deep_dive:
            print("\n[*] PHASE 2b: DEEP DIVE — AI investigating high-confidence targets...")
            high_conf = [h for h in self.hypotheses if h.confidence >= 0.7]
            evidence_map = {e.evidence_id: e for e in self.evidence}

            # Find unique targets
            targets = set()
            for h in high_conf:
                for ev_id in h.evidence_refs:
                    if ev_id in evidence_map:
                        ev = evidence_map[ev_id]
                        pid = ev.data.get("pid", 0)
                        name = ev.data.get("process_name", ev.data.get("name", "unknown"))
                        if pid > 0:
                            targets.add((pid, name))

            for pid, name in list(targets)[:5]:  # Limit to top 5
                deep_hyp = self.analyzer.deep_dive_process(pid, name, self.evidence)
                if deep_hyp:
                    self.hypotheses.append(deep_hyp)
                    print(f"    Deep dive on {name} (PID {pid}): confidence {deep_hyp.confidence:.0%}")

        # Phase 3: Verdict
        print("\n[*] PHASE 3: VERDICT — Cross-validating findings...")
        evidence_map = {e.evidence_id: e for e in self.evidence}
        self.reports = self.verdict.render_verdicts(self.hypotheses, self.evidence, evidence_map)

        # Phase 4: Action
        print("\n[*] PHASE 4: ACTOR — Executing approved actions...")
        action_results = self.actor.execute(self.reports, self.vault)

        # Phase 5: Report
        print("\n" + "="*70)
        print("SCAN RESULTS")
        print("="*70)
        print(f"Total Evidence Collected: {len(self.evidence)}")
        print(f"AI Hypotheses Generated: {len(self.hypotheses)}")
        print(f"Verified Threats: {len(self.reports)}")
        print(f"\nActions Taken:")
        print(f"  Terminated: {len(action_results['terminated'])}")
        print(f"  Quarantined: {len(action_results['quarantined'])}")
        print(f"  Pending Approval: {len(action_results['investigated'])}")
        print(f"  Cookie Vaults: {len(action_results['cookies_encrypted'])}")
        print(f"  Failed: {len(action_results['failed'])}")

        if self.reports:
            print(f"\n--- TOP THREATS ---")
            for r in self.reports[:10]:
                status = "✓" if r.action_taken not in ["PENDING", "PENDING_APPROVAL"] else "○"
                print(f"{status} [{r.severity}] {r.target_name} (PID:{r.target_pid}) — "
                      f"Consensus: {r.consensus_score:.0%} — Action: {r.action_taken}")
                if r.description:
                    for line in r.description.split("\n")[:2]:
                        print(f"    {line}")

        # Save report
        report_path = self._save_report()
        print(f"\n[+] Full report: {report_path}")

        return {
            "evidence_count": len(self.evidence),
            "hypotheses_count": len(self.hypotheses),
            "threats": len(self.reports),
            "actions": action_results,
            "report_path": report_path
        }

    def _save_report(self) -> str:
        report = {
            "scanner": "KJAGU-AI v3.0",
            "timestamp": datetime.now().isoformat(),
            "model": self.config.model,
            "provider": self.config.ai_provider.value,
            "evidence_count": len(self.evidence),
            "hypotheses_count": len(self.hypotheses),
            "threats": [{
                "id": r.threat_id,
                "type": r.threat_type,
                "severity": r.severity,
                "target": r.target_name,
                "pid": r.target_pid,
                "path": r.target_path,
                "consensus": r.consensus_score,
                "action": r.action_taken,
                "description": r.description,
                "mitre": [h.mitre_technique for h in r.hypotheses],
            } for r in self.reports],
        }
        path = Path.home() / "kjagu_ai_report.json"
        with open(path, 'w') as f:
            json.dump(report, f, indent=2)
        return str(path)


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


def setup_wizard():
    """Interactive setup for first run"""
    print("""
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║              KJAGU AI — FIRST TIME SETUP                            ║
    ╚═══════════════════════════════════════════════════════════════════════╝
    """)

    config = KjaguConfig()

    print("Choose AI Provider:")
    print("  1. Ollama (local, free, recommended)")
    print("  2. OpenAI (GPT-4o-mini, fast, requires API key)")
    print("  3. Anthropic (Claude, requires API key)")
    print("  4. DeepSeek (cheap, requires API key)")
    choice = input("\nChoice [1-4]: ").strip()

    if choice == "1":
        config.ai_provider = AIProvider.OLLAMA
        url = input("Ollama URL [http://localhost:11434]: ").strip()
        config.api_base = url or "http://localhost:11434"
        model = input("Model [qwen2.5:14b]: ").strip()
        config.model = model or "qwen2.5:14b"
    elif choice == "2":
        config.ai_provider = AIProvider.OPENAI
        config.api_key = input("OpenAI API Key: ").strip()
        config.api_base = "https://api.openai.com/v1"
        config.model = "gpt-4o-mini"
    elif choice == "3":
        config.ai_provider = AIProvider.ANTHROPIC
        config.api_key = input("Anthropic API Key: ").strip()
        config.api_base = "https://api.anthropic.com"
        config.model = "claude-3-haiku-20240307"
    elif choice == "4":
        config.ai_provider = AIProvider.DEEPSEEK
        config.api_key = input("DeepSeek API Key: ").strip()
        config.api_base = "https://api.deepseek.com/v1"
        config.model = "deepseek-chat"

    print("\nUser Context (helps reduce false positives):")
    print("  e.g., 'gamer', 'developer', 'crypto trader', 'general user'")
    config.user_context = input("Your context: ").strip().lower()

    print("\nAggressive Mode:")
    print("  If enabled, Kjagu will auto-kill threats without asking.")
    aggro = input("Enable? [y/N]: ").strip().lower()
    config.enable_aggressive_mode = aggro == 'y'

    config.save()
    print("\n[+] Configuration saved to ~/.kjagu/config.json")
    print("[+] You can change settings anytime by editing that file or setting env vars.")
    return config


def main():
    """CLI entry point"""
    # Check for setup
    config_path = Path.home() / ".kjagu" / "config.json"
    if not config_path.exists():
        config = setup_wizard()
    else:
        config = KjaguConfig.load()
        # Allow env vars to override
        if os.environ.get("KJAGU_OPENAI_KEY"):
            config.ai_provider = AIProvider.OPENAI
            config.api_key = os.environ["KJAGU_OPENAI_KEY"]

    # Check if LLM is reachable
    if config.ai_provider == AIProvider.OLLAMA:
        try:
            req = urllib.request.Request(f"{config.api_base}/api/tags", method='GET')
            with urllib.request.urlopen(req, timeout=5):
                pass
        except:
            print("[!] WARNING: Cannot connect to Ollama. Make sure it's running:")
            print("    ollama serve")
            print("    ollama pull qwen2.5:14b")
            print("\n[!] Kjagu will fall back to heuristic-only mode (no AI analysis).")
            input("Press Enter to continue anyway...")

    kjagu = KjaguMain(config)
    results = kjagu.run(deep_dive=True)

    print("\n[*] Kjagu Agentic Scan Complete.")
    return results


if __name__ == "__main__":
    main()
