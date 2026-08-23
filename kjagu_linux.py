#!/usr/bin/env python3
"""
KJAGU LINUX KERNEL SCANNER
LKM (Loadable Kernel Module) rootkit detection
For when the Boss runs Linux and spyware goes kernel-deep.
"""

import os
import sys
import re
import subprocess
import hashlib
from pathlib import Path
from typing import List, Dict, Optional
import ctypes
from ctypes import cdll, CDLL, c_void_p, c_char_p, c_int, c_ulong, c_size_t, Structure, POINTER

class LinuxKernelScanner:
    """Deep Linux kernel scanner — LKM hooks, syscall table, kprobes"""
    
    # Known rootkit module names
    ROOTKIT_SIGNATURES = [
        r"suterusu", r"adore", r"knark", r"override", r"phide",
        r"modhide", r"mod_ko", r"kernel_hook", r"sys_call_table",
        r"rk_", r"rootkit", r"hook_", r"hide_", r"backdoor"
    ]
    
    # Critical syscalls to check for hooks
    CRITICAL_SYSCALLS = [
        "sys_read", "sys_write", "sys_open", "sys_close",
        "sys_getdents", "sys_getdents64", "sys_kill", "sys_exit",
        "sys_ptrace", "sys_mkdir", "sys_rmdir", "sys_unlink",
        "sys_socketcall", "sys_connect", "sys_accept"
    ]
    
    def __init__(self):
        self.threats = []
        self.syscall_table_addr = None
    
    def scan_all(self):
        """Run full Linux kernel scan"""
        print("[KJAGU-LINUX] Initiating kernel deep scan...")
        
        self._check_loaded_modules()
        self._check_syscall_table()
        self._check_kprobes()
        self._check_debugfs()
        self._check_ld_preload()
        self._check_proc_hooks()
        self._check_network_hooks()
        
        return self.threats
    
    def _check_loaded_modules(self):
        """Scan /proc/modules for suspicious LKMs"""
        try:
            with open('/proc/modules', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 3:
                        continue
                    
                    module_name = parts[0]
                    size = parts[1]
                    use_count = parts[2]
                    
                    # Check against signatures
                    for pattern in self.ROOTKIT_SIGNATURES:
                        if re.search(pattern, module_name, re.IGNORECASE):
                            self._add_threat(
                                "SUSPICIOUS_LKM",
                                "CRITICAL",
                                module_name,
                                f"Module name matches rootkit signature: {pattern}",
                                f"Size:{size} Uses:{use_count}"
                            )
                            break
                    
                    # Check for modules with no dependencies but high usage (stealth sign)
                    if use_count != '0' and len(parts) <= 3:
                        self._add_threat(
                            "ORPHAN_LKM",
                            "HIGH",
                            module_name,
                            "Module loaded with no visible dependencies — possible hidden module",
                            f"Size:{size}"
                        )
                        
        except PermissionError:
            print("[!] Need root to read /proc/modules properly")
    
    def _check_syscall_table(self):
        """Detect syscall table hooking"""
        try:
            # Read System.map or /proc/kallsyms
            sym_file = Path('/boot/System.map-' + os.uname().release)
            kallsyms = Path('/proc/kallsyms')
            
            if kallsyms.exists():
                self._parse_kallsyms(kallsyms)
            elif sym_file.exists():
                self._parse_system_map(sym_file)
            
            # Check current syscall addresses vs expected
            self._verify_syscall_integrity()
            
        except Exception as e:
            print(f"[!] Syscall table check failed: {e}")
    
    def _parse_kallsyms(self, path: Path):
        """Parse /proc/kallsyms to find syscall table"""
        try:
            with open(path, 'r') as f:
                for line in f:
                    if 'sys_call_table' in line:
                        addr = line.split()[0]
                        self.syscall_table_addr = int(addr, 16)
                        print(f"[+] Found sys_call_table at {addr}")
                        break
        except:
            pass
    
    def _parse_system_map(self, path: Path):
        """Parse System.map for syscall addresses"""
        try:
            with open(path, 'r') as f:
                for line in f:
                    if 'sys_call_table' in line:
                        addr = line.split()[0]
                        self.syscall_table_addr = int(addr, 16)
                        break
        except:
            pass
    
    def _verify_syscall_integrity(self):
        """Check if syscall addresses point to kernel text section"""
        if not self.syscall_table_addr:
            return
        
        # Read kernel text bounds from /proc/iomem
        kernel_start = None
        kernel_end = None
        
        try:
            with open('/proc/iomem', 'r') as f:
                for line in f:
                    if 'Kernel code' in line:
                        parts = line.split('-')
                        kernel_start = int(parts[0].strip(), 16)
                        kernel_end = int(parts[1].split(':')[0].strip(), 16)
                        break
        except:
            return
        
        if not kernel_start:
            return
        
        # Read syscall table entries (needs kernel module or /dev/mem access)
        # This is a simplified check — full implementation needs kernel module
        print(f"[+] Kernel text: {hex(kernel_start)} - {hex(kernel_end)}")
        print("[*] Full syscall verification requires kjagu-kmod.ko")
    
    def _check_kprobes(self):
        """Detect unauthorized kprobes (kernel breakpoints)"""
        kprobe_events = Path('/sys/kernel/debug/tracing/kprobe_events')
        if not kprobe_events.exists():
            return
        
        try:
            with open(kprobe_events, 'r') as f:
                content = f.read()
                lines = content.strip().split('\n')
                
                for line in lines:
                    if not line:
                        continue
                    
                    # Check for probes on security-critical functions
                    critical_funcs = ['sys_read', 'sys_write', 'sys_open', 
                                     'vfs_read', 'vfs_write', 'do_fork',
                                     'commit_creds', 'prepare_creds']
                    
                    for func in critical_funcs:
                        if func in line:
                            self._add_threat(
                                "KPROBE_ON_CRITICAL",
                                "CRITICAL",
                                "kprobe",
                                f"Kprobe registered on critical function: {func}",
                                line
                            )
                            break
                            
        except PermissionError:
            pass
    
    def _check_debugfs(self):
        """Scan debugfs for hidden entries"""
        debugfs = Path('/sys/kernel/debug')
        if not debugfs.exists():
            return
        
        suspicious_names = ['hidden', 'hook', 'rootkit', 'backdoor', 
                          'hide_pid', 'hide_file', 'hide_module']
        
        try:
            for item in debugfs.rglob('*'):
                name = item.name.lower()
                for pattern in suspicious_names:
                    if pattern in name:
                        self._add_threat(
                            "SUSPICIOUS_DEBUGFS",
                            "HIGH",
                            str(item),
                            f"Suspicious debugfs entry: {name}",
                            f"Type: {'dir' if item.is_dir() else 'file'}"
                        )
                        break
        except PermissionError:
            pass
    
    def _check_ld_preload(self):
        """Check LD_PRELOAD and /etc/ld.so.preload for rootkit libraries"""
        # Check environment
        ld_preload = os.environ.get('LD_PRELOAD', '')
        if ld_preload:
            self._add_threat(
                "LD_PRELOAD_ACTIVE",
                "HIGH",
                "environment",
                f"LD_PRELOAD is set: {ld_preload}",
                "Possible library injection"
            )
        
        # Check system-wide preload
        preload_file = Path('/etc/ld.so.preload')
        if preload_file.exists():
            try:
                with open(preload_file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        self._add_threat(
                            "SYSTEM_LD_PRELOAD",
                            "CRITICAL",
                            str(preload_file),
                            f"System-wide library preloading: {content}",
                            "All processes will load this library"
                        )
            except PermissionError:
                pass
    
    def _check_proc_hooks(self):
        """Check /proc for hidden processes (readdir hook indicator)"""
        try:
            # Get process list from ps
            ps_output = subprocess.run(['ps', '-eo', 'pid='], 
                                      capture_output=True, text=True, timeout=10)
            ps_pids = set(int(x) for x in ps_output.stdout.strip().split('\n') if x.strip().isdigit())
            
            # Get process list from /proc
            proc_pids = set()
            for entry in Path('/proc').iterdir():
                if entry.name.isdigit():
                    proc_pids.add(int(entry.name))
            
            # Compare
            hidden = proc_pids - ps_pids
            if hidden:
                for pid in hidden:
                    self._add_threat(
                        "HIDDEN_PROCESS",
                        "CRITICAL",
                        str(pid),
                        f"Process {pid} exists in /proc but not visible to ps — rootkit hook",
                        "getdents/getdents64 syscall likely hooked"
                    )
            
            # Also check for processes in ps but not in /proc (impossible without hook)
            impossible = ps_pids - proc_pids
            if impossible:
                for pid in impossible:
                    self._add_threat(
                        "FAKE_PROCESS",
                        "CRITICAL",
                        str(pid),
                        f"Process {pid} visible to ps but no /proc entry — deep rootkit",
                        "Possible VFS hook or kernel data manipulation"
                    )
                    
        except Exception as e:
            print(f"[!] Process visibility check failed: {e}")
    
    def _check_network_hooks(self):
        """Check for network-level rootkit hooks"""
        # Check netfilter hooks
        nf_hooks = Path('/proc/net/netfilter')
        if nf_hooks.exists():
            try:
                with open(nf_hooks, 'r') as f:
                    content = f.read()
                    # Look for unusual hook priorities or unknown modules
                    # This is simplified — full check needs kernel introspection
                    pass
            except:
                pass
        
        # Check for hidden network connections
        try:
            # Compare /proc/net/tcp with ss output
            proc_tcp = subprocess.run(['cat', '/proc/net/tcp'], 
                                     capture_output=True, text=True, timeout=5)
            ss_output = subprocess.run(['ss', '-tan'], 
                                      capture_output=True, text=True, timeout=5)
            
            # Parse and compare (simplified)
            proc_ports = set(re.findall(r':([0-9A-F]{4})', proc_tcp.stdout))
            ss_ports = set(re.findall(r':(\d+)', ss_output.stdout))
            
            # Convert hex to decimal for comparison
            proc_ports_dec = set(int(p, 16) for p in proc_ports if len(p) == 4)
            ss_ports_dec = set(int(p) for p in ss_ports if p.isdigit())
            
            hidden_ports = proc_ports_dec - ss_ports_dec
            if hidden_ports:
                for port in hidden_ports:
                    self._add_threat(
                        "HIDDEN_CONNECTION",
                        "CRITICAL",
                        f"port:{port}",
                        f"Connection on port {port} visible in /proc but hidden from ss",
                        "Possible netfilter hook or socket hiding"
                    )
                    
        except Exception as e:
            print(f"[!] Network hook check failed: {e}")
    
    def _add_threat(self, threat_type: str, severity: str, target: str, 
                    description: str, details: str = ""):
        """Add threat to list"""
        self.threats.append({
            "type": threat_type,
            "severity": severity,
            "target": target,
            "description": description,
            "details": details,
            "timestamp": subprocess.check_output(['date', '+%Y-%m-%d %H:%M:%S']).decode().strip()
        })
        print(f"[!] [{severity}] {threat_type}: {description}")


def main():
    """Linux entry point"""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║           KJAGU LINUX KERNEL SCANNER v1.0                   ║
    ║        LKM Rootkit Detection & Syscall Integrity              ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    if os.geteuid() != 0:
        print("[!] WARNING: Not running as root. Deep kernel scan limited.")
        print("[!] Run with sudo for full syscall table verification.\n")
    
    scanner = LinuxKernelScanner()
    threats = scanner.scan_all()
    
    print(f"\n[+] Scan complete. Threats found: {len(threats)}")
    
    if threats:
        print("\n--- THREAT SUMMARY ---")
        critical = [t for t in threats if t['severity'] == 'CRITICAL']
        high = [t for t in threats if t['severity'] == 'HIGH']
        print(f"    CRITICAL: {len(critical)}")
        print(f"    HIGH: {len(high)}")
        
        print("\n--- MANUAL VERIFICATION COMMANDS ---")
        print("    lsmod | grep -i <module>     # Check suspicious modules")
        print("    cat /proc/kallsyms | grep sys_call_table")
        print("    dmesg | grep -i hook         # Check kernel messages")
        print("    rmmod <suspicious_module>    # Remove module (DANGEROUS)")
    
    return scanner


if __name__ == "__main__":
    main()
