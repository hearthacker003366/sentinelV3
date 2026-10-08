import os
"""
Sentinel Ransomware / APT Simulator (V3)
========================================
Synthetic telemetry generator modeling a realistic 5-stage enterprise
ransomware outbreak. Produces RAW Sysmon / Windows-Event-style dicts that
`backend.ingestion.log_normalizer.LogNormalizer` converts to OCSF.

SAFETY INVARIANT:
  This generator only PRODUCES LOG EVENTS. It never executes system commands,
  never touches files, and never opens network sockets. Every event it emits
  is labeled SYNTHETIC_SIMULATION by the pipeline.

Stage model (mirrors the documented V1 scenario):
  1. Initial Access / Execution  - Office dropper -> PowerShell beacon -> C2
  2. Inhibit System Recovery     - vssadmin delete shadows (MITRE T1490)
  3. Lateral Movement Discovery  - internal SMB port-445 enumeration sweep
  4. Credential Access / Target  - LSASS dump + NTLM logon to backup vault
  5. Impact                      - encryptor staged against the backup vault
"""

from typing import Dict, Any, List

C2_IP = os.getenv("C2_IP", "185.220.101.49")  # [DEMO ONLY] Simulated C2 Server IP
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

    # Exposed as a class attribute so instances (and MCP tool handlers) can
    # access narrative text via self.STAGE_NARRATIVES.
    STAGE_NARRATIVES = STAGE_NARRATIVES

    def __init__(self, target_host: str = "WKSTN-04"):
        self.target_host = target_host

    # ------------------------------------------------------------------
    # Baseline topology (used by tests + GNN warm-up)
    # ------------------------------------------------------------------
    def get_baseline_network_topology(self) -> List[Dict[str, Any]]:
        """Events that build the enterprise graph: hosts, users, SMB links."""
        events: List[Dict[str, Any]] = []

        # WKSTN-04 connects out to every internal host on SMB 445 (host -> IP edges)
        for host, ip in INTERNAL_HOSTS.items():
            events.append({
                "event_id": 3,
                "Computer": self.target_host,
                "user": "SYSTEM",
                "Image": "C:\\Windows\\System32\\svchost.exe",
                "SourceIp": WKSTN04_IP,
                "DestinationIp": ip,
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
            events.append({
                "event_id": 1,
                "Computer": host,
                "user": "SYSTEM",
                "Image": f"C:\\Program Files\\SentinelLab\\{benign_proc[host]}",
                "CommandLine": f'"{benign_proc[host]}" --service',
                "ParentImage": "C:\\Windows\\System32\\services.exe",
                "ProcessId": 1000 + abs(hash(host)) % 8000,
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
    # Stage generators
    # ------------------------------------------------------------------
    def generate_stage(self, stage: int) -> List[Dict[str, Any]]:
        if not isinstance(stage, int) or stage < 1 or stage > 5:
            raise ValueError(f"Invalid APT stage: {stage!r}. Must be an integer 1..5.")
        return {
            1: self._stage1_initial_access,
            2: self._stage2_inhibit_recovery,
            3: self._stage3_lateral_discovery,
            4: self._stage4_credential_access,
            5: self._stage5_impact,
        }[stage]()

    def _stage1_initial_access(self) -> List[Dict[str, Any]]:
        return [
            {
                "event_id": 1,
                "Computer": self.target_host,
                "user": "j.malhotra",
                "Image": "C:\\Users\\j.malhotra\\AppData\\Local\\Temp\\invoice.pdf.exe",
                "CommandLine": '"invoice.pdf.exe" /quiet /dropper',
                "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "ProcessId": 4416,
                "ParentProcessId": 2204,
            },
            {
                "event_id": 1,
                "Computer": self.target_host,
                "user": "j.malhotra",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": (
                    "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
                ),
                "ParentImage": "C:\\Users\\j.malhotra\\AppData\\Local\\Temp\\invoice.pdf.exe",
                "ProcessId": 6180,
                "ParentProcessId": 4416,
            },
            {
                "event_id": 3,
                "Computer": self.target_host,
                "user": "SYSTEM",
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
                "user": "j.malhotra",
                "Image": "C:\\Windows\\System32\\vssadmin.exe",
                "CommandLine": "vssadmin delete shadows /all /quiet",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "ProcessId": 5240,
                "ParentProcessId": 6180,
            },
        ]

    def _stage3_lateral_discovery(self) -> List[Dict[str, Any]]:
        return [
            {
                "event_id": 3,
                "Computer": self.target_host,
                "user": "SYSTEM",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "SourceIp": WKSTN04_IP,
                "DestinationIp": ip,
                "DestinationPort": 445,
                "Protocol": "tcp",
            }
            for ip in INTERNAL_HOSTS.values()
        ]

    def _stage4_credential_access(self) -> List[Dict[str, Any]]:
        return [
            {
                "event_id": 10,
                "Computer": self.target_host,
                "user": "SYSTEM",
                "SourceImage": "C:\\Windows\\Temp\\pypykatz.exe",
                "TargetImage": "C:\\Windows\\system32\\lsass.exe",
                "GrantedAccess": "0x1010",
            },
            {
                "event_id": 3,
                "Computer": self.target_host,
                "user": "SYSTEM",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "SourceIp": WKSTN04_IP,
                "DestinationIp": INTERNAL_HOSTS["BACKUP-VAULT-01"],
                "DestinationPort": 445,
                "Protocol": "tcp",
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
        vault_share = f"\\\\BACKUP-VAULT-01\\backup$"
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
                "Computer": self.target_host,
                "user": "SYSTEM",
                "Image": "C:\\Windows\\Temp\\svhost64.exe",
                "TargetFilename": f"{vault_share}\\Q3_Financials.xlsx.locked",
            },
        ]

    # ------------------------------------------------------------------
    def run_stage(self, stage: int) -> List[Dict[str, Any]]:
        """Backwards-compatible alias."""
        return self.generate_stage(stage)
