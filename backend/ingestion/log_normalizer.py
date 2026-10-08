"""
Sentinel Log Normalizer
Converts raw Windows Event Logs (4624, 4625, 4688) and Sysmon Events (1, 3, 10, 11)
into standardized Open Cybersecurity Schema Framework (OCSF) dictionaries.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional


class LogNormalizer:
    @staticmethod
    def get_iso_timestamp(ts: Optional[str] = None) -> str:
        if ts:
            return ts
        return datetime.now(timezone.utc).isoformat()

    @classmethod
    def normalize(cls, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        event_id = raw_event.get("event_id") or raw_event.get("EventID") or 0
        provider = raw_event.get("provider", "Microsoft-Windows-Sysmon")
        timestamp = cls.get_iso_timestamp(raw_event.get("timestamp") or raw_event.get("UtcTime"))

        normalized = {
            "timestamp": timestamp,
            "raw_id": event_id,
            "provider": provider,
            "host": raw_event.get("host", raw_event.get("Computer", "UNKNOWN-HOST")).upper(),
            "user": raw_event.get("user", raw_event.get("User", "SYSTEM")),
            "event_type": "UNKNOWN",
            "process": {},
            "network": {},
            "file": {},
            "raw_data": raw_event
        }

        # Sysmon Event ID 1: Process Creation
        if event_id == 1 or event_id == 4688:
            normalized["event_type"] = "PROCESS_CREATION"
            image = raw_event.get("Image", raw_event.get("NewProcessName", ""))
            parent_image = raw_event.get("ParentImage", raw_event.get("ParentProcessName", ""))
            cmdline = raw_event.get("CommandLine", "")
            pid = raw_event.get("ProcessId", "")
            parent_pid = raw_event.get("ParentProcessId", "")

            normalized["process"] = {
                "name": image.split("\\")[-1] if image else "unknown.exe",
                "path": image,
                "command_line": cmdline,
                "pid": str(pid),
                "parent_name": parent_image.split("\\")[-1] if parent_image else "",
                "parent_path": parent_image,
                "parent_pid": str(parent_pid),
                "integrity_level": raw_event.get("IntegrityLevel", "Medium")
            }

        # Sysmon Event ID 3: Network Connection
        elif event_id == 3:
            normalized["event_type"] = "NETWORK_CONNECTION"
            image = raw_event.get("Image", "")
            normalized["process"] = {
                "name": image.split("\\")[-1] if image else "",
                "path": image,
                "pid": str(raw_event.get("ProcessId", ""))
            }
            normalized["network"] = {
                "protocol": raw_event.get("Protocol", "tcp").upper(),
                "src_ip": raw_event.get("SourceIp", ""),
                "src_port": int(raw_event.get("SourcePort", 0) or 0),
                "dest_ip": raw_event.get("DestinationIp", ""),
                "dest_port": int(raw_event.get("DestinationPort", 0) or 0),
                "dest_hostname": raw_event.get("DestinationHostname", "")
            }

        # Sysmon Event ID 10: Process Access (e.g. LSASS dump)
        elif event_id == 10:
            normalized["event_type"] = "PROCESS_ACCESS"
            src_image = raw_event.get("SourceImage", "")
            target_image = raw_event.get("TargetImage", "")
            normalized["process"] = {
                "source_name": src_image.split("\\")[-1] if src_image else "",
                "source_path": src_image,
                "target_name": target_image.split("\\")[-1] if target_image else "",
                "target_path": target_image,
                "granted_access": raw_event.get("GrantedAccess", "")
            }

        # Sysmon Event ID 11: File Creation
        elif event_id == 11:
            normalized["event_type"] = "FILE_CREATION"
            image = raw_event.get("Image", "")
            target_file = raw_event.get("TargetFilename", "")
            normalized["process"] = {
                "name": image.split("\\")[-1] if image else "",
                "path": image
            }
            normalized["file"] = {
                "path": target_file,
                "name": target_file.split("\\")[-1] if target_file else ""
            }

        # Windows Event ID 4624 / 4625: Logon Events
        elif event_id in (4624, 4625):
            normalized["event_type"] = "AUTHENTICATION"
            normalized["auth"] = {
                "success": (event_id == 4624),
                "logon_type": raw_event.get("LogonType", 3),
                "ip_address": raw_event.get("IpAddress", "127.0.0.1")
            }

        return normalized
