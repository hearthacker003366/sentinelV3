"""
Sentinel Graph Schema
Defines property graph entities and relationship types for cybersecurity threat graphs.
"""

from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class Node(BaseModel):
    id: str
    label: str
    properties: Dict[str, Any] = Field(default_factory=dict)


class Edge(BaseModel):
    source: str
    target: str
    type: str
    properties: Dict[str, Any] = Field(default_factory=dict)


# Graph Node Factory Helpers
class GraphSchema:
    # Relationship Types
    PARENT_OF = "PARENT_OF"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    INJECTED_INTO = "INJECTED_INTO"
    CREATED_FILE = "CREATED_FILE"
    AUTHENTICATED_TO = "AUTHENTICATED_TO"
    LOGICAL_PATH = "LOGICAL_PATH"
    PREDICTED_ATTACK_PATH = "PREDICTED_ATTACK_PATH"

    # Node Labels
    LABEL_HOST = "Host"
    LABEL_USER = "User"
    LABEL_PROCESS = "Process"
    LABEL_IP = "IPAddress"
    LABEL_FILE = "File"

    @classmethod
    def make_host_id(cls, hostname: str) -> str:
        return f"HOST:{hostname.upper()}"

    @classmethod
    def make_user_id(cls, username: str) -> str:
        return f"USER:{username.upper()}"

    @classmethod
    def make_process_id(cls, host: str, pid: str, name: str) -> str:
        return f"PROC:{host.upper()}:{pid}:{name.lower()}"

    @classmethod
    def make_ip_id(cls, ip: str) -> str:
        return f"IP:{ip}"

    @classmethod
    def make_file_id(cls, host: str, filepath: str) -> str:
        return f"FILE:{host.upper()}:{filepath.lower()}"
