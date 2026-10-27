"""Trusted MITRE ATT&CK Enterprise & Cloud Technique Reference Catalog.

Used to validate extracted technique IDs and ensure hallucinated or malformed
T-codes from LLMs or untrusted reports are rejected.
"""
from __future__ import annotations

import re

# Comprehensive catalog of standard Enterprise & Cloud MITRE ATT&CK Techniques
ATTACK_CATALOG: dict[str, dict[str, str]] = {
    # Initial Access / Execution
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access", "platform": "Cloud, Linux, Windows"},
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access", "platform": "Cloud, Network, Windows"},
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access, Defense Evasion, Persistence, Privilege Escalation", "platform": "Cloud, Linux, Windows"},
    "T1078.001": {"name": "Valid Accounts: Default Accounts", "tactic": "Defense Evasion, Persistence", "platform": "Cloud, Linux"},
    "T1078.003": {"name": "Valid Accounts: Local Accounts", "tactic": "Defense Evasion, Persistence", "platform": "Linux, Windows"},
    "T1078.004": {"name": "Valid Accounts: Cloud Accounts", "tactic": "Initial Access, Defense Evasion, Persistence, Privilege Escalation", "platform": "Cloud, SaaS, IaaS"},
    "T1204": {"name": "User Execution", "tactic": "Execution", "platform": "Linux, Windows"},
    "T1610": {"name": "Deploy Container", "tactic": "Execution, Defense Evasion", "platform": "Containers"},

    # Persistence & Privilege Escalation
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence", "platform": "Cloud, Identity Provider"},
    "T1098.001": {"name": "Additional Cloud Credentials", "tactic": "Persistence", "platform": "Cloud, Identity Provider"},
    "T1098.003": {"name": "Additional Cloud Roles", "tactic": "Persistence", "platform": "Cloud"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation, Defense Evasion", "platform": "Linux, Windows"},

    # Credential Access
    "T1110": {"name": "Brute Force", "tactic": "Credential Access", "platform": "Cloud, Identity Provider"},
    "T1110.001": {"name": "Password Guessing", "tactic": "Credential Access", "platform": "Cloud, Network"},
    "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access", "platform": "Cloud, Identity Provider"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access", "platform": "Cloud, Linux, Windows"},
    "T1552.001": {"name": "Credentials In Files", "tactic": "Credential Access", "platform": "Cloud, Linux, Windows"},
    "T1552.005": {"name": "Cloud Instance Metadata API", "tactic": "Credential Access", "platform": "Cloud (AWS, GCP, Azure)"},
    "T1539": {"name": "Steal Web Session Cookie", "tactic": "Credential Access", "platform": "SaaS, Office"},

    # Discovery & Lateral Movement
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery", "platform": "Cloud, Linux, Windows"},
    "T1580": {"name": "Cloud Infrastructure Discovery", "tactic": "Discovery", "platform": "Cloud"},
    "T1526": {"name": "Cloud Service Discovery", "tactic": "Discovery", "platform": "Cloud"},
    "T1087.004": {"name": "Account Discovery: Cloud Account", "tactic": "Discovery", "platform": "Cloud"},
    "T1021.001": {"name": "Remote Services: Remote Desktop Protocol", "tactic": "Lateral Movement", "platform": "Windows"},
    "T1021.004": {"name": "Remote Services: SSH", "tactic": "Lateral Movement", "platform": "Linux"},

    # Defense Evasion
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion", "platform": "Cloud, Linux, Windows"},
    "T1562.008": {"name": "Disable or Modify Cloud Logs", "tactic": "Defense Evasion", "platform": "Cloud (CloudTrail, CloudWatch)"},
    "T1562.001": {"name": "Disable or Modify Tools", "tactic": "Defense Evasion", "platform": "Linux, Windows"},

    # Collection & Exfiltration
    "T1530": {"name": "Data from Cloud Storage", "tactic": "Collection", "platform": "Cloud (S3, GCS, Blob)"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration", "platform": "Cloud, SaaS"},
    "T1567.002": {"name": "Exfiltration to Cloud Storage", "tactic": "Exfiltration", "platform": "Cloud"},

    # Impact & Reconnaissance
    "T1485": {"name": "Data Destruction", "tactic": "Impact", "platform": "Cloud, Linux, Windows"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "platform": "Cloud, Linux, Windows"},
    "T1496": {"name": "Resource Hijacking (Cryptomining)", "tactic": "Impact", "platform": "Cloud, Containers"},
    "T1498": {"name": "Network Denial of Service", "tactic": "Impact", "platform": "Cloud, Network"},
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance", "platform": "Network"},
}

VALID_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")


def is_valid_technique(tid: str) -> bool:
    """Return True if tid matches ATT&CK syntax and exists in the trusted catalog or parent."""
    if not tid or not VALID_ID_PATTERN.match(tid):
        return False
    # Check exact match or base ID match in trusted catalog
    base = tid.split(".")[0]
    return tid in ATTACK_CATALOG or base in ATTACK_CATALOG


def get_technique_info(tid: str) -> dict:
    """Return technique name and tactic if known, otherwise placeholder."""
    if tid in ATTACK_CATALOG:
        return ATTACK_CATALOG[tid]
    base = tid.split(".")[0]
    if base in ATTACK_CATALOG:
        info = ATTACK_CATALOG[base].copy()
        info["name"] = f"{info['name']} (Sub-technique {tid})"
        return info
    return {"name": "Unknown ATT&CK Technique", "tactic": "Unknown", "platform": "Unknown"}
