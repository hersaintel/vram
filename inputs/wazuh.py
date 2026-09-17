"""Wazuh security telemetry adapter.

Normalises Wazuh-style JSON alerts into VRAM Observation objects.
Does not depend on a live Wazuh manager — accepts JSON events.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from models.observation import Observation


# Wazuh rule level (0-15) → VRAM severity (0-10)
# Documented mapping:
#   0-2  → informational (0-1)
#   3-4  → low (2-3)
#   5-6  → medium (4-5)
#   7-8  → high (6-7)
#   9-10 → critical (8)
#  11-15 → critical (9-10)
def _map_severity(level: int | None) -> int:
    if level is None:
        return 2
    if level <= 2:
        return max(0, level)
    if level <= 4:
        return 2 + (level - 3)
    if level <= 6:
        return 4 + (level - 5)
    if level <= 8:
        return 6 + (level - 7)
    if level <= 10:
        return 8
    return min(10, 8 + (level - 10))


_RULE_HINTS: list[tuple[list[str], str, list[str]]] = [
    (["authentication failed", "failed login", "sshd: authentication failure", "pam: authentication failure"],
     "authentication_failure", ["authentication", "failure"]),
    (["authentication success", "successful login", "session opened", "accepted password", "accepted publickey"],
     "authentication_success", ["authentication"]),
    (["sudo", "privilege escalation", "escalat", "got root", "uid=0"],
     "privilege_escalation", ["privilege"]),
    (["new user", "useradd", "account created", "adduser"],
     "account_modification", ["account", "lifecycle"]),
    (["password changed", "passwd", "chpasswd"],
     "account_modification", ["account"]),
    (["file modified", "syscheck", "integrity checksum changed", "file added", "file deleted"],
     "file_modification", ["file", "integrity"]),
    (["process", "executed", "command executed", "new process"],
     "process_execution", ["process"]),
    (["suspicious command", "base64", "encoded command", "powershell -enc"],
     "suspicious_command", ["process", "suspicious"]),
    (["network connection", "outbound", "connected to", "firewall"],
     "network_connection", ["network"]),
    (["external connection", "unusual outbound", "c2", "exfil"],
     "external_connection", ["network", "exfiltration"]),
    (["malware", "virus", "trojan", "rootkit", "yara"],
     "malware_alert", ["malware"]),
    (["policy violation", "compliance", "cis ", "pci"],
     "policy_violation", ["policy"]),
    (["vpn", "openvpn", "ipsec", "wireguard"],
     "vpn_login", ["authentication", "vpn"]),
    (["brute force", "multiple failures", "too many"],
     "multiple_failed_logins", ["authentication", "failure", "brute_force"]),
]


def _parse_timestamp(raw: Any) -> datetime:
    if raw is None:
        return datetime.now(timezone.utc)
    if isinstance(raw, (int, float)):
        if raw > 1e12:
            raw = raw / 1000.0
        return datetime.fromtimestamp(raw, tz=timezone.utc)
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _classify(rule_desc: str, rule_id: str | None, full_text: str) -> tuple[str, list[str]]:
    text = (rule_desc + " " + full_text).lower()
    for keywords, event_type, tags in _RULE_HINTS:
        if any(k in text for k in keywords):
            return event_type, list(tags)
    return "security_event", ["wazuh"]


class WazuhAdapter:
    """Convert Wazuh JSON alerts into normalised Observations."""

    SOURCE = "wazuh"

    def parse_event(self, event: dict[str, Any]) -> Observation:
        """Parse a single Wazuh-style alert into an Observation."""
        rule = event.get("rule") or {}
        agent = event.get("agent") or {}
        data = event.get("data") or {}
        predecoder = event.get("predecoder") or {}
        decoder = event.get("decoder") or {}

        rule_id = str(rule.get("id") or "")
        rule_desc = str(rule.get("description") or rule.get("desc") or "")
        rule_level = rule.get("level")
        try:
            rule_level = int(rule_level) if rule_level is not None else None
        except (TypeError, ValueError):
            rule_level = None

        groups = rule.get("groups") or []
        full_text = " ".join(
            str(x) for x in [
                rule_desc,
                " ".join(str(g) for g in groups),
                data.get("title") or "",
                event.get("full_log") or "",
            ]
        )

        event_type, tags = _classify(rule_desc, rule_id, full_text)

        user = (
            data.get("dstuser")
            or data.get("srcuser")
            or data.get("user")
            or data.get("destinationuser")
            or data.get("uid")
            or predecoder.get("user")
        )
        source_ip = (
            data.get("srcip")
            or data.get("src_ip")
            or data.get("source_ip")
            or event.get("srcip")
        )
        dest_ip = (
            data.get("dstip")
            or data.get("dst_ip")
            or data.get("destination_ip")
        )
        host = (
            agent.get("name")
            or agent.get("id")
            or event.get("hostname")
            or predecoder.get("hostname")
        )

        severity = _map_severity(rule_level)

        for g in groups:
            g_str = str(g).lower()
            if g_str not in tags:
                tags.append(g_str)

        metadata: dict[str, Any] = {
            "rule_id": rule_id or None,
            "rule_description": rule_desc or None,
            "rule_level": rule_level,
            "agent_id": agent.get("id"),
            "decoder": decoder.get("name"),
            "full_log": event.get("full_log"),
        }
        for key in ("command", "path", "file", "process_name", "protocol", "dstport", "srcport"):
            if key in data:
                metadata[key] = data[key]
        metadata = {k: v for k, v in metadata.items() if v is not None}

        return Observation(
            id=str(event.get("id") or event.get("uid") or uuid4()),
            timestamp=_parse_timestamp(
                event.get("timestamp") or event.get("time") or data.get("timestamp")
            ),
            source=self.SOURCE,
            event_type=event_type,
            user=str(user) if user else None,
            host=str(host) if host else None,
            source_ip=str(source_ip) if source_ip else None,
            destination_ip=str(dest_ip) if dest_ip else None,
            action=rule_desc[:120] if rule_desc else event_type,
            severity=severity,
            tags=tags,
            metadata=metadata,
        )

    def parse_file(self, path: str) -> list[Observation]:
        import json
        from pathlib import Path

        raw = Path(path).read_text(encoding="utf-8")
        data = json.loads(raw)
        if isinstance(data, list):
            return [self.parse_event(e) for e in data]
        return [self.parse_event(data)]

    def parse_many(self, events: list[dict[str, Any]]) -> list[Observation]:
        return [self.parse_event(e) for e in events]