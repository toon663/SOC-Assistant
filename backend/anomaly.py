"""Review rules for Windows Security events; matches require analyst review."""
from __future__ import annotations

from gatherer import SecurityLogBatch


# Audit success and failure can both have Windows event level 0: use event IDs.
SECURITY_RULES = {
    4625: ("failed_logon", "medium", "An account failed to log on"),
    4740: ("account_lockout", "medium", "A user account was locked out"),
    4719: ("audit_policy_changed", "medium", "System audit policy was changed"),
    1102: ("security_log_cleared", "high", "The Security audit log was cleared"),
}


def detect_anomalies(batch: SecurityLogBatch) -> list[dict]:
    """Select review-worthy records while preserving their original evidence."""
    findings = []
    for record in batch.events:
        rule = SECURITY_RULES.get(record.event_id)
        if not rule:
            continue
        event_type, severity, message = rule
        data = record.data
        user = data.get("TargetUserName") or data.get("SubjectUserName")
        domain = data.get("TargetDomainName") or data.get("SubjectDomainName")
        if user and domain and domain != "-":
            user = f"{domain}\\{user}"
        findings.append({
            "event_id": record.identity,
            "windows_event_id": record.event_id,
            "record_id": record.record_id,
            "timestamp": record.timestamp,
            "host": record.host,
            "log_name": "Security",
            "provider": record.provider,
            "event_type": event_type,
            "severity": severity,
            "user": user if user != "-" else None,
            "source_ip": data.get("IpAddress") if data.get("IpAddress") != "-" else None,
            "message": f"Windows Security {record.event_id}: {message}",
            "data": data,
        })
    return findings
