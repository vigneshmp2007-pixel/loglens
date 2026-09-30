import csv
import io
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from .geolocation import enrich_attackers

MAX_STORED_REPORTS = 50
REPORTS = OrderedDict()  # bounded in-memory store (oldest evicted first)

CSV_FIELDS = ["ip", "timestamp", "method", "path", "status",
              "attack_type", "attack_label", "severity", "detection"]


def make_report(parsed_count, malformed_count, attacks, type_counts, ip_counts, hour_counts, severity_counts):
    report_id = uuid.uuid4().hex[:12]
    report = {
        "report_id": report_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_lines": parsed_count + malformed_count,
            "parsed_lines": parsed_count,
            "malformed_lines": malformed_count,
            # Use the counters (cover every detection), not len(attacks),
            # because `attacks` is capped to the most recent events.
            "total_attacks": sum(type_counts.values()),
            "unique_attackers": len(ip_counts),
            "high_severity": severity_counts.get("high", 0),
            "medium_severity": severity_counts.get("medium", 0),
            "low_severity": severity_counts.get("low", 0),
        },
        "attack_types": [{"type": k, "count": v} for k, v in type_counts.most_common()],
        "timeline": [{"hour": k, "attacks": v} for k, v in sorted(hour_counts.items())],
        "top_attackers": enrich_attackers([{"ip": k, "attacks": v} for k, v in ip_counts.most_common(20)]),
        "events": [
            {key: event.get(key, "") for key in (
                "ip", "timestamp", "method", "path", "status", "user_agent",
                "attack_type", "attack_label", "severity", "detection"
            )} for event in attacks
        ],
    }
    REPORTS[report_id] = report
    while len(REPORTS) > MAX_STORED_REPORTS:
        REPORTS.popitem(last=False)
    return report


def _safe_cell(value):
    """Neutralise CSV/Excel formula injection from attacker-controlled log data."""
    text = "" if value is None else str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def report_csv(report):
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=CSV_FIELDS)
    writer.writeheader()
    for row in report["events"]:
        writer.writerow({f: _safe_cell(row.get(f, "")) for f in CSV_FIELDS})
    return out.getvalue()
