import json
import re
from collections import Counter, defaultdict, deque
from datetime import timedelta
from pathlib import Path

from .config import (
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_SECONDS,
    MAX_RECENT_EVENTS,
    SIGNATURES_FILE,
)
from .parser import decode_payload

MAX_HAYSTACK_CHARS = 4096  # bounds regex work on very long / hostile lines


def load_signatures():
    return json.loads(Path(SIGNATURES_FILE).read_text(encoding="utf-8"))


SIGNATURES = load_signatures()
COMPILED = [
    {**sig, "compiled": [re.compile(p) for p in sig["patterns"]]}
    for sig in SIGNATURES
]


def build_haystack(event):
    raw = f'{event["path"]} {event["user_agent"]} {event.get("referrer", "")}'
    decoded = decode_payload(raw)
    # Scan both raw and decoded forms so encoded and plain payloads are caught.
    return f"{raw} {decoded}"[:MAX_HAYSTACK_CHARS]


def detect_signatures(event):
    haystack = build_haystack(event)
    matches = []
    for sig in COMPILED:
        if any(p.search(haystack) for p in sig["compiled"]):
            matches.append({"type": sig["id"], "label": sig["label"], "severity": sig["severity"]})
    return matches


def analyze(events):
    """Consume an iterable of events in a single pass (no need to hold them all).

    Returns (attacks, type_counts, ip_counts, hour_counts, severity_counts).
    `attacks` only keeps the most recent MAX_RECENT_EVENTS entries; the counters
    always cover every detection.
    """
    attacks = deque(maxlen=MAX_RECENT_EVENTS)
    type_counts, ip_counts = Counter(), Counter()
    hour_counts, severity_counts = Counter(), Counter()
    failed = defaultdict(deque)
    brute_force_reported = set()

    for event in events:
        matches = detect_signatures(event)
        dt = event["datetime"]
        hour = dt.strftime("%Y-%m-%d %H:00") if dt else "unknown"

        for m in matches:
            attacks.append({**event, "attack_type": m["type"], "attack_label": m["label"],
                            "severity": m["severity"], "detection": "signature"})
            type_counts[m["type"]] += 1
            ip_counts[event["ip"]] += 1
            severity_counts[m["severity"]] += 1
            hour_counts[hour] += 1

        if event["status"] == 401 and dt:
            q = failed[event["ip"]]
            cutoff = dt - timedelta(seconds=BRUTE_FORCE_WINDOW_SECONDS)
            while q and q[0] < cutoff:
                q.popleft()
            q.append(dt)
            if len(q) >= BRUTE_FORCE_THRESHOLD and event["ip"] not in brute_force_reported:
                brute_force_reported.add(event["ip"])
                attacks.append({**event, "attack_type": "brute_force",
                                "attack_label": "Brute Force", "severity": "high",
                                "detection": "401 frequency"})
                type_counts["brute_force"] += 1
                ip_counts[event["ip"]] += 1
                severity_counts["high"] += 1
                hour_counts[hour] += 1

    return attacks, type_counts, ip_counts, hour_counts, severity_counts
