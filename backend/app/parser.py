import re
from datetime import datetime, timezone
from urllib.parse import unquote_plus

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?\s*$'
)


def parse_timestamp(value):
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            dt = datetime.strptime(value, fmt)
        except ValueError:
            continue
        # Naive timestamps are assumed UTC so aware/naive values can be compared.
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return None


def split_request(request):
    """Split 'METHOD /path with spaces HTTP/1.1' safely.

    Attack payloads often contain raw spaces (e.g. "' OR 1=1"), so we take the
    method from the front and the protocol from the back; everything in
    between is the path.
    """
    request = request.strip()
    if not request or request == "-":
        return "", "", ""
    parts = request.split(" ")
    method = parts[0]
    protocol = ""
    if len(parts) > 2 and parts[-1].upper().startswith("HTTP/"):
        protocol = parts[-1]
        parts = parts[:-1]
    path = " ".join(parts[1:])
    return method, path, protocol


def decode_payload(value, rounds=2):
    """URL-decode (up to twice) so %3Cscript%3E and double-encoded payloads match."""
    for _ in range(rounds):
        decoded = unquote_plus(value)
        if decoded == value:
            break
        value = decoded
    return value


def parse_line(line):
    line = line.rstrip("\r\n")
    match = LOG_PATTERN.match(line)
    if not match:
        return None
    data = match.groupdict()
    method, path, protocol = split_request(data["request"])
    return {
        "ip": data["ip"],
        "timestamp": data["timestamp"],
        "datetime": parse_timestamp(data["timestamp"]),
        "method": method,
        "path": path,
        "protocol": protocol,
        "status": int(data["status"]),
        "size": int(data["size"]) if data["size"].isdigit() else 0,
        "referrer": data.get("referrer") or "-",
        "user_agent": data.get("user_agent") or "-",
    }


def iter_parsed_lines(stream):
    """Stream the upload one line at a time.

    Yields a dict for each parsed line and None for each malformed line.
    Blank lines are skipped (they are not malformed log entries).
    """
    for raw in stream:
        line = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
        if not line.strip():
            continue
        yield parse_line(line)
