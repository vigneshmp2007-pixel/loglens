from app.parser import parse_line, iter_parsed_lines
from app.detector import analyze, detect_signatures
from app.report import make_report, report_csv
from app.config import DEMO_LOG_FILE


def line(path, status=200, ip="10.0.0.1", ts="27/Sep/2026:08:00:01 +0530", ua="Test"):
    return f'{ip} - - [{ts}] "GET {path} HTTP/1.1" {status} 12 "-" "{ua}"'


def types_for(path):
    return {m["type"] for m in detect_signatures(parse_line(line(path)))}


def test_parse():
    row = parse_line('127.0.0.1 - - [27/Sep/2026:08:00:01 +0530] "GET / HTTP/1.1" 200 12 "-" "Test"')
    assert row["ip"] == "127.0.0.1"
    assert row["method"] == "GET"
    assert row["status"] == 200


def test_path_with_spaces_is_kept_whole():
    row = parse_line(line("/search?q=' OR 1=1"))
    assert row["path"] == "/search?q=' OR 1=1"
    assert row["protocol"] == "HTTP/1.1"


def test_malformed_and_blank_lines():
    rows = list(iter_parsed_lines([b"garbage line\n", b"\n", (line("/") + "\n").encode()]))
    assert rows[0] is None          # malformed
    assert len(rows) == 2           # blank line skipped
    assert rows[1]["status"] == 200


def test_sql_injection_detected():
    assert "sql_injection" in types_for("/search?q=' OR 1=1")
    assert "sql_injection" in types_for("/p?id=1 UNION SELECT username,password FROM users--")


def test_url_encoded_xss_detected():
    assert "xss" in types_for("/c?q=%3Cscript%3Ealert(1)%3C/script%3E")


def test_directory_traversal_detected():
    assert "directory_traversal" in types_for("/../../etc/passwd")
    assert "directory_traversal" in types_for("/%2e%2e/%2e%2e/etc/passwd")


def test_clean_request_not_flagged():
    assert types_for("/index.html") == set()


def test_brute_force_needs_threshold_within_window():
    lines = [line("/login", 401, ip="1.2.3.4", ts=f"27/Sep/2026:08:10:{s:02d} +0530") for s in range(0, 50, 10)]
    events = [parse_line(l) for l in lines]
    attacks, types, *_ = analyze(events)
    assert types["brute_force"] == 1
    # 4 failures are not enough
    attacks, types, *_ = analyze(events[:4])
    assert types["brute_force"] == 0


def test_demo_log_end_to_end():
    with DEMO_LOG_FILE.open("rb") as stream:
        events = (e for e in iter_parsed_lines(stream) if e)
        attacks, types, ips, hours, sev = analyze(events)
    assert set(types) == {"sql_injection", "xss", "directory_traversal", "brute_force"}
    report = make_report(12, 0, attacks, types, ips, hours, sev)
    assert report["summary"]["total_attacks"] == sum(types.values())


def test_csv_formula_injection_is_neutralised():
    report = {"events": [{"ip": "1.1.1.1", "path": "=HYPERLINK(\"http://evil\")"}]}
    assert "'=HYPERLINK" in report_csv(report)


def test_geolocation_does_not_fake_reserved_ips():
    from app.geolocation import locate_public_ip
    geo = locate_public_ip("203.0.113.10")
    assert geo["status"] in {"private", "reserved"}
    assert geo["latitude"] is None
    assert geo["longitude"] is None
