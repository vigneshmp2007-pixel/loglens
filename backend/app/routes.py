from flask import Blueprint, jsonify, request, Response
from .config import DEMO_LOG_FILE
from .parser import iter_parsed_lines
from .detector import analyze, SIGNATURES
from .report import make_report, REPORTS, report_csv

api = Blueprint("api", __name__)


def process_stream(stream):
    """Parse + analyze in one streaming pass; memory stays bounded."""
    counts = {"parsed": 0, "malformed": 0}

    def events():
        for event in iter_parsed_lines(stream):
            if event is None:
                counts["malformed"] += 1
            else:
                counts["parsed"] += 1
                yield event

    attacks, type_counts, ip_counts, hour_counts, severity_counts = analyze(events())
    return make_report(counts["parsed"], counts["malformed"], attacks,
                       type_counts, ip_counts, hour_counts, severity_counts)


@api.get("/health")
def health():
    return jsonify({"status": "ok", "service": "loglens-api"})


@api.get("/signatures")
def signatures():
    return jsonify(SIGNATURES)


@api.post("/analyze")
def analyze_upload():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return jsonify({"error": "No .log file supplied in field 'file'"}), 400
    if not uploaded.filename.lower().endswith(".log"):
        return jsonify({"error": "Only .log files are supported"}), 400
    return jsonify(process_stream(uploaded.stream))


@api.post("/demo")
def demo():
    with DEMO_LOG_FILE.open("rb") as stream:
        return jsonify(process_stream(stream))


@api.get("/report/<report_id>")
def get_report(report_id):
    report = REPORTS.get(report_id)
    return jsonify(report) if report else (jsonify({"error": "Report not found"}), 404)


@api.get("/report/<report_id>/csv")
def get_csv(report_id):
    report = REPORTS.get(report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    return Response(report_csv(report), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="loglens-{report_id}.csv"'})
