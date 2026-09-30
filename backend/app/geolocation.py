import ipaddress
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache


RESERVED_LABELS = {
    "private": "Private / LAN address",
    "loopback": "Loopback address",
    "reserved": "Reserved / documentation address",
    "link_local": "Link-local address",
    "multicast": "Multicast address",
    "unspecified": "Unspecified address",
}

def classify_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if addr.is_private:
        return "private"
    if addr.is_link_local:
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_reserved or addr.is_unspecified:
        return "reserved"
    return "public"

@lru_cache(maxsize=1024)
def locate_public_ip(ip):
    """Best-effort public-IP geolocation. Never blocks report generation on failure."""
    if classify_ip(ip) != "public":
        kind = classify_ip(ip)
        return {
            "ip": ip, "status": kind, "label": RESERVED_LABELS.get(kind, "Non-routable address"),
            "country": None, "country_code": None, "city": None, "region": None,
            "latitude": None, "longitude": None, "isp": None, "org": None,
        }
    try:
        import requests
        response = requests.get(
            f"https://ipwho.is/{ip}",
            timeout=3,
            headers={"User-Agent": "LogLens/1.0 security-log-dashboard"},
        )
        response.raise_for_status()
        data = response.json()
        if not data.get("success"):
            raise ValueError("geolocation lookup failed")
        return {
            "ip": ip, "status": "located", "label": "Public IP",
            "country": data.get("country"), "country_code": data.get("country_code"),
            "city": data.get("city"), "region": data.get("region"),
            "latitude": data.get("latitude"), "longitude": data.get("longitude"),
            "isp": data.get("connection", {}).get("isp"),
            "org": data.get("connection", {}).get("org"),
        }
    except Exception:
        return {
            "ip": ip, "status": "lookup_failed", "label": "Geolocation unavailable",
            "country": None, "country_code": None, "city": None, "region": None,
            "latitude": None, "longitude": None, "isp": None, "org": None,
        }

def enrich_attackers(attackers):
    """Locate unique attacker IPs without making geolocation a hard dependency."""
    if not attackers:
        return []
    # Keep lookups bounded and parallel so one slow provider does not serialize
    # the entire report. Failed lookups are represented in the report, never raised.
    with ThreadPoolExecutor(max_workers=min(5, len(attackers))) as pool:
        geos = list(pool.map(lambda item: locate_public_ip(item["ip"]), attackers))
    return [{**attacker, "geo": geo} for attacker, geo in zip(attackers, geos)]
