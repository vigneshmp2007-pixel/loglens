# LogLens — Cyberpunk Security Log Intelligence Console

LogLens is a full-stack security-log analysis dashboard. It parses Apache/Nginx-style Common Log Format logs, detects common web attacks, correlates attacker IPs, and displays routable public IP origins on an interactive world map.

## Key features
- Cyberpunk SOC-style responsive UI
- SQL injection, XSS, directory traversal and brute-force detection
- Interactive global attack-origin map using OpenStreetMap + Leaflet
- Best-effort public-IP geolocation with `ipwho.is`
- Private/loopback/reserved IPs are explicitly not mapped, preventing false locations
- Top attacker table with country/city when available
- Attack timeline, attack-type charts, recent detections
- CSV export with formula-injection protection
- Streaming log parser with bounded report storage
- Demo log included

> Geolocation is approximate IP-based location, not a physical-address locator. Accuracy depends on the IP geolocation provider and network.

## Run

### Backend (Windows PowerShell)
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```
API: `http://127.0.0.1:5000`

### Frontend
Open a second terminal:
```powershell
cd frontend
npm install
npm run dev
```
Open the Vite URL shown in the terminal.

### Production frontend build
```powershell
npm run build
npm run preview
```

### Tests
```powershell
cd backend
pip install -r requirements-dev.txt
python -m pytest -q
```

## Map behavior
- Public IP: queried for approximate city/region/country coordinates.
- Private IP (for example 192.168.x.x): shown as non-routable and not plotted.
- Reserved/documentation IP (for example 198.51.100.x / 203.0.113.x): shown as reserved/test data and not plotted.
- Lookup failure: kept in the attacker table with `Geolocation unavailable`.

The included demo log intentionally uses documentation/test IP ranges, so it will not pretend those sources came from real countries. Upload a real log containing public attacker IPs to populate the map with actual IP-based locations.
