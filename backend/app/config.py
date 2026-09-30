from pathlib import Path
BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
SIGNATURES_FILE = DATA_DIR / "signatures.json"
DEMO_LOG_FILE = DATA_DIR / "demo.log"
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 300
MAX_RECENT_EVENTS = 5000
