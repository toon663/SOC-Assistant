from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
WINDOWS_LOG_DIR = DATA_DIR / "windows_logs"
PROCESSED_DIR = DATA_DIR / "processed"
MODEL_DIR = ROOT / "models"
OUTPUT_DIR = ROOT / "outputs"
KNOWLEDGE_DIR = ROOT / "knowledge"

for folder in (RAW_DIR, WINDOWS_LOG_DIR, PROCESSED_DIR, MODEL_DIR, OUTPUT_DIR, KNOWLEDGE_DIR):
    folder.mkdir(parents=True, exist_ok=True)

UNSW_DATA_PATH = RAW_DIR / "UNSW-NB15_Dataset2.csv"
UNSW_RF_PATH = MODEL_DIR / "unsw_random_forest.joblib"
UNSW_ISO_PATH = MODEL_DIR / "unsw_isolation_forest.joblib"
UNSW_META_PATH = MODEL_DIR / "unsw_metadata.json"
WINDOWS_ISO_PATH = MODEL_DIR / "windows_isolation_forest.joblib"
WINDOWS_META_PATH = MODEL_DIR / "windows_metadata.json"
INCIDENT_DB = OUTPUT_DIR / "soc_incidents.db"
EVENTS_CSV = WINDOWS_LOG_DIR / "windows_events.csv"
ALERTS_CSV = OUTPUT_DIR / "alerts.csv"
