import os
import logging
from datetime import datetime

# Setup log directory
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Configure logging
log_path = os.path.join(LOG_DIR, "jwt_analysis.log")
logging.basicConfig(
    filename=log_path,
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.INFO
)

def log_analysis(token_summary):
    logging.info("Analysis Result: %s", token_summary)

def current_timestamp():
    return datetime.utcnow().isoformat()

# Optional replay detection placeholder
def detect_replay(token_id, seen_ids):
    if token_id in seen_ids:
        return True
    seen_ids.add(token_id)
    return False
