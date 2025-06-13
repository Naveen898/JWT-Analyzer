# utils/logger.py

import logging
import os

LOG_FILE = "logs/jwt_analysis.log"

def setup_logger():
    os.makedirs("logs", exist_ok=True)
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )

def log_token_analysis(token_snippet, risk_level, issues_found="", source="CLI"):
    logging.info(
        f"Source: {source} | Token: {token_snippet} | Risk: {risk_level} | Issues: {issues_found}"
    )
