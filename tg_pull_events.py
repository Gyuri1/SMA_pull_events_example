#!/usr/bin/env python3
"""
tg_pull_events.py

Pulls structured JSON-formatted events from Cisco Secure Malware Analytics
(formerly Threat Grid) and writes them to a log file.

Usage:
    python3 tg_pull_events.py                          # defaults to /var/log/Threatgrid.log
    python3 tg_pull_events.py -l /path/to/custom.log   # custom log file path
    python3 tg_pull_events.py --logfile /tmp/tg.log     # long-form flag

Requirements:
  - Python 3.6+
  - requests library (pip install requests)
  - tg_config.py in the same directory (or on PYTHONPATH)

Cisco Secure Malware Analytics API Reference:
  https://panacea.threatgrid.com/mask/doc/mask/index
"""

import argparse
import json
import logging
import os
import sys
from logging.handlers import RotatingFileHandler

import requests

# ── Import authentication parameters from the separate config file ──────────
try:
    from tg_config import API_KEY, BASE_URL
except ImportError:
    sys.exit(
        "ERROR: Cannot import tg_config.py. "
        "Ensure tg_config.py exists in the same directory and contains "
        "API_KEY and BASE_URL."
    )

# ── Default log file path ──────────────────────────────────────────────────
DEFAULT_LOG_FILE = "/var/log/Threatgrid.log"


# ── Argument parsing ───────────────────────────────────────────────────────

def parse_arguments() -> argparse.Namespace:
    """
    Parses command-line arguments.

    Returns:
        Namespace with the parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Pull structured JSON events from Cisco Secure Malware Analytics "
            "(Threat Grid) and write them to a log file."
        )
    )
    parser.add_argument(
        "-l", "--logfile",
        type=str,
        default=DEFAULT_LOG_FILE,
        help=(
            f"Path to the output log file. "
            f"Default: {DEFAULT_LOG_FILE}"
        ),
    )
    return parser.parse_args()


# ── Logging configuration ──────────────────────────────────────────────────

def configure_logging(log_file: str) -> logging.Logger:
    """
    Configures and returns a logger that writes to the specified file and
    to stdout.

    Args:
        log_file: Absolute or relative path to the desired log file.

    Returns:
        Configured Logger instance.
    """
    logger = logging.getLogger("ThreatGridEvents")
    logger.setLevel(logging.INFO)

    # Avoid adding duplicate handlers if this function is called more than once
    if logger.handlers:
        return logger

    # Ensure the parent directory exists
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
        except OSError as e:
            sys.exit(f"ERROR: Cannot create log directory '{log_dir}': {e}")

    # RotatingFileHandler — 10 MB max, 5 backups
    file_handler = RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=5
    )
    file_handler.setLevel(logging.INFO)

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Console handler for interactive debugging
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


# ── API interaction ─────────────────────────────────────────────────────────

def get_threat_grid_submissions(
    api_key: str,
    base_url: str,
    logger: logging.Logger,
) -> dict | None:
    """
    Fetches submission aggregation events from Cisco Secure Malware Analytics.

    Endpoint:
        GET /api/v3/aggregations/submissions

    Docs: https://panacea.threatgrid.com/mask/doc/mask/index

    Args:
        api_key:  Cisco Secure Malware Analytics API key.
        base_url: Base URL of the Threat Grid cloud instance.
        logger:   Logger instance for recording errors.

    Returns:
        Parsed JSON response as a Python dict, or None on failure.
    """

    url = f"{base_url}/api/v3/aggregations/submissions"

    headers = {
        "Accept": "application/json",
        "Authorization": f"bearer {api_key}",
    }

    params = {
        "span": "2026-03-07T23:59:59+01:00/2026-03-14T22:53:11+01:00",
        "visibility": "org",
        "buckets": "day|status",
        "tz": "Europe/Budapest",
        "tg-dc": "US",
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        return response.json()

    except requests.exceptions.HTTPError as http_err:
        logger.error(
            "HTTP error: %s | Status: %s | Body: %s",
            http_err, response.status_code, response.text,
        )
    except requests.exceptions.ConnectionError as conn_err:
        logger.error("Connection error: %s", conn_err)
    except requests.exceptions.Timeout as timeout_err:
        logger.error("Timeout error: %s", timeout_err)
    except requests.exceptions.RequestException as req_err:
        logger.error("Request error: %s", req_err)

    return None


def save_events_to_log(events: dict, logger: logging.Logger) -> None:
    """
    Serialises the event data as structured JSON and writes it to the log.

    Args:
        events: The parsed JSON response dictionary from the API.
        logger: Logger instance used for output.
    """
    json_str = json.dumps(events, indent=4, default=str)
    logger.info("Threat Grid Events:\n%s", json_str)


# ── Main entry point ───────────────────────────────────────────────────────

def main() -> None:
    args = parse_arguments()
    log_file = args.logfile

    logger = configure_logging(log_file)

    logger.info("Log file path: %s", log_file)
    logger.info("Starting Cisco Secure Malware Analytics event pull …")

    result = get_threat_grid_submissions(
        api_key=API_KEY, base_url=BASE_URL, logger=logger
    )

    if result:
        save_events_to_log(result, logger)
        logger.info("Events successfully written to %s", log_file)
    else:
        logger.warning("Failed to retrieve events from Threat Grid.")


if __name__ == "__main__":
    main()