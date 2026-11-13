"""
detector.py - Analytical processing and detection engine for the AV7SCM Mini-SIEM.

Public entry points:
    process_log_data(json_content)   -> takes a raw JSON string (array of log objects)
    process_log_file(json_file_path) -> reads a JSON file and delegates to the above

Detection rule: 5 or more failed logins from one source IP within a 60-second sliding
window raises a CRITICAL alert. After a trigger, that IP's tracking queue is cleared so
the same burst does not generate duplicate alerts.
"""

from __future__ import annotations

import json
import logging
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Optional

import database

logger = logging.getLogger("mini_siem.detector")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

FAILURE_THRESHOLD = 5
WINDOW = timedelta(seconds=60)
SEVERITY_CRITICAL = "CRITICAL"

_FAILED_VALUES = {"failed", "failure", "fail", "failed_login", "denied"}
_SUCCESS_VALUES = {"success", "succeeded", "successful", "ok", "login_success"}

_FALLBACK_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y/%m/%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%dT%H:%M",
    "%d-%b-%Y %H:%M:%S",
)


def parse_timestamp(raw) -> Optional[datetime]:
    """
    Convert many timestamp variations into a timezone-aware UTC datetime.
    Handles ISO 8601 (with 'Z', offsets, or no zone), epoch seconds/milliseconds,
    and a handful of common formats. Naive values are assumed to be UTC.
    Returns None if the value cannot be understood.
    """
    if raw is None or isinstance(raw, bool):
        return None

    if isinstance(raw, (int, float)):
        try:
            value = float(raw)
            if value > 1e11:  # milliseconds
                value /= 1000.0
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    if not isinstance(raw, str):
        return None

    text = raw.strip()
    if not text:
        return None

    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"

    parsed: Optional[datetime] = None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in _FALLBACK_FORMATS:
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue

    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def to_iso_utc(dt: datetime) -> str:
    """Format a datetime as a clean UTC ISO 8601 string ending in 'Z'."""
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_status(raw) -> Optional[str]:
    """Map a raw event value to 'failed' or 'success'; return None if unrecognized."""
    if not isinstance(raw, str):
        return None
    value = raw.strip().lower()
    if value in _FAILED_VALUES:
        return "failed"
    if value in _SUCCESS_VALUES:
        return "success"
    return None


def build_remediation_message(
    source_ip: str, attempts: int, usernames: list[str], first_seen: str, last_seen: str
) -> str:
    """Write a plain-language remediation plan for a non-technical business owner."""
    accounts = ", ".join(sorted(set(usernames))) if usernames else "unknown accounts"
    return (
        f"WHAT HAPPENED: A computer at internet address {source_ip} tried and failed to log in "
        f"{attempts} times in under a minute (between {first_seen} and {last_seen} UTC). "
        f"The accounts targeted were: {accounts}. A speed like this is almost never a real "
        f"person who forgot a password. It is usually automated software guessing passwords.\n\n"
        f"WHY IT MATTERS: If one of those guesses succeeds, the attacker could read or steal "
        f"company data, send email as you, or lock you out of your systems.\n\n"
        f"WHAT TO DO RIGHT NOW:\n"
        f"1. Block the address {source_ip}. Log in to your firewall or router (or ask your IT "
        f"provider) and add this address to the block list so it cannot reach your systems.\n"
        f"2. Change the passwords for the targeted accounts ({accounts}). Use long, unique "
        f"passwords and make sure each one is different from passwords used elsewhere.\n"
        f"3. Check your history. Look through your login records for any SUCCESSFUL login from "
        f"{source_ip}. If you find one, treat that account as compromised and tell your IT "
        f"provider immediately.\n"
        f"4. Turn on two-step verification (a code sent to a phone) for these accounts so a "
        f"stolen password alone is not enough.\n"
        f"5. Write down what happened and when, and tell your team to report anything unusual "
        f"such as unexpected password-reset emails or strange account activity."
    )


def process_log_data(json_content: str) -> dict:
    """
    Parse a raw JSON string containing an array of log objects, store every valid event,
    run the sliding-window brute-force detection, and store any resulting alerts.

    Expected keys per record: 'timestamp', 'source_ip', 'event', 'username'.

    Returns a summary dictionary:
        {
          "success": bool,
          "error": str | None,
          "total_records": int,
          "events_processed": int,
          "invalid_records": int,
          "alerts_generated": int,
        }
    """
    summary = {
        "success": False,
        "error": None,
        "total_records": 0,
        "events_processed": 0,
        "invalid_records": 0,
        "alerts_generated": 0,
    }

    # 1. Parse the JSON safely.
    try:
        records = json.loads(json_content)
    except json.JSONDecodeError as exc:
        message = f"Invalid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})."
        logger.error(message)
        summary["error"] = message
        return summary
    except (TypeError, ValueError) as exc:
        message = f"Could not read log content: {exc}"
        logger.error(message)
        summary["error"] = message
        return summary

    if not isinstance(records, list):
        summary["error"] = "The log file must contain a JSON array of log objects."
        logger.error(summary["error"])
        return summary

    summary["total_records"] = len(records)

    # 2. Standardize records, skipping any that are malformed.
    standardized: list[tuple[datetime, str, str, str]] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            summary["invalid_records"] += 1
            logger.warning("Record %d skipped: not a JSON object.", index)
            continue

        when = parse_timestamp(record.get("timestamp"))
        status = _normalize_status(record.get("event"))
        source_ip = record.get("source_ip")
        username = record.get("username")

        if (
            when is None
            or status is None
            or not isinstance(source_ip, str)
            or not source_ip.strip()
            or not isinstance(username, str)
            or not username.strip()
        ):
            summary["invalid_records"] += 1
            logger.warning("Record %d skipped: missing or malformed fields.", index)
            continue

        standardized.append((when, source_ip.strip(), status, username.strip()))

    # 3. Sort chronologically (stable sort keeps original order for identical timestamps).
    standardized.sort(key=lambda item: item[0])

    # 4. Persist all valid events in one atomic transaction.
    try:
        database.init_db()
        database.insert_events_bulk(
            [(to_iso_utc(when), ip, status, user) for when, ip, status, user in standardized]
        )
    except Exception as exc:  # database errors must never crash the UI
        message = f"Database error while saving events: {exc}"
        logger.exception(message)
        summary["error"] = message
        return summary
    summary["events_processed"] = len(standardized)

    # 5. Sliding-window detection. One queue of (time, username) per source IP.
    tracking: dict[str, deque] = {}
    try:
        for when, ip, status, user in standardized:
            if status != "failed":
                continue

            queue = tracking.setdefault(ip, deque())
            queue.append((when, user))

            # Drop failures that fell outside the 60-second window.
            while queue and (when - queue[0][0]) > WINDOW:
                queue.popleft()

            if len(queue) >= FAILURE_THRESHOLD:
                attempts = len(queue)
                usernames = [name for _, name in queue]
                first_seen = to_iso_utc(queue[0][0])
                last_seen = to_iso_utc(when)
                message = build_remediation_message(ip, attempts, usernames, first_seen, last_seen)
                database.insert_alert(SEVERITY_CRITICAL, ip, attempts, last_seen, message)
                summary["alerts_generated"] += 1
                logger.info("CRITICAL alert raised for %s (%d failures).", ip, attempts)
                queue.clear()  # prevent redundant double-alerts for this burst
    except Exception as exc:
        message = f"Database error while saving alerts: {exc}"
        logger.exception(message)
        summary["error"] = message
        return summary

    summary["success"] = True
    return summary


def process_log_file(json_file_path: str) -> dict:
    """Read a JSON log file from disk and analyze it with process_log_data()."""
    try:
        with open(json_file_path, "r", encoding="utf-8-sig") as handle:
            content = handle.read()
    except (OSError, UnicodeDecodeError) as exc:
        message = f"Could not read file '{json_file_path}': {exc}"
        logger.error(message)
        return {
            "success": False,
            "error": message,
            "total_records": 0,
            "events_processed": 0,
            "invalid_records": 0,
            "alerts_generated": 0,
        }
    return process_log_data(content)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python detector.py <path_to_logs.json>")
        raise SystemExit(1)
    print(process_log_file(sys.argv[1]))
