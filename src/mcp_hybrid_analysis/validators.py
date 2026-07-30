"""Input validation utilities."""

import re
from typing import Any

HASH_LENGTHS = {32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512"}

DATE_PATTERN = r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$"
URL_PATTERN = r"^https?://.+"


def validate_hash(hash_value: str) -> dict[str, Any] | None:
    """Validate hash format. Returns error dict if invalid, None if valid."""
    hash_clean = hash_value.strip().lower()
    if len(hash_clean) not in HASH_LENGTHS:
        valid_formats = ", ".join(f"{name} ({length} chars)" for length, name in HASH_LENGTHS.items())
        return {
            "error": "Invalid hash format",
            "details": f"Hash must be one of: {valid_formats}",
        }
    return None


def validate_date_format(date_str: str, field_name: str) -> dict[str, Any] | None:
    """Validate date format. Returns error dict if invalid, None if valid."""
    if not re.match(DATE_PATTERN, date_str):
        return {
            "error": f"Invalid {field_name} format",
            "details": "Use format: YYYY-MM-DD HH:MM (e.g., 2024-01-01 00:00)",
        }
    return None


def validate_url(url: str) -> dict[str, Any] | None:
    """Validate URL format. Returns error dict if invalid, None if valid."""
    if not url or not url.strip():
        return {"error": "Invalid URL", "details": "URL cannot be empty"}

    if not re.match(URL_PATTERN, url.strip(), re.IGNORECASE):
        return {"error": "Invalid URL format", "details": "URL must start with http:// or https://"}

    return None


def validate_verdict(verdict: int) -> dict[str, Any] | None:
    """Validate verdict value. Returns error dict if invalid, None if valid."""
    if verdict not in [1, 2, 3, 4, 5]:
        return {
            "error": "Invalid verdict value",
            "details": "Verdict must be 1 (whitelisted), 2 (no verdict), 3 (no specific threat), 4 (suspicious), or 5 (malicious)",
        }
    return None


def validate_report_id(report_id: str) -> dict[str, Any] | None:
    """Validate report ID. Returns error dict if invalid, None if valid."""
    if not report_id or not report_id.strip():
        return {"error": "Invalid report_id", "details": "Report ID cannot be empty"}
    return None
