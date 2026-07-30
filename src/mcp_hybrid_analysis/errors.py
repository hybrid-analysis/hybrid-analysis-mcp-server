"""Centralized error handling and response formatting."""

from typing import Any

# Reusable error messages
AUTH_ERROR_MESSAGE = {
    "error": "Authentication failed (403 Forbidden)",
    "details": "Your API key is invalid, expired, or missing required permissions",
    "how_to_fix": (
        "To obtain a valid API key:\n"
        "1. Log into www.hybrid-analysis.com\n"
        "2. Open your profile\n"
        "3. Navigate to the 'API Key' tab\n"
        "4. Copy your API key and update HYBRID_ANALYSIS_KEY in your .env file"
    ),
}


def auth_error_response(additional_context: str = "") -> dict[str, Any]:
    """Return a standardized 403 authentication error response."""
    response = AUTH_ERROR_MESSAGE.copy()
    if additional_context:
        response["troubleshooting"] = additional_context
    return response


def http_error_response(status_code: int, details: str, note: str = "") -> dict[str, Any]:
    """Return a standardized HTTP error response."""
    response = {
        "error": f"HTTP error: {status_code}",
        "details": details,
    }
    if note:
        response["note"] = note
    return response


def validation_error_response(field: str, message: str) -> dict[str, Any]:
    """Return a standardized validation error response."""
    return {
        "error": f"Invalid {field}",
        "details": message,
    }
