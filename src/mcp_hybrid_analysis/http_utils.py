"""Centralized HTTP request handling with unified error handling."""

import json
import logging
from typing import Any

import httpx

from mcp_hybrid_analysis.config import settings
from mcp_hybrid_analysis.errors import auth_error_response, http_error_response

logger = logging.getLogger(__name__)

# Transport-level failures are nested under this reserved key so they cannot be
# confused with the upstream API's own "error" field, which appears in successful
# responses too (as null on SUCCESS, as a message string on ERROR states).
REQUEST_ERROR_KEY = "_request_error"


def request_error(result: dict[str, Any]) -> dict[str, Any] | None:
    """Return the transport error payload if the request failed, else None."""
    if isinstance(result, dict):
        error = result.get(REQUEST_ERROR_KEY)
        if isinstance(error, dict):
            return error
    return None


async def make_api_request(
    http_client: httpx.AsyncClient,
    method: str,
    url: str,
    params: dict[str, Any] | None = None,
    data: dict[str, Any] | None = None,
    files: dict[str, Any] | None = None,
    error_context: str = "",
    return_headers: bool = False,
) -> dict[str, Any] | tuple[dict[str, Any], httpx.Headers]:
    """
    Make an API request with unified error handling.

    Args:
        http_client: The httpx AsyncClient instance
        method: HTTP method (GET, POST, etc.)
        url: URL path (will be appended to base URL)
        params: URL query parameters
        data: Form data for POST requests
        files: Files for multipart upload
        error_context: Additional context for error messages
        return_headers: If True, returns tuple of (response_json, headers)

    Returns:
        Dict with either the successful JSON response or error information
        If return_headers=True, returns tuple of (response_json, headers)
    """
    try:
        response = await http_client.request(
            method=method,
            url=url,
            params=params,
            data=data,
            files=files,
            headers={"api-key": settings.HYBRID_ANALYSIS_KEY},
        )
        response.raise_for_status()
        json_data = response.json()

        if return_headers:
            return json_data, response.headers
        return json_data

    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error {error_context}: {e.response.status_code} - {e.response.text}")

        if e.response.status_code == 403:
            error_response = auth_error_response("Use validate_api_key tool to test your API key")
        else:
            error_response = http_error_response(e.response.status_code, e.response.text)

        if return_headers:
            return error_response, e.response.headers
        return error_response

    except httpx.RequestError as e:
        logger.error(f"Request error {error_context}: {e}")
        error_response = {"error": "Request failed", "details": str(e)}
        if return_headers:
            return error_response, httpx.Headers()
        return error_response

    except json.JSONDecodeError as e:
        logger.warning(f"JSON decode error {error_context}: {e}")
        error_response = {"error": "Invalid JSON response", "details": str(e)}
        if return_headers:
            return error_response, httpx.Headers()
        return error_response

    except Exception as e:
        logger.error(f"Unexpected error {error_context}: {e}")
        error_response = {"error": "Unexpected error occurred", "details": str(e)}
        if return_headers:
            return error_response, httpx.Headers()
        return error_response
