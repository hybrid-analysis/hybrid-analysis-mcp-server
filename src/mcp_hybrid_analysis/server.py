import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated, Any, Literal
from urllib.parse import quote

import httpx
import truststore
from fastmcp import Context, FastMCP
from pydantic import Field

from mcp_hybrid_analysis.config import settings
from mcp_hybrid_analysis.http_utils import make_api_request, request_error
from mcp_hybrid_analysis.logging_config import setup_logging
from mcp_hybrid_analysis.validators import (
    validate_date_format,
    validate_hash,
    validate_report_id,
    validate_url,
    validate_verdict,
)

setup_logging()
logger = logging.getLogger(__name__)
truststore.inject_into_ssl()


@dataclass(frozen=True)
class AppContext:
    http_client: httpx.AsyncClient


@asynccontextmanager
async def app_lifespan(server: FastMCP):
    async with httpx.AsyncClient(
        base_url=settings.HYBRID_ANALYSIS_API_URL,
        headers={"User-Agent": settings.USER_AGENT, "accept": "application/json"},
        timeout=30,
    ) as http:
        try:
            yield AppContext(http_client=http)
        finally:
            ...


mcp = FastMCP(name="hybrid-analysis", lifespan=app_lifespan)


# ============================================================================
# MCP Resources - Provide context about capabilities
# ============================================================================


@mcp.resource("hybrid-analysis://capabilities")
async def get_capabilities() -> str:
    """
    Overview of Hybrid Analysis malware sandbox capabilities.

    Read this resource when the user mentions: files, samples, executables, malware,
    viruses, suspicious files, analysis, scanning, threat detection, or behavioral analysis.
    """
    return """# Hybrid Analysis Malware Sandbox

This MCP server provides malware analysis and threat intelligence capabilities.

## What You Can Do

**Analyze Suspicious Files**:
- Submit executables, documents, archives for sandbox detonation
- Get verdict: malicious (5), suspicious (4), no specific threat (3), no verdict (2), whitelisted (1)
- View behavior: network connections, registry changes, processes, dropped files
- See antivirus detections from 50+ engines
- Supported: EXE, DLL, PDF, DOCX, XLSX, ZIP, RAR, APK, scripts, and more

**Quick Scan Files** (Fast triage):
- Instant hash reputation lookup against known malware databases
- CrowdStrike ML static analysis
- MetaDefender multi-engine scan
- Results in seconds (no sandbox execution)
- Use for triage before full sandbox analysis

**Check File Hashes**:
- Look up if a file hash is known malware (MD5/SHA1/SHA256/SHA512)
- Get previous analysis reports without re-submitting files
- Faster than new submission if file was analyzed before

**Scan URLs and Websites**:
- Check if websites are phishing or malicious
- Analyze downloadable files from URLs without downloading locally
- Detect drive-by download attacks

## Common Workflows

### "Quick check this file" (fastest - seconds)
1. quick_scan_file(file_path="/path/to/file.exe")
2. If finished=false, poll with get_quick_scan(id)
3. Review ML verdict and AV detections

### "Analyze this suspicious file" (deep analysis - minutes)
1. submit_file(file_path="/path/to/file.exe", environment_id=110)
2. wait_for_report(job_id, return_summary=True) - auto-polls for 5-10 minutes
3. Review verdict, threat score, and behavioral indicators

### "Is this hash known malware?" (hash lookup - recommended)
1. get_labs_sample_overview(sha256) - aggregated view across all sandbox runs
2. Review verdict, AV detections, and list of sandbox job_ids
3. ONLY IF you need sandbox-run-specific details (network traffic, processes from a particular environment):
   - get_report_summary(job_id) for quick summary of that run

### "Search for related samples"
1. search_by_hash(hash_value) - finds all reports for a hash (any format: MD5/SHA1/SHA256)
2. Or search_labs(query) for advanced queries like 'tag:"ransomware"'

### "Check if this link is safe"
1. submit_url(url="https://...", environment_id=110)
2. wait_for_report(job_id, return_summary=True)
3. Check for phishing, malicious scripts, or dangerous downloads

### "Analyze multiple samples"
1. Loop through files, submit each with submit_file()
2. Collect all job_ids
3. Wait for all with wait_for_report() for each job_id
4. Compare verdicts across samples

## Environment IDs
- 110: Windows 7 64-bit (recommended for most Windows files)
- 120: Windows 10 64-bit
- 100: Windows 7 32-bit
- 200: Android (for APK files)
- 300: Linux Ubuntu 64-bit

## Important Notes
- Quick scan: instant (seconds), no behavioral analysis
- Full sandbox: 5-10 minutes, complete behavioral analysis
- Always use wait_for_report after submission (saves API calls vs manual polling)
- Free tier has daily quota limits
- Files are executed in isolated sandbox - safe for malware analysis
"""


@mcp.resource("hybrid-analysis://help/when-to-use")
async def get_when_to_use() -> str:
    """
    Guidance on when to use Hybrid Analysis MCP tools.

    Read this when deciding whether to use these tools for a user's request about files or analysis.
    """
    return """# When to Use Hybrid Analysis Tools

## ✅ USE these tools when the user mentions:

**File Analysis Keywords**:
- "analyze [file]", "scan [file]", "check [file]", "inspect [file]"
- "is this file safe/malicious/suspicious/dangerous"
- "malware analysis", "virus scan", "threat analysis", "security analysis"
- "sandbox", "detonation", "behavioral analysis"
- File patterns: "case_*", "sample_*", "malware_*", "suspicious_*", "unknown_*"
- File extensions: ".exe", ".dll", ".pdf", ".docx", ".apk", ".bin"
- "what does this file do", "file behavior"

**Quick Scan Keywords** (use quick_scan_file for fast triage):
- "quick scan", "quick check", "fast scan", "triage"
- "just check if it's malicious", "quick verdict"
- When scanning many files and need fast results

**Hash Lookups**:
- "check this hash", "is [hash] known malware", "hash reputation"
- "lookup [hash]", "search for [hash]"
- Any 32-char (MD5), 40-char (SHA1), 64-char (SHA256), or 128-char (SHA512) hex string

**URL/Website Scanning**:
- "is this link safe", "check this URL", "scan this website"
- "phishing check", "malicious website", "dangerous link"
- "scan this download link", "check before I visit"

**Investigation Workflows**:
- "what does this file do", "file capabilities"
- "network connections", "dropped files", "registry changes", "processes created"
- "antivirus detections", "threat verdict", "threat score"
- "analyze multiple samples", "batch scan", "check these files"

**Common Scenarios**:
- SOC/IR work: "suspicious attachment", "unknown executable from email"
- Malware research: "analyze this specimen", "reverse this sample"


## Choosing the Right Tool

| Need | Tool | Time |
|------|------|------|
| Fast verdict, many files | quick_scan_file | Seconds |
| Deep behavioral analysis | submit_file | 5-10 min |
| Hash lookup (aggregated overview) | get_labs_sample_overview | Instant |
| Hash search (find reports) | search_by_hash | Instant |
| Sandbox-run-specific details | get_report_summary | Instant |
| Website/URL check | submit_url | 5-10 min |

## Examples

✅ "Quick scan this file" → Use quick_scan_file
✅ "Triage these 10 samples" → Use quick_scan_file for each (fast)
✅ "Analyze the suspicious.exe file" → Use submit_file (deep analysis)
✅ "Check if malware_sample.bin is dangerous" → Use submit_file
✅ "Take a look at case_newfam files and analyze them" → Use submit_file for each
✅ "Is this download link safe?" → Use submit_url
✅ "What does unknown_binary do?" → Use submit_file (behavioral analysis)
✅ "What's known about this SHA256?" → Use get_labs_sample_overview (aggregated view first)
✅ "Check hash 44d88612fea8a8f36de82e1278abb02f" → Use search_by_hash or get_labs_sample_overview
✅ "Show me network traffic from that analysis" → Use get_report_summary(job_id) for sandbox-specific data
✅ "Give me an overview of the malware.exe behavior" → Use submit_file + wait_for_report

"""


# ============================================================================
# Search Tools
# ============================================================================


@mcp.tool
async def validate_api_key(ctx: Context) -> dict[str, Any]:
    """
    Validate the current API key by checking /key/current endpoint.

    This is useful for:
    - Testing if your API key is valid before making other requests
    - Checking your API key's permissions and quota limits
    - Troubleshooting authentication issues

    Returns information about the API key if valid, or an error if invalid (403).

    To obtain an API key:
    1. Log into www.hybrid-analysis.com
    2. Open your profile
    3. Navigate to the "API Key" tab
    """
    http: httpx.AsyncClient = ctx.request_context.lifespan_context.http_client
    result, headers = await make_api_request(
        http, "GET", "/key/current", error_context="validating API key", return_headers=True
    )

    if error := request_error(result):
        return error

    # Filter out sensitive data before returning
    filtered_result = {
        "status": "valid",
        "message": "API key is valid and active",
        "auth_level": result.get("auth_level"),
        "auth_level_name": result.get("auth_level_name"),
    }

    # Include non-sensitive user info if present
    if "user" in result:
        filtered_result["user"] = {
            "name": result["user"].get("name"),
        }

    # Extract quota information from headers (forward JSON headers as-is)
    quota_info = {}

    if "api-limits" in headers:
        try:
            quota_info["api_limits"] = json.loads(headers["api-limits"])
        except json.JSONDecodeError:
            pass

    if "submission-limits" in headers:
        try:
            quota_info["submission_limits"] = json.loads(headers["submission-limits"])
        except json.JSONDecodeError:
            pass

    if "sample-download-limits" in headers:
        try:
            quota_info["sample_download_limits"] = json.loads(headers["sample-download-limits"])
        except json.JSONDecodeError:
            pass

    if quota_info:
        filtered_result["quota"] = quota_info

    return filtered_result


# ============================================================================
# Search Tools
# ============================================================================


@mcp.tool
async def search_by_hash(
    hash_value: Annotated[str, Field(description="MD5, SHA1, SHA256, or SHA512 hash of the file to look up")],
    ctx: Context,
) -> dict[str, Any]:
    """
    Search for malware samples by file hash (MD5, SHA1, SHA512 - or SHA256 when you need raw report list).

    **For SHA256 hashes, prefer get_labs_sample_overview** - it provides aggregated verdicts,
    threat scores, and AV detection summaries across all sandbox runs.

    Use this tool (search_by_hash) when you need to:
    - Look up MD5, SHA1, or SHA512 hashes (get_labs_sample_overview only supports SHA256)
    - Get the raw list of all detonation reports for a hash
    - Verify if a file has been seen before

    Accepts any hash format: MD5 (32 chars), SHA1 (40 chars), SHA256 (64 chars), or SHA512 (128 chars).
    Returns all associated detonation reports and analysis history for the given hash.

    This is faster than submitting a new file if the hash has already been analyzed.

    IMPORTANT: Always compute the hash from the actual file contents - do NOT assume filenames
    are hashes, even if they look like hex strings. Use: sha256sum <filepath> | cut -d' ' -f1
    """
    # Validate hash format
    if error := validate_hash(hash_value):
        return error

    http: httpx.AsyncClient = ctx.request_context.lifespan_context.http_client
    hash_clean = hash_value.strip().lower()

    result = await make_api_request(
        http, "GET", "/search/hash", params={"hash": hash_clean}, error_context="during hash search"
    )

    if error := request_error(result):
        return error

    return result


@mcp.tool
async def search_by_terms(
    ctx: Context,
    verdict: Annotated[
        int | None,
        Field(description="1=whitelisted, 2=no verdict, 3=no specific threat, 4=suspicious, 5=malicious"),
    ] = None,
    vx_family: Annotated[str | None, Field(description="AV family name (e.g., 'nemucod', 'emotet')")] = None,
    filename: Annotated[str | None, Field(description="Filename to search for (e.g., 'invoice.exe')")] = None,
    filetype: Annotated[str | None, Field(description="File type (e.g., 'docx', 'exe', 'pdf', 'apk')")] = None,
    domain: Annotated[str | None, Field(description="Domain contacted (e.g., 'evil.com')")] = None,
    host: Annotated[str | None, Field(description="IP address contacted (e.g., '192.168.0.1')")] = None,
    url: Annotated[str | None, Field(description="HTTP request substring to search")] = None,
    country: Annotated[str | None, Field(description="Country code (3-digit ISO, e.g., 'usa', 'rus')")] = None,
    tag: Annotated[str | None, Field(description="Hashtag (e.g., 'ransomware', 'banker')")] = None,
    date_from: Annotated[
        str | None, Field(description="Start date in 'YYYY-MM-DD HH:MM' format (e.g., '2024-01-01 00:00')")
    ] = None,
    date_to: Annotated[
        str | None, Field(description="End date in 'YYYY-MM-DD HH:MM' format (e.g., '2024-12-31 23:59')")
    ] = None,
    port: Annotated[int | None, Field(description="Network port number (e.g., 8080, 443)")] = None,
    av_detect: Annotated[str | None, Field(description="AV detection range (e.g., '50-70' for 50-70%)")] = None,
    filetype_desc: Annotated[str | None, Field(description="File type description (e.g., 'PE32 executable')")] = None,
) -> dict[str, Any]:
    """
    Advanced search using multiple criteria. All parameters are optional, but at least one should be provided.
    Returns samples matching the search criteria with detailed information.
    """
    # Build form data, filtering out None values
    data = {
        "verdict": verdict,
        "vx_family": vx_family,
        "filename": filename,
        "filetype": filetype,
        "domain": domain,
        "host": host,
        "url": url,
        "country": country,
        "tag": tag,
        "date_from": date_from,
        "date_to": date_to,
        "port": port,
        "av_detect": av_detect,
        "filetype_desc": filetype_desc,
    }
    filtered_data = {k: v for k, v in data.items() if v is not None}

    # Validate at least one search criterion
    if not filtered_data:
        return {
            "error": "No search criteria provided",
            "details": "Please provide at least one search parameter (verdict, filename, domain, etc.)",
        }

    # Validate verdict range
    if verdict is not None and (error := validate_verdict(verdict)):
        return error

    # Validate date formats
    if date_from and (error := validate_date_format(date_from, "date_from")):
        return error
    if date_to and (error := validate_date_format(date_to, "date_to")):
        return error

    http: httpx.AsyncClient = ctx.request_context.lifespan_context.http_client
    result = await make_api_request(
        http, "POST", "/search/terms", data=filtered_data, error_context="during terms search"
    )

    if error := request_error(result):
        return error

    return result


# ============================================================================
# Report Tools
# ============================================================================


def _add_incomplete_analysis_note(error: dict[str, Any]) -> dict[str, Any]:
    """Hint that a missing report may simply not be finished yet.

    The API answers an unknown or unfinished sample with 400 as well as 404, so both
    status codes get the note.
    """
    if any(code in str(error.get("error")) for code in ("400", "404")):
        error["note"] = (
            "The sample may not exist, or its analysis may not be complete yet. "
            "Use get_report_state to check status first."
        )
    return error


@mcp.tool
async def get_report_summary(
    report_id: Annotated[str, Field(description="Report ID in 'jobId' format")],
    ctx: Context,
) -> dict[str, Any]:
    """
    Get a summary of a specific sandbox run by its job_id.

    This returns sandbox-run-specific data: verdict, threat score, AV detections for ONE execution.
    If you have a SHA256 hash and want aggregated data across all runs, use get_labs_sample_overview first.

    IMPORTANT: This only works when analysis is complete (state = SUCCESS).
    Use get_report_state or wait_for_report first to ensure the report is ready.
    Calling this while analysis is in progress will result in an error.
    """
    if error := validate_report_id(report_id):
        return error

    http: httpx.AsyncClient = ctx.request_context.lifespan_context.http_client
    report_id_encoded = quote(report_id.strip(), safe="")
    result = await make_api_request(
        http, "GET", f"/report/{report_id_encoded}/summary", error_context="getting report summary"
    )

    if error := request_error(result):
        return _add_incomplete_analysis_note(error)

    return result


@mcp.tool
async def get_report_state(
    report_id: Annotated[str, Field(description="Report ID in 'jobId' format")],
    ctx: Context,
) -> dict[str, Any]:
    """
    Check the processing state of a submission. Use this BEFORE trying to fetch reports.

    Returns state like: IN_QUEUE, IN_PROGRESS, SUCCESS, ERROR, etc.

    IMPORTANT: Only fetch reports (get_report_summary) when state is 'SUCCESS'.
    For IN_QUEUE or IN_PROGRESS states, analysis is still running - wait before fetching reports.

    Typical analysis time: 5-10 minutes depending on file complexity and queue depth.
    Consider using wait_for_report tool for automatic polling with backoff instead of manual checks.
    """
    if error := validate_report_id(report_id):
        return error

    http: httpx.AsyncClient = ctx.request_context.lifespan_context.http_client
    report_id_encoded = quote(report_id.strip(), safe="")
    result = await make_api_request(
        http, "GET", f"/report/{report_id_encoded}/state", error_context="getting report state"
    )

    if error := request_error(result):
        # Add note for 403 errors
        if "403" in str(error.get("error")):
            error["note"] = "Use validate_api_key tool to test your API key. Do not retry until you fix the API key."
        return error

    # Add helpful guidance based on state
    state = result.get("state", "UNKNOWN")
    if state in ["IN_QUEUE", "IN_PROGRESS"]:
        result["guidance"] = (
            f"Analysis is {state.lower().replace('_', ' ')}. "
            "Reports are not yet available. Wait 1-2 minutes before checking again, "
            "or use wait_for_report tool for automatic polling."
        )
    elif state == "SUCCESS":
        result["guidance"] = "Analysis complete! You can now fetch the report using get_report_summary."
    elif state == "ERROR":
        result["guidance"] = (
            "Analysis failed. Check the error details and consider resubmitting with different parameters."
        )

    return result


@mcp.tool
async def wait_for_report(
    report_id: Annotated[str, Field(description="Report ID (job_id) from submit_file or submit_url")],
    ctx: Context,
    max_wait_minutes: Annotated[
        int, Field(description="Maximum time to wait in minutes (default: 10, min: 1, max: 15)")
    ] = 10,
    return_summary: Annotated[
        bool, Field(description="If True, returns report summary when ready (default: False)")
    ] = False,
) -> dict[str, Any]:
    """
    Wait for a submitted analysis to complete with intelligent polling and exponential backoff.
    This is the RECOMMENDED way to wait for analysis results after submitting a file or URL.

    Use this tool when you need to:
    - Automatically wait for malware analysis to complete
    - Avoid manual polling and wasting API calls
    - Get results immediately when analysis finishes

    Polling strategy (optimized to save API quota):
    - First check: immediate
    - Checks 2-4: every 30 seconds (analysis startup phase)
    - Checks 5+: every 60 seconds (analysis running phase)
    - Max wait: configurable (1-15 minutes, default 10)

    Use this after submit_file or submit_url instead of manually polling with get_report_state.

    Returns:
    - If return_summary=False: Final state information with timing details
    - If return_summary=True: Complete report summary when state is SUCCESS (verdict, threat score, etc.)
    - If timeout: State at timeout with elapsed time (analysis may still be running)
    - If ERROR state: Error details from the analysis

    Analysis typically takes 5-10 minutes for most files.
    """
    if error := validate_report_id(report_id):
        return error

    http: httpx.AsyncClient = ctx.request_context.lifespan_context.http_client

    # Validate max_wait_minutes
    max_wait_minutes = max(1, min(15, max_wait_minutes))
    max_wait_seconds = max_wait_minutes * 60
    report_id = report_id.strip()
    report_id_encoded = quote(report_id, safe="")

    start_time = asyncio.get_event_loop().time()
    check_count = 0
    last_state = None

    logger.info(f"Starting wait for report {report_id}, max wait: {max_wait_minutes} minutes")

    try:
        while True:
            check_count += 1
            elapsed_seconds = int(asyncio.get_event_loop().time() - start_time)

            # Check state
            state_result = await make_api_request(
                http,
                "GET",
                f"/report/{report_id_encoded}/state",
                error_context=f"checking state (check #{check_count})",
            )

            # Handle transport errors (especially 403). The API's own "error" field is
            # part of a successful response and must not end polling.
            if error := request_error(state_result):
                return {
                    **error,
                    "status": "auth_failed" if "403" in str(error.get("error")) else "api_error",
                    "elapsed_seconds": elapsed_seconds,
                    "checks_performed": check_count,
                    "note": "Polling stopped due to API error",
                }

            last_state = state_result.get("state", "UNKNOWN")
            logger.info(f"Check #{check_count} (T+{elapsed_seconds}s): state={last_state}")

            # Handle terminal states
            if last_state == "SUCCESS":
                logger.info(f"Report {report_id} completed successfully after {elapsed_seconds}s")

                result = {
                    "status": "completed",
                    "report_id": report_id,
                    "state": last_state,
                    "elapsed_seconds": elapsed_seconds,
                    "checks_performed": check_count,
                    "message": f"Analysis completed successfully in {elapsed_seconds} seconds",
                }

                # Optionally fetch summary
                if return_summary:
                    summary = await make_api_request(
                        http, "GET", f"/report/{report_id_encoded}/summary", error_context="fetching summary"
                    )
                    if error := request_error(summary):
                        result["summary_error"] = error
                    else:
                        result["summary"] = summary

                return result

            elif last_state == "ERROR":
                return {
                    "status": "failed",
                    "report_id": report_id,
                    "state": last_state,
                    "elapsed_seconds": elapsed_seconds,
                    "checks_performed": check_count,
                    "message": "Analysis failed with ERROR state",
                    "state_details": state_result,
                }

            # Check timeout
            if elapsed_seconds >= max_wait_seconds:
                return {
                    "status": "timeout",
                    "report_id": report_id,
                    "state": last_state,
                    "elapsed_seconds": elapsed_seconds,
                    "checks_performed": check_count,
                    "max_wait_seconds": max_wait_seconds,
                    "message": f"Timed out after {max_wait_minutes} minutes. Analysis is still {last_state}.",
                    "suggestion": "Analysis may still complete. Check again later with get_report_state.",
                }

            # Calculate next check interval with exponential backoff
            if check_count <= 1:
                wait_seconds = 0  # First check is immediate
            elif check_count <= 4:
                wait_seconds = 30  # Checks 2-4: 30 seconds (startup phase)
            else:
                wait_seconds = 60  # Checks 5+: 60 seconds (running phase)

            if wait_seconds > 0:
                # Don't sleep longer than remaining time
                remaining_seconds = max_wait_seconds - elapsed_seconds
                wait_seconds = min(wait_seconds, remaining_seconds)

                if wait_seconds > 0:
                    logger.debug(f"Waiting {wait_seconds}s before next check")
                    await asyncio.sleep(wait_seconds)

    except Exception as e:
        logger.error(f"Unexpected error in wait_for_report: {e}")
        return {
            "error": "Unexpected error during polling",
            "details": str(e),
            "last_known_state": last_state,
            "elapsed_seconds": int(asyncio.get_event_loop().time() - start_time),
            "checks_performed": check_count,
        }


# ============================================================================
# Submission Tools - Malware Analysis, Virus Scanning, Threat Detection
# Use these tools to scan suspicious files and URLs for malware
# ============================================================================


def _read_file_bytes(path: str) -> bytes:
    """Read a file synchronously; call via asyncio.to_thread from async code."""
    with open(path, "rb") as f:
        return f.read()


def _add_submission_note(error: dict[str, Any]) -> dict[str, Any]:
    """Point at the usual causes of a rejected submission."""
    error["note"] = "Check that your API key has submission quota remaining and the environment_id is valid"
    return error


@mcp.tool
async def submit_file(
    ctx: Context,
    file_path: Annotated[
        str,
        Field(
            description="Absolute path to the suspicious file to scan (supports executables, documents, archives, APKs, etc.)"
        ),
    ],
    environment_id: Annotated[
        int,
        Field(
            description="Sandbox environment - 100: Windows 7 32-bit, 110: Windows 7 64-bit (recommended for most files), 120: Windows 10 64-bit, 200: Android, 300: Linux Ubuntu 64-bit"
        ),
    ],
    comment: Annotated[
        str | None,
        Field(
            description="Optional comment about the submission (WARNING: publicly visible on hybrid-analysis.com - do not include sensitive information)"
        ),
    ] = None,
    custom_cmd_line: Annotated[str | None, Field(description="Optional command line arguments")] = None,
    document_password: Annotated[str | None, Field(description="Password for protected Office/PDF documents")] = None,
    submit_name: Annotated[
        str | None, Field(description="Optional filename override for detection (use if file has no extension)")
    ] = None,
) -> dict[str, Any]:
    """
    Submit a file for malware/virus scanning and behavioral analysis in a sandbox environment.

    Use this tool when you need to:
    - Check if a file is malicious, suspicious, or safe
    - Analyze suspicious executables, documents, or unknown files
    - Scan files for malware, viruses, trojans, ransomware
    - Investigate file behavior (network activity, registry changes, processes)
    - Get threat verdict and antivirus detection results

    Returns a job ID that can be used to retrieve the report.

    Recommended workflow:
    1. Submit file with this tool to get a job_id
    2. Use wait_for_report(job_id, return_summary=True) to automatically wait for completion
    3. Review the verdict and threat score in the returned summary

    Analysis typically takes 5-10 minutes depending on file complexity and queue depth.
    The file will be executed in an isolated sandbox to observe its behavior safely.

    IMPORTANT: Comments are publicly visible on hybrid-analysis.com. Only include comments
    if they add value to the public threat intelligence database. Avoid sensitive information
    (internal system names, usernames, case numbers, customer details).
    """
    # Validate file exists
    if not os.path.isfile(file_path):
        return {
            "error": "File not found",
            "details": f"The file '{file_path}' does not exist or is not accessible",
            "hint": "Provide an absolute path to the suspicious file you want to analyze",
        }

    # Validate environment_id
    if environment_id <= 0:
        return {"error": "Invalid environment_id", "details": "Environment ID must be a positive integer"}

    try:
        # Read file off the event loop; samples can be large
        file_content = await asyncio.to_thread(_read_file_bytes, file_path)

        # Build form data
        data = {"environment_id": environment_id}
        if comment:
            data["comment"] = comment
        if custom_cmd_line:
            data["custom_cmd_line"] = custom_cmd_line
        if document_password:
            data["document_password"] = document_password
        if submit_name:
            data["submit_name"] = submit_name

        # Prepare file for upload
        files = {"file": (os.path.basename(file_path), file_content, "application/octet-stream")}

        http: httpx.AsyncClient = ctx.request_context.lifespan_context.http_client
        result = await make_api_request(
            http, "POST", "/submit/file", data=data, files=files, error_context="during file submission"
        )

        if error := request_error(result):
            return _add_submission_note(error)

        return result

    except FileNotFoundError:
        return {"error": "File not found", "details": f"Could not read file: {file_path}"}
    except PermissionError:
        return {"error": "Permission denied", "details": f"No permission to read file: {file_path}"}
    except Exception as e:
        logger.error(f"Unexpected error reading file: {e}")
        return {"error": "File read error", "details": str(e)}


@mcp.tool
async def submit_url(
    ctx: Context,
    url: Annotated[str, Field(description="URL to submit for analysis (website or downloadable file link)")],
    environment_id: Annotated[
        int,
        Field(
            description="Sandbox environment - 100: Windows 7 32-bit, 110: Windows 7 64-bit (recommended), 120: Windows 10 64-bit"
        ),
    ],
    comment: Annotated[
        str | None,
        Field(
            description="Optional comment about the submission (WARNING: publicly visible on hybrid-analysis.com - do not include sensitive information)"
        ),
    ] = None,
) -> dict[str, Any]:
    """
    Submit a URL for malware analysis and threat scanning. Analyzes both websites and downloadable files.

    Use this tool when you need to:
    - Check if a website is malicious, phishing, or hosting malware
    - Scan a suspicious link before visiting it
    - Analyze files hosted at a URL without downloading them locally
    - Investigate potentially dangerous download links
    - Get threat verdict for web content or online files

    Returns a job ID that can be used to retrieve the report.

    Recommended workflow:
    1. Submit URL with this tool to get a job_id
    2. Use wait_for_report(job_id, return_summary=True) to automatically wait for completion
    3. Review the verdict, network activity, and threat indicators

    Analysis typically takes 5-10 minutes. The URL will be visited in an isolated sandbox
    to safely observe behavior and network connections.

    IMPORTANT: Comments are publicly visible on hybrid-analysis.com. Only include comments
    if they add value to the public threat intelligence database. Avoid sensitive information
    (internal system names, usernames, case numbers, customer details).
    """
    # Validate URL format
    if error := validate_url(url):
        return error

    # Validate environment_id
    if environment_id <= 0:
        return {"error": "Invalid environment_id", "details": "Environment ID must be a positive integer"}

    # Build form data
    data = {
        "url": url.strip(),
        "environment_id": environment_id,
    }
    if comment:
        data["comment"] = comment

    http: httpx.AsyncClient = ctx.request_context.lifespan_context.http_client
    result = await make_api_request(http, "POST", "/submit/url", data=data, error_context="during URL submission")

    if error := request_error(result):
        return _add_submission_note(error)

    return result


# ============================================================================
# Quick Scan Tools - Instant lightweight scanning (no sandbox execution)
# ============================================================================


@mcp.tool
async def quick_scan_file(
    ctx: Context,
    file_path: Annotated[str, Field(description="Absolute path to the file to quick scan")],
    comment: Annotated[str | None, Field(description="Optional comment about the scan")] = None,
    submit_name: Annotated[
        str | None, Field(description="Optional filename override (use if file has no extension)")
    ] = None,
) -> dict[str, Any]:
    """
    Quick scan a file for malware without full sandbox execution. Results are returned within seconds.

    Use this tool when you need to:
    - Get a fast verdict on a file (instant hash reputation + ML/multi-engine scan)
    - Triage files before deciding whether to run full sandbox analysis (submit_file)
    - Check many files quickly against known malware databases

    Runs all available scanners: hash lookups, CrowdStrike ML, and MetaDefender multi-engine scan.
    Unlike submit_file, no behavioral analysis is performed and no job needs to be waited on.
    If the response has finished=false, poll for the final result with get_quick_scan(id).

    For deep behavioral analysis (processes, network traffic, registry changes) use submit_file instead.
    """
    if not os.path.isfile(file_path):
        return {
            "error": "File not found",
            "details": f"The file '{file_path}' does not exist or is not accessible",
            "hint": "Provide an absolute path to the file you want to scan",
        }

    try:
        # Read file off the event loop; samples can be large
        file_content = await asyncio.to_thread(_read_file_bytes, file_path)

        data: dict[str, Any] = {"scan_type": "all"}
        if comment:
            data["comment"] = comment
        if submit_name:
            data["submit_name"] = submit_name

        files = {"file": (os.path.basename(file_path), file_content, "application/octet-stream")}

        http: httpx.AsyncClient = ctx.request_context.lifespan_context.http_client
        result = await make_api_request(
            http, "POST", "/quick-scan/file", data=data, files=files, error_context="during quick scan"
        )

        if error := request_error(result):
            return _add_submission_note(error)

        if not result.get("finished") and result.get("id"):
            result["hint"] = "Scan not finished yet - poll for the result with get_quick_scan(id)"

        return result

    except FileNotFoundError:
        return {"error": "File not found", "details": f"Could not read file: {file_path}"}
    except PermissionError:
        return {"error": "Permission denied", "details": f"No permission to read file: {file_path}"}
    except Exception as e:
        logger.error(f"Unexpected error reading file: {e}")
        return {"error": "File read error", "details": str(e)}


@mcp.tool
async def get_quick_scan(
    ctx: Context,
    quick_scan_id: Annotated[
        str, Field(description="Quick scan ID returned by quick_scan_file (the 'id' field of its response)")
    ],
) -> dict[str, Any]:
    """
    Retrieve the result of a quick scan started with quick_scan_file.

    Use this when quick_scan_file returned finished=false - some scanners need extra time.
    When the response has finished=true, the scan is complete and the verdicts are final.
    """
    validation_error = validate_report_id(quick_scan_id)
    if validation_error:
        return validation_error

    encoded_id = quote(quick_scan_id.strip(), safe="")
    http: httpx.AsyncClient = ctx.request_context.lifespan_context.http_client
    result = await make_api_request(
        http, "GET", f"/quick-scan/{encoded_id}", error_context="fetching quick scan result"
    )

    if error := request_error(result):
        if "403" in str(error.get("error")):
            error["note"] = "Use validate_api_key tool to test your API key."
        return error

    return result


# ============================================================================
# Labs Tools - Hybrid Analysis Labs API (base: /api/labs)
# YARA hunting, sample overview and free-form search. Same API key as v2 API.
# ============================================================================


def _labs_url(path: str) -> str:
    """Build an absolute URL for the Labs API (separate base from the v2 API)."""
    return f"{settings.HYBRID_ANALYSIS_LABS_API_URL}{path}"


@mcp.tool
async def search_labs(
    ctx: Context,
    query: Annotated[
        str,
        Field(
            description="Search query string. Values should be wrapped in double quotes, e.g. 'filename:\"invoice.exe\"' or 'tag:\"ransomware\"'. "
            "Supports field queries similar to the Hybrid Analysis web search"
        ),
    ],
    page: Annotated[int, Field(description="Page number to display (1-based)")] = 1,
    size: Annotated[int, Field(description="Number of results per page (default 50)")] = 50,
    date_from: Annotated[
        str | None, Field(description="Start of date range to search from (inclusive), YYYY-MM-DD")
    ] = None,
    date_to: Annotated[str | None, Field(description="End of date range to search to (inclusive), YYYY-MM-DD")] = None,
) -> dict[str, Any]:
    """
    Run a free-form search query against Hybrid Analysis samples.

    Use this tool when you need to:
    - Search the sample collection by filename, tag, verdict or other attributes
    - Find samples matching a date range

    Different from search_by_terms (v2 API): this hits the search endpoint.
    For large result sets the query may run asynchronously - use get_labs_search_results(query_id) then.
    """
    if not query or not query.strip():
        return {"error": "Invalid query", "details": "Query string cannot be empty"}

    for label, value in (("date_from", date_from), ("date_to", date_to)):
        if value:
            validation_error = validate_date_format(value)
            if validation_error:
                validation_error["details"] = f"{label}: {validation_error['details']}"
                return validation_error

    body: dict[str, Any] = {"query": query.strip(), "page": page, "size": size}
    if date_from:
        body["date_from"] = date_from.strip()
    if date_to:
        body["date_to"] = date_to.strip()

    http: httpx.AsyncClient = ctx.request_context.lifespan_context.http_client
    result = await make_api_request(
        http, "POST", _labs_url("/search/query/run"), json_body=body, error_context="running labs search"
    )

    if not result.get("error") and result.get("id"):
        result["hint"] = "Query is running asynchronously - fetch its results with get_labs_search_results(id)"

    return result


@mcp.tool
async def get_labs_search_results(
    ctx: Context,
    query_id: Annotated[str, Field(description="Query ID returned by search_labs (the 'id' field of its response)")],
) -> dict[str, Any]:
    """
    Retrieve results of an asynchronous Labs search query started with search_labs.
    """
    validation_error = validate_report_id(query_id)
    if validation_error:
        return validation_error

    encoded_id = quote(query_id.strip(), safe="")
    http: httpx.AsyncClient = ctx.request_context.lifespan_context.http_client
    return await make_api_request(
        http, "GET", _labs_url(f"/search/query/{encoded_id}/results"), error_context="fetching labs search results"
    )


@mcp.tool
async def get_labs_sample_overview(
    ctx: Context,
    sha256: Annotated[str, Field(description="SHA256 hash of the sample (64 hex characters)")],
) -> dict[str, Any]:
    """
    Get the aggregated overview for a sample by its SHA256 hash.

    This is the RECOMMENDED first step when investigating a known hash. The overview contains:
    - Verdict and threat score aggregated across all sandbox runs
    - AV detection summary
    - List of all sandbox job_ids with their environments and verdicts

    Use this tool when you need to:
    - Quickly look up what Hybrid Analysis knows about a file hash
    - Get a summary before deciding if deeper analysis is needed
    - Find job_ids for specific sandbox runs

    Only use get_report_summary if you need sandbox-run-specific details
    (e.g., network traffic from a particular environment, specific behavioral indicators).
    """
    validation_error = validate_hash(sha256)
    if validation_error:
        return validation_error

    sha256_clean = sha256.strip().lower()
    if len(sha256_clean) != 64:
        return {"error": "Invalid sha256", "details": "overview requires a SHA256 hash (64 hex characters)"}

    http: httpx.AsyncClient = ctx.request_context.lifespan_context.http_client
    return await make_api_request(
        http, "GET", _labs_url(f"/sample/{sha256_clean}/overview"), error_context="fetching sample overview"
    )


@mcp.tool
async def get_yara_matches(
    ctx: Context,
    items_count: Annotated[int | None, Field(description="Maximum number of matches to return")] = None,
    search_after: Annotated[
        str | None, Field(description="Pagination cursor from a previous response to fetch older matches")
    ] = None,
) -> dict[str, Any]:
    """
    List recent YARA hunting rule matches (samples that matched your YARA hunting rules).

    Use this tool when you need to:
    - See which recent samples triggered your YARA hunting rules
    - Page through the match history (use search_after from the previous response)
    """
    params: dict[str, Any] = {}
    if items_count is not None:
        params["items_count"] = items_count
    if search_after:
        params["search_after"] = search_after.strip()

    http: httpx.AsyncClient = ctx.request_context.lifespan_context.http_client
    return await make_api_request(
        http, "GET", _labs_url("/hunting/matches/recent"), params=params, error_context="fetching YARA matches"
    )


YARA_RULE_STATUS = Literal["active", "paused"]


@mcp.tool
async def list_yara_rules(
    ctx: Context,
    search: Annotated[str | None, Field(description="Filter rules by name/identifier")] = None,
    threat_category: Annotated[list[str] | None, Field(description="Filter by threat categories (repeatable)")] = None,
    status: Annotated[YARA_RULE_STATUS | None, Field(description="Filter by rule status")] = None,
) -> dict[str, Any]:
    """
    List your YARA hunting rules on Hybrid Analysis.
    """
    params: dict[str, Any] = {}
    if search:
        params["search"] = search.strip()
    if threat_category:
        params["threat_category"] = threat_category
    if status:
        params["status"] = status

    http: httpx.AsyncClient = ctx.request_context.lifespan_context.http_client
    return await make_api_request(
        http, "GET", _labs_url("/hunting/yara-rules"), params=params, error_context="listing YARA rules"
    )


@mcp.tool
async def get_yara_rule(
    ctx: Context,
    rule_id: Annotated[str, Field(description="ID of the YARA hunting rule")],
) -> dict[str, Any]:
    """
    Fetch a single YARA hunting rule by ID (use list_yara_rules to find IDs).
    """
    validation_error = validate_report_id(rule_id)
    if validation_error:
        return validation_error

    encoded_id = quote(rule_id.strip(), safe="")
    http: httpx.AsyncClient = ctx.request_context.lifespan_context.http_client
    return await make_api_request(
        http, "GET", _labs_url(f"/hunting/yara-rules/{encoded_id}"), error_context="fetching YARA rule"
    )


@mcp.tool
async def create_yara_rule(
    ctx: Context,
    identifier: Annotated[str, Field(description="Unique name of the rule (required)")],
    threat_categories: Annotated[list[str], Field(description="Threat categories the rule targets (at least one required)")],
    rule: Annotated[str, Field(description="YARA rule source code (required)")],
    active: Annotated[bool, Field(description="Whether the rule is active and hunting")] = True,
    daily_notifications_limit: Annotated[
        int | None, Field(description="Maximum number of notifications per day")
    ] = None,
) -> dict[str, Any]:
    """
    Create a YARA hunting rule that continuously matches new samples on Hybrid Analysis.
    View matches with get_yara_matches.
    """
    body: dict[str, Any] = {
        "identifier": identifier.strip(),
        "threat_categories": threat_categories,
        "rule": rule,
        "active": active,
    }
    if daily_notifications_limit is not None:
        body["daily_notifications_limit"] = daily_notifications_limit

    http: httpx.AsyncClient = ctx.request_context.lifespan_context.http_client
    return await make_api_request(
        http, "POST", _labs_url("/hunting/yara-rules"), json_body=body, error_context="creating YARA rule"
    )


@mcp.tool
async def update_yara_rule(
    ctx: Context,
    rule_id: Annotated[str, Field(description="ID of the YARA hunting rule to update")],
    identifier: Annotated[str | None, Field(description="New unique name of the rule")] = None,
    threat_categories: Annotated[list[str] | None, Field(description="New threat categories")] = None,
    rule: Annotated[str | None, Field(description="New YARA rule source code")] = None,
    active: Annotated[bool | None, Field(description="Activate (true) or pause (false) the rule")] = None,
    daily_notifications_limit: Annotated[int | None, Field(description="Max notifications per day")] = None,
    reset_counter: Annotated[bool, Field(description="When true, resets the all-time matches counter")] = False,
) -> dict[str, Any]:
    """
    Update an existing YARA hunting rule (only fields you provide are changed).
    """
    validation_error = validate_report_id(rule_id)
    if validation_error:
        return validation_error

    body: dict[str, Any] = {}
    if identifier is not None:
        body["identifier"] = identifier.strip()
    if threat_categories is not None:
        body["threat_categories"] = threat_categories
    if rule is not None:
        body["rule"] = rule
    if active is not None:
        body["active"] = active
    if daily_notifications_limit is not None:
        body["daily_notifications_limit"] = daily_notifications_limit
    if reset_counter:
        body["reset_counter"] = True

    if not body:
        return {"error": "Nothing to update", "details": "Provide at least one field to change"}

    encoded_id = quote(rule_id.strip(), safe="")
    http: httpx.AsyncClient = ctx.request_context.lifespan_context.http_client
    return await make_api_request(
        http, "POST", _labs_url(f"/hunting/yara-rules/{encoded_id}"), json_body=body, error_context="updating YARA rule"
    )


@mcp.tool
async def delete_yara_rule(
    ctx: Context,
    rule_id: Annotated[str, Field(description="ID of the YARA hunting rule to delete")],
) -> dict[str, Any]:
    """
    Delete a YARA hunting rule. This is irreversible - the rule and its notifications are removed.
    """
    validation_error = validate_report_id(rule_id)
    if validation_error:
        return validation_error

    encoded_id = quote(rule_id.strip(), safe="")
    http: httpx.AsyncClient = ctx.request_context.lifespan_context.http_client
    return await make_api_request(
        http, "DELETE", _labs_url(f"/hunting/yara-rules/{encoded_id}"), error_context="deleting YARA rule"
    )


if __name__ == "__main__":
    if settings.MCP_TRANSPORT == "stdio":
        # stdio transport doesn't accept host/port/path parameters
        mcp.run(transport="stdio")
    else:
        # HTTP-based transports (streamable-http, sse) need host/port/path
        http_host, _, http_port = settings.HTTP_LISTEN.rpartition(":")
        http_port = int(http_port)
        mcp.run(
            transport=settings.MCP_TRANSPORT,
            host=http_host,
            port=http_port,
            path=settings.MCP_PATH,
        )
