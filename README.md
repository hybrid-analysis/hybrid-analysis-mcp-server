# Hybrid Analysis MCP Server

**Malware analysis sandbox for AI assistants** - scan suspicious files and URLs for viruses, trojans, ransomware, and behavioral threats.

[Model Context Protocol](https://modelcontextprotocol.io/) server for [Hybrid Analysis](https://hybrid-analysis.com/) API. Enables AI gents to submit files/URLs for sandbox detonation, search malware samples, and retrieve detailed threat analysis reports.

**Use this when users say**: "analyze this file", "is this file safe", "check for malware", "scan suspicious executable", "is this link phishing", "what does this file do", or mention case files, samples, or unknown binaries.

## Tools

**API Validation**
- `validate_api_key` - Verify API key and check quota

**Search**
- `search_by_hash` - Lookup by MD5/SHA1/SHA256/SHA512
- `search_by_terms` - Filter by verdict, filetype, domain, AV family, date range

**Reports**
- `get_report_state` - Check analysis status (IN_QUEUE → IN_PROGRESS → SUCCESS)
- `get_report_summary` - Verdict, threat score, AV detections
- `wait_for_report` - Poll with backoff until analysis completes

**Submission**
- `submit_file` - Upload file for sandbox detonation (executables, documents, scripts, APKs)
- `submit_url` - Submit URL for analysis (phishing detection, malicious websites)

## Resources

The server exposes MCP resources with context about capabilities:
- `hybrid-analysis://capabilities` - Overview of malware analysis features and workflows
- `hybrid-analysis://help/when-to-use` - Guidance on when to use these tools (vs other tools)

## Quick Start

**Prerequisites**: Python 3.13+, [Poetry](https://python-poetry.org/)

```bash
# Install
poetry install --with dev
pre-commit install

# Configure API key
cp template.env .env
# Edit .env and set HYBRID_ANALYSIS_KEY

# Run
poetry run python -m mcp_hybrid_analysis.server
```

**Get your API key**: [hybrid-analysis.com](https://www.hybrid-analysis.com/) → Profile → API Key tab

## MCP Client Setup

**Claude Desktop** - Add to `~/.claude/mcp.json`:
```json
{
  "mcpServers": {
    "hybrid-analysis": {
      "command": "poetry",
      "args": ["run", "python", "-m", "mcp_hybrid_analysis.server"],
      "env": {
        "HYBRID_ANALYSIS_KEY": "YOUR_API_KEY_HERE",
        "MCP_TRANSPORT": "stdio"
      },
      "cwd": "/absolute/path/to/mcp-hybrid-analysis"
    }
  }
}
```

**Other MCP clients**: Default transport is `streamable-http` on `127.0.0.1:8000`. Override via `MCP_TRANSPORT` and `HTTP_LISTEN` environment variables.

## Example Workflow

```python
# 1. Submit file
submit_file(file_path="/tmp/suspicious.exe", environment_id=110)  # Windows 7 x64
# → Returns job_id

# 2. Wait for completion (auto-polls with backoff)
wait_for_report(report_id=job_id, max_wait_minutes=10, return_summary=True)
# → Analysis typically takes 5-10 minutes, returns summary when ready
```

**Common environment IDs**: 100=Win7 32-bit, 110=Win7 64-bit, 120=Win10 64-bit, 200=Android, 300=Linux Ubuntu

## Development

```bash
# Format code (automatic via pre-commit hooks)
poetry run black src/
poetry run isort src/
```

## License

MIT - See [LICENSE.md](LICENSE.md) for full text.