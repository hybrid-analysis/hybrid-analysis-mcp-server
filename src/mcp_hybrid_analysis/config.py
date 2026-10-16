from functools import cached_property
from typing import Literal

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    HTTP_LISTEN: str = "127.0.0.1:8000"
    MCP_TRANSPORT: Literal["sse", "streamable-http", "stdio"] = "streamable-http"
    MCP_PATH: str = "/mcp/"
    HYBRID_ANALYSIS_KEY: str = ""
    HYBRID_ANALYSIS_BASE_URL: str = "https://hybrid-analysis.com"
    USER_AGENT: str = "HybridAnalysisMCP/1.0"

    @cached_property
    def HYBRID_ANALYSIS_API_URL(self) -> str:
        """Full URL for the v2 API (base + /api/v2)."""
        return f"{self.HYBRID_ANALYSIS_BASE_URL.rstrip('/')}/api/v2"

    @cached_property
    def HYBRID_ANALYSIS_LABS_API_URL(self) -> str:
        """Full URL for the labs API (base + /api/labs)."""
        return f"{self.HYBRID_ANALYSIS_BASE_URL.rstrip('/')}/api/labs"


settings = Settings()
