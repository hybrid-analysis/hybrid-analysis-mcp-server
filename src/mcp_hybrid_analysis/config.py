from typing import Literal

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    HTTP_LISTEN: str = "127.0.0.1:8000"
    MCP_TRANSPORT: Literal["sse", "streamable-http", "stdio"] = "streamable-http"
    MCP_PATH: str = "/mcp/"
    HYBRID_ANALYSIS_KEY: str = ""
    HYBRID_ANALYSIS_API_URL: str = "https://hybrid-analysis.com/api/v2"
    USER_AGENT: str = "HybridAnalysisMCP/1.0"


settings = Settings()
