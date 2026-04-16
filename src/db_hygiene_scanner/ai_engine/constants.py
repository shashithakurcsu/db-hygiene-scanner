"""Constants for AI engine: model names, token limits, pricing."""

DEFAULT_SCAN_MODEL = "claude-sonnet-4-6"
DEFAULT_FIX_MODEL = "claude-opus-4-6"
DEFAULT_REVIEW_MODEL = "claude-opus-4-6"

DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAYS = [1.0, 2.0, 4.0]
DEFAULT_MAX_CONCURRENT = 5

# Approximate pricing per 1M tokens (USD)
MODEL_PRICING = {
    "claude-sonnet-4-6": {"input": 3.00, "output": 15.00},
    "claude-opus-4-6": {"input": 15.00, "output": 75.00},
}

MAX_TOKENS_PER_REQUEST = 4096
