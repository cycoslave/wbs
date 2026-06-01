# src/helper.py
"""
Helper functions
"""

def clean_message(text: str, max_bytes: int = 255) -> str:
    """
    Sanitize and truncate an IRC message to fit within a byte limit.

    Normalizes line endings, collapses whitespace, and truncates to
    `max_bytes` bytes (UTF-8), appending '...' if truncated.

    Args:
        text: The raw message string to clean.
        max_bytes: Maximum byte length of the output (default: 255).

    Returns:
        A cleaned, byte-safe string.

    Raises:
        ValueError: If max_bytes is less than 4.
    """
    if not text:
        return ""

    if max_bytes < 4:
        raise ValueError(f"max_bytes must be at least 4, got {max_bytes}")

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("\n", " ")
    text = " ".join(text.split())

    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text

    truncated = raw[:max_bytes - 3]
    while True:
        try:
            decoded = truncated.decode("utf-8")
            result = decoded + "..."
            if len(result.encode("utf-8")) <= max_bytes:
                return result
            truncated = truncated[:-1]
        except UnicodeDecodeError:
            truncated = truncated[:-1]
            if not truncated:
                return ""