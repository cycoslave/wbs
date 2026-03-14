# src/helper.py
"""
Helper functions
"""

def clean_message(text: str, max_len: int = 255) -> str:
    # Remove LF (\n) and CR (\r) by replacing with space
    cleaned = text.replace('\n', ' ').replace('\r', ' ')
    # Truncate to max_len - 3 (for '...'), add ellipsis if truncated
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len - 3] + '...'
    return cleaned.strip()
