# src/helper.py
"""
Helper functions
"""

def clean_message(text: str, max_bytes: int = 255) -> str:
    if not text:
        return ""

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("\n", " ")
    text = " ".join(text.split())

    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text

    truncated = raw[:max_bytes - 3]
    while True:
        try:
            return truncated.decode("utf-8") + "..."
        except UnicodeDecodeError:
            truncated = truncated[:-1]