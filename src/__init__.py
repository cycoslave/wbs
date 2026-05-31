# src/__init__.py
"""WBS"""

__version__ = "6.0.0"
__build__ = 6000001
__author__ = "cyco"

__all__ = ["__version__", "__build__","__author__"]

if " " in __version__:
    raise RuntimeError(
        f"__version__ must not contain spaces (got: {repr(__version__)}). "
        "Version strings are embedded in botnet protocol lines split on whitespace."
    )