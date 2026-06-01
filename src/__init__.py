# src/__init__.py
"""WBS"""

__version__ = "5.9.2"
__build__ = 5090200
__author__ = "cyco"

__all__ = ["__version__", "__build__","__author__"]

if " " in __version__:
    raise RuntimeError(
        f"__version__ must not contain spaces (got: {repr(__version__)}). "
        "Version strings are embedded in botnet protocol lines split on whitespace."
    )