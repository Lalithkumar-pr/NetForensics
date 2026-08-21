"""
NetForensics API package (Final Phase).
"""

from .router import get_available_scenarios, run_investigation

__all__ = [
    "get_available_scenarios",
    "run_investigation",
]
