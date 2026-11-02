"""Scam Shield: check whether a message is likely a scam, in plain language."""
from .analyzer import analyze, Result

__all__ = ["analyze", "Result"]
