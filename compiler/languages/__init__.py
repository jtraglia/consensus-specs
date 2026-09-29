from .base import Target
from .lean import Lean
from .python import Python

PYTHON = Python(Lean())
LANGUAGES = PYTHON.languages

__all__ = ["LANGUAGES", "PYTHON", "Target"]
