from .base import Foreign, Language, LANGUAGES, register, Target
from .lean import Lean
from .python import Python

register(Python())
register(Lean())

__all__ = ["LANGUAGES", "Foreign", "Language", "Target"]
