from .base import register
from .lean import Lean
from .python import Python

PYTHON = Python()
LEAN = Lean()

register(PYTHON)
register(LEAN)
