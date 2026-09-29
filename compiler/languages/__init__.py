from .base import Language
from .python import Python

LANGUAGES: dict[str, Language] = {language.name: language for language in (Python(),)}
