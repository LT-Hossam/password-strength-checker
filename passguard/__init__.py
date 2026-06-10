"""PassGuard — offline password strength analysis + privacy-preserving breach check."""

from .strength import analyze, detect_patterns
from .breach import check_pwned, hash_password, parse_range_response

__version__ = "1.0.0"

__all__ = [
    "analyze",
    "detect_patterns",
    "check_pwned",
    "hash_password",
    "parse_range_response",
    "__version__",
]
