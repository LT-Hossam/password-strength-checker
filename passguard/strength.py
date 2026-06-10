"""
Offline password strength analysis.

Estimates how resistant a password is to guessing, using only the password
string — no network, no third-party libraries. The approach:

1. Estimate raw entropy from the character pool and length.
2. Detect predictable patterns (common passwords, keyboard runs, sequences,
   repeats) and discount the entropy accordingly, because a "random-looking"
   length is meaningless if the password is `Password123!`.
3. Translate the effective entropy into a rating and a rough offline
   crack-time estimate, plus actionable suggestions.

Entropy thresholds follow widely used rules of thumb; they are guidance, not a
guarantee. Pair this with the breach check (see breach.py) for a real verdict.
"""

from __future__ import annotations

import math
import re

# A compact list of the most common breached/guessed passwords. Membership here
# means the password is effectively worthless regardless of its length.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "1234567", "111111", "1234567890", "123123", "abc123", "1234",
    "password1", "iloveyou", "1q2w3e4r", "000000", "qwerty123", "zaq12wsx",
    "dragon", "sunshine", "654321", "master", "666666", "123321", "monkey",
    "letmein", "welcome", "login", "admin", "princess", "qwertyuiop",
    "solo", "passw0rd", "starwars", "whatever", "trustno1", "654321",
    "superman", "asdfghjkl", "football", "baseball", "michael", "shadow",
    "ashley", "jennifer", "hunter", "buster", "soccer", "harley", "ranger",
    "daniel", "hannah", "thomas", "summer", "george", "computer", "michelle",
    "jessica", "pepper", "1111", "zxcvbnm", "555555", "11111111", "131313",
    "freedom", "777777", "pass", "maggie", "159753", "aaaaaa", "ginger",
    "princess1", "joshua", "cheese", "amanda", "summer1", "love", "robert",
    "batman", "p@ssw0rd", "test", "qazwsx", "123qwe", "killer", "hello",
    "charlie", "samsung", "internet", "secret", "matrix", "tigger",
    "changeme", "default", "guest", "root", "toor", "user",
}

# Adjacency runs on a QWERTY keyboard (forward; reverse is checked too).
_KEYBOARD_RUNS = (
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "qwerty", "qazwsx", "zaq12wsx", "1q2w3e4r",
)

# Character-class pool sizes used for the entropy estimate.
_POOL_LOWER = 26
_POOL_UPPER = 26
_POOL_DIGITS = 10
_POOL_SYMBOLS = 33  # printable ASCII punctuation, approximately

# Assumed guess rate for an offline attack against a fast, unsalted hash.
_GUESSES_PER_SECOND = 1e10


def _character_pool(password: str) -> int:
    """Size of the character set the password draws from."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += _POOL_LOWER
    if re.search(r"[A-Z]", password):
        pool += _POOL_UPPER
    if re.search(r"[0-9]", password):
        pool += _POOL_DIGITS
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += _POOL_SYMBOLS
    return pool


def _raw_entropy_bits(password: str) -> float:
    """Upper-bound entropy assuming each character is drawn independently and
    uniformly from the detected pool: bits = length * log2(pool)."""
    pool = _character_pool(password)
    if pool <= 1 or not password:
        return 0.0
    return len(password) * math.log2(pool)


def _has_sequential_run(password: str, run_len: int = 4) -> bool:
    """True if the password contains a run of consecutive characters such as
    'abcd' or '4567' (forward or backward)."""
    lowered = password.lower()
    for i in range(len(lowered) - run_len + 1):
        window = lowered[i:i + run_len]
        ascending = all(
            ord(window[j + 1]) - ord(window[j]) == 1 for j in range(run_len - 1)
        )
        descending = all(
            ord(window[j]) - ord(window[j + 1]) == 1 for j in range(run_len - 1)
        )
        if ascending or descending:
            return True
    return False


def _has_keyboard_run(password: str, run_len: int = 4) -> bool:
    lowered = password.lower()
    for run in _KEYBOARD_RUNS:
        for i in range(len(run) - run_len + 1):
            chunk = run[i:i + run_len]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def _has_repeated_run(password: str, run_len: int = 3) -> bool:
    """True if any character repeats run_len+ times in a row (e.g. 'aaaa')."""
    return re.search(r"(.)\1{" + str(run_len - 1) + r",}", password) is not None


def detect_patterns(password: str) -> list[str]:
    """Return a list of predictable-pattern warnings found in the password."""
    warnings: list[str] = []
    if password.lower() in COMMON_PASSWORDS:
        warnings.append("This is one of the most common passwords in existence.")
    if _has_keyboard_run(password):
        warnings.append("Contains a keyboard pattern (e.g. 'qwerty', 'asdf').")
    if _has_sequential_run(password):
        warnings.append("Contains a sequential run (e.g. 'abcd', '1234').")
    if _has_repeated_run(password):
        warnings.append("Contains a long run of repeated characters.")
    if re.fullmatch(r"\d+", password or ""):
        warnings.append("Made up entirely of digits — very fast to brute-force.")
    return warnings


def _effective_entropy(password: str, warnings: list[str]) -> float:
    """Discount raw entropy for detected predictability."""
    bits = _raw_entropy_bits(password)
    if any("most common" in w for w in warnings):
        return min(bits, 8.0)  # common passwords are cracked instantly
    penalty = 0.0
    for w in warnings:
        if "keyboard" in w or "sequential" in w or "repeated" in w:
            penalty += 12.0
        if "entirely of digits" in w:
            penalty += 8.0
    return max(bits - penalty, 0.0)


def _rating(bits: float) -> str:
    if bits < 28:
        return "Very Weak"
    if bits < 36:
        return "Weak"
    if bits < 60:
        return "Fair"
    if bits < 128:
        return "Strong"
    return "Very Strong"


def _format_crack_time(bits: float) -> str:
    """Human-readable average offline crack time from effective entropy."""
    guesses = (2 ** bits) / 2  # average half the keyspace
    seconds = guesses / _GUESSES_PER_SECOND
    if seconds < 1:
        return "less than a second"
    units = (
        ("years", 365 * 24 * 3600),
        ("days", 24 * 3600),
        ("hours", 3600),
        ("minutes", 60),
        ("seconds", 1),
    )
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            if name == "years" and value > 1e9:
                return "billions of years"
            return f"about {value:,.0f} {name}"
    return "less than a second"


def _suggestions(password: str, warnings: list[str]) -> list[str]:
    tips: list[str] = []
    if len(password) < 12:
        tips.append("Use at least 12-16 characters; length matters most.")
    if not re.search(r"[A-Z]", password):
        tips.append("Add uppercase letters.")
    if not re.search(r"[a-z]", password):
        tips.append("Add lowercase letters.")
    if not re.search(r"[0-9]", password):
        tips.append("Add digits.")
    if not re.search(r"[^a-zA-Z0-9]", password):
        tips.append("Add symbols (e.g. !@#$%).")
    if warnings:
        tips.append("Avoid common words, keyboard patterns, and sequences.")
    if not tips:
        tips.append("Consider a passphrase of random words and a password manager.")
    return tips


def analyze(password: str) -> dict:
    """Analyze a password and return a structured report (no network)."""
    warnings = detect_patterns(password)
    raw_bits = _raw_entropy_bits(password)
    eff_bits = _effective_entropy(password, warnings)
    score = max(0, min(100, round(eff_bits / 128 * 100)))
    return {
        "length": len(password),
        "raw_entropy_bits": round(raw_bits, 1),
        "effective_entropy_bits": round(eff_bits, 1),
        "rating": _rating(eff_bits),
        "score": score,
        "estimated_offline_crack_time": _format_crack_time(eff_bits),
        "warnings": warnings,
        "suggestions": _suggestions(password, warnings),
    }
