"""
Check whether a password has appeared in known data breaches, using the
Have I Been Pwned "Pwned Passwords" range API — with k-anonymity so the
password (and even its full hash) never leaves this machine.

How k-anonymity works here:
    1. Hash the password with SHA-1 and uppercase the hex digest.
    2. Send ONLY the first 5 hex characters of that hash to the API.
    3. The API returns every breached-hash suffix that shares that 5-char
       prefix (hundreds of them), each with a breach count.
    4. We search that list locally for our hash's suffix.

The server never learns which password we asked about — only a prefix shared
by many thousands of hashes. This module uses only urllib from the standard
library, so there is nothing to install.
"""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request

API_RANGE_URL = "https://api.pwnedpasswords.com/range/"


def hash_password(password: str) -> tuple[str, str]:
    """Return the (5-char prefix, remaining suffix) of the SHA-1 hex digest."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def parse_range_response(body: str, suffix: str) -> int:
    """Search an API range response for our hash suffix.

    The response body is newline-separated 'SUFFIX:COUNT' records. Returns the
    breach count for the matching suffix, or 0 if not present. Pure string
    parsing, so this is fully testable offline.
    """
    target = suffix.strip().upper()
    for line in body.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        record_suffix, _, count = line.partition(":")
        if record_suffix.strip().upper() == target:
            try:
                return int(count.strip())
            except ValueError:
                return 0
    return 0


def check_pwned(password: str, timeout: float = 6.0) -> int | None:
    """Return how many times the password appears in breaches (0 if none),
    or None if the check could not be performed (e.g. no network)."""
    prefix, suffix = hash_password(password)
    request = urllib.request.Request(
        API_RANGE_URL + prefix,
        headers={"User-Agent": "passguard-cli"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError, OSError):
        return None  # offline or API unreachable — caller degrades gracefully
    return parse_range_response(body, suffix)
