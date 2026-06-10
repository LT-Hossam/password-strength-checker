# PassGuard — Password Strength Analyzer + Breach Checker

A command-line tool that scores password strength **offline** and checks whether
a password has appeared in real data breaches — without ever sending the
password (or even its full hash) over the network.

**Zero dependencies.** It uses only the Python standard library, so there is
nothing to `pip install`. If you have Python, you can run it.

```
$ python -m passguard check --password "qwerty123"

  Rating:        Very Weak
  Strength:      [#-----------------------] 6/100
  Length:        9 characters
  Entropy:       8.0 bits (raw 46.5)
  Est. crack:    less than a second (offline, fast hash)
  Breach check:  FOUND IN BREACHES — do not use this password
                 seen 1,000,000+ times in breaches

  Warnings:
    - This is one of the most common passwords in existence.
    - Contains a keyboard pattern (e.g. 'qwerty', 'asdf').
```

---

## The interesting part: privacy-preserving breach checks (k-anonymity)

The breach check queries the [Have I Been Pwned](https://haveibeenpwned.com)
"Pwned Passwords" database, but it never reveals your password to the server:

1. Hash the password with SHA-1.
2. Send **only the first 5 characters** of that hash to the API.
3. The API returns *every* breached-hash suffix sharing that prefix — hundreds
   of them — each with a count.
4. PassGuard searches that list **locally** for your hash's suffix.

The server only ever sees a 5-character prefix shared by thousands of different
hashes, so it can't tell which password you asked about. This is the
**k-anonymity** model, and being able to explain it is a genuinely strong
interview talking point. The whole thing is implemented with `hashlib` and
`urllib` from the standard library — see
[`passguard/breach.py`](passguard/breach.py).

If the API can't be reached, the tool says so and still gives you the full
offline strength analysis — it never fails closed.

---

## How the strength score works

All of this runs offline from the password string alone
([`passguard/strength.py`](passguard/strength.py)):

- **Entropy estimate** — bits = length × log2(character-pool size), where the
  pool grows with each character class present (lowercase, uppercase, digits,
  symbols).
- **Pattern detection** — common-password list, keyboard runs (`qwerty`,
  `asdf`), sequential runs (`abcd`, `1234`), long repeats (`aaaa`), and
  all-digit PINs. Detected patterns *discount* the entropy, because a
  long-but-predictable password isn't actually strong.
- **Rating + crack-time** — the effective entropy maps to a rating (Very Weak →
  Very Strong) and a rough average offline crack time assuming a fast,
  unsalted-hash attacker (~10^10 guesses/second).
- **Actionable suggestions** — concrete steps to improve the password.

---

## Install & run

**Option 1 — no install (easiest).** Clone the repo and run it in place:

```bash
git clone <your-fork-url> password-strength-checker
cd password-strength-checker
python -m passguard check
```

You'll be prompted to type the password; input is hidden and never echoed.

**Option 2 — install the `passguard` command:**

```bash
pip install -e .
passguard check
```

Requires Python 3.10+. There are no third-party dependencies either way.

### Usage

```bash
# Interactive: type the password hidden (recommended)
python -m passguard check

# Offline only — skip the breach API entirely
python -m passguard check --no-breach

# Machine-readable JSON (good for piping into other tools)
python -m passguard check --json

# Pass a password inline (convenient, but it lands in your shell history)
python -m passguard check --password "hunter2"
```

The command exits `0` for a healthy password, `2` if it was found in a breach,
and `3` if it's rated weak — so you can use it in scripts and CI.

---

## Testing

No test framework needed — the suite runs on the standard library:

```bash
python -m unittest discover -s tests -v
```

It covers the strength logic (common passwords, patterns, entropy ordering,
empty input) and the breach layer. The breach tests run **fully offline** by
checking the k-anonymity hash split and parsing a synthetic API response, so
they pass anywhere with no network.

---

## Security & privacy notes

- Your password is never sent anywhere. Only a 5-character SHA-1 prefix leaves
  the machine, and only when the breach check is enabled.
- Prefer the interactive prompt over `--password`, which can be recorded in
  shell history and process listings.
- This is an educational/auditing tool. The strength score is an estimate, not
  a guarantee — a unique passphrase plus a password manager beats any single
  scored password.

---

## Project structure

```
password-strength-checker/
├── passguard/
│   ├── strength.py     # offline strength analysis (the core)
│   ├── breach.py       # HIBP k-anonymity breach check (stdlib only)
│   ├── cli.py          # the `passguard` command
│   ├── __init__.py
│   └── __main__.py     # enables `python -m passguard`
├── tests/test_passguard.py
├── pyproject.toml      # optional install; zero runtime dependencies
├── LICENSE
└── README.md
```

## License

MIT — see [LICENSE](LICENSE).
