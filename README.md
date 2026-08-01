# c2lint.py

A lightweight, **unofficial** syntax linter, formatter, and version-compliance
checker for Cobalt Strike **Malleable C2 profiles** — written in plain Python
with no external dependencies.

It checks the *structure* of a profile file (brace balance, missing
semicolons, unterminated strings, unknown blocks/directives), can
minify or beautify a profile, and can flag options that require a newer
Cobalt Strike version than the one you're targeting.

> ⚠️ **This tool does not generate, modify, or transmit C2 traffic.**
> It only parses profile files as text, the same way a linter checks an
> nginx or JSON config file.

---

## ⚠️ Disclaimer — please read

- **This is an unofficial, community script.** It is not written, reviewed,
  or endorsed by Fortra / Cobalt Strike.
- **It is a quick sanity check, not a validator.** It catches obvious
  syntax mistakes and known version-gated options — it does **not**
  fully parse or semantically validate a profile the way the real
  Cobalt Strike teamserver does.
- **Version coverage stops at Cobalt Strike 4.12.** The version-compliance
  list (`--check-version`) is hand-built from public changelogs available
  at the time this tool was written. It will not know about anything
  released after 4.12.
- **For anything used on an actual engagement**, always validate with the
  official `c2lint` binary bundled with your Cobalt Strike teamserver
  install, and check the current documentation and release notes at the
  official site: **https://www.cobaltstrike.com/** (see the
  [release notes page](https://www.cobaltstrike.com/release-page) for
  what's changed since 4.12).
- This tool is provided as-is, with no warranty. Use your own judgment
  before relying on it for anything security-relevant.

---

## Features

- **Syntax linting**
  - Unbalanced / unclosed braces
  - Missing `;` statement terminators
  - Unterminated string literals (odd quote counts)
  - Unknown / misspelled top-level blocks (e.g. `htttp-post`)
  - Unrecognized top-level directives
  - Duplicate blocks that are normally expected once
  - Optional `--strict` style checks (trailing whitespace, tabs)
- **Minify** (`--minify`) — strips comments and blank lines, collapses
  redundant whitespace, leaves strings untouched
- **Beautify** (`--beautify`) — re-indents the profile by brace depth;
  comments and string contents are preserved exactly as written
- **Version compliance check** (`--check-version X.Y`) — flags any
  recognized option that requires a Cobalt Strike version newer than
  the target you specify (best-effort, up to 4.12 — see disclaimer above)
- Works on multiple files in one invocation
- No dependencies — just Python 3 standard library

## Requirements

- Python 3.9+

## Installation

```bash
git clone https://github.com/mynksh/c2lint.git
cd c2lint
python3 c2lint.py --help
```

No `pip install` needed — it's a single self-contained script.

## Usage

### Basic lint

```bash
python3 c2lint.py profile.profile
```

```
== profile.profile ==
  [WARNING] line 12: statement does not end with ';' — likely missing terminator
  [ERROR  ] line 24: odd number of double-quote characters — unterminated string literal
  1 error(s), 1 warning(s)
```

### Lint multiple files

```bash
python3 c2lint.py profile1.profile profile2.profile
```

### Strict mode (style nits too)

```bash
python3 c2lint.py --strict profile.profile
```

### Treat warnings as failures (useful in CI)

```bash
python3 c2lint.py --warnings-as-errors profile.profile
```

### Minify

```bash
python3 c2lint.py --minify profile.profile
python3 c2lint.py --minify -o profile.min.profile profile.profile
```

### Beautify

```bash
python3 c2lint.py --beautify profile.profile
python3 c2lint.py --beautify -o profile.clean.profile profile.profile
```

### Version compliance check

```bash
python3 c2lint.py --check-version 4.9 profile.profile
```

```
[ERROR] line 18: option 'rdll_use_driploading' requires Cobalt Strike >= 4.12,
        newer than target 4.9 — will not be recognized on the target version
```

### Format and lint together

By default, `--minify`/`--beautify` skip the normal lint output and just
print the formatted profile. Combine with `--lint-and-format` to get both:

```bash
python3 c2lint.py --minify --lint-and-format profile.profile
```

## Exit codes

- `0` — no errors found (warnings alone don't fail, unless
  `--warnings-as-errors` is set)
- `1` — one or more errors found, or a file couldn't be read

## Known limitations

- Heuristic parser, not a full grammar implementation — deeply unusual
  but valid syntax may produce false positives/negatives
- Version-compliance data only covers what's publicly documented up to
  Cobalt Strike **4.12**
- Does not validate semantic correctness (e.g. whether a `client`/`server`
  block is nested inside the right parent, whether a referenced keystore
  file exists, etc.)
- Not a replacement for the official `c2lint` shipped with Cobalt Strike

## Roadmap / ideas

- JSON output for CI integration
- Auto-fix mode (insert missing semicolons)
- Structural diff between two profiles
- OPSEC checks against known public/default profile signatures
- Parent/child block semantic validation

Contributions and PRs welcome.
