#!/usr/bin/env python3
"""
c2lint.py - A syntax/structure linter for Cobalt Strike Malleable C2 profiles.

This tool does NOT generate, modify traffic behavior, or interact with any
C2 infrastructure. It only parses a profile file as text and reports
structural/syntax problems, similar to a linter for an nginx or json config
file: unbalanced braces, missing semicolons, duplicate/unknown top-level
blocks, unquoted strings, etc.

Usage:
    python3 c2lint.py profile.profile
    python3 c2lint.py --strict profile.profile
    python3 c2lint.py profile1.profile profile2.profile
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class Finding:
    severity: Severity
    line: int
    message: str

    def __str__(self) -> str:
        return f"[{self.severity.value.upper():7}] line {self.line}: {self.message}"


# Top-level blocks recognized by Cobalt Strike's Malleable C2 profile grammar.
# (Structural names only -- used to flag typos/unknown blocks, not to
# validate or improve evasion characteristics.)
KNOWN_TOP_LEVEL_BLOCKS = {
    "http-get", "http-post", "http-stager", "https-certificate",
    "dns-beacon", "code-signer", "stage", "process-inject",
    "post-ex", "ssh", "smb", "tcp", "http-config", "ssl-config",
}

# Top-level scalar directives (key value; -- no braces).
KNOWN_TOP_LEVEL_DIRECTIVES = {
    "set", "sleeptime", "jitter", "maxdns", "useragent", "host_stage",
}

STRING_DIRECTIVE_HINT = re.compile(r'^\s*(\w[\w-]*)\s+"')

# Malleable C2 options tagged with the Cobalt Strike version that introduced
# them, per public Cobalt Strike release notes / changelogs (cobaltstrike.com
# release page, threatexpress/malleable-c2 changelog). This list is NOT
# exhaustive and is not a substitute for Fortra's official documentation or
# the c2lint binary shipped with the Cobalt Strike teamserver — treat it as a
# best-effort "does this profile use something newer than my target version"
# check, not an authoritative compliance certification.
#
# Keyed by (block, option-name) where block is "*" for a directive that can
# appear at top level or isn't tied to one specific block.
VERSIONED_OPTIONS = {
    ("stage", "syscall_method"): "4.8",
    ("post-ex", "cleanup"): "4.9",
    ("*", "library"): "4.9",            # http-beacon library (wininet/winhttp)
    ("stage", "beacon_gate"): "4.11",
    ("stage", "rdll_use_driploading"): "4.12",
    ("stage", "rdll_dripload_delay"): "4.12",
    ("process-inject", "use_driploading"): "4.12",
    ("process-inject", "dripload_delay"): "4.12",
}


def _version_tuple(v: str):
    return tuple(int(p) for p in v.split("."))


@dataclass
class LintResult:
    findings: list = field(default_factory=list)

    def add(self, severity: Severity, line: int, message: str) -> None:
        self.findings.append(Finding(severity, line, message))

    @property
    def errors(self):
        return [f for f in self.findings if f.severity == Severity.ERROR]

    @property
    def warnings(self):
        return [f for f in self.findings if f.severity == Severity.WARNING]

    def ok(self) -> bool:
        return not self.errors


def strip_comments_and_strings(text: str):
    """
    Walk the text char by char, tracking whether we're inside a quoted
    string or a comment, so brace-counting and other structural checks
    don't get confused by braces/semicolons that appear inside string
    literals or after '#'.

    Returns a list of (line_no, cleaned_line) pairs, where cleaned_line has
    string contents blanked out (but quotes kept) and comments removed.
    """
    lines = text.splitlines()
    cleaned = []
    in_block_comment = False  # Malleable C2 profiles don't have /* */ but
                               # some hand-edited files creep in C-style; we
                               # still guard for it defensively.
    for i, raw_line in enumerate(lines, start=1):
        out_chars = []
        in_string = False
        j = 0
        n = len(raw_line)
        while j < n:
            ch = raw_line[j]
            if in_block_comment:
                if ch == "*" and j + 1 < n and raw_line[j + 1] == "/":
                    in_block_comment = False
                    j += 2
                    continue
                j += 1
                continue
            if in_string:
                out_chars.append(ch)
                if ch == "\\" and j + 1 < n:
                    out_chars.append(raw_line[j + 1])
                    j += 2
                    continue
                if ch == '"':
                    in_string = False
                j += 1
                continue
            # Not in string or comment
            if ch == "#":
                break  # rest of line is a comment
            if ch == "/" and j + 1 < n and raw_line[j + 1] == "*":
                in_block_comment = True
                j += 2
                continue
            if ch == '"':
                in_string = True
                out_chars.append(ch)
                j += 1
                continue
            out_chars.append(ch)
            j += 1
        cleaned.append((i, "".join(out_chars)))
    return cleaned


def check_braces(cleaned_lines, result: LintResult):
    stack = []  # list of (line_no, block_name_guess)
    block_name_stack = []
    pending_name = None
    for line_no, line in cleaned_lines:
        stripped = line.strip()
        if not stripped:
            continue
        # crude "name {" detection to give better error messages
        m = re.match(r'^([\w\-\.]+)\s*\{', stripped)
        if m:
            pending_name = m.group(1)

        for ch in line:
            if ch == "{":
                stack.append(line_no)
                block_name_stack.append(pending_name or "?")
                pending_name = None
            elif ch == "}":
                if not stack:
                    result.add(
                        Severity.ERROR, line_no,
                        "unmatched closing brace '}' with no corresponding '{'",
                    )
                else:
                    stack.pop()
                    block_name_stack.pop()
    for line_no in stack:
        result.add(
            Severity.ERROR, line_no,
            "unclosed '{' — no matching '}' found before end of file",
        )


def check_top_level_blocks(cleaned_lines, result: LintResult):
    depth = 0
    seen_at_depth0 = {}
    for line_no, line in cleaned_lines:
        stripped = line.strip()
        if not stripped:
            continue

        if depth == 0:
            m = re.match(r'^([\w\-\.]+)\s*\{', stripped)
            if m:
                name = m.group(1)
                if name not in KNOWN_TOP_LEVEL_BLOCKS:
                    result.add(
                        Severity.WARNING, line_no,
                        f"unrecognized top-level block '{name}' "
                        f"(check for a typo?)",
                    )
                elif name in seen_at_depth0 and name != "http-get" and name != "http-post":
                    # http-get/http-post/etc. can legitimately repeat in some
                    # profile styles; most others are expected once.
                    result.add(
                        Severity.INFO, line_no,
                        f"block '{name}' also appeared at line "
                        f"{seen_at_depth0[name]} — verify this duplication is intentional",
                    )
                seen_at_depth0[name] = line_no
            else:
                sm = re.match(r'^(\w[\w-]*)\s+', stripped)
                if sm and sm.group(1) not in KNOWN_TOP_LEVEL_DIRECTIVES and not stripped.startswith("}"):
                    result.add(
                        Severity.WARNING, line_no,
                        f"unrecognized top-level directive '{sm.group(1)}'",
                    )

        depth += line.count("{") - line.count("}")


def check_statement_termination(cleaned_lines, result: LintResult):
    """
    Inside blocks, most Malleable C2 statements should end with ';'.
    Lines that open/close a brace, or are blank/comment-only, are exempt.
    """
    for line_no, line in cleaned_lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.endswith("{") or stripped.endswith("}") or stripped == "}":
            continue
        if stripped.endswith(";"):
            continue
        # Directives that are themselves block openers spanning to next line
        # (rare) are hard to detect generically; only warn on lines that
        # look like a complete simple statement (word ... value) with no
        # trailing brace/semicolon.
        if re.match(r'^[\w\-\.]+(\s+.*)?$', stripped):
            result.add(
                Severity.WARNING, line_no,
                "statement does not end with ';' — likely missing terminator",
            )


def check_quotes_balanced(text: str, result: LintResult):
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        # Count unescaped quote chars
        count = 0
        j = 0
        n = len(raw_line)
        while j < n:
            ch = raw_line[j]
            if ch == "\\" and j + 1 < n:
                j += 2
                continue
            if ch == '"':
                count += 1
            j += 1
        if count % 2 != 0:
            result.add(
                Severity.ERROR, line_no,
                "odd number of double-quote characters — unterminated string literal",
            )


def check_version_compliance(cleaned_lines, result: LintResult, target_version: str):
    """
    Flags any 'set <option> ...' statement whose known introduction version
    is newer than target_version -- i.e. it would be silently ignored (or
    rejected) by an older/target Cobalt Strike teamserver. Also emits an
    INFO note for every recognized versioned option purely for visibility.

    This tracks the *nearest enclosing named block* by a simple stack, so
    "library" inside "http-get { ... }" is distinguished from a same-named
    option elsewhere. It is a heuristic, not a full parser.
    """
    target = _version_tuple(target_version)
    block_stack = []
    pending_name = None

    for line_no, line in cleaned_lines:
        stripped = line.strip()
        if not stripped:
            continue

        m = re.match(r'^([\w\-\.]+)\s*\{', stripped)
        if m:
            pending_name = m.group(1)

        sm = re.match(r'^set\s+([\w\-]+)\s+', stripped)
        if sm:
            option = sm.group(1)
            current_block = block_stack[-1] if block_stack else "*"
            key = (current_block, option)
            alt_key = ("*", option)
            entry = VERSIONED_OPTIONS.get(key) or VERSIONED_OPTIONS.get(alt_key)
            if entry:
                needed = _version_tuple(entry)
                if needed > target:
                    result.add(
                        Severity.ERROR, line_no,
                        f"option '{option}' requires Cobalt Strike >= {entry}, "
                        f"newer than target {target_version} — will not be "
                        f"recognized on the target version",
                    )
                else:
                    result.add(
                        Severity.INFO, line_no,
                        f"option '{option}' requires Cobalt Strike >= {entry} "
                        f"(OK for target {target_version})",
                    )

        for ch in line:
            if ch == "{":
                block_stack.append(pending_name or "?")
                pending_name = None
            elif ch == "}":
                if block_stack:
                    block_stack.pop()

    result.add(
        Severity.INFO, 0,
        f"version check target: Cobalt Strike {target_version}. This list of "
        f"versioned options is derived from public changelogs and is NOT "
        f"exhaustive — run the official 'c2lint' bundled with your "
        f"teamserver install for authoritative validation before an engagement.",
    )


def check_trailing_whitespace_and_tabs(text: str, result: LintResult, strict: bool):
    if not strict:
        return
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        if raw_line != raw_line.rstrip():
            result.add(Severity.INFO, line_no, "trailing whitespace")
        if "\t" in raw_line:
            result.add(Severity.INFO, line_no, "line contains a tab character (mixed indentation risk)")


def _strip_comments_preserve_strings(text: str):
    """
    Like strip_comments_and_strings, but keeps string contents intact
    (only removes comments) — used for minify/beautify, which should not
    mangle string literals the way the lint-only cleaner does.
    Returns a list of (line_no, line_without_comments) — lines that become
    empty after comment removal are kept as "" so callers can drop them.
    """
    lines = text.splitlines()
    out = []
    in_block_comment = False
    for i, raw_line in enumerate(lines, start=1):
        chars = []
        in_string = False
        j = 0
        n = len(raw_line)
        while j < n:
            ch = raw_line[j]
            if in_block_comment:
                if ch == "*" and j + 1 < n and raw_line[j + 1] == "/":
                    in_block_comment = False
                    j += 2
                    continue
                j += 1
                continue
            if in_string:
                chars.append(ch)
                if ch == "\\" and j + 1 < n:
                    chars.append(raw_line[j + 1])
                    j += 2
                    continue
                if ch == '"':
                    in_string = False
                j += 1
                continue
            if ch == "#":
                break
            if ch == "/" and j + 1 < n and raw_line[j + 1] == "*":
                in_block_comment = True
                j += 2
                continue
            if ch == '"':
                in_string = True
                chars.append(ch)
                j += 1
                continue
            chars.append(ch)
            j += 1
        out.append((i, "".join(chars)))
    return out


def _collapse_whitespace_outside_strings(line: str) -> str:
    out = []
    in_string = False
    prev_space = False
    j = 0
    n = len(line)
    while j < n:
        ch = line[j]
        if in_string:
            out.append(ch)
            if ch == "\\" and j + 1 < n:
                out.append(line[j + 1])
                j += 2
                continue
            if ch == '"':
                in_string = False
            prev_space = False
            j += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            prev_space = False
            j += 1
            continue
        if ch in " \t":
            if not prev_space:
                out.append(" ")
            prev_space = True
            j += 1
            continue
        out.append(ch)
        prev_space = False
        j += 1
    return "".join(out).strip()


def minify_profile(text: str) -> str:
    """
    Strip comments and blank lines, and collapse internal whitespace runs
    to a single space. Keeps one statement/brace per output line (a true
    single-line minify is possible but hurts readability for something
    you'll likely still hand-edit later; use this for a "diff-friendly,
    comment-free" copy rather than a byte-minimal one).
    """
    stripped = _strip_comments_preserve_strings(text)
    out_lines = []
    for _, line in stripped:
        collapsed = _collapse_whitespace_outside_strings(line)
        if collapsed:
            out_lines.append(collapsed)
    return "\n".join(out_lines) + "\n"


def beautify_profile(text: str, indent_size: int = 4) -> str:
    """
    Re-indent the profile based on brace depth. Non-destructive: comments
    and string contents are left exactly as written; only leading
    whitespace on each line is normalized. Blank lines are preserved as
    single blank separators (collapsing runs of 2+ blank lines to 1).
    """
    cleaned_for_depth = strip_comments_and_strings(text)  # blanks strings, safe for counting braces
    raw_lines = text.splitlines()
    depth = 0
    out_lines = []
    prev_blank = False

    for (line_no, cleaned_line), raw_line in zip(cleaned_for_depth, raw_lines):
        stripped_raw = raw_line.strip()

        if not stripped_raw:
            if not prev_blank and out_lines:
                out_lines.append("")
            prev_blank = True
            continue
        prev_blank = False

        starts_with_close = stripped_raw.startswith("}")
        this_line_indent = depth - 1 if starts_with_close else depth
        this_line_indent = max(this_line_indent, 0)
        out_lines.append(" " * (indent_size * this_line_indent) + stripped_raw)

        depth += cleaned_line.count("{") - cleaned_line.count("}")
        depth = max(depth, 0)

    return "\n".join(out_lines) + "\n"


def lint_profile(text: str, strict: bool = False, target_version: str | None = None) -> LintResult:
    result = LintResult()
    cleaned_lines = strip_comments_and_strings(text)

    check_quotes_balanced(text, result)
    check_braces(cleaned_lines, result)
    check_top_level_blocks(cleaned_lines, result)
    check_statement_termination(cleaned_lines, result)
    check_trailing_whitespace_and_tabs(text, result, strict)
    if target_version:
        check_version_compliance(cleaned_lines, result, target_version)

    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Lint Cobalt Strike Malleable C2 profile files for "
                     "syntax/structural problems (brace balance, missing "
                     "semicolons, unknown blocks, unterminated strings)."
    )
    parser.add_argument("files", nargs="+", help="profile file(s) to lint")
    parser.add_argument(
        "--strict", action="store_true",
        help="also report style nits (trailing whitespace, tabs)",
    )
    parser.add_argument(
        "--warnings-as-errors", action="store_true",
        help="treat warnings as failing the lint (non-zero exit code)",
    )
    parser.add_argument(
        "--check-version", metavar="X.Y", default=None,
        help="flag any option whose known introduction version is newer "
             "than X.Y (e.g. --check-version 4.9). Best-effort, based on "
             "public changelogs only — see notes in output.",
    )
    fmt_group = parser.add_mutually_exclusive_group()
    fmt_group.add_argument(
        "--minify", action="store_true",
        help="strip comments/blank lines and collapse whitespace; "
             "print result instead of (or alongside) lint findings",
    )
    fmt_group.add_argument(
        "--beautify", action="store_true",
        help="re-indent the profile by brace depth (comments/strings "
             "preserved); print result instead of (or alongside) lint findings",
    )
    parser.add_argument(
        "-o", "--output",
        help="write --minify/--beautify result to this path instead of "
             "stdout (only valid with a single input file)",
    )
    parser.add_argument(
        "--lint-and-format", action="store_true",
        help="with --minify/--beautify, also run and print the normal lint "
             "findings (default when a format flag is used is to skip "
             "lint output and just emit the formatted profile)",
    )
    args = parser.parse_args(argv)

    if args.output and len(args.files) != 1:
        parser.error("-o/--output requires exactly one input file")

    overall_ok = True
    for path in args.files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as e:
            print(f"{path}: cannot read file: {e}", file=sys.stderr)
            overall_ok = False
            continue

        if args.minify or args.beautify:
            formatted = minify_profile(text) if args.minify else beautify_profile(text)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as out_fh:
                    out_fh.write(formatted)
                print(f"{path}: wrote formatted profile to {args.output}")
            else:
                print(f"== {path} ({'minified' if args.minify else 'beautified'}) ==")
                print(formatted)
            if not args.lint_and_format:
                continue

        result = lint_profile(text, strict=args.strict, target_version=args.check_version)
        print(f"== {path} ==")
        if not result.findings:
            print("  no issues found")
        else:
            for finding in sorted(result.findings, key=lambda f: f.line):
                print(f"  {finding}")
            print(
                f"  {len(result.errors)} error(s), "
                f"{len(result.warnings)} warning(s)"
            )

        if not result.ok():
            overall_ok = False
        if args.warnings_as_errors and result.warnings:
            overall_ok = False

    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
