"""Project 5: heuristic scan for embedded prompts and injection phrases."""

import re
import sys
from pathlib import Path

SYSTEM_PROMPT_PATTERNS = [
    r"""\bSYSTEM_PROMPT\s*=\s*(?:[rubf]{0,2})?["']""",
    r"""\bsystem_message\s*=\s*(?:[rubf]{0,2})?["']""",
    r"""["']role["']\s*:\s*["']system["']""",
]

INJECTION_PHRASES = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "you are now",
    "pretend you are",
    "act as if you have no restrictions",
]

SKIP_DIRS = {
    ".audit-tools",
    ".git", ".venv", "venv", "ai-lab", "__pycache__",
    "node_modules", "site-packages",
}


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    if not root.is_dir():
        print(f"ERROR: not a directory: {root}")
        return 2

    findings = 0
    scan_error = False
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if path.resolve() == Path(__file__).resolve():
            continue  # Do not flag this scanner's own detection lists.
        if SKIP_DIRS.intersection(relative.parts[:-1]):
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            print(f"ERROR: cannot read {relative}: {error}")
            scan_error = True
            continue

        patterns = [(p, "embedded system prompt") for p in SYSTEM_PROMPT_PATTERNS]
        patterns += [(re.escape(p), "injection phrase") for p in INJECTION_PHRASES]
        for pattern, label in patterns:
            for match in re.finditer(pattern, source, re.IGNORECASE):
                line = source.count("\n", 0, match.start()) + 1
                print(f"{relative}:{line}: {label}")
                findings += 1

    if scan_error:
        print("ERROR: scan incomplete; gate blocked.")
        return 2
    if findings:
        print(f"FAIL: {findings} potential prompt security issue(s).")
        return 1
    print("PASS: no configured prompt patterns found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
