#!/usr/bin/env python3
"""Require a clean checkout at the exact requested package source commit."""

import argparse
import re
import subprocess
import sys
from pathlib import Path


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    args = parser.parse_args()
    commit = args.source_commit.lower()
    if not COMMIT_RE.fullmatch(commit):
        parser.error("source commit must be a full 40-character Git SHA")
    repository = args.repository.resolve()
    try:
        actual = subprocess.check_output(["git", "-C", str(repository), "rev-parse", "HEAD"], text=True).strip()
        dirty = subprocess.check_output(["git", "-C", str(repository), "status", "--porcelain", "--untracked-files=normal"], text=True).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"Package source check blocked: {error}", file=sys.stderr)
        return 1
    if actual != commit:
        print(f"Package source check blocked: checkout is {actual}, requested {commit}", file=sys.stderr)
        return 1
    if dirty:
        print("Package source check blocked: checkout is not clean", file=sys.stderr)
        return 1
    print(f"Verified clean source checkout at {commit}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
