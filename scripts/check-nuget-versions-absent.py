#!/usr/bin/env python3
"""Fail before push if any immutable package ID/version already exists in GitHub Packages."""

import argparse
import json
import os
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


API_ROOT = "https://api.github.com/orgs/OpenPhysical/packages/nuget"


def package_versions(package_id: str, state: str, token: str) -> set[str]:
    found = set()
    page = 1
    while True:
        url = f"{API_ROOT}/{quote(package_id.casefold(), safe='')}/versions?state={state}&per_page=100&page={page}"
        request = Request(url, headers={"Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}", "X-GitHub-Api-Version": "2026-03-10"})
        try:
            with urlopen(request, timeout=30) as response:
                values = json.loads(response.read().decode("utf-8"))
                if not isinstance(values, list):
                    raise ValueError(f"GitHub package API returned an invalid version list for {package_id}")
                page_versions = {str(item.get("name", "")) for item in values if isinstance(item, dict)}
                found.update(page_versions)
                if len(values) < 100:
                    return found
                page += 1
        except HTTPError as error:
            if error.code == 404 and page == 1:
                return found
            raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        parser.error("GITHUB_TOKEN is required for immutable-version preflight")
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        packages = manifest.get("packages")
        if not isinstance(packages, list) or not packages:
            raise ValueError("package manifest has no package records")
        existing = []
        for package in packages:
            package_id = package.get("id")
            version = package.get("version")
            if not package_id or not version:
                raise ValueError("package manifest contains an incomplete package identity")
            active = package_versions(package_id, "active", token)
            deleted = package_versions(package_id, "deleted", token)
            if version in active or version in deleted:
                existing.append(f"{package_id} {version}")
        if existing:
            raise ValueError("immutable package versions already exist; increment the source-declared version: " + ", ".join(existing))
    except (OSError, json.JSONDecodeError, ValueError, HTTPError, URLError) as error:
        print(f"Package publication preflight blocked: {error}", file=sys.stderr)
        return 1
    print(f"Verified all {len(packages)} DEV package versions are unused.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
