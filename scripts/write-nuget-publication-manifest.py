#!/usr/bin/env python3
"""Bind every NuGet archive and its native/model payload inventory to source."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile


ROOT = Path(__file__).resolve().parents[1]
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DEV_VERSION_RE = re.compile(r"^[0-9A-Za-z.+-]*-dev\.[0-9A-Za-z.-]+$")


def digest(stream) -> tuple[int, str]:
    hasher = hashlib.sha256()
    size = 0
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        size += len(block)
        hasher.update(block)
    return size, hasher.hexdigest()


def project_identity(project: Path, package_version: str | None) -> tuple[str, str]:
    command = ["dotnet", "msbuild", str(project), "-nologo"]
    if package_version:
        command.extend(["-p:Version=" + package_version, "-p:PackageVersion=" + package_version])
    command.append("-getProperty:PackageId,PackageVersion,Version")
    result = subprocess.check_output(command, cwd=ROOT, text=True)
    properties = json.loads(result).get("Properties", {})
    package_id = properties.get("PackageId")
    version = properties.get("PackageVersion") or properties.get("Version")
    if not isinstance(package_id, str) or not package_id or not isinstance(version, str) or not version:
        raise ValueError(f"project does not resolve a package ID/version: {project.relative_to(ROOT)}")
    if not DEV_VERSION_RE.fullmatch(version):
        raise ValueError(f"only source-declared DEV package versions can be published: {package_id} {version}")
    return package_id, version


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def inspect_package(path: Path, expected_id: str, expected_version: str, commit: str) -> dict:
    package_entries = []
    native_assets = []
    model_assets = []
    with zipfile.ZipFile(path) as archive:
        nuspecs = [item for item in archive.namelist() if item.lower().endswith(".nuspec")]
        if len(nuspecs) != 1:
            raise ValueError(f"{path.name} must contain exactly one .nuspec")
        nuspec = ET.fromstring(archive.read(nuspecs[0]))
        metadata = next((node for node in nuspec.iter() if local_name(node.tag) == "metadata"), None)
        if metadata is None:
            raise ValueError(f"{path.name} has no package metadata")
        values = {local_name(node.tag): (node.text or "").strip() for node in metadata.iter() if list(node) == []}
        if values.get("id", "").casefold() != expected_id.casefold() or values.get("version") != expected_version:
            raise ValueError(f"{path.name} package identity differs from source project")
        repository = next((node for node in metadata.iter() if local_name(node.tag) == "repository"), None)
        if repository is None or repository.get("commit") != commit:
            raise ValueError(f"{path.name} does not bind its NuGet metadata to source {commit}")
        for item in archive.infolist():
            if item.is_dir():
                continue
            with archive.open(item) as stream:
                size, sha = digest(stream)
            entry = {"path": item.filename, "size": size, "sha256": sha}
            package_entries.append(entry)
            lower = item.filename.lower()
            if "/runtimes/" in "/" + lower and "/native/" in lower:
                native_assets.append(entry)
            if lower.endswith((".onnx", ".tflite", ".pb", ".model")) or "/models/" in lower:
                model_assets.append(entry)
    with path.open("rb") as stream:
        size, sha = digest(stream)
    return {"id": expected_id, "version": expected_version, "file": path.name, "size": size,
            "sha256": sha, "contents": package_entries, "nativeAssets": native_assets, "modelAssets": model_assets}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--packages", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, default=Path(__file__).with_name("nuget-package-projects.json"))
    parser.add_argument("--package-version", help="consumer-pinned version override for a bootstrap package")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        commit = args.source_commit.lower()
        if not COMMIT_RE.fullmatch(commit):
            raise ValueError("source commit must be a full 40-character Git SHA")
        projects = json.loads(args.catalog.read_text(encoding="utf-8")).get("projects", [])
        resolved = [(ROOT / relative).resolve() for relative in projects]
        if any(not project.is_relative_to(ROOT) or not project.is_file() for project in resolved):
            raise ValueError("publisher catalog contains a missing or out-of-repository project")
        expected = {project_identity(project, args.package_version) for project in resolved}
        if not expected:
            raise ValueError("publisher catalog does not identify any package projects")
        actual = sorted(path for path in args.packages.glob("*.nupkg") if not path.name.endswith(".symbols.nupkg"))
        records = []
        consumed = set()
        for package_id, version in sorted(expected):
            matches = [path for path in actual if path.stem.casefold() == f"{package_id}.{version}".casefold()]
            if len(matches) != 1:
                raise ValueError(f"expected one package archive for {package_id} {version}, found {len(matches)}")
            package = matches[0]
            consumed.add(package)
            records.append(inspect_package(package, package_id, version, commit))
        if consumed != set(actual):
            extras = sorted(path.name for path in set(actual) - consumed)
            raise ValueError(f"package output has uncatalogued archives: {extras}")
        manifest = {"schemaVersion": 1, "repository": args.repository, "sourceCommit": commit,
                    "packages": records,
                    "nativeInventory": [{"package": p["id"], "version": p["version"], **entry}
                                        for p in records for entry in p["nativeAssets"]],
                    "modelInventory": [{"package": p["id"], "version": p["version"], **entry}
                                       for p in records for entry in p["modelAssets"]]}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    except (OSError, json.JSONDecodeError, ValueError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        print(f"NuGet publication manifest blocked: {error}", file=sys.stderr)
        return 1
    print(f"Manifested {len(records)} source-bound NuGet packages for {args.repository}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
