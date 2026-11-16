#!/usr/bin/env python3
"""Check release project references against the product repository boundaries."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

PRODUCTS = {
    'OpenPhysical.Net': 'sdk',
    'OpenPhysical.Biometrics': 'biometrics',
    'OpenPhysical.Enrollment.Studio': 'enrollment',
    'OpenPhysical.Issuer.Studio': 'issuer',
    'OpenPhysical.Issuance.Server': 'server',
    'OpenPhysical.Directory': 'directory',
}
APP_PREFIXES = ('OpenPhysical.Enrollment.', 'OpenPhysical.Issuer.', 'OpenPhysical.Issuance.Authority',
                'OpenPhysical.Issuance.Server', 'OpenPhysical.Directory')
SKIP = {'.git', 'artifacts', 'bin', 'obj', 'node_modules', 'lib'}

def owned_projects(root: Path):
    for project in root.rglob('*.csproj'):
        parts = project.relative_to(root).parts
        if not any(part in SKIP for part in parts):
            yield project

def check(root: Path, role: str, publish_dir: Path | None = None) -> tuple[list[str], int]:
    failures = []
    projects = sorted(owned_projects(root))
    for project in projects:
        relative = project.relative_to(root)
        test = any(part.lower() in ('test', 'tests') for part in relative.parts) or '.Tests' in project.stem
        try:
            xml = ET.parse(project).getroot()
        except ET.ParseError as error:
            failures.append(f'{relative}: invalid XML: {error}')
            continue
        for reference in xml.iter('ProjectReference'):
            value = reference.get('Include', '').replace('\\', '/')
            if '$(' in value:
                failures.append(f'{relative}: release project reference must be explicit: {value}')
                continue
            target = (project.parent / value).resolve()
            if not target.is_relative_to(root):
                failures.append(f'{relative}: sibling source dependency: {value}')
            elif not target.is_file():
                failures.append(f'{relative}: missing project: {value}')
        if test:
            continue
        def check_package(name: str, source: str) -> None:
            if role in ('sdk', 'biometrics') and name.startswith(APP_PREFIXES):
                failures.append(f'{relative}: {source} library depends on product: {name}')
            if role == 'biometrics' and name.startswith(('OpenPhysical.Station.', 'OpenPhysical.CredentialOperations',
                                                       'OpenPhysical.Verification', 'OpenPhysical.CardEdge',
                                                       'OpenPhysical.Hosting', 'OpenPhysical.Cards')):
                failures.append(f'{relative}: {source} biometric library depends on workstation implementation: {name}')
            if role != 'enrollment' and name.startswith('OpenPhysical.Biometrics.Capture'):
                # Capture abstractions belong to the biometric library graph.
                if role != 'biometrics':
                    failures.append(f'{relative}: {source} capture dependency outside Enrollment: {name}')
            if role == 'enrollment' and name.startswith(('OpenPhysical.Issuer.', 'OpenPhysical.Issuance.Authority')):
                failures.append(f'{relative}: {source} Enrollment depends on manufacturing/authority: {name}')
            if role == 'issuer' and name.startswith(('OpenPhysical.Enrollment.', 'OpenPhysical.Issuance.Authority')):
                failures.append(f'{relative}: {source} Issuer depends on another product implementation: {name}')
            if role == 'server' and name.startswith(('OpenPhysical.Enrollment.', 'OpenPhysical.Issuer.')):
                failures.append(f'{relative}: {source} Server depends on a desktop implementation: {name}')

        for package in xml.iter('PackageReference'):
            check_package(package.get('Include', ''), 'direct')
        lock_path = project.with_name('packages.lock.json')
        if lock_path.is_file():
            try:
                locked = json.loads(lock_path.read_text(encoding='utf-8'))
                for framework, packages in locked.get('dependencies', {}).items():
                    for name, dependency in packages.items():
                        if isinstance(dependency, dict) and dependency.get('type') != 'Project':
                            check_package(name, f'locked {framework}')
            except (OSError, json.JSONDecodeError, AttributeError) as error:
                failures.append(f'{relative}: invalid package lock {lock_path.name}: {error}')
    if publish_dir is not None:
        publish_dir = publish_dir.resolve()
        if not publish_dir.is_relative_to(root.resolve()) or not publish_dir.is_dir():
            failures.append(f'{publish_dir}: publish output must be an existing directory inside {root}')
        else:
            dependency_files = sorted(publish_dir.rglob('*.deps.json'))
            if not dependency_files:
                failures.append(f'{publish_dir}: no .deps.json runtime dependency graph found')
            for dependency_file in dependency_files:
                try:
                    graph = json.loads(dependency_file.read_text(encoding='utf-8'))
                    libraries = graph.get('libraries', {})
                    if not isinstance(libraries, dict) or not libraries:
                        failures.append(f'{dependency_file.relative_to(root)}: runtime dependency graph has no libraries')
                        continue
                    for name, details in libraries.items():
                        if not isinstance(details, dict) or details.get('type') not in ('package', 'project'):
                            continue
                        package_name = str(name).rsplit('/', 1)[0]
                        check_package(package_name, f'published {dependency_file.name}')
                except (OSError, json.JSONDecodeError, AttributeError) as error:
                    failures.append(f'{dependency_file.relative_to(root)}: invalid .deps.json: {error}')
    if not projects:
        failures.append(f'{root}: no owned projects found')
    return failures, len(projects)

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace-root', type=Path)
    parser.add_argument('--repository', type=Path)
    parser.add_argument('--role', choices=sorted(set(PRODUCTS.values())))
    parser.add_argument('--publish-dir', type=Path, help='inspect the built or published .deps.json closure under this repository')
    args = parser.parse_args()
    if args.workspace_root and (args.repository or args.role or args.publish_dir):
        parser.error('choose --workspace-root or --repository/--role/--publish-dir')
    if args.workspace_root:
        candidates = [(args.workspace_root / name, role) for name, role in PRODUCTS.items()]
    else:
        root = (args.repository or Path(__file__).resolve().parents[1]).resolve()
        role = args.role or PRODUCTS.get(root.name)
        if role is None:
            parser.error('an unknown repository name requires --role')
        candidates = [(root, role)]
    failures = []
    results = []
    for root, role in candidates:
        errors, count = check(root.resolve(), role, args.publish_dir)
        failures.extend(errors)
        results.append({'repository': root.name, 'role': role, 'projects': count, 'errors': len(errors)})
    print(json.dumps({'repositories': results, 'failures': failures}, indent=2))
    return 1 if failures else 0

if __name__ == '__main__':
    sys.exit(main())
