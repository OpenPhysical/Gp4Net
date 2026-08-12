# Gp4Net

[![Build and Test](https://github.com/OpenPhysical/Gp4Net/actions/workflows/build.yml/badge.svg)](https://github.com/OpenPhysical/Gp4Net/actions/workflows/build.yml)
[![.NET 10](https://img.shields.io/badge/.NET-10.0-512BD4)](https://dotnet.microsoft.com/)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

Gp4Net is a .NET 10 toolkit for GlobalPlatform card management. It provides a reusable library,
a command-line interface, and a virtual-card emulator, with support centered on GlobalPlatform
Card Specification 2.3.1 and SCP02/SCP03 secure channels.

> [!IMPORTANT]
> This repository is public and the project is pre-release. NuGet publishing is planned, but the
> packages are not available yet. Build and run Gp4Net from source for now.

## Capabilities

- SCP02 and SCP03 secure-channel establishment
- Command and response MAC processing, plus command and response encryption
- Static, diversified, and session key handling
- Card discovery, card data inspection, and ISD data operations
- CAP validation, loading, installation, instantiation, listing, and deletion
- Java Card SDK package scanning and EXP analysis
- APDU trace conversion and validation support
- Deterministic virtual-card profiles for development and integration testing
- Result-oriented error handling with `CSharpFunctionalExtensions`
- Cryptographic operations implemented through Bouncy Castle

## Repository layout

- `src/Gp4Net/`: reusable GlobalPlatform library
- `src/Gp4Net.Tool/`: `gp4net` command-line application
- `src/Gp4Net.CardEmulator/`: virtual-card implementation and profiles
- `tests/`: unit, compliance, CLI, emulator, integration, and benchmark projects
- `docs/architecture/`: architecture notes and implementation guides

## Requirements

- .NET 10 SDK
- Git
- A PC/SC-compatible reader and its system driver for physical-card operations

No reader is required for CAP validation or virtual-card workflows.

## Build and test

```bash
git clone git@github.com:OpenPhysical/Gp4Net.git
cd Gp4Net
dotnet restore
dotnet build
dotnet test
```

GitHub Actions also collects Cobertura coverage and enforces total line and branch baselines for
every solution test project: 25% for the core suite, 10% for the emulator suite, and 4% for the CLI
suite. It uploads all reports and publishes the Ubuntu reports to Codecov when a `CODECOV_TOKEN`
secret is configured.

Skip slower integration scenarios while iterating:

```bash
dotnet test --filter "Category!=Integration"
```

Format C# sources with the repository-pinned CSharpier version:

```bash
dotnet tool restore
dotnet csharpier .
```

## CLI quick start

Run the CLI directly from source:

```bash
dotnet run --project src/Gp4Net.Tool/Gp4Net.Tool.csproj -- --help
dotnet run --project src/Gp4Net.Tool/Gp4Net.Tool.csproj -- card list-readers
```

Inspect the included virtual P71 profile without card hardware:

```bash
dotnet run --project src/Gp4Net.Tool/Gp4Net.Tool.csproj -- \
  card info \
  --reader virtual:src/Gp4Net.CardEmulator/Profiles/p71_card_1.json
```

Validate an included CAP file:

```bash
dotnet run --project src/Gp4Net.Tool/Gp4Net.Tool.csproj -- \
  applet validate tests/applets/AlgTest_v1.8.0_jc305.cap --detailed
```

Reader selection follows this order:

1. `--reader <name>`
2. `GP4NET_READER`
3. interactive selection when available

A virtual reader uses the form `virtual:path/to/profile.json`.

### Command groups

```text
gp4net card       # reader, card data, key, and secure-channel operations
gp4net applet     # CAP validation and applet lifecycle operations
gp4net packages   # Java Card SDK and EXP package analysis
gp4net trace      # trace conversion
```

Use `--help` at any level for the authoritative options, for example:

```bash
dotnet run --project src/Gp4Net.Tool/Gp4Net.Tool.csproj -- applet validate --help
dotnet run --project src/Gp4Net.Tool/Gp4Net.Tool.csproj -- card test-sc --help
```

## Library architecture

The core library separates protocol, state, and side-effect concerns:

- `Domain`: commands, keys, security levels, CAP models, and protocol state
- `Services`: pure SCP, CAP, TLV, capability, and GlobalPlatform operation modules
- `Transport`: APDU construction, transmission, and response handling
- `Constants`: shared GlobalPlatform, Java Card, APDU, TLV, and status-word constants

`CardOperation<T>` threads immutable `CardSession` state through command workflows. Channel and
transport exchanges return their updated state explicitly, including immutable virtual-card state.
Public operations favor `Result<T, SmartCardError>` and `Maybe<T>` over implicit failure or optional
state. The CLI uses an explicit command catalog and startup composition, with no application DI
container.

## Protocol support

| Protocol | Static keys | Session derivation | Command security | Response security |
| --- | --- | --- | --- | --- |
| SCP02 | 3DES | SCP02 derivation data | C-MAC, C-ENC | R-MAC, R-ENC |
| SCP03 | AES | Counter-mode KDF | AES-CMAC, C-ENC | R-MAC, R-ENC |

Protocol behavior is tested against unit vectors, emulator workflows, and captured-card trace
fixtures. Hardware and card-specific behavior can still vary, so validate destructive operations
against the exact card profile before deployment.

## Documentation

- [Architecture](docs/architecture/README.md)
- [SCP02 notes](docs/SCP02_specification.md)
- [Contributing guide](CONTRIBUTING.md)
- [Contributor copyright assignment](CONTRIBUTOR_ASSIGNMENT.md)
- [Commercial licensing](COMMERCIAL-LICENSING.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)
- [Security policy](SECURITY.md)
- [Bounded Contribution Policy](CODE_OF_CONDUCT.md)

## Security


Use well-known test keys only with disposable test cards and emulator profiles. Report
vulnerabilities through the private process in the [security policy](SECURITY.md).

## Package publishing

NuGet publishing is planned for the `Gp4Net` library after the pre-release API and packaging checks
are complete. Until then, the supported workflow is building from this repository.

## License

Gp4Net is licensed under the [GNU Affero General Public License v3.0 only](LICENSE), identified by
SPDX as `AGPL-3.0-only`. Organizations that need different terms may request a separately
negotiated [commercial license](COMMERCIAL-LICENSING.md). Licensing fees for Gp4Net support the
development of OpenPhysical software and services.
