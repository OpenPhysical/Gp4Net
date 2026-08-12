# Contributing to Gp4Net

Gp4Net welcomes focused technical contributions. Participation is governed by the
[Bounded Contribution Policy](CODE_OF_CONDUCT.md), and every contributor must accept the
[Contributor Copyright Assignment](CONTRIBUTOR_ASSIGNMENT.md) before a pull request can merge.

## Before contributing

You must own or control the rights to your contribution. Obtain employer approval when required and
identify third-party, generated, or externally sourced material in the pull request. If an employer
or another entity owns the work, an authorized representative must accept the assignment.

The CLA service records electronic acceptance. Accepted contributions remain available under
`AGPL-3.0-only` and may also be offered under separate commercial licenses. The contributor keeps a
broad license to reuse their contribution.

## Development setup

Requirements:

- .NET 10 SDK
- Git
- A PC/SC-compatible reader only for physical-card scenarios

```bash
git clone https://github.com/your-account/Gp4Net.git
cd Gp4Net
git switch -c feature/short-description master
dotnet restore
dotnet build
dotnet test
```

Use the virtual card for integration work when possible. Never use production keys in tests,
fixtures, logs, or traces.

## Engineering rules

- Represent optional state with `Maybe<T>`, not nullable types.
- Return `Result<T, SmartCardError>` for expected failures instead of throwing exceptions.
- Use CSharpFunctionalExtensions for functional results and composition.
- Route cryptographic operations through Bouncy Castle.
- Prefer immutable state and side-effect-free domain logic.
- Add XML documentation for public APIs and cite the relevant GP 2.3.1 section for protocol changes.
- Keep shared protocol constants under `src/Gp4Net/Constants/`.

Do not introduce APIs such as `IDisposable? BeginScope<TState>(TState state)`. Model the supported
state explicitly and keep nullable values out of project-owned APIs.

## Validation

Before opening a pull request, run:

```bash
dotnet restore
dotnet build -c Release
dotnet test -c Release
dotnet tool restore
dotnet csharpier . --check
```

Behavior changes need tests. Prefer the card emulator for integration scenarios and validate both
SCP02 and SCP03 when shared secure-channel behavior changes. GitHub Actions builds on Linux, macOS,
and Windows and validates the repository coverage baseline.

## Pull requests

Complete the pull request template, pass the CLA check, and keep commits signed. A pull request must
include:

- a focused summary and related issue or specification;
- tests and their results;
- documentation for public API or user-visible changes;
- disclosure and license details for third-party material; and
- confirmation that formatting and coverage validation pass.

Security vulnerabilities must follow [SECURITY.md](SECURITY.md), not a public issue. Questions about
contributor rights or commercial licensing may be sent to
[opensource@mistial.dev](mailto:opensource@mistial.dev).
