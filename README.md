# Gp4Net

[![Build Status](https://github.com/mistial-dev/Gp4Net/workflows/build/badge.svg)](https://github.com/mistial-dev/Gp4Net/actions)
[![NuGet Version](https://img.shields.io/nuget/v/Gp4Net.svg)](https://www.nuget.org/packages/Gp4Net/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Gp4Net.svg)](https://www.nuget.org/packages/Gp4Net/)
[![License](https://img.shields.io/github/license/mistial-dev/Gp4Net.svg)](LICENSE)

A purely functional .NET implementation of GlobalPlatform card specification for managing Java Card applications with secure channel protocols (SCP02/SCP03).

## Features

- **SCP02 Support**: Triple DES based secure channel protocol
- **SCP03 Support**: AES based secure channel protocol with enhanced security
- **Key Derivation**: SP 800-108 compliant key derivation for SCP03
- **Message Authentication**: C-MAC and R-MAC support
- **Encryption**: Command and response data encryption
- **Functional Design**: No nulls, no exceptions - uses Result<T> and Maybe<T> patterns
- **Cross-Platform**: Targets .NET 8.0
- **Well-Tested**: Comprehensive unit tests with test vectors (800+ tests)
- **Fully Documented**: XML documentation for IntelliSense support
- **Virtual Card Emulator**: Built-in card emulator for testing

## Installation

```bash
dotnet add package Gp4Net
```

Or via Package Manager:

```bash
Install-Package Gp4Net
```

## Quick Start

### SCP03 Example

```csharp
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Services;

// Create a key set with your card's static keys
var keySetResult = Scp03KeySet.Create(
    keyEnc: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
    keyMac: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
    keyDek: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
    keyVersion: 0x01
);

if (keySetResult.IsFailure)
{
    Console.WriteLine($"Failed to create key set: {keySetResult.Error}");
    return;
}

// Create the GlobalPlatform service
var gpService = new GlobalPlatformService(cardService);

// Establish secure channel
var secureChannelResult = await gpService.EstablishSecureChannelAsync(
    keySetResult.Value, 
    SecurityLevel.CMacAndCDecryption
);

if (secureChannelResult.IsSuccess)
{
    Console.WriteLine("Secure channel established successfully!");
}
```

### SCP02 Example

```csharp
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;

// Create SCP02 key set
var keySetResult = Scp02KeySet.Create(
    keyEnc: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
    keyMac: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
    keyDek: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
    keyVersion: 0x01
);

// Establish SCP02 secure channel
var secureChannelResult = await gpService.EstablishSecureChannelAsync(
    keySetResult.Value, 
    SecurityLevel.CMac
);
```

### Virtual Card Testing

```csharp
using Gp4Net.CardEmulator.Services;

// Create virtual card service for testing
var virtualCardService = new VirtualCardService();
virtualCardService.SetupTestEnvironment();

// Connect to virtual P71 card
var connected = virtualCardService.Connect("Virtual P71 Reader 00 00");
if (connected)
{
    // Use virtualCardService like any other card service
    var gpService = new GlobalPlatformService(virtualCardService);
    // ... perform GP operations
}
```

## Command Line Tool

Gp4Net includes a powerful command-line tool for interacting with smart cards:

```bash
# Install the tool globally
dotnet tool install -g Gp4Net.Tool

# Get card information
gp4net card info --reader "Virtual P71 Reader 00 00"

# List available readers
gp4net card list-readers

# Test secure channel establishment
gp4net card test-secure-channel --reader "My Reader" --keyset GP_TEST_KEYS
```

## Architecture

Gp4Net follows functional programming principles:

- **No Nulls**: All nullable types are replaced with `Maybe<T>`
- **No Exceptions**: All operations return `Result<T, SmartCardError>`
- **Immutable Data**: All data structures are immutable
- **Pure Functions**: Domain logic is side-effect free
- **Composable**: Operations can be chained using `Bind` and `Map`

## Supported Protocols

| Protocol | Support | Key Derivation | MAC | Encryption |
|----------|---------|---------------|-----|------------|
| SCP02    | ✅      | Static        | 3DES-MAC | 3DES |
| SCP03    | ✅      | KDF (SP 800-108) | AES-CMAC | AES |

## Card Support

- **P71D321**: NXP SmartMX3 platform (tested)
- **JCOP**: NXP JCOP cards
- **Generic GP 2.3.1**: Any card implementing GP Card Spec v2.3.1

## Documentation

- [API Documentation](docs/api/)
- [Architecture Guide](docs/architecture/)
- [Secure Channel Protocols](docs/protocols/)
- [Contributing Guide](CONTRIBUTING.md)

## Building from Source

```bash
git clone https://github.com/mistial-dev/Gp4Net.git
cd Gp4Net
dotnet build
dotnet test
```

### Requirements

- .NET 8.0 SDK
- Visual Studio 2022 or VS Code (optional)

## Contributing

We welcome technical contributions! Please see our [Contributing Guide](CONTRIBUTING.md) and [Bounded Collaboration Policy](docs/BOUNDED_COLLABORATION_POLICY.md) for details.

## License

This project is licensed under the GNU Affero General Public License v3.0 only.

## Acknowledgments

- Based on GlobalPlatform Card Specification v2.3.1
- Uses BouncyCastle for cryptographic operations
- Implements NIST SP 800-108 KDF for SCP03

## Security

If you discover a security vulnerability, please see our [Security Policy](SECURITY.md) for reporting instructions.