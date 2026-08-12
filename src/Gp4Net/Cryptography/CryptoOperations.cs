// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using CSharpFunctionalExtensions;
using JetBrains.Annotations;

namespace Gp4Net.Cryptography;

/// <summary>
/// Unified cryptographic service consolidating ALL crypto operations in the Gp4Net codebase.
/// Replaces 8+ existing crypto classes with a single, comprehensive, functionally pure service.
/// Organized by operation type with nested static classes for logical grouping.
/// All methods are static, pure functional, and return Result&lt;T, SmartCardError&gt;.
/// Uses BouncyCastle exclusively for all cryptographic operations.
/// </summary>
[PublicAPI]
public static partial class CryptoOperations
{
    /// <summary>
    /// Secure Channel Protocol version enumeration.
    /// Reference: GlobalPlatform Card Specification v2.3.1
    /// </summary>
    public enum ScpVersion : byte
    {
        /// <summary>SCP02 - Triple DES based secure channel protocol.</summary>
        Scp02 = 0x02,

        /// <summary>SCP03 - AES based secure channel protocol.</summary>
        Scp03 = 0x03,
    }

    /// <summary>
    /// Cryptogram type enumeration for SCP protocols.
    /// </summary>
    public enum CryptogramType
    {
        /// <summary>Card cryptogram.</summary>
        Card = 0,

        /// <summary>Host cryptogram.</summary>
        Host = 1,
    }
}
