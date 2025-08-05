// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

namespace Gp4Net.Constants;

/// <summary>
/// Cryptographic constants for GlobalPlatform secure channel protocols.
/// </summary>
[PublicAPI]
public static class CryptographicConstants
{
    /// <summary>
    /// Triple DES key length for 2-key format (K1||K2||K1).
    /// </summary>
    public const int Des3KeyLength16 = 16;

    /// <summary>
    /// Triple DES key length for 3-key format (K1||K2||K3).
    /// </summary>
    public const int Des3KeyLength24 = 24;

    /// <summary>
    /// AES block size in bytes.
    /// </summary>
    public const int AesBlockSize = 16;

    /// <summary>
    /// DES/3DES block size in bytes.
    /// </summary>
    public const int DesBlockSize = 8;

    /// <summary>
    /// AES key length for 128-bit keys.
    /// </summary>
    public const int AesKeyLength128 = 16;

    /// <summary>
    /// AES key length for 192-bit keys.
    /// </summary>
    public const int AesKeyLength192 = 24;

    /// <summary>
    /// AES key length for 256-bit keys.
    /// </summary>
    public const int AesKeyLength256 = 32;

    /// <summary>
    /// Key check value length as defined by GlobalPlatform.
    /// </summary>
    public const int KeyCheckValueLength = 3;

    /// <summary>
    /// ISO 7816-4 padding marker byte.
    /// </summary>
    public const byte Iso7816PaddingMarker = 0x80;

    /// <summary>
    /// SCP02 sequence counter length for 2-byte format.
    /// </summary>
    public const int SequenceCounterLength2 = 2;

    /// <summary>
    /// SCP03 sequence counter length for 3-byte format.
    /// </summary>
    public const int SequenceCounterLength3 = 3;

    /// <summary>
    /// CMAC (Cipher-based Message Authentication Code) length.
    /// </summary>
    public const int CmacLength = 8;

    /// <summary>
    /// CMAC length for AES-based secure channels.
    /// </summary>
    public const int AesCmacLength = 16;

    /// <summary>
    /// IV (Initialization Vector) length for encryption operations.
    /// </summary>
    public const int EncryptionIvLength = 16;

    /// <summary>
    /// Default MAC chaining value for secure channel initialization.
    /// </summary>
    public static readonly byte[] DefaultMacChainingValue = new byte[DesBlockSize];
}