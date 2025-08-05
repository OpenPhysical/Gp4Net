using System;
using CSharpFunctionalExtensions;
using JetBrains.Annotations;
using Gp4Net.Core;

namespace Gp4Net.Domain.Keys;

/// <summary>
/// Provides GlobalPlatform test keys for development and testing purposes.
/// These are the standard test keys defined in the GlobalPlatform specification.
/// </summary>
[PublicAPI]
public static class GpTestKeys
{
    /// <summary>
    /// The standard GP test key (40414243...4E4F).
    /// This is the well-known test key used in GlobalPlatform testing.
    /// </summary>
    public static readonly byte[] StandardTestKey = Convert.FromHexString(
        "404142434445464748494A4B4C4D4E4F"
    );

    /// <summary>
    /// Alternative GP test key (all zeros).
    /// Sometimes used in development environments.
    /// </summary>
    public static readonly byte[] ZeroTestKey = new byte[16];

    /// <summary>
    /// Alternative GP test key (all 0xFF).
    /// Used in some test environments.
    /// </summary>
    public static readonly byte[] AllOnesTestKey =
    {
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
    };

    /// <summary>
    /// Creates an SCP02 key set using the standard GP test keys.
    /// </summary>
    /// <param name="keyVersion">The key version (default: 0x00).</param>
    /// <returns>The SCP02 test key set.</returns>
    public static Scp02KeySet CreateScp02TestKeySet(byte keyVersion = 0x00)
    {
        return Scp02KeySet.Create(
            encKey: (byte[])StandardTestKey.Clone(),
            macKey: (byte[])StandardTestKey.Clone(),
            dekKey: (byte[])StandardTestKey.Clone(),
            keyVersion: keyVersion
        ).Match(
            onSuccess: keySet => keySet,
            onFailure: error => throw new InvalidOperationException($"Failed to create SCP02 test key set: {error.Message}"));
    }

    /// <summary>
    /// Creates an SCP03 key set using the standard GP test keys.
    /// </summary>
    /// <param name="keyVersion">The key version (default: 0x00).</param>
    /// <returns>The SCP03 test key set.</returns>
    public static Scp03KeySet CreateScp03TestKeySet(byte keyVersion = 0x00)
    {
        return Scp03KeySet.Create(
            encKey: (byte[])StandardTestKey.Clone(),
            macKey: (byte[])StandardTestKey.Clone(),
            dekKey: (byte[])StandardTestKey.Clone(),
            keyVersion: keyVersion
        ).Match(
            onSuccess: keySet => keySet,
            onFailure: error => throw new InvalidOperationException($"Failed to create SCP03 test key set: {error.Message}"));
    }

    /// <summary>
    /// Creates an SCP02 key set using zero test keys.
    /// </summary>
    /// <param name="keyVersion">The key version (default: 0x00).</param>
    /// <returns>The SCP02 zero key set.</returns>
    public static Scp02KeySet CreateScp02ZeroKeySet(byte keyVersion = 0x00)
    {
        return Scp02KeySet.Create(
            encKey: (byte[])ZeroTestKey.Clone(),
            macKey: (byte[])ZeroTestKey.Clone(),
            dekKey: (byte[])ZeroTestKey.Clone(),
            keyVersion: keyVersion
        ).Match(
            onSuccess: keySet => keySet,
            onFailure: error => throw new InvalidOperationException($"Failed to create SCP02 zero key set: {error.Message}"));
    }

    /// <summary>
    /// Creates an SCP03 key set using zero test keys.
    /// </summary>
    /// <param name="keyVersion">The key version (default: 0x00).</param>
    /// <returns>The SCP03 zero key set.</returns>
    public static Scp03KeySet CreateScp03ZeroKeySet(byte keyVersion = 0x00)
    {
        return Scp03KeySet.Create(
            encKey: (byte[])ZeroTestKey.Clone(),
            macKey: (byte[])ZeroTestKey.Clone(),
            dekKey: (byte[])ZeroTestKey.Clone(),
            keyVersion: keyVersion
        ).Match(
            onSuccess: keySet => keySet,
            onFailure: error => throw new InvalidOperationException($"Failed to create SCP03 zero key set: {error.Message}"));
    }

    /// <summary>
    /// Creates an SCP02 key set using custom keys.
    /// </summary>
    /// <param name="encKey">The encryption key (16 or 24 bytes).</param>
    /// <param name="macKey">The MAC key (16 or 24 bytes).</param>
    /// <param name="dekKey">The DEK key (16 or 24 bytes).</param>
    /// <param name="keyVersion">The key version (default: 0x00).</param>
    /// <returns>The SCP02 custom key set.</returns>
    public static Scp02KeySet CreateScp02CustomKeySet(
        byte[] encKey,
        byte[] macKey,
        byte[] dekKey,
        byte keyVersion = 0x00
    )
    {
        return Scp02KeySet.Create(encKey, macKey, dekKey, keyVersion)
            .Match(
                onSuccess: keySet => keySet,
                onFailure: error => throw new InvalidOperationException($"Failed to create SCP02 custom key set: {error.Message}"));
    }

    /// <summary>
    /// Creates an SCP03 key set using custom keys.
    /// </summary>
    /// <param name="encKey">The encryption key (16, 24, or 32 bytes).</param>
    /// <param name="macKey">The MAC key (16, 24, or 32 bytes).</param>
    /// <param name="dekKey">The DEK key (16, 24, or 32 bytes).</param>
    /// <param name="keyVersion">The key version (default: 0x00).</param>
    /// <returns>The SCP03 custom key set.</returns>
    public static Scp03KeySet CreateScp03CustomKeySet(
        byte[] encKey,
        byte[] macKey,
        byte[] dekKey,
        byte keyVersion = 0x00
    )
    {
        return Scp03KeySet.Create(encKey, macKey, dekKey, keyVersion)
            .Match(
                onSuccess: keySet => keySet,
                onFailure: error => throw new InvalidOperationException($"Failed to create SCP03 custom key set: {error.Message}"));
    }

    /// <summary>
    /// Creates a key set from a hex string.
    /// Uses the same key for ENC, MAC, and DEK.
    /// </summary>
    /// <param name="hexKey">The hex string representation of the key.</param>
    /// <param name="protocolVersion">The protocol version (SCP02 or SCP03).</param>
    /// <param name="keyVersion">The key version (default: 0x00).</param>
    /// <returns>The key set.</returns>
    public static Result<IKeySet, SmartCardError> CreateFromHex(
        string hexKey,
        byte protocolVersion,
        byte keyVersion = 0x00
    )
    {
        if (string.IsNullOrWhiteSpace(hexKey))
        {
            return SmartCardError.InvalidArgument("Hex key cannot be null or empty.");
        }

        try
        {
            var key = Convert.FromHexString(hexKey);

            return protocolVersion switch
            {
                0x02 => Scp02KeySet.Create(key, key, key, keyVersion).Map(ks => (IKeySet)ks),
                0x03 => Scp03KeySet.Create(key, key, key, keyVersion).Map(ks => (IKeySet)ks),
                _ => SmartCardError.InvalidArgument($"Unsupported protocol version: {protocolVersion:X2}")
            };
        }
        catch (FormatException ex)
        {
            return SmartCardError.InvalidArgument($"Invalid hex string: {ex.Message}");
        }
    }

    /// <summary>
    /// Gets the appropriate test key set for the given protocol version.
    /// Uses standard GP test keys.
    /// </summary>
    /// <param name="protocolVersion">The protocol version.</param>
    /// <param name="keyVersion">The key version (default: 0x00).</param>
    /// <returns>The test key set.</returns>
    public static Result<IKeySet, SmartCardError> GetTestKeySet(byte protocolVersion, byte keyVersion = 0x00)
    {
        return protocolVersion switch
        {
            0x02 => Scp02KeySet.Create(
                (byte[])StandardTestKey.Clone(),
                (byte[])StandardTestKey.Clone(),
                (byte[])StandardTestKey.Clone(),
                keyVersion
            ).Map(ks => (IKeySet)ks),
            0x03 => Scp03KeySet.Create(
                (byte[])StandardTestKey.Clone(),
                (byte[])StandardTestKey.Clone(),
                (byte[])StandardTestKey.Clone(),
                keyVersion
            ).Map(ks => (IKeySet)ks),
            _ => SmartCardError.InvalidArgument($"Unsupported protocol version: {protocolVersion:X2}")
        };
    }

    /// <summary>
    /// Common key versions used in testing and development.
    /// </summary>
    public static class CommonKeyVersions
    {
        /// <summary>
        /// Key version 0x00 (default).
        /// </summary>
        public const byte Version00 = 0x00;

        /// <summary>
        /// Key version 0xFF (any available key).
        /// </summary>
        public const byte VersionFf = 0xFF;

        /// <summary>
        /// Key version 0x01.
        /// </summary>
        public const byte Version01 = 0x01;

        /// <summary>
        /// Key version 0x02.
        /// </summary>
        public const byte Version02 = 0x02;
    }

    /// <summary>
    /// Well-known test AIDs for development and testing.
    /// </summary>
    public static class TestAids
    {
        /// <summary>
        /// Standard ISD AID.
        /// </summary>
        public static readonly byte[] IsdAid = Convert.FromHexString("A000000003000000");

        /// <summary>
        /// Common test application AID.
        /// </summary>
        public static readonly byte[] TestAppAid = Convert.FromHexString("A000000001020304");

        /// <summary>
        /// OpenFIPS201 applet AID.
        /// </summary>
        public static readonly byte[] OpenFips201Aid = Convert.FromHexString(
            "A000000308000010000100"
        );

        /// <summary>
        /// OpenFIPS201 package AID.
        /// </summary>
        public static readonly byte[] OpenFips201PackageAid = Convert.FromHexString(
            "A0000003080000100001"
        );
    }
}