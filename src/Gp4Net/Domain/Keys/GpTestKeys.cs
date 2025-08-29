using System;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Keys;

/// <summary>
/// Provides standard GlobalPlatform test keys (404142434445464748494A4B4C4D4E4F) for testing.
/// Only provides the standard test key - no zero keys, no FF keys, no card-specific diversification.
/// This is a pure test utility for development and testing scenarios.
/// </summary>
[PublicAPI]
public static class GpTestKeys
{
    /// <summary>
    /// The standard GP test key (404142434445464748494A4B4C4D4E4F).
    /// This is the only test key provided - no zero keys or FF keys.
    /// </summary>
    public static readonly byte[] StandardTestKey = Convert.FromHexString(
        "404142434445464748494A4B4C4D4E4F"
    );

    /// <summary>
    /// Gets the standard GP test key set for the given protocol version.
    /// Always returns the same test key (404142...4F) for ENC, MAC, and DEK.
    /// </summary>
    /// <param name="protocolVersion">The protocol version (SCP02 or SCP03).</param>
    /// <param name="keyVersion">The key version (default: 0x00).</param>
    /// <returns>The standard test key set.</returns>
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
            _ => Result.Failure<IKeySet, SmartCardError>(
                SmartCardError.InvalidArgument($"Unsupported protocol version: {protocolVersion:X2}"))
        };
    }

    /// <summary>
    /// Gets the standard GP test key set for the given protocol version using ScpVersion enum.
    /// Always returns the same test key (404142...4F) for ENC, MAC, and DEK.
    /// </summary>
    /// <param name="protocolVersion">The protocol version.</param>
    /// <param name="keyVersion">The key version (default: 0x00).</param>
    /// <returns>The standard test key set.</returns>
    public static Result<IKeySet, SmartCardError> GetTestKeySet(ScpVersion protocolVersion, byte keyVersion = 0x00)
    {
        return protocolVersion switch
        {
            ScpVersion.Scp02 => Scp02KeySet.Create(
                (byte[])StandardTestKey.Clone(),
                (byte[])StandardTestKey.Clone(),
                (byte[])StandardTestKey.Clone(),
                keyVersion
            ).Map(ks => (IKeySet)ks),
            ScpVersion.Scp03 => Scp03KeySet.Create(
                (byte[])StandardTestKey.Clone(),
                (byte[])StandardTestKey.Clone(),
                (byte[])StandardTestKey.Clone(),
                keyVersion
            ).Map(ks => (IKeySet)ks),
            _ => Result.Failure<IKeySet, SmartCardError>(
                SmartCardError.InvalidArgument($"Unsupported protocol version: {protocolVersion}"))
        };
    }

    /// <summary>
    /// Gets the standard GP test key set for the given card response.
    /// Uses the response only for protocol/version info - always returns standard test keys.
    /// </summary>
    /// <param name="cardResponse">The INITIALIZE UPDATE response (optional).</param>
    /// <returns>The standard test key set.</returns>
    public static Result<IKeySet, SmartCardError> GetTestKeys(Maybe<InitializeUpdateResponse> cardResponse)
    {
        return cardResponse.Match(
            response => response.ScpId.Match(
                scpVersion => GetTestKeySet(scpVersion, response.KeyVersion),
                () => GetTestKeySet(ScpVersion.Scp02, 0x00) // Default to SCP02 v00 if ScpId is not available
            ),
            () => GetTestKeySet(ScpVersion.Scp02, 0x00) // Default to SCP02 v00
        );
    }

    /// <summary>
    /// Creates an SCP02 test key set using the standard GP test keys.
    /// </summary>
    /// <param name="keyVersion">The key version (default: 0x00).</param>
    /// <returns>The SCP02 test key set.</returns>
    public static Result<Scp02KeySet, SmartCardError> CreateScp02TestKeySet(byte keyVersion = 0x00)
    {
        return Scp02KeySet.Create(
            (byte[])StandardTestKey.Clone(),
            (byte[])StandardTestKey.Clone(),
            (byte[])StandardTestKey.Clone(),
            keyVersion
        );
    }

    /// <summary>
    /// Creates an SCP03 test key set using the standard GP test keys.
    /// </summary>
    /// <param name="keyVersion">The key version (default: 0x00).</param>
    /// <returns>The SCP03 test key set.</returns>
    public static Result<Scp03KeySet, SmartCardError> CreateScp03TestKeySet(byte keyVersion = 0x00)
    {
        return Scp03KeySet.Create(
            (byte[])StandardTestKey.Clone(),
            (byte[])StandardTestKey.Clone(),
            (byte[])StandardTestKey.Clone(),
            keyVersion
        );
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