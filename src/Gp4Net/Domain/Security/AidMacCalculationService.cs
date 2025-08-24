using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Protocol;
using JetBrains.Annotations;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Service for calculating MAC over AID for SCP02 implicit secure channel initiation.
/// Per GP Card Specification v2.3.1 Section E.3.3.
/// All methods are pure functions following functional programming principles.
/// </summary>
[PublicAPI]
public static class AidMacCalculationService
{
    /// <summary>
    /// Calculates the Initial Chaining Vector (ICV) from MAC over AID for implicit mode implementations.
    /// Per GP Section E.3.3: "When using implicit Secure Channel Session initiation, the ICV shall be 
    /// a MAC computed on the AID of the selected Application."
    /// </summary>
    /// <param name="selectedAid">The AID of the selected application</param>
    /// <param name="cMacSessionKey">The 16-byte C-MAC session key</param>
    /// <param name="implementation">The SCP02 implementation parameter</param>
    /// <returns>Result containing the 8-byte ICV calculated from AID MAC</returns>
    public static Result<byte[], SmartCardError> CalculateIcvFromAidMac(
        byte[] selectedAid,
        byte[] cMacSessionKey,
        ScpImplementation implementation)
    {
        if (selectedAid == null)
        {
            return SmartCardError.InvalidArgument("Selected AID cannot be null");
        }

        if (cMacSessionKey == null)
        {
            return SmartCardError.InvalidArgument("C-MAC session key cannot be null");
        }

        if (cMacSessionKey.Length != 16)
        {
            return SmartCardError.InvalidArgument("C-MAC session key must be 16 bytes for SCP02");
        }

        if (!implementation.IsScp02())
        {
            return SmartCardError.InvalidArgument("AID MAC calculation only applies to SCP02 implementations");
        }

        if (!implementation.HasMacOverAid())
        {
            return SmartCardError.InvalidArgument("Implementation does not support MAC over AID");
        }

        // Apply GP padding per Section E.3.3
        return ApplyGpPadding(selectedAid)
            .Bind(paddedAid => CalculateMacOverPaddedData(paddedAid, cMacSessionKey));
    }

    /// <summary>
    /// Determines whether the initial ICV should be calculated from AID MAC.
    /// Pure function that encapsulates the GP specification rules.
    /// </summary>
    /// <param name="implementation">The SCP02 implementation parameter</param>
    /// <returns>True if ICV should be calculated from AID MAC, false for zero ICV</returns>
    public static bool ShouldCalculateIcvFromAid(ScpImplementation implementation)
    {
        // GP Table E-1: bit b4 (0x08) indicates ICV set to MAC over AID
        // Only applies to implicit mode implementations
        return implementation.IsScp02() && 
               !implementation.IsExplicitMode() && 
               implementation.HasMacOverAid();
    }

    /// <summary>
    /// Creates the appropriate initial MAC chaining state based on implementation requirements.
    /// For implicit mode with MAC over AID, calculates ICV from AID MAC.
    /// For all other cases, returns zero-initialized ICV.
    /// </summary>
    /// <param name="selectedAid">The AID of the selected application (can be null for explicit mode)</param>
    /// <param name="cMacSessionKey">The C-MAC session key</param>
    /// <param name="implementation">The SCP02 implementation parameter</param>
    /// <param name="protocolVersion">The protocol version</param>
    /// <returns>Result containing the appropriate MacChainingState</returns>
    public static Result<MacChainingState, SmartCardError> CreateInitialMacChainingState(
        byte[] selectedAid,
        byte[] cMacSessionKey,
        ScpImplementation implementation,
        byte protocolVersion)
    {
        if (ShouldCalculateIcvFromAid(implementation))
        {
            if (selectedAid == null)
            {
                return SmartCardError.InvalidArgument(
                    "Selected AID is required for implicit mode implementations with MAC over AID");
            }

            return CalculateIcvFromAidMac(selectedAid, cMacSessionKey, implementation)
                .Bind(icv => MacChainingState.Create(icv, protocolVersion, (byte)implementation));
        }
        else
        {
            // Use zero-initialized ICV for explicit mode or implementations without MAC over AID
            return MacChainingState.CreateZeroInitialized(protocolVersion, (byte)implementation);
        }
    }

    /// <summary>
    /// Applies GP padding to the AID per Section E.3.3.
    /// Pads with 0x80 followed by zeros to reach a multiple of 8 bytes.
    /// </summary>
    private static Result<byte[], SmartCardError> ApplyGpPadding(byte[] data)
    {
        if (data.Length == 0)
        {
            return SmartCardError.InvalidArgument("Data cannot be empty for GP padding");
        }

        try
        {
            var paddingNeeded = data.Length % 8 == 0 ? 0 : 8 - (data.Length % 8);
            
            if (paddingNeeded == 0)
            {
                // Already multiple of 8, no padding needed
                return Result.Success<byte[], SmartCardError>(data);
            }

            // Apply GP padding: 0x80 followed by zeros
            var paddedData = data
                .Concat(new[] { (byte)0x80 })
                .Concat(Enumerable.Repeat((byte)0x00, paddingNeeded - 1))
                .ToArray();

            return Result.Success<byte[], SmartCardError>(paddedData);
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"GP padding failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Calculates 3DES MAC over the padded AID using ISO 9797-1 Algorithm 3.
    /// Uses zero ICV for the MAC calculation per GP specification.
    /// </summary>
    private static Result<byte[], SmartCardError> CalculateMacOverPaddedData(
        byte[] paddedData,
        byte[] macKey)
    {
        try
        {
            // Use 3DES MAC with zero ICV per GP Section E.3.3
            var engine = new DesEngine();
            var desMac = new ISO9797Alg3Mac(engine);
            desMac.Init(new KeyParameter(macKey));
            
            // Calculate MAC with zero ICV (implicit by BouncyCastle implementation)
            desMac.BlockUpdate(paddedData, 0, paddedData.Length);
            
            var mac = new byte[8];
            _ = desMac.DoFinal(mac, 0);
            
            return Result.Success<byte[], SmartCardError>(mac);
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"AID MAC calculation failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Validates that the implementation, AID, and session keys are compatible with AID MAC requirements.
    /// </summary>
    /// <param name="implementation">The SCP02 implementation parameter</param>
    /// <param name="selectedAid">The selected AID</param>
    /// <param name="cMacSessionKey">The C-MAC session key</param>
    /// <returns>Result indicating validation success or specific error</returns>
    public static Result ValidateAidMacRequirements(
        ScpImplementation implementation,
        byte[] selectedAid,
        byte[] cMacSessionKey)
    {
        if (!implementation.IsScp02())
        {
            return Result.Failure("AID MAC calculation only applies to SCP02 implementations");
        }

        if (ShouldCalculateIcvFromAid(implementation))
        {
            if (selectedAid == null || selectedAid.Length == 0)
            {
                return Result.Failure(
                    "Selected AID is required for implicit mode implementations with MAC over AID");
            }

            if (selectedAid.Length > 16)
            {
                return Result.Failure("AID length cannot exceed 16 bytes per ISO 7816-4");
            }

            if (cMacSessionKey == null || cMacSessionKey.Length != 16)
            {
                return Result.Failure(
                    "MAC over AID implementations require 16-byte C-MAC session key");
            }
        }

        return Result.Success();
    }
}