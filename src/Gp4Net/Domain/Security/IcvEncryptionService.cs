using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Protocol;
using JetBrains.Annotations;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Service for applying SCP02 ICV encryption per GP Card Specification v2.3.1 Section E.3.4.
/// All methods are pure functions following functional programming principles.
/// </summary>
[PublicAPI]
public static class IcvEncryptionService
{
    /// <summary>
    /// Applies ICV encryption to the MAC chaining value if required by the implementation.
    /// Per GP Section E.3.4: "The encryption mechanism used is single DES with the first half
    /// of the Secure Channel C-MAC session key."
    /// </summary>
    /// <param name="macChainingValue">The current MAC chaining value (ICV)</param>
    /// <param name="cMacSessionKey">The 16-byte C-MAC session key</param>
    /// <param name="implementation">The SCP02 implementation parameter</param>
    /// <param name="isFirstIcvOfSession">True if this is the first ICV of the session (never encrypted)</param>
    /// <returns>Result containing the processed ICV (encrypted or unencrypted based on requirements)</returns>
    public static Result<byte[], SmartCardError> ProcessIcvForMacCalculation(
        byte[] macChainingValue,
        byte[] cMacSessionKey,
        ScpImplementation implementation,
        bool isFirstIcvOfSession)
    {
        if (macChainingValue == null)
        {
            return SmartCardError.InvalidArgument("MAC chaining value cannot be null");
        }
        
        if (cMacSessionKey == null)
        {
            return SmartCardError.InvalidArgument("C-MAC session key cannot be null");
        }

        if (macChainingValue.Length != 8)
        {
            return SmartCardError.InvalidArgument("MAC chaining value must be 8 bytes for SCP02");
        }

        if (cMacSessionKey.Length != 16)
        {
            return SmartCardError.InvalidArgument("C-MAC session key must be 16 bytes");
        }

        // GP Section E.3.4: First ICV of session is never encrypted
        if (isFirstIcvOfSession)
        {
            return Result.Success<byte[], SmartCardError>(macChainingValue);
        }

        // Check if implementation requires ICV encryption
        if (!implementation.HasIcvEncryption())
        {
            return Result.Success<byte[], SmartCardError>(macChainingValue);
        }

        // Apply ICV encryption per GP Section E.3.4
        return EncryptIcvWithFirstHalfOfCMacKey(macChainingValue, cMacSessionKey);
    }

    /// <summary>
    /// Encrypts the ICV using single DES with the first half of the C-MAC session key.
    /// Per GP Section E.3.4: "The encryption mechanism used is single DES with the first half
    /// of the Secure Channel C-MAC session key."
    /// </summary>
    private static Result<byte[], SmartCardError> EncryptIcvWithFirstHalfOfCMacKey(
        byte[] icv,
        byte[] cMacSessionKey)
    {
        try
        {
            // Extract first 8 bytes of C-MAC session key for ICV encryption
            var icvEncryptionKey = cMacSessionKey.Take(8).ToArray();
            
            // Apply single DES encryption per GP specification
            var desEngine = new DesEngine();
            var keyParam = new KeyParameter(icvEncryptionKey);
            desEngine.Init(true, keyParam); // true for encryption
            
            var encryptedIcv = new byte[8];
            desEngine.ProcessBlock(icv, 0, encryptedIcv, 0);
            
            return Result.Success<byte[], SmartCardError>(encryptedIcv);
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"ICV encryption failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Determines whether ICV encryption should be applied based on implementation and session state.
    /// This is a pure function that encapsulates the GP specification rules.
    /// </summary>
    /// <param name="implementation">The SCP02 implementation parameter</param>
    /// <param name="isFirstIcvOfSession">True if this is the first ICV of the session</param>
    /// <returns>True if ICV encryption should be applied, false otherwise</returns>
    public static bool ShouldApplyIcvEncryption(ScpImplementation implementation, bool isFirstIcvOfSession)
    {
        // GP Section E.3.4: First ICV is never encrypted
        if (isFirstIcvOfSession)
        {
            return false;
        }

        // GP Table E-1: bit b5 (0x10) indicates ICV encryption
        return implementation.HasIcvEncryption();
    }

    /// <summary>
    /// Validates that the implementation and session keys are compatible with ICV encryption requirements.
    /// </summary>
    /// <param name="implementation">The SCP02 implementation parameter</param>
    /// <param name="cMacSessionKey">The C-MAC session key</param>
    /// <returns>Result indicating validation success or specific error</returns>
    public static Result ValidateIcvEncryptionRequirements(
        ScpImplementation implementation,
        byte[] cMacSessionKey)
    {
        if (!implementation.IsScp02())
        {
            return Result.Failure("ICV encryption only applies to SCP02 implementations");
        }

        if (implementation.HasIcvEncryption())
        {
            if (cMacSessionKey == null || cMacSessionKey.Length != 16)
            {
                return Result.Failure(
                    "ICV encryption implementations require 16-byte C-MAC session key");
            }
        }

        return Result.Success();
    }
}