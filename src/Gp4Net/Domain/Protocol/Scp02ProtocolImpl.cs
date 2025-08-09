using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// SCP02 protocol implementation using the minimal functional interface.
/// Contains only SCP02-specific cryptographic operations.
/// Based on GlobalPlatform Card Specification v2.3.1 Section E.4 and Appendix E.
/// </summary>
[PublicAPI]
public sealed class Scp02ProtocolImpl : IScpProtocol<Scp02ProtocolImpl>
{
    /// <inheritdoc />
    public static byte ProtocolVersion
    {
        get
        {
            return 0x02;
        }
    }

    /// <inheritdoc />
    public static int BlockSize
    {
        get
        {
            return 8;

            // 3DES block size
        }
    }

    /// <inheritdoc />
    public static int MacSize
    {
        get
        {
            return 8;

            // 8-byte MAC for SCP02
        }
    }

    /// <summary>
    /// Checks if the given implementation parameter is a valid SCP02 implementation.
    /// </summary>
    /// <param name="implementationParameter">The implementation parameter to check.</param>
    /// <returns>True if valid, false otherwise.</returns>
    private static bool IsValidScp02Implementation(byte implementationParameter)
    {
        return implementationParameter switch
        {
            0x00 or 0x02 or 0x04 or 0x05 or 0x0A or 0x14 or 0x15 or 0x1A or
            0x24 or 0x25 or 0x2A or 0x34 or 0x35 or 0x3A or 0x44 or 0x45 or
            0x4A or 0x54 or 0x55 or 0x64 or 0x65 or 0x6A or 0x74 or 0x75 or 0x7A => true,
            _ => false
        };
    }

    /// <inheritdoc />
    public static int ChainingValueSize
    {
        get
        {
            return 8;

            // 3DES block size
        }
    }

    /// <inheritdoc />
    public static int CardChallengeLength
    {
        get
        {
            return 6;

            // SCP02 uses 6-byte card challenge
        }
    }

    /// <inheritdoc />
    public static Result<byte[], SmartCardError> CalculateMac(byte[] key, byte[] data)
    {
        // For C-MAC and R-MAC: use retail MAC (ISO 9797-1 Algorithm 3)
        // Per GlobalPlatform Card Specification v2.3.1 Section E.6.1 - Command MAC Generation
        return CryptographicOperations.CalculateRetailMac(key, data);
    }
    
    /// <inheritdoc />
    public static Result<byte[], SmartCardError> CalculateCryptogramMac(byte[] key, byte[] data)
    {
        // For authentication cryptograms: use Full Triple DES MAC
        // Per GlobalPlatform Card Specification v2.3.1 Section E.4.2 - Authentication Cryptogram Generation
        // Uses full Triple DES MAC with the S-ENC session key
        return CryptographicOperations.CalculateFull3DesMac(key, data);
    }
    
    /// <inheritdoc />
    public static Result<byte[], SmartCardError> Encrypt(byte[] key, byte[] iv, byte[] data)
    {
        return CryptographicOperations.Encrypt3DesCbc(key, iv, data);
    }
    
    /// <inheritdoc />
    public static Result<byte[], SmartCardError> Decrypt(byte[] key, byte[] iv, byte[] encryptedData)
    {
        return CryptographicOperations.Decrypt3DesCbc(key, iv, encryptedData);
    }
    
    /// <inheritdoc />
    public static Result<byte[], SmartCardError> UpdateMacChaining(byte[] currentChaining, byte[] calculatedMac)
    {
        if (currentChaining == null)
        {
            return SmartCardError.InvalidArgument("Current chaining cannot be null");
        }

        if (calculatedMac == null)
        {
            return SmartCardError.InvalidArgument("Calculated MAC cannot be null");
        }

        if (calculatedMac.Length < MacSize)
        {
            return SmartCardError.InvalidArgument($"MAC must be at least {MacSize} bytes");
        }

        // For SCP02, the MAC itself becomes the new chaining value
        var newChaining = new byte[ChainingValueSize];
        Array.Copy(calculatedMac, 0, newChaining, 0, Math.Min(MacSize, ChainingValueSize));
        
        return Result.Success<byte[], SmartCardError>(newChaining);
    }
    
    /// <inheritdoc />
    public static Result<SessionKeys, SmartCardError> DeriveSessionKeys(
        IKeySet keySet,
        byte[] hostChallenge,
        byte[] cardChallenge,
        byte[] sequenceCounter,
        byte implementationParameter)
    {
        // Per GlobalPlatform Card Specification v2.3.1 Section E.4.1 - Session Key Derivation
        // Validate inputs per NO NULLS rule - nulls should be converted at boundaries
        // Validate host challenge length (8 bytes)
        if (hostChallenge?.Length != 8)
        {
            return Result.Failure<SessionKeys, SmartCardError>(
                new InvalidLengthError("hostChallenge", 8, hostChallenge?.Length ?? 0));
        }
        
        // Validate card challenge length (6 bytes for SCP02)
        if (cardChallenge?.Length != 6)
        {
            return Result.Failure<SessionKeys, SmartCardError>(
                new InvalidLengthError("cardChallenge", 6, cardChallenge?.Length ?? 0));
        }
        
        // Validate sequence counter (exactly 2 bytes for SCP02)
        if (sequenceCounter?.Length != 2)
        {
            return Result.Failure<SessionKeys, SmartCardError>(
                new InvalidLengthError("sequenceCounter", 2, sequenceCounter?.Length ?? 0));
        }

        // Check if implementation parameter is valid before mapping
        if (!IsValidScp02Implementation(implementationParameter))
        {
            return Result.Failure<SessionKeys, SmartCardError>(
                new UnsupportedImplementationError($"SCP02 i={implementationParameter:X2} (valid: 00, 02, 04, 05, 0A, 14, 15, 1A, 24, 25, 2A, 34, 35, 3A, 44, 45, 4A, 54, 55, 64, 65, 6A, 74, 75, 7A)"));
        }

        // Map implementation parameter to ScpImplementation enum
        var implementation = (ScpImplementation)implementationParameter;
            
        // Create key derivation context using the new centralized approach
        var contextResult = KeyDerivationContext.CreateForScp02(
            keySet,
            hostChallenge,
            cardChallenge,
            sequenceCounter,
            implementation);
            
        if (contextResult.IsFailure)
        {
            return Result.Failure<SessionKeys, SmartCardError>(contextResult.Error);
        }

        // Use centralized key derivation service
        var keyDerivationService = new KeyDerivationService();
        return keyDerivationService.DeriveSessionKeys(contextResult.Value);
    }
    
    /// <inheritdoc />
    public static Result<byte[], SmartCardError> BuildCardCryptogramData(
        InitializeUpdateResponse response,
        byte[] hostChallenge)
    {
        // Per GlobalPlatform Card Specification v2.3.1 Section E.4.2.1 - Card Authentication Cryptogram
        // Format: Host Challenge (8) || Sequence Counter (2) || Card Challenge (6) || Padding
        return ScpCryptogramOperations.BuildScp02CardCryptogramData(response, hostChallenge);
    }
    
    /// <inheritdoc />
    public static Result<byte[], SmartCardError> BuildHostCryptogramData(
        InitializeUpdateResponse response,
        byte[] hostChallenge)
    {
        // Per GlobalPlatform Card Specification v2.3.1 Section E.4.2.2 - Host Authentication Cryptogram
        // Format: Sequence Counter (2) || Card Challenge (6) || Host Challenge (8) || Padding
        return ScpCryptogramOperations.BuildScp02HostCryptogramData(response, hostChallenge);
    }
    
    /// <inheritdoc />
    public static Result<byte[], SmartCardError> CreateEncryptionIv(
        byte[] chainingValue, 
        uint encryptionCounter)
    {
        if (chainingValue == null)
        {
            return SmartCardError.InvalidArgument("Chaining value cannot be null");
        }

        if (chainingValue.Length != ChainingValueSize)
        {
            return SmartCardError.InvalidArgument($"Chaining value must be {ChainingValueSize} bytes");
        }

        // For SCP02 C-ENC, IV is the current MAC chaining value
        var iv = new byte[ChainingValueSize];
        Array.Copy(chainingValue, 0, iv, 0, ChainingValueSize);
        
        return Result.Success<byte[], SmartCardError>(iv);
    }
    
    /// <inheritdoc />
    public static Result<byte[], SmartCardError> CreateResponseEncryptionIv(uint encryptionCounter)
    {
        // For SCP02 R-ENC, IV is typically zeros
        var iv = new byte[ChainingValueSize];
        return Result.Success<byte[], SmartCardError>(iv);
    }
}