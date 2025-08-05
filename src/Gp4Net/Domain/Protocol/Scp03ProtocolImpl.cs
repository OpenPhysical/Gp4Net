using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// SCP03 protocol implementation using the minimal functional interface.
/// Contains only SCP03-specific cryptographic operations.
/// </summary>
[PublicAPI]
public sealed class Scp03ProtocolImpl : IScpProtocol<Scp03ProtocolImpl>
{
    /// <inheritdoc />
    public static byte ProtocolVersion
    {
        get
        {
            return 0x03;
        }
    }

    /// <inheritdoc />
    public static int BlockSize
    {
        get
        {
            return 16;

            // AES block size
        }
    }

    /// <inheritdoc />
    public static int MacSize
    {
        get
        {
            return 8;

            // Truncated MAC for commands/responses
        }
    }

    /// <inheritdoc />
    public static int ChainingValueSize
    {
        get
        {
            return 16;

            // Full AES-CMAC size for chaining
        }
    }

    /// <inheritdoc />
    public static int CardChallengeLength
    {
        get
        {
            return 8;

            // SCP03 uses 8-byte card challenge
        }
    }

    /// <inheritdoc />
    public static Result<byte[], SmartCardError> CalculateMac(byte[] key, byte[] data)
    {
        return CryptographicOperations.CalculateAesCmac(key, data);
    }
    
    /// <inheritdoc />
    public static Result<byte[], SmartCardError> CalculateCryptogramMac(byte[] key, byte[] data)
    {
        // For SCP03, cryptogram MAC uses the same AES-CMAC algorithm
        return CryptographicOperations.CalculateAesCmac(key, data);
    }
    
    /// <inheritdoc />
    public static Result<byte[], SmartCardError> Encrypt(byte[] key, byte[] iv, byte[] data)
    {
        return CryptographicOperations.EncryptAesCbc(key, iv, data);
    }
    
    /// <inheritdoc />
    public static Result<byte[], SmartCardError> Decrypt(byte[] key, byte[] iv, byte[] encryptedData)
    {
        return CryptographicOperations.DecryptAesCbc(key, iv, encryptedData);
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

        if (calculatedMac.Length < ChainingValueSize)
        {
            return SmartCardError.InvalidArgument($"MAC must be at least {ChainingValueSize} bytes for SCP03");
        }

        // For SCP03, the full 16-byte MAC becomes the new chaining value
        var newChaining = new byte[ChainingValueSize];
        Array.Copy(calculatedMac, 0, newChaining, 0, ChainingValueSize);
        
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
        // Note: implementationParameter is unused for SCP03 key derivation
        // but kept for interface consistency
        
        // Validate inputs
        if (keySet == null)
        {
            return SmartCardError.InvalidArgument("KeySet cannot be null");
        }

        // Map implementation parameter to ScpImplementation enum
        var implementation = implementationParameter switch
        {
            0x70 => ScpImplementation.Scp03PseudoRandom,
            0x60 => ScpImplementation.Scp03RandomChallenge,
            0x11 => ScpImplementation.Scp03NoResponseMac,
            _ => ScpImplementation.Scp03PseudoRandom
        };
        
        // Create key derivation context using the new centralized approach
        var contextResult = KeyDerivationContext.CreateForScp03(
            keySet,
            hostChallenge,
            cardChallenge,
            Maybe<ScpImplementation>.From(implementation));
            
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
        return ScpCryptogramOperations.BuildScp03CardCryptogramData(response, hostChallenge);
    }
    
    /// <inheritdoc />
    public static Result<byte[], SmartCardError> BuildHostCryptogramData(
        InitializeUpdateResponse response,
        byte[] hostChallenge)
    {
        return ScpCryptogramOperations.BuildScp03HostCryptogramData(response, hostChallenge);
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

        // For SCP03 C-ENC, IV is derived from encryption counter
        var iv = new byte[BlockSize];
        
        // Build ICV: counter with MSB set appropriately for command encryption
        iv[12] = (byte)(encryptionCounter >> 24);
        iv[13] = (byte)(encryptionCounter >> 16);
        iv[14] = (byte)(encryptionCounter >> 8);
        iv[15] = (byte)encryptionCounter;
        
        return Result.Success<byte[], SmartCardError>(iv);
    }
    
    /// <inheritdoc />
    public static Result<byte[], SmartCardError> CreateResponseEncryptionIv(uint encryptionCounter)
    {
        // For SCP03 R-ENC, IV is counter with MSB set to 0x80
        var iv = new byte[BlockSize];
        iv[12] = (byte)(0x80 | (encryptionCounter >> 24));
        iv[13] = (byte)(encryptionCounter >> 16);
        iv[14] = (byte)(encryptionCounter >> 8);
        iv[15] = (byte)encryptionCounter;
        
        return Result.Success<byte[], SmartCardError>(iv);
    }
}