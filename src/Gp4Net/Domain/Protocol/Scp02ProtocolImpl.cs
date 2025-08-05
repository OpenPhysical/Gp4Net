using System;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
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
    public static byte ProtocolVersion => 0x02;
    
    /// <inheritdoc />
    public static int BlockSize => 8; // 3DES block size
    
    /// <inheritdoc />
    public static int MacSize => 8; // 8-byte MAC for SCP02
    
    /// <inheritdoc />
    public static int ChainingValueSize => 8; // 3DES block size
    
    /// <inheritdoc />
    public static int CardChallengeLength => 6; // SCP02 uses 6-byte card challenge
    
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
            return SmartCardError.InvalidArgument("Current chaining cannot be null");
        if (calculatedMac == null)
            return SmartCardError.InvalidArgument("Calculated MAC cannot be null");
        if (calculatedMac.Length < MacSize)
            return SmartCardError.InvalidArgument($"MAC must be at least {MacSize} bytes");
            
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
        byte[]? sequenceCounter,
        byte implementationParameter)
    {
        // Per GlobalPlatform Card Specification v2.3.1 Section E.4.1 - Session Key Derivation
        // Validate inputs
        if (keySet == null)
            return SmartCardError.InvalidArgument("KeySet cannot be null");
        if (sequenceCounter == null)
            return SmartCardError.InvalidArgument("Sequence counter is required for SCP02");
            
        // Map implementation parameter to ScpImplementation enum
        var implementation = implementationParameter switch
        {
            0x15 => ScpImplementation.Scp02StaticMac,
            0x55 => ScpImplementation.Scp02CmacMult,
            0x1A => ScpImplementation.Scp02CmacXor,
            0x04 => ScpImplementation.Scp02ExplicitInitVector,
            0x05 => ScpImplementation.Scp02ImplicitInitVector,
            _ => ScpImplementation.Scp02StaticMac
        };
            
        // Create key derivation context using the new centralized approach
        var contextResult = KeyDerivationContext.CreateForScp02(
            keySet,
            hostChallenge,
            cardChallenge,
            sequenceCounter,
            implementation);
            
        if (contextResult.IsFailure)
            return Result.Failure<SessionKeys, SmartCardError>(contextResult.Error);
            
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
            return SmartCardError.InvalidArgument("Chaining value cannot be null");
        if (chainingValue.Length != ChainingValueSize)
            return SmartCardError.InvalidArgument($"Chaining value must be {ChainingValueSize} bytes");
            
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