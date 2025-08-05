using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Minimal interface for SCP protocol implementations using static abstract members.
/// Contains only truly protocol-specific operations that cannot be shared.
/// </summary>
/// <typeparam name="TSelf">The implementing type (CRTP pattern).</typeparam>
[PublicAPI]
public interface IScpProtocol<TSelf> where TSelf : IScpProtocol<TSelf>
{
    /// <summary>
    /// The protocol version identifier (0x02 for SCP02, 0x03 for SCP03).
    /// </summary>
    static abstract byte ProtocolVersion { get; }
    
    /// <summary>
    /// The cryptographic block size in bytes (8 for SCP02/3DES, 16 for SCP03/AES).
    /// </summary>
    static abstract int BlockSize { get; }
    
    /// <summary>
    /// The MAC size in bytes (8 for both protocols, but full MAC size differs).
    /// </summary>
    static abstract int MacSize { get; }
    
    /// <summary>
    /// The size of the MAC chaining value in bytes (8 for SCP02, 16 for SCP03).
    /// </summary>
    static abstract int ChainingValueSize { get; }
    
    /// <summary>
    /// The expected card challenge length for this protocol (6 for SCP02, 8 for SCP03).
    /// </summary>
    static abstract int CardChallengeLength { get; }
    
    // Protocol-specific cryptographic operations
    
    /// <summary>
    /// Calculates MAC over the provided data using protocol-specific algorithm.
    /// For SCP02: Uses retail MAC (ISO 9797-1 Algorithm 3) for C-MAC/R-MAC.
    /// For SCP03: Uses AES-CMAC.
    /// </summary>
    /// <param name="key">The MAC key.</param>
    /// <param name="data">The data to MAC (must be padded to block size).</param>
    /// <returns>The calculated MAC.</returns>
    static abstract Result<byte[], SmartCardError> CalculateMac(byte[] key, byte[] data);
    
    /// <summary>
    /// Calculates MAC for authentication cryptograms using protocol-specific algorithm.
    /// For SCP02: Uses Full Triple DES MAC.
    /// For SCP03: Uses AES-CMAC (same as CalculateMac).
    /// </summary>
    /// <param name="key">The MAC key.</param>
    /// <param name="data">The cryptogram data.</param>
    /// <returns>The calculated cryptogram MAC.</returns>
    static abstract Result<byte[], SmartCardError> CalculateCryptogramMac(byte[] key, byte[] data);
    
    /// <summary>
    /// Encrypts data using protocol-specific algorithm and parameters.
    /// </summary>
    /// <param name="key">The encryption key.</param>
    /// <param name="iv">The initialization vector.</param>
    /// <param name="data">The data to encrypt (must be padded to block size).</param>
    /// <returns>The encrypted data.</returns>
    static abstract Result<byte[], SmartCardError> Encrypt(byte[] key, byte[] iv, byte[] data);
    
    /// <summary>
    /// Decrypts data using protocol-specific algorithm and parameters.
    /// </summary>
    /// <param name="key">The decryption key.</param>
    /// <param name="iv">The initialization vector.</param>
    /// <param name="encryptedData">The encrypted data.</param>
    /// <returns>The decrypted data.</returns>
    static abstract Result<byte[], SmartCardError> Decrypt(byte[] key, byte[] iv, byte[] encryptedData);
    
    /// <summary>
    /// Updates MAC chaining value after C-MAC calculation.
    /// Protocol-specific rules: SCP02 uses MAC itself, SCP03 uses full 16-byte MAC.
    /// </summary>
    /// <param name="currentChaining">The current chaining value.</param>
    /// <param name="calculatedMac">The calculated MAC (full size, not truncated).</param>
    /// <returns>The new chaining value.</returns>
    static abstract Result<byte[], SmartCardError> UpdateMacChaining(byte[] currentChaining, byte[] calculatedMac);
    
    /// <summary>
    /// Derives session keys from static keys and challenge data.
    /// Protocol-specific key derivation (3DES for SCP02, NIST SP 800-108 for SCP03).
    /// </summary>
    /// <param name="keySet">The static key set.</param>
    /// <param name="hostChallenge">The host challenge (8 bytes).</param>
    /// <param name="cardChallenge">The card challenge (protocol-specific length).</param>
    /// <param name="sequenceCounter">The sequence counter (SCP02 only, optional for SCP03).</param>
    /// <param name="implementationParameter">The implementation parameter (SCP02 i-parameter, unused for SCP03).</param>
    /// <returns>The derived session keys.</returns>
    static abstract Result<SessionKeys, SmartCardError> DeriveSessionKeys(
        IKeySet keySet,
        byte[] hostChallenge,
        byte[] cardChallenge,
        byte[]? sequenceCounter,
        byte implementationParameter);
    
    /// <summary>
    /// Builds cryptogram data for card cryptogram verification.
    /// Protocol-specific data structure and padding.
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <returns>The card cryptogram data ready for MAC calculation.</returns>
    static abstract Result<byte[], SmartCardError> BuildCardCryptogramData(
        InitializeUpdateResponse response,
        byte[] hostChallenge);
    
    /// <summary>
    /// Builds cryptogram data for host cryptogram calculation.
    /// Protocol-specific data structure and padding.
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <returns>The host cryptogram data ready for MAC calculation.</returns>
    static abstract Result<byte[], SmartCardError> BuildHostCryptogramData(
        InitializeUpdateResponse response,
        byte[] hostChallenge);
        
    /// <summary>
    /// Creates the initialization vector for command encryption.
    /// Protocol-specific IV generation (chaining for SCP02, counter for SCP03).
    /// </summary>
    /// <param name="chainingValue">The current MAC chaining value.</param>
    /// <param name="encryptionCounter">The current encryption counter.</param>
    /// <returns>The IV for encryption.</returns>
    static abstract Result<byte[], SmartCardError> CreateEncryptionIv(
        byte[] chainingValue, 
        uint encryptionCounter);
        
    /// <summary>
    /// Creates the initialization vector for response encryption.
    /// Protocol-specific IV generation.
    /// </summary>
    /// <param name="encryptionCounter">The current encryption counter.</param>
    /// <returns>The IV for response encryption.</returns>
    static abstract Result<byte[], SmartCardError> CreateResponseEncryptionIv(uint encryptionCounter);

    // Default implementations for operations that can be shared with slight protocol variations
    
    /// <summary>
    /// Validates that a key set is compatible with this protocol.
    /// Default implementation checks key set type against protocol version.
    /// </summary>
    /// <param name="keySet">The key set to validate.</param>
    /// <returns>Success if valid, failure otherwise.</returns>
    static virtual Result ValidateKeySet(IKeySet keySet)
    {
        return TSelf.ProtocolVersion switch
        {
            0x02 when keySet is Scp02KeySet => Result.Success(),
            0x03 when keySet is Scp03KeySet => Result.Success(),
            _ => Result.Failure($"{typeof(TSelf).Name} requires {(TSelf.ProtocolVersion == 0x02 ? "Scp02KeySet" : "Scp03KeySet")}")
        };
    }
    
    /// <summary>
    /// Validates protocol version in INITIALIZE UPDATE response.
    /// Default implementation checks SCP ID matches protocol version.
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <returns>Success if valid, failure otherwise.</returns>
    static virtual Result ValidateInitializeUpdateResponse(InitializeUpdateResponse response)
    {
        if (response == null)
            return Result.Failure("Response cannot be null");
            
        var scpVersion = (byte)(response.ScpId & 0x03);
        if (scpVersion != TSelf.ProtocolVersion)
            return Result.Failure($"Expected {TSelf.ProtocolVersion:X2} but received {scpVersion:X2}");
            
        return Result.Success();
    }
}