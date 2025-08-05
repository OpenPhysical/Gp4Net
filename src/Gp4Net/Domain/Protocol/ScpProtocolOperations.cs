using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Generic protocol operations that work with any SCP protocol implementation.
/// All methods are pure static functions using functional composition.
/// </summary>
[PublicAPI]
public static class ScpProtocolOperations
{
    /// <summary>
    /// Processes an INITIALIZE UPDATE response using the specified protocol.
    /// </summary>
    /// <typeparam name="TProtocol">The protocol implementation.</typeparam>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge that was sent.</param>
    /// <param name="keySet">The key set for session key derivation.</param>
    /// <param name="implementationParameter">The implementation parameter (SCP02 i-parameter, unused for SCP03).</param>
    /// <returns>A secure channel context with derived session keys.</returns>
    public static Result<SecureChannelContext, SmartCardError> ProcessInitializeUpdate<TProtocol>(
        InitializeUpdateResponse response,
        byte[] hostChallenge,
        IKeySet keySet,
        byte implementationParameter)
        where TProtocol : IScpProtocol<TProtocol>
    {
        // Validate inputs
        if (response == null)
        {
            return SmartCardError.InvalidArgument("Response cannot be null");
        }

        if (hostChallenge == null)
        {
            return SmartCardError.InvalidArgument("Host challenge cannot be null");
        }

        if (keySet == null)
        {
            return SmartCardError.InvalidArgument("Key set cannot be null");
        }

        var responseValidation = TProtocol.ValidateInitializeUpdateResponse(response);
        if (responseValidation.IsFailure)
        {
            return SmartCardError.InvalidData(responseValidation.Error);
        }

        var keySetValidation = TProtocol.ValidateKeySet(keySet);
        if (keySetValidation.IsFailure)
        {
            return SmartCardError.InvalidArgument(keySetValidation.Error);
        }

        return DeriveAndVerifySessionKeys()
            .Map(sessionKeys => CreateSecureChannelContext(sessionKeys));
            
        Result<SessionKeys, SmartCardError> DeriveAndVerifySessionKeys()
        {
            return TProtocol.DeriveSessionKeys(keySet, hostChallenge, response.CardChallenge, response.SequenceCounter, implementationParameter)
                .Bind(sessionKeys => VerifyCardCryptogram<TProtocol>(response, hostChallenge, sessionKeys)
                    .Bind(isValid => isValid
                        ? Result.Success<SessionKeys, SmartCardError>(sessionKeys)
                        : SmartCardError.SecurityError("Card cryptogram verification failed")));
        }
        
        SecureChannelContext CreateSecureChannelContext(SessionKeys sessionKeys)
        {
            return new SecureChannelContext(
                hostChallenge,
                response,
                sessionKeys,
                TProtocol.ProtocolVersion,
                keySet);
        }
    }
    
    /// <summary>
    /// Creates an EXTERNAL AUTHENTICATE command using the specified protocol.
    /// </summary>
    /// <typeparam name="TProtocol">The protocol implementation.</typeparam>
    /// <param name="context">The secure channel context.</param>
    /// <param name="securityLevel">The requested security level.</param>
    /// <returns>The EXTERNAL AUTHENTICATE command with MAC if required.</returns>
    public static Result<ExternalAuthenticateCommand, SmartCardError> CreateExternalAuthenticate<TProtocol>(
        SecureChannelContext context,
        SecurityLevel securityLevel)
        where TProtocol : IScpProtocol<TProtocol>
    {
        if (context == null)
        {
            return SmartCardError.InvalidArgument("Context cannot be null");
        }

        return CalculateHostCryptogram<TProtocol>(context)
            .Bind(hostCryptogram => CreateCommandWithMacIfNeeded(securityLevel, hostCryptogram, context));
            
        Result<ExternalAuthenticateCommand, SmartCardError> CreateCommandWithMacIfNeeded(
            SecurityLevel securityLevel,
            byte[] hostCryptogram,
            SecureChannelContext context)
        {
            if (!securityLevel.HasCMac())
            {
                return ExternalAuthenticateCommand.CreateWithoutMac(securityLevel, hostCryptogram);
            }
            
            // Create command without MAC first to get APDU structure
            return ExternalAuthenticateCommand.CreateWithoutMac(securityLevel, hostCryptogram)
                .Bind(tempCommand => BuildCommandApdu(tempCommand)
                    .Bind(apdu => CalculateInitialCommandMac<TProtocol>(apdu, context.SessionKeys.SMac))
                    .Bind(mac => ExternalAuthenticateCommand.CreateWithMac(securityLevel, hostCryptogram, mac.Take(TProtocol.MacSize).ToArray())));
        }
    }
    
    /// <summary>
    /// Applies command security using the specified protocol.
    /// </summary>
    /// <typeparam name="TProtocol">The protocol implementation.</typeparam>
    /// <param name="command">The original command.</param>
    /// <param name="securityLevel">The security level to apply.</param>
    /// <param name="sessionKeys">The session keys.</param>
    /// <param name="chainingValue">The current MAC chaining value.</param>
    /// <param name="encryptionCounter">The current encryption counter.</param>
    /// <returns>The secured command and new chaining value.</returns>
    public static Result<(byte[] securedCommand, byte[] newChainingValue), SmartCardError> ApplyCommandSecurity<TProtocol>(
        byte[] command,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        byte[] chainingValue,
        uint encryptionCounter = 0)
        where TProtocol : IScpProtocol<TProtocol>
    {
        if (command == null)
        {
            return SmartCardError.InvalidArgument("Command cannot be null");
        }

        if (sessionKeys == null)
        {
            return SmartCardError.InvalidArgument("Session keys cannot be null");
        }

        if (chainingValue == null)
        {
            return SmartCardError.InvalidArgument("Chaining value cannot be null");
        }

        if (chainingValue.Length != TProtocol.ChainingValueSize)
        {
            return SmartCardError.InvalidArgument($"Chaining value must be {TProtocol.ChainingValueSize} bytes");
        }

        var processedCommand = command;
        var newChainingValue = chainingValue;
        
        // Apply C-ENCRYPTION if required
        if (securityLevel.HasCEncryption())
        {
            var encryptResult = ApplyCommandEncryption<TProtocol>(processedCommand, sessionKeys.SEnc, chainingValue, encryptionCounter);
            if (encryptResult.IsFailure)
            {
                return encryptResult.Error;
            }

            processedCommand = encryptResult.Value;
        }
        
        // Apply C-MAC if required
        if (securityLevel.HasCMac())
        {
            return ApplyCommandMac<TProtocol>(processedCommand, sessionKeys.SMac, chainingValue)
                .Map(macResult =>
                {
                    var (macCommand, updatedChaining) = macResult;
                    return (macCommand, updatedChaining);
                });
        }
        
        return Result.Success<(byte[], byte[]), SmartCardError>((processedCommand, newChainingValue));
    }
    
    /// <summary>
    /// Applies response security using the specified protocol.
    /// </summary>
    /// <typeparam name="TProtocol">The protocol implementation.</typeparam>
    /// <param name="response">The original response.</param>
    /// <param name="securityLevel">The security level to apply.</param>
    /// <param name="sessionKeys">The session keys.</param>
    /// <param name="chainingValue">The current MAC chaining value.</param>
    /// <param name="encryptionCounter">The current encryption counter.</param>
    /// <returns>The secured response and chaining value (unchanged per spec).</returns>
    public static Result<(byte[] securedResponse, byte[] newChainingValue), SmartCardError> ApplyResponseSecurity<TProtocol>(
        byte[] response,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        byte[] chainingValue,
        uint encryptionCounter = 0)
        where TProtocol : IScpProtocol<TProtocol>
    {
        if (response == null)
        {
            return SmartCardError.InvalidArgument("Response cannot be null");
        }

        if (response.Length < 2)
        {
            return SmartCardError.InvalidArgument("Response must contain at least status word");
        }

        if (sessionKeys == null)
        {
            return SmartCardError.InvalidArgument("Session keys cannot be null");
        }

        if (chainingValue == null)
        {
            return SmartCardError.InvalidArgument("Chaining value cannot be null");
        }

        return ScpCommonOperations.ExtractStatusWord(response)
            .Bind(statusWord => ProcessResponseSecurity(response, securityLevel, sessionKeys, chainingValue, encryptionCounter, statusWord));
            
        Result<(byte[], byte[]), SmartCardError> ProcessResponseSecurity(
            byte[] response,
            SecurityLevel securityLevel,
            SessionKeys sessionKeys,
            byte[] chainingValue,
            uint encryptionCounter,
            ushort statusWord)
        {
            // Check if response security should be applied
            if (!ScpCommonOperations.ShouldApplyResponseSecurity(statusWord))
            {
                return Result.Success<(byte[], byte[]), SmartCardError>((response, chainingValue));
            }
            
            var processedResponse = response;
            var newChainingValue = chainingValue; // R-MAC does not update chaining per spec
            
            // Apply R-ENCRYPTION if required
            if (securityLevel.HasREncryption() && ScpCommonOperations.HasResponseData(response))
            {
                var encryptResult = ApplyResponseEncryption<TProtocol>(processedResponse, sessionKeys.SEnc, encryptionCounter);
                if (encryptResult.IsFailure)
                {
                    return encryptResult.Error;
                }

                processedResponse = encryptResult.Value;
            }
            
            // Apply R-MAC if required
            if (securityLevel.HasRMac())
            {
                var macResult = ApplyResponseMac<TProtocol>(processedResponse, sessionKeys.SrMac, chainingValue);
                if (macResult.IsFailure)
                {
                    return macResult.Error;
                }

                processedResponse = macResult.Value;
                // Note: R-MAC does not update chaining value per GlobalPlatform spec
            }
            
            return Result.Success<(byte[], byte[]), SmartCardError>((processedResponse, newChainingValue));
        }
    }
    
    // Private helper methods
    
    private static Result<bool, SmartCardError> VerifyCardCryptogram<TProtocol>(
        InitializeUpdateResponse response,
        byte[] hostChallenge,
        SessionKeys sessionKeys)
        where TProtocol : IScpProtocol<TProtocol>
    {
        return TProtocol.BuildCardCryptogramData(response, hostChallenge)
            .Bind(cryptogramData => 
            {
                // Debug: Check the S-ENC key size (per GP spec E.4.2)
                if (sessionKeys.SEnc == null)
                {
                    return SmartCardError.InvalidArgument("Session S-ENC key is null");
                }

                if (sessionKeys.SEnc.Length == 0)
                {
                    return SmartCardError.InvalidArgument("Session S-ENC key is empty");
                }

                return TProtocol.CalculateCryptogramMac(sessionKeys.SEnc, cryptogramData);
            })
            .Map(expectedCryptogram => CryptographicOperations.CompareBytes(expectedCryptogram, response.CardCryptogram));
    }
    
    private static Result<byte[], SmartCardError> CalculateHostCryptogram<TProtocol>(SecureChannelContext context)
        where TProtocol : IScpProtocol<TProtocol>
    {
        return TProtocol.BuildHostCryptogramData(context.InitializeUpdateResponse, context.HostChallenge)
            .Bind(cryptogramData => TProtocol.CalculateCryptogramMac(context.SessionKeys.SEnc, cryptogramData));
    }
    
    private static Result<byte[], SmartCardError> BuildCommandApdu(ExternalAuthenticateCommand command)
    {
        return ScpCommonOperations.BuildApdu(
            0x84, // CLA with secure messaging bit
            command.Ins,
            command.P1,
            command.P2,
            command.Data);
    }
    
    private static Result<byte[], SmartCardError> CalculateInitialCommandMac<TProtocol>(
        byte[] apdu,
        byte[] macKey)
        where TProtocol : IScpProtocol<TProtocol>
    {
        var zeroChaining = new byte[TProtocol.ChainingValueSize];
        var macInput = ScpCommonOperations.BuildMacInput(zeroChaining, apdu);
        
        return ScpCommonOperations.ApplyIso7816Padding(macInput, TProtocol.BlockSize)
            .Bind(paddedData => TProtocol.CalculateMac(macKey, paddedData));
    }
    
    private static Result<(byte[] macCommand, byte[] newChaining), SmartCardError> ApplyCommandMac<TProtocol>(
        byte[] command,
        byte[] macKey,
        byte[] chainingValue)
        where TProtocol : IScpProtocol<TProtocol>
    {
        var macInput = ScpCommonOperations.BuildMacInput(chainingValue, command);
        
        return ScpCommonOperations.ApplyIso7816Padding(macInput, TProtocol.BlockSize)
            .Bind(paddedData => TProtocol.CalculateMac(macKey, paddedData))
            .Bind(fullMac => 
            {
                var truncatedMac = fullMac.Take(TProtocol.MacSize).ToArray();
                
                return ScpCommonOperations.InsertMacInCommand(command, truncatedMac, TProtocol.MacSize)
                    .Bind(macCommand => TProtocol.UpdateMacChaining(chainingValue, fullMac)
                        .Map(newChaining => (macCommand, newChaining)));
            });
    }
    
    private static Result<byte[], SmartCardError> ApplyResponseMac<TProtocol>(
        byte[] response,
        byte[] rMacKey,
        byte[] chainingValue)
        where TProtocol : IScpProtocol<TProtocol>
    {
        var macInput = ScpCommonOperations.BuildMacInput(chainingValue, response);
        
        return ScpCommonOperations.ApplyIso7816Padding(macInput, TProtocol.BlockSize)
            .Bind(paddedData => TProtocol.CalculateMac(rMacKey, paddedData))
            .Map(fullMac => fullMac.Take(TProtocol.MacSize).ToArray())
            .Bind(truncatedMac => InsertResponseMac(response, truncatedMac));
            
        static Result<byte[], SmartCardError> InsertResponseMac(byte[] response, byte[] mac)
        {
            // Insert R-MAC before status word
            var statusOffset = response.Length - 2;
            var securedResponse = new byte[response.Length + mac.Length];
            
            if (statusOffset > 0)
            {
                Array.Copy(response, 0, securedResponse, 0, statusOffset); // Data before status
            }
            Array.Copy(mac, 0, securedResponse, statusOffset, mac.Length); // R-MAC
            Array.Copy(response, statusOffset, securedResponse, securedResponse.Length - 2, 2); // Status word
            
            return Result.Success<byte[], SmartCardError>(securedResponse);
        }
    }
    
    private static Result<byte[], SmartCardError> ApplyCommandEncryption<TProtocol>(
        byte[] command,
        byte[] sEncKey,
        byte[] chainingValue,
        uint encryptionCounter)
        where TProtocol : IScpProtocol<TProtocol>
    {
        return ScpCommonOperations.ExtractCommandData(command)
            .Bind(data => data.Length == 0 
                ? Result.Success<byte[], SmartCardError>(command) // No data to encrypt
                : EncryptCommandData(data, sEncKey, chainingValue, encryptionCounter, command));
                
        Result<byte[], SmartCardError> EncryptCommandData(
            byte[] data,
            byte[] sEncKey,
            byte[] chainingValue,
            uint encryptionCounter,
            byte[] originalCommand)
        {
            return TProtocol.CreateEncryptionIv(chainingValue, encryptionCounter)
                .Bind(iv => CryptographicOperations.ApplyPkcs7Padding(data, TProtocol.BlockSize)
                    .Bind(paddedData => TProtocol.Encrypt(sEncKey, iv, paddedData))
                    .Map(encryptedData => ReplaceCommandData(originalCommand, encryptedData)));
        }
        
        static byte[] ReplaceCommandData(byte[] originalCommand, byte[] newData)
        {
            var hasLe = originalCommand.Length > 5 && originalCommand[4] > 0 
                        ? originalCommand.Length > 5 + originalCommand[4] 
                        : false;
                        
            var newCommand = new byte[5 + newData.Length + (hasLe ? 1 : 0)];
            
            // Copy header and set secure messaging bit
            Array.Copy(originalCommand, 0, newCommand, 0, 4);
            newCommand[0] = ScpCommonOperations.SetSecureMessagingBit(originalCommand[0]);
            newCommand[4] = (byte)newData.Length; // New Lc
            
            // Copy encrypted data
            Array.Copy(newData, 0, newCommand, 5, newData.Length);
            
            // Copy Le if present
            if (hasLe)
            {
                newCommand[newCommand.Length - 1] = originalCommand[originalCommand.Length - 1];
            }
            
            return newCommand;
        }
    }
    
    private static Result<byte[], SmartCardError> ApplyResponseEncryption<TProtocol>(
        byte[] response,
        byte[] sEncKey,
        uint encryptionCounter)
        where TProtocol : IScpProtocol<TProtocol>
    {
        var dataLength = response.Length - 2; // Exclude status word
        if (dataLength <= 0)
        {
            return Result.Success<byte[], SmartCardError>(response); // No data to encrypt
        }

        var responseData = new byte[dataLength];
        Array.Copy(response, 0, responseData, 0, dataLength);
        
        return TProtocol.CreateResponseEncryptionIv(encryptionCounter)
            .Bind(iv => CryptographicOperations.ApplyPkcs7Padding(responseData, TProtocol.BlockSize)
                .Bind(paddedData => TProtocol.Encrypt(sEncKey, iv, paddedData))
                .Map(encryptedData =>
                {
                    // Combine encrypted data with original status word
                    var result = new byte[encryptedData.Length + 2];
                    Array.Copy(encryptedData, 0, result, 0, encryptedData.Length);
                    Array.Copy(response, response.Length - 2, result, encryptedData.Length, 2);
                    return result;
                }));
    }
}