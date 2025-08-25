using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Functional processor for applying security to APDU commands.
/// All methods are pure functions with no side effects.
/// </summary>
[PublicAPI]
public static class CommandSecurityProcessor
{
    /// <summary>
    /// Applies command security (C-MAC and/or C-DECRYPTION) to a command APDU.
    /// Returns the wrapped command and updated secure channel state.
    /// This is the main entry point for command security processing.
    /// </summary>
    public static Result<(byte[] securedCommand, SecureChannelState newState), SmartCardError> ApplyCommandSecurity(
        IApduCommand command,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        uint encryptionCounter,
        byte protocolVersion)
    {
        return SecurityValidation.ValidateCommandInputs(command, sessionKeys, macChainingValue)
            .Bind(_ => BuildCommandData(command))
            .Bind(commandData => ProcessCommand(
                commandData,
                command,
                securityLevel,
                sessionKeys,
                macChainingValue,
                encryptionCounter,
                protocolVersion));
    }

    /// <summary>
    /// Applies command security with full MAC chaining state support including ICV encryption.
    /// This overload supports SCP02 ICV encryption per GP Card Specification v2.3.1 Section E.3.4.
    /// </summary>
    public static Result<(byte[] securedCommand, SecureChannelState newState), SmartCardError> ApplyCommandSecurity(
        IApduCommand command,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        MacChainingState macChainingState,
        uint encryptionCounter)
    {
        return SecurityValidation.ValidateCommandInputs(command, sessionKeys, [..macChainingState.ToArray()])
            .Bind(_ => BuildCommandData(command))
            .Bind(commandData => ProcessCommandWithIcvEncryption(
                commandData,
                command,
                securityLevel,
                sessionKeys,
                macChainingState,
                encryptionCounter));
    }

    private static Result<(byte[] securedCommand, SecureChannelState newState), SmartCardError> ProcessCommand(
        byte[] commandData,
        IApduCommand originalCommand,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        uint encryptionCounter,
        byte protocolVersion)
    {
        var hasData = originalCommand.Data is { Length: > 0 };
        var newCounter = encryptionCounter;
        var newMacChainingValue = macChainingValue;
        
        // Apply encryption if required
        var encryptionResult = securityLevel.HasCDecryption() && hasData
            ? ApplyEncryption(commandData, sessionKeys, encryptionCounter, protocolVersion)
                .Map(encrypted => 
                {
                    newCounter = protocolVersion == ProtocolIdentifiers.Scp03 ? encryptionCounter + 1 : encryptionCounter;
                    return encrypted;
                })
            : Result.Success<byte[], SmartCardError>(commandData);

        return encryptionResult.Bind(encryptedData =>
        {
            // Apply MAC if required
            if (securityLevel.HasCMac())
            {
                return ApplyMac(encryptedData, sessionKeys, macChainingValue, protocolVersion)
                    .Bind(macResult =>
                    {
                        newMacChainingValue = macResult.NewMacChainingValue;
                        return CreateNewState(
                            macResult.WrappedCommand,
                            sessionKeys,
                            securityLevel,
                            protocolVersion,
                            newMacChainingValue,
                            newCounter);
                    });
            }

            return CreateNewState(
                encryptedData,
                sessionKeys,
                securityLevel,
                protocolVersion,
                newMacChainingValue,
                newCounter);
        });
    }

    private static Result<(byte[] securedCommand, SecureChannelState newState), SmartCardError> ProcessCommandWithIcvEncryption(
        byte[] commandData,
        IApduCommand originalCommand,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        MacChainingState macChainingState,
        uint encryptionCounter)
    {
        var hasData = originalCommand.Data is { Length: > 0 };
        var newCounter = encryptionCounter;
        var newMacChainingState = macChainingState;
        
        // Apply encryption if required
        var encryptionResult = securityLevel.HasCDecryption() && hasData
            ? ApplyEncryption(commandData, sessionKeys, encryptionCounter, macChainingState.ProtocolVersion)
                .Map(encrypted => 
                {
                    newCounter = macChainingState.ProtocolVersion == ProtocolIdentifiers.Scp03 ? encryptionCounter + 1 : encryptionCounter;
                    return encrypted;
                })
            : Result.Success<byte[], SmartCardError>(commandData);

        return encryptionResult.Bind(encryptedData =>
        {
            // Apply MAC if required
            if (securityLevel.HasCMac())
            {
                return ApplyMacWithIcvEncryption(encryptedData, sessionKeys, macChainingState)
                    .Bind(macResult =>
                    {
                        newMacChainingState = macResult.NewMacChainingState;
                        return CreateNewStateWithMacChaining(
                            macResult.WrappedCommand,
                            sessionKeys,
                            securityLevel,
                            newMacChainingState,
                            newCounter);
                    });
            }

            return CreateNewStateWithMacChaining(
                encryptedData,
                sessionKeys,
                securityLevel,
                newMacChainingState,
                newCounter);
        });
    }

    private static Result<(byte[] securedCommand, SecureChannelState newState), SmartCardError> CreateNewState(
        byte[] securedCommand,
        SessionKeys sessionKeys,
        SecurityLevel securityLevel,
        byte protocolVersion,
        ImmutableArray<byte> newMacChainingValue,
        uint newEncryptionCounter)
    {
        // Create MAC chaining state
        return MacChainingState.Create(newMacChainingValue.ToArray(), protocolVersion, 0x00)
            .Bind(macState => SecureChannelState.Create(
                sessionKeys,
                securityLevel,
                protocolVersion,
                newMacChainingValue.ToArray(),
                0x00)
                .Bind(state => state.UpdateCounterAndMac(newEncryptionCounter, macState))
                .Map(updatedState => (securedCommand, updatedState)));
    }

    /// <summary>
    /// Result of MAC application containing the wrapped command and new chaining value.
    /// </summary>
    private record MacResult(byte[] WrappedCommand, ImmutableArray<byte> NewMacChainingValue);

    /// <summary>
    /// Result of MAC application with full MAC chaining state including implementation parameter.
    /// </summary>
    private record MacResultWithState(byte[] WrappedCommand, MacChainingState NewMacChainingState);

    private static Result<MacResult, SmartCardError> ApplyMac(
        byte[] command,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        byte protocolVersion)
    {
        if (command.Length < 4)
        {
            return SmartCardError.InvalidData("Command too short for MAC");
        }

        // Determine command structure
        var (hasData, originalLc, originalLe) = ParseCommandStructure(command);

        // Create MAC input according to protocol
        return (protocolVersion == ProtocolIdentifiers.Scp03
                ? CreateScp03MacInput(command, hasData, originalLc)
                : CreateScp02MacInput(command))
            .Bind(macInput => CalculateCMac(macInput, sessionKeys, macChainingValue, protocolVersion))
            .Map(macCalcResult =>
            {
                var (mac, newChainingValue) = macCalcResult;
                
                // Build new command with MAC
                var macCommand = BuildMacCommand(command, mac, hasData, originalLc, originalLe);
                
                // Set secure messaging indicator in CLA byte (bit 2)
                macCommand[0] |= 0x04;
                
                return new MacResult(macCommand, newChainingValue);
            });
    }

    private static Result<byte[], SmartCardError> ApplyEncryption(
        byte[] command,
        SessionKeys sessionKeys,
        uint encryptionCounter,
        byte protocolVersion)
    {
        if (command.Length <= 5) // No data to encrypt
        {
            return Result.Success<byte[], SmartCardError>(command);
        }

        var lc = command[4];
        if (lc == 0 || command.Length < 5 + lc)
        {
            return Result.Success<byte[], SmartCardError>(command);
        }

        // Extract data to encrypt
        var dataToEncrypt = new byte[lc];
        Array.Copy(command, 5, dataToEncrypt, 0, lc);

        return CryptographicOperations.ApplyIso7816Padding(dataToEncrypt, 16)
            .Bind(paddedData => CryptographicOperations.GenerateCommandIcv(sessionKeys.SEnc, encryptionCounter, protocolVersion)
                .Bind(icv => protocolVersion == ProtocolIdentifiers.Scp03
                    ? CryptographicOperations.EncryptAesCbc(sessionKeys.SEnc, icv, paddedData)
                    : CryptographicOperations.Encrypt3DesCbc(sessionKeys.SEnc, new byte[8], paddedData)))
            .Map(encryptedData =>
            {
                // Build new command
                var newCommand = new byte[5 + encryptedData.Length + (command.Length > 5 + lc ? 1 : 0)];
                Array.Copy(command, 0, newCommand, 0, 4);
                
                // Set secure messaging indicator in CLA byte (bit 2)
                newCommand[0] |= 0x04;
                
                newCommand[4] = (byte)encryptedData.Length; // New Lc for encrypted data only
                Array.Copy(encryptedData, 0, newCommand, 5, encryptedData.Length);

                // Copy Le if present
                if (command.Length > 5 + lc)
                {
                    newCommand[newCommand.Length - 1] = command[command.Length - 1];
                }

                return newCommand;
            });
    }

    private static Result<(byte[] mac, ImmutableArray<byte> newChainingValue), SmartCardError> CalculateCMac(
        byte[] command,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        byte protocolVersion)
    {
        var macInput = new byte[macChainingValue.Length + command.Length];
        macChainingValue.CopyTo(macInput, 0);
        Array.Copy(command, 0, macInput, macChainingValue.Length, command.Length);

        if (protocolVersion == ProtocolIdentifiers.Scp03)
        {
            var macService = new MacService();
            
            // Calculate full 16-byte AES-CMAC and return both truncated and full MAC
            return macService.CalculateAesCmac(sessionKeys.SMac, macInput, macLength: 16)
                .Map(fullMac => 
                {
                    // Return truncated 8-byte MAC and full 16-byte chaining value
                    var mac = new byte[8];
                    Array.Copy(fullMac, 0, mac, 0, 8);
                    
                    return (mac, fullMac.ToImmutableArray());
                });
        }
        else
        {
            // SCP02 uses 3DES MAC - ISO9797Alg3Mac expects DesEngine, not DesEdeEngine
            var engine = new DesEngine();
            var desMac = new ISO9797Alg3Mac(engine);
            desMac.Init(new KeyParameter(sessionKeys.SMac)); // ISO9797Alg3Mac handles 16/24 byte keys internally
            desMac.BlockUpdate(macInput, 0, macInput.Length);
            var mac = new byte[8];
            _ = desMac.DoFinal(mac, 0);
            
            // For SCP02, update only first 8 bytes of chaining value
            var newChainingValue = macChainingValue.ToArray();
            Array.Copy(mac, 0, newChainingValue, 0, 8);
            
            return Result.Success<(byte[], ImmutableArray<byte>), SmartCardError>(
                (mac, [..newChainingValue])
            );
        }
    }

    private static Result<byte[], SmartCardError> CreateScp03MacInput(byte[] command, bool hasData, byte originalLc)
    {
        if (command.Length < 4)
        {
            return SmartCardError.InvalidData("Command too short for SCP03 MAC");
        }

        // Extract header
        var ins = command[1];
        var p1 = command[2];
        var p2 = command[3];

        // Build modified APDU for MAC calculation per GP spec
        byte[] macInput;
        
        if (hasData)
        {
            // Command has data: CLA | INS | P1 | P2 | Lc+8 | data
            macInput = new byte[5 + originalLc];
            macInput[0] = 0x84; // Fixed CLA for MAC calculation
            macInput[1] = ins;
            macInput[2] = p1;
            macInput[3] = p2;
            macInput[4] = (byte)(originalLc + 8); // Modified Lc for MAC calculation
            
            // Copy data
            Array.Copy(command, 5, macInput, 5, originalLc);
        }
        else
        {
            // Command has no data: CLA | INS | P1 | P2 | 0x08
            macInput = new byte[5];
            macInput[0] = 0x84; // Fixed CLA for MAC calculation
            macInput[1] = ins;
            macInput[2] = p1;
            macInput[3] = p2;
            macInput[4] = 0x08; // Lc = 8 for MAC only
        }

        return Result.Success<byte[], SmartCardError>(macInput);
    }

    private static Result<byte[], SmartCardError> CreateScp02MacInput(byte[] command)
    {
        if (command.Length < 4)
        {
            return SmartCardError.InvalidData("Command too short for SCP02 MAC");
        }

        // Extract header
        var cla = command[0];
        var ins = command[1];
        var p1 = command[2];
        var p2 = command[3];

        // Parse command structure to distinguish between Case 2 (Le) and Case 3/4 (Lc+data)
        var (hasData, originalLc, originalLe) = ParseCommandStructure(command);

        // Build modified APDU for MAC calculation
        byte[] macInput;
        if (hasData)
        {
            // Case 3/4: Has data
            macInput = new byte[5 + originalLc];
            macInput[0] = cla;
            macInput[1] = ins;
            macInput[2] = p1;
            macInput[3] = p2;
            macInput[4] = (byte)(originalLc + 8); // Modified Lc for MAC calculation
            Array.Copy(command, 5, macInput, 5, originalLc);
        }
        else
        {
            // Case 1/2: No data
            macInput = new byte[5];
            macInput[0] = cla;
            macInput[1] = ins;
            macInput[2] = p1;
            macInput[3] = p2;
            macInput[4] = 0x08; // Lc = 8 for MAC only
        }

        return Result.Success<byte[], SmartCardError>(macInput);
    }

    private static (bool hasData, byte originalLc, byte? originalLe) ParseCommandStructure(byte[] command)
    {
        switch (command.Length)
        {
            case <= 4:
                return (false, 0, null);
            case 5:
                // Could be Case 2 (P1 P2 P3=Le) or Case 3 with Lc=0
                return (false, 0, command[4]);
        }

        var potentialLc = command[4];
        if (command.Length >= 5 + potentialLc)
        {
            // This is Lc followed by data
            var hasData = true;
            var originalLc = potentialLc;
            byte? originalLe = null;
            
            // Check for Le after data
            if (command.Length > 5 + originalLc)
            {
                originalLe = command[5 + originalLc];
            }
            
            return (hasData, originalLc, originalLe);
        }

        // Malformed command
        return (false, 0, null);
    }

    private static byte[] BuildMacCommand(
        byte[] command,
        byte[] mac,
        bool hasData,
        byte originalLc,
        byte? originalLe)
    {
        byte[] macCommand;
        
        if (hasData)
        {
            // CLA INS P1 P2 Lc' Data MAC [Le]
            var newLc = (byte)(originalLc + 8);
            macCommand = new byte[5 + originalLc + 8 + (originalLe.HasValue ? 1 : 0)];
            
            // Copy header
            Array.Copy(command, 0, macCommand, 0, 4);
            
            // Set new Lc
            macCommand[4] = newLc;
            
            // Copy data
            Array.Copy(command, 5, macCommand, 5, originalLc);
            
            // Copy MAC
            Array.Copy(mac, 0, macCommand, 5 + originalLc, 8);
            
            // Copy Le if present
            if (originalLe.HasValue)
            {
                macCommand[macCommand.Length - 1] = originalLe.Value;
            }
        }
        else
        {
            // CLA INS P1 P2 Lc MAC [Le]
            macCommand = new byte[5 + 8 + (originalLe.HasValue ? 1 : 0)];
            
            // Copy header
            Array.Copy(command, 0, macCommand, 0, 4);
            
            // Set Lc = 8 (MAC only)
            macCommand[4] = 0x08;
            
            // Copy MAC
            Array.Copy(mac, 0, macCommand, 5, 8);
            
            // Copy Le if present
            if (originalLe.HasValue)
            {
                macCommand[macCommand.Length - 1] = originalLe.Value;
            }
        }

        return macCommand;
    }


    private static Result<byte[], SmartCardError> BuildCommandData(IApduCommand command)
    {
        // Use ApduBuilder to get the exact command structure including Le byte if present
        return Result.Success<byte[], SmartCardError>(ApduBuilder.BuildApdu(command));
    }

    /// <summary>
    /// Applies MAC with ICV encryption support for SCP02 implementations.
    /// Per GP Card Specification v2.3.1 Section E.3.4.
    /// </summary>
    private static Result<MacResultWithState, SmartCardError> ApplyMacWithIcvEncryption(
        byte[] command,
        SessionKeys sessionKeys,
        MacChainingState macChainingState)
    {
        if (command.Length < 4)
        {
            return SmartCardError.InvalidData("Command too short for MAC");
        }

        // Determine command structure
        var (hasData, originalLc, originalLe) = ParseCommandStructure(command);

        // Create MAC input according to protocol
        var macInputResult = macChainingState.ProtocolVersion == ProtocolIdentifiers.Scp03
            ? CreateScp03MacInput(command, hasData, originalLc)
            : CreateScp02MacInput(command);

        return macInputResult.Bind(macInput =>
            CalculateCMacWithIcvEncryption(macInput, sessionKeys, macChainingState))
            .Map(macCalcResult =>
            {
                var (mac, newChainingState) = macCalcResult;
                
                // Build new command with MAC
                var macCommand = BuildMacCommand(command, mac, hasData, originalLc, originalLe);
                
                // Set secure messaging indicator in CLA byte (bit 2)
                macCommand[0] |= 0x04;
                
                return new MacResultWithState(macCommand, newChainingState);
            });
    }

    /// <summary>
    /// Calculates C-MAC with ICV encryption support for SCP02.
    /// Applies ICV encryption per GP Card Specification v2.3.1 Section E.3.4.
    /// </summary>
    private static Result<(byte[] mac, MacChainingState newChainingState), SmartCardError> CalculateCMacWithIcvEncryption(
        byte[] command,
        SessionKeys sessionKeys,
        MacChainingState macChainingState)
    {
        // Determine if this is the first ICV of the session
        var isFirstIcv = macChainingState.ToArray().All(b => b == 0);

        // Apply ICV encryption if required by implementation
        return IcvEncryptionService.ProcessIcvForMacCalculation(
                macChainingState.ToArray(),
                sessionKeys.SMac,
                (ScpImplementation)macChainingState.ImplementationParameter,
                isFirstIcv)
            .Bind(processedIcv =>
            {
                // Build MAC input with processed ICV
                var macInput = new byte[processedIcv.Length + command.Length];
                Array.Copy(processedIcv, 0, macInput, 0, processedIcv.Length);
                Array.Copy(command, 0, macInput, processedIcv.Length, command.Length);

                if (macChainingState.ProtocolVersion == ProtocolIdentifiers.Scp03)
                {
                    var macService = new MacService();
                    
                    // Calculate full 16-byte AES-CMAC and return both truncated and full MAC
                    return macService.CalculateAesCmac(sessionKeys.SMac, macInput, macLength: 16)
                        .Bind(fullMac =>
                        {
                            // Return truncated 8-byte MAC and full 16-byte chaining value
                            var mac = new byte[8];
                            Array.Copy(fullMac, 0, mac, 0, 8);
                            
                            return MacChainingState.Create(fullMac, macChainingState.ProtocolVersion, macChainingState.ImplementationParameter)
                                .Map(newState => (mac, newState));
                        });
                }
                else
                {
                    // SCP02 uses 3DES MAC - ISO9797Alg3Mac expects DesEngine, not DesEdeEngine
                    var engine = new DesEngine();
                    var desMac = new ISO9797Alg3Mac(engine);
                    desMac.Init(new KeyParameter(sessionKeys.SMac));
                    desMac.BlockUpdate(macInput, 0, macInput.Length);
                    var mac = new byte[8];
                    _ = desMac.DoFinal(mac, 0);
                    
                    // For SCP02, new chaining value is the MAC result
                    return MacChainingState.Create(mac, macChainingState.ProtocolVersion, macChainingState.ImplementationParameter)
                        .Map(newState => (mac, newState));
                }
            });
    }

    /// <summary>
    /// Creates a new secure channel state with updated MAC chaining state.
    /// </summary>
    private static Result<(byte[] securedCommand, SecureChannelState newState), SmartCardError> CreateNewStateWithMacChaining(
        byte[] securedCommand,
        SessionKeys sessionKeys,
        SecurityLevel securityLevel,
        MacChainingState newMacChainingState,
        uint newEncryptionCounter)
    {
        return SecureChannelState.Create(
                sessionKeys,
                securityLevel,
                newMacChainingState.ProtocolVersion,
                newMacChainingState.ToArray(),
                newMacChainingState.ImplementationParameter)
            .Bind(state => state.UpdateCounterAndMac(newEncryptionCounter, newMacChainingState))
            .Map(updatedState => (securedCommand, updatedState));
    }
}