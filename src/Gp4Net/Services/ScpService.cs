// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Transport;
using JetBrains.Annotations;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.Services;

/// <summary>
/// Unified SCP service consolidating ALL secure channel protocol operations.
/// Replaces SecureChannelEstablishment + Scp02Protocol + Scp03Protocol + 7 other classes
/// with a single, comprehensive, functionally pure service organized by operation type.
/// 
/// Consolidates:
/// - SecureChannelService + ScpService duplicate operations → Security
/// - SecureChannelEstablishment + Protocol classes → Establishment  
/// - Multiple ApplyCommandSecurity/ProcessResponse methods → Security
/// - Protocol-specific logic → Protocol
/// - State management → State
/// 
/// Per GlobalPlatform Card Specification v2.3.1 Appendix E "Secure Channel Protocol".
/// All methods are static, pure functional, and return Result&lt;T, SmartCardError&gt;.
/// </summary>
[PublicAPI]
public static partial class ScpService
{
    /// <summary>
    /// Supporting types for SCP operations
    /// </summary>
    [PublicAPI]
    public static class Types
    {
        /// <summary>
        /// SCP protocol and implementation parameter combination
        /// Immutable value object representing a specific SCP variant
        /// </summary>
        public sealed record ScpOption(
            CryptoService.ScpVersion Protocol,     // 0x02 or 0x03
            byte Implementation     // i-parameter (0x00, 0x02, 0x04, etc.)
        )
        {
            /// <summary>
            /// Creates a validated SCP option
            /// </summary>
            public static Result<ScpOption, SmartCardError> Create(CryptoService.ScpVersion protocol, byte implementation) =>
                ValidateImplementation(protocol, implementation)
                    .Map(() => new ScpOption(protocol, implementation));
                    
            private static UnitResult<SmartCardError> ValidateImplementation(CryptoService.ScpVersion protocol, byte implementation) =>
                protocol switch
                {
                    CryptoService.ScpVersion.Scp02 => Domain.Protocol.Scp02Protocol.IsValidScp02Implementation(implementation)
                        ? UnitResult.Success<SmartCardError>()
                        : UnitResult.Failure(SmartCardError.InvalidArgument($"Invalid SCP02 implementation: {implementation:X2}")),
                    CryptoService.ScpVersion.Scp03 => IsValidScp03Implementation(implementation)  
                        ? UnitResult.Success<SmartCardError>()
                        : UnitResult.Failure(SmartCardError.InvalidArgument($"Invalid SCP03 implementation: {implementation:X2}")),
                    _ => UnitResult.Failure(SmartCardError.InvalidArgument($"Unsupported protocol: {protocol}"))
                };

            private static bool IsValidScp03Implementation(byte implementation) =>
                implementation switch
                {
                    0x00 or 0x10 or 0x20 or 0x60 or 0x70 => true,
                    _ => false
                };
        }

        /// <summary>
        /// Result of secure channel establishment containing state and capabilities
        /// </summary>
        public sealed record SecureChannelSession(
            SecureChannelState State,
            ScpOption ScpOption,
            byte[] SessionId
        );

        /// <summary>
        /// Result of a secure command execution
        /// </summary>
        public sealed record SecureCommandResult(
            byte[] Response,
            SecureChannelState NewState,
            StatusWord StatusWord
        );
    }


    /// <summary>
    /// SCP-specific error factory methods
    /// </summary>
    private static class ScpErrors
    {
        public static SmartCardError InvalidScpOption(Types.ScpOption option) =>
            SmartCardError.InvalidArgument($"Invalid SCP option: {option.Protocol:X2}/{option.Implementation:X2}");
            
        public static SmartCardError ChannelEstablishmentFailed(string reason) =>
            SmartCardError.SecurityError($"Secure channel establishment failed: {reason}");
            
        public static SmartCardError MacVerificationFailed(string details) =>
            SmartCardError.SecurityError($"MAC verification failed: {details}");
            
        public static SmartCardError CryptogramMismatch(byte[] expected, byte[] actual) =>
            SmartCardError.AuthenticationFailed($"Cryptogram mismatch - expected: {Convert.ToHexString(expected)}, actual: {Convert.ToHexString(actual)}");
    }
}