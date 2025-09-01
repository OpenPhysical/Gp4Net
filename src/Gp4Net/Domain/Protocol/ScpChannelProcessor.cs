// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Core.Functional;
using Gp4Net.Cryptography;
using Gp4Net.Transport;
using JetBrains.Annotations;
using static Gp4Net.Cryptography.CryptoService;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Unified channel processor that handles command wrapping and response unwrapping for both SCP02 and SCP03.
/// Consolidates all secure messaging operations into a single functional service.
/// Per GlobalPlatform Card Specification v2.3.1 Appendix E "Secure Channel Protocol".
/// </summary>
[PublicAPI]
public sealed class ScpChannelProcessor
{
    /// <summary>
    /// Private constructor for functional creation pattern.
    /// </summary>
    private ScpChannelProcessor()
    {
        // Pure functional processor with no dependencies
    }

    /// <summary>
    /// Creates a new ScpChannelProcessor instance.
    /// </summary>
    /// <returns>A result containing the processor or error.</returns>
    public static Result<ScpChannelProcessor, SmartCardError> Create()
    {
        return Result.Success<ScpChannelProcessor, SmartCardError>(new ScpChannelProcessor());
    }

    /// <summary>
    /// Applies command security (C-MAC, C-ENC) to an APDU command based on the secure channel state.
    /// Handles both SCP02 and SCP03 protocols transparently.
    /// </summary>
    /// <param name="command">The command to secure.</param>
    /// <param name="state">The current secure channel state.</param>
    /// <returns>A result containing the secured command and updated state or error.</returns>
    public Result<
        (byte[] securedCommand, SecureChannelState newState),
        SmartCardError
    > ApplyCommandSecurity(IApduCommand command, SecureChannelState state)
    {
        // Delegate entirely to unified ScpService.Security
        return Gp4Net.Services.ScpService.Security.ApplyCommandSecurity(command, state);
    }

    /// <summary>
    /// Applies response security (R-MAC verification, R-ENC decryption) to an APDU response.
    /// Handles both SCP02 and SCP03 protocols transparently.
    /// </summary>
    /// <param name="response">The response to process.</param>
    /// <param name="state">The current secure channel state.</param>
    /// <returns>A result containing the processed response and updated state or error.</returns>
    public Result<
        (byte[] processedResponse, SecureChannelState newState),
        SmartCardError
    > ApplyResponseSecurity(byte[] response, SecureChannelState state)
    {
        // Delegate entirely to unified ScpService.Security
        return Gp4Net.Services.ScpService.Security.ProcessResponse(response, state);
    }

    // All implementation now delegates to unified ScpService.Security
}
