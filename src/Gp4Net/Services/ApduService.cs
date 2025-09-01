// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Transport;
using JetBrains.Annotations;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.Services;

/// <summary>
/// Unified APDU service consolidating ALL APDU operations in the Gp4Net codebase.
/// Replaces 28+ existing APDU building/parsing classes with a single, comprehensive, 
/// functionally pure service. Organized by operation type with nested static classes
/// for logical grouping following the CryptoService pattern.
/// 
/// Consolidates:
/// - ApduBuilder + ApduFactory + Extension Methods → Commands
/// - ApduParser + Command parsing logic → Parsing  
/// - Multiple ApduResponse classes → Responses
/// - Format utilities and builders → Formatting
/// 
/// All methods are static, pure functional, and return Result&lt;T, SmartCardError&gt;.
/// </summary>
[PublicAPI]
public static partial class ApduService
{
    /// <summary>
    /// Simple APDU command implementation for unified service.
    /// Pure functional immutable record replacing multiple command implementations.
    /// </summary>
    [PublicAPI]
    public sealed record UnifiedApduCommand(
        byte Cla,
        byte Ins, 
        byte P1,
        byte P2,
        byte[] Data,
        Maybe<int> ExpectedResponseLength
    ) : IApduCommand
    {
        /// <summary>
        /// Gets whether this command uses extended length format.
        /// Per ISO 7816-4 extended length encoding rules.
        /// </summary>
        public bool IsExtendedLength => Data.Length > 255 || 
            ExpectedResponseLength.Match(length => length > 255, () => false);

        /// <summary>
        /// Constructor with optional expected response length.
        /// </summary>
        public UnifiedApduCommand(byte cla, byte ins, byte p1, byte p2, byte[] data)
            : this(cla, ins, p1, p2, data, Maybe<int>.None)
        {
        }
    }

    /// <summary>
    /// Unified APDU response record consolidating multiple response implementations.
    /// Combines functionality from Core.ApduResponse, CardEmulator.ApduResponse, and Transport.ApduResponse.
    /// </summary>
    [PublicAPI]
    public sealed record UnifiedApduResponse(
        byte[] Data,
        StatusWord StatusWord
    )
    {
        /// <summary>
        /// Gets whether this response indicates success (SW=9000).
        /// </summary>
        public bool IsSuccess => StatusWord == new StatusWord(GlobalPlatform.StatusWords.Success);

        /// <summary>
        /// Gets whether this response indicates successful execution including continuation responses.
        /// Per GP specification section 8.2, success responses include chained data responses.
        /// </summary>
        public bool IsSuccessful => IsSuccess || HasContinuation;

        /// <summary>
        /// Gets whether this response indicates continuation available (0x61XX or 0x9FXX).
        /// Enhanced logic from CardEmulator implementation.
        /// </summary>
        public bool HasContinuation => 
            StatusWord.SW1 == GlobalPlatform.StatusWords.MoreData || 
            (StatusWord.SW1 == GlobalPlatform.StatusWords.ProprietaryContinuation && StatusWord.SW2 != 0x00);

        /// <summary>
        /// Gets the remaining bytes available for GET RESPONSE continuation.
        /// </summary>
        public Maybe<byte> ContinuationLength =>
            StatusWord.SW1 == GlobalPlatform.StatusWords.MoreData ? Maybe<byte>.From(StatusWord.SW2) : Maybe<byte>.None;

        /// <summary>
        /// Gets SW1 byte for compatibility with Transport.ApduResponse.
        /// </summary>
        public byte Sw1 => StatusWord.SW1;

        /// <summary>
        /// Gets SW2 byte for compatibility with Transport.ApduResponse.
        /// </summary>
        public byte Sw2 => StatusWord.SW2;

        /// <summary>
        /// Converts this response to wire format byte array.
        /// </summary>
        public byte[] ToBytes()
        {
            byte[] result = new byte[Data.Length + 2];
            Array.Copy(Data, 0, result, 0, Data.Length);
            result[Data.Length] = StatusWord.SW1;
            result[Data.Length + 1] = StatusWord.SW2;
            return result;
        }

        /// <summary>
        /// Converts response to byte array (alias for ToBytes for compatibility).
        /// </summary>
        public byte[] ToByteArray() => ToBytes();

        /// <summary>
        /// Creates a success response with data.
        /// </summary>
        public static UnifiedApduResponse Success(byte[] data = null) =>
            new(data ?? [], new StatusWord(GlobalPlatform.StatusWords.Success));

        /// <summary>
        /// Creates a success response with no data.
        /// </summary>
        public static UnifiedApduResponse Success() =>
            new([], new StatusWord(GlobalPlatform.StatusWords.Success));

        /// <summary>
        /// Creates an error response with status word.
        /// </summary>
        public static UnifiedApduResponse Error(StatusWord statusWord) =>
            new([], statusWord);

        /// <summary>
        /// Creates an error response with SW1/SW2 bytes.
        /// </summary>
        public static UnifiedApduResponse Error(byte sw1, byte sw2) =>
            new([], new StatusWord(sw1, sw2));

        /// <summary>
        /// Creates an error response with ushort status word.
        /// </summary>
        public static UnifiedApduResponse Error(ushort statusWord) =>
            new([], new StatusWord((byte)(statusWord >> 8), (byte)(statusWord & 0xFF)));

        /// <summary>
        /// Creates an error response for wrong length.
        /// </summary>
        public static UnifiedApduResponse WrongLength() =>
            Error(Gp4Net.Constants.Constants.StatusWords.Legacy.WrongLength);

        /// <summary>
        /// Creates an error response for instruction not supported.
        /// </summary>
        public static UnifiedApduResponse InstructionNotSupported() =>
            Error(Gp4Net.Constants.Constants.StatusWords.Legacy.InstructionNotSupported);

        /// <summary>
        /// Creates an error response for conditions not satisfied.
        /// </summary>
        public static UnifiedApduResponse ConditionsNotSatisfied() =>
            Error(Gp4Net.Constants.Constants.StatusWords.Legacy.ConditionsNotSatisfied);

        /// <summary>
        /// Creates an error response for security status not satisfied.
        /// </summary>
        public static UnifiedApduResponse SecurityStatusNotSatisfied() =>
            Error(Gp4Net.Constants.Constants.StatusWords.Legacy.SecurityStatusNotSatisfied);
    }
}