// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Constants;

/// <summary>
/// ISO 7816-4 and GlobalPlatform status word constants for APDU responses.
/// </summary>
[PublicAPI]
public static class StatusWords
{
    /// <summary>
    /// Success - Command completed successfully.
    /// </summary>
    public static readonly StatusWord Success = new(0x9000);

    /// <summary>
    /// Incorrect data field or parameters in data field.
    /// </summary>
    public static readonly StatusWord IncorrectData = new(0x6A80);

    /// <summary>
    /// Memory problem or insufficient memory.
    /// </summary>
    public static readonly StatusWord MemoryError = new(0x6A84);

    /// <summary>
    /// Conditions of use not satisfied.
    /// </summary>
    public static readonly StatusWord ConditionsNotSatisfied = new(0x6985);

    /// <summary>
    /// Generic failure or internal error.
    /// </summary>
    public static readonly StatusWord GenericFailure = new(0x6F00);

    /// <summary>
    /// Wrong length - Le field incorrect.
    /// </summary>
    public static readonly StatusWord WrongLength = new(0x6700);

    /// <summary>
    /// Class not supported.
    /// </summary>
    public static readonly StatusWord ClassNotSupported = new(0x6E00);

    /// <summary>
    /// Instruction not supported.
    /// </summary>
    public static readonly StatusWord InstructionNotSupported = new(0x6D00);

    /// <summary>
    /// Function not supported.
    /// </summary>
    public static readonly StatusWord FunctionNotSupported = new(0x6A81);

    /// <summary>
    /// File not found.
    /// </summary>
    public static readonly StatusWord FileNotFound = new(0x6A82);

    /// <summary>
    /// Record not found.
    /// </summary>
    public static readonly StatusWord RecordNotFound = new(0x6A83);

    /// <summary>
    /// Wrong parameters P1-P2.
    /// </summary>
    public static readonly StatusWord WrongParameters = new(0x6A86);

    /// <summary>
    /// Lc inconsistent with P1-P2.
    /// </summary>
    public static readonly StatusWord LcInconsistent = new(0x6A87);

    /// <summary>
    /// Referenced data not found.
    /// </summary>
    public static readonly StatusWord ReferencedDataNotFound = new(0x6A88);

    /// <summary>
    /// Security status not satisfied.
    /// </summary>
    public static readonly StatusWord SecurityStatusNotSatisfied = new(0x6982);

    /// <summary>
    /// Authentication method blocked.
    /// </summary>
    public static readonly StatusWord AuthenticationMethodBlocked = new(0x6983);

    /// <summary>
    /// Reference data not usable.
    /// </summary>
    public static readonly StatusWord ReferenceDataNotUsable = new(0x6984);

    /// <summary>
    /// Command not allowed (no current EF).
    /// </summary>
    public static readonly StatusWord CommandNotAllowed = new(0x6986);

    /// <summary>
    /// Expected secure messaging data objects missing.
    /// </summary>
    public static readonly StatusWord SecureMessagingMissing = new(0x6987);

    /// <summary>
    /// Incorrect secure messaging data objects.
    /// </summary>
    public static readonly StatusWord SecureMessagingIncorrect = new(0x6988);
}