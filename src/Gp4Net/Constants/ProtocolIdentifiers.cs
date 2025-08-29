// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

namespace Gp4Net.Constants;

/// <summary>
/// Secure Channel Protocol identifiers as defined in GlobalPlatform specifications.
/// </summary>
[PublicAPI]
public static class ProtocolIdentifiers
{
    /// <summary>
    /// Mask for extracting the base protocol identifier.
    /// </summary>
    public const byte ProtocolMask = 0x0F;

    /// <summary>
    /// Mask for extracting implementation options.
    /// </summary>
    public const byte OptionsMask = 0xF0;
}
