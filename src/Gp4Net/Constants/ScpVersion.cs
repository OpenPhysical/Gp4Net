// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

namespace Gp4Net.Constants;

/// <summary>
/// Secure Channel Protocol versions for type-safe protocol handling.
/// Per GlobalPlatform Card Specification v2.3.1 Section 7.1.
/// </summary>
[PublicAPI]
public enum ScpVersion : byte
{

    /// <summary>
    /// SCP02 protocol per GlobalPlatform Card Specification v2.3.1 Appendix E.4.
    /// Uses 3DES for encryption and MAC operations.
    /// </summary>
    Scp02 = 0x02,

    /// <summary>
    /// SCP03 protocol per GlobalPlatform SCP03 v1.1.1.
    /// Uses AES for encryption and AES-CMAC for MAC operations.
    /// </summary>
    Scp03 = 0x03
}