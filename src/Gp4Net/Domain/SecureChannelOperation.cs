using JetBrains.Annotations;

namespace Gp4Net.Domain;

/// <summary>
/// Enumeration of secure channel operation types for validation.
/// Represents different types of operations that can be performed on a secure channel.
/// </summary>
[PublicAPI]
public enum SecureChannelOperation
{
    /// <summary>
    /// Command wrapping operation (requires C-MAC/C-ENC capabilities).
    /// Used when applying security to outgoing commands.
    /// </summary>
    CommandWrapping,

    /// <summary>
    /// Response unwrapping operation (requires R-MAC/R-ENC capabilities).
    /// Used when removing security from incoming responses.
    /// </summary>
    ResponseUnwrapping,

    /// <summary>
    /// General secure messaging operation.
    /// Used for bidirectional secure communication.
    /// </summary>
    SecureMessaging,
}
