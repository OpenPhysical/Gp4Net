using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;
using static Gp4Net.Cryptography.CryptoOperations;

namespace Gp4Net.Domain;

/// <summary>
/// Immutable value object representing the MAC chaining state in a secure channel.
/// Encapsulates the chaining value and protocol-specific validation rules.
/// </summary>
[PublicAPI]
public record MacChainingState(
    ImmutableArray<byte> Value,
    ScpVersion ProtocolVersion,
    byte ImplementationParameter
)
{
    /// <summary>
    /// Creates a new MAC chaining state with validation.
    /// </summary>
    /// <param name="initialValue">The initial chaining value.</param>
    /// <param name="protocolVersion">The protocol version (SCP02 or SCP03).</param>
    /// <param name="implementationParameter">The implementation parameter (i-value) for protocol-specific behavior.</param>
    /// <returns>A Result containing the created state or an error.</returns>
    public static Result<MacChainingState, SmartCardError> Create(
        byte[] initialValue,
        ScpVersion protocolVersion,
        byte implementationParameter
    )
    {
        if (initialValue == null)
        {
            return new NullParameterError(nameof(initialValue));
        }

        // Validate protocol version
        if (protocolVersion != ScpVersion.Scp02 && protocolVersion != ScpVersion.Scp03)
        {
            return new InvalidFormatError("ProtocolVersion", "SCP02 (0x02) or SCP03 (0x03)");
        }

        // Validate chaining value size based on protocol
        int expectedSize = protocolVersion == ScpVersion.Scp03 ? 16 : 8;
        if (initialValue.Length != expectedSize)
        {
            return new InvalidLengthError(
                $"SCP{(byte)protocolVersion:X2} chaining value",
                expectedSize,
                initialValue.Length
            );
        }

        return Result.Success<MacChainingState, SmartCardError>(
            new MacChainingState([.. initialValue], protocolVersion, implementationParameter)
        );
    }

    /// <summary>
    /// Creates a zero-initialized MAC chaining state for the specified protocol.
    /// </summary>
    /// <param name="protocolVersion">The protocol version.</param>
    /// <param name="implementationParameter">The implementation parameter (i-value).</param>
    /// <returns>A Result containing the created state or an error.</returns>
    public static Result<MacChainingState, SmartCardError> CreateZeroInitialized(
        ScpVersion protocolVersion,
        byte implementationParameter
    )
    {
        int size = protocolVersion == ScpVersion.Scp03 ? 16 : 8;
        return Create(new byte[size], protocolVersion, implementationParameter);
    }

    /// <summary>
    /// Gets the size of the chaining value in bytes.
    /// </summary>
    public int Size
    {
        get { return Value.Length; }
    }

    /// <summary>
    /// Gets whether this is an SCP03 chaining state.
    /// </summary>
    public bool IsScp03
    {
        get { return ProtocolVersion == ScpVersion.Scp03; }
    }

    /// <summary>
    /// Gets whether this is an SCP02 chaining state.
    /// </summary>
    public bool IsScp02
    {
        get { return ProtocolVersion == ScpVersion.Scp02; }
    }

    /// <summary>
    /// Converts the chaining value to a byte array.
    /// </summary>
    public byte[] ToArray()
    {
        return [.. Value];
    }

    /// <summary>
    /// Updates the chaining value, maintaining protocol version and implementation parameter.
    /// </summary>
    /// <param name="newValue">The new chaining value.</param>
    /// <returns>A Result containing the updated state or an error.</returns>
    public Result<MacChainingState, SmartCardError> UpdateValue(byte[] newValue)
    {
        return Create(newValue, ProtocolVersion, ImplementationParameter);
    }
}
