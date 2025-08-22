using System;
using System.Linq;
using System.Text;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.Domain.CardInfo;

/// <summary>
/// Security Domain Management Data (tag C1) parser.
/// Contains information about the current state of the security domain.
/// </summary>
public class SecurityDomainStatus
{
    /// <summary>
    /// Gets the raw status data.
    /// </summary>
    public byte[] RawData { get; }
    
    /// <summary>
    /// Gets the security domain state byte.
    /// </summary>
    public byte StateByte { get; }
    
    /// <summary>
    /// Gets additional status bytes if present.
    /// </summary>
    public Maybe<byte[]> AdditionalData { get; }
    
    private SecurityDomainStatus(byte[] rawData, byte stateByte, Maybe<byte[]> additionalData)
    {
        RawData = rawData;
        StateByte = stateByte;
        AdditionalData = additionalData;
    }
    
    /// <summary>
    /// Parses Security Domain Management Data from tag C1.
    /// </summary>
    /// <param name="data">The tag C1 data bytes.</param>
    /// <returns>Result containing parsed status or error.</returns>
    public static Result<SecurityDomainStatus, SmartCardError> Parse(Maybe<byte[]> data)
    {
        return data.Match(
            Some: bytes => ParseFromBytes(bytes),
            None: () => Result.Failure<SecurityDomainStatus, SmartCardError>(
                SmartCardError.InvalidData("Security domain status data cannot be null"))
        );
    }
    
    private static Result<SecurityDomainStatus, SmartCardError> ParseFromBytes(byte[] data)
    {
        if (data.Length < 3) // Minimum: tag (1) + length (1) + state (1)
        {
            return Result.Failure<SecurityDomainStatus, SmartCardError>(
                SmartCardError.InvalidData($"Security domain status data too short: {data.Length} bytes"));
        }
        
        // Verify tag
        if (data[0] != 0xC1)
        {
            return Result.Failure<SecurityDomainStatus, SmartCardError>(
                SmartCardError.InvalidData($"Invalid tag: expected 0xC1, got 0x{data[0]:X2}"));
        }
        
        // Get length
        var length = data[1];
        if (data.Length < 2 + length)
        {
            return Result.Failure<SecurityDomainStatus, SmartCardError>(
                SmartCardError.InvalidData($"Data length mismatch: expected {2 + length}, got {data.Length}"));
        }
        
        // Extract state byte
        var stateByte = data[2];
        
        // Extract additional data if present
        var additionalData = length > 1 
            ? Maybe<byte[]>.From(data[3..(2 + length)])
            : Maybe<byte[]>.None;
        
        return Result.Success<SecurityDomainStatus, SmartCardError>(
            new SecurityDomainStatus(data, stateByte, additionalData));
    }
    
    /// <summary>
    /// Gets the ISD state from the state byte.
    /// </summary>
    public IsdState GetIsdState()
    {
        // Check for special states first (full byte values)
        return StateByte switch
        {
            0x7F => IsdState.CardLocked,
            0xFF => IsdState.Terminated,
            _ => (IsdState)(StateByte & 0x0F) // For normal states, mask the flags
        };
    }
    
    /// <summary>
    /// Gets whether the ISD is personalized.
    /// </summary>
    public bool IsPersonalized()
    {
        return (StateByte & 0x10) != 0;
    }
    
    /// <summary>
    /// Gets whether the ISD is locked.
    /// </summary>
    public bool IsLocked()
    {
        return (StateByte & 0x80) != 0;
    }
    
    /// <summary>
    /// Gets the sequence counter value if present.
    /// For C1020004, this would be 0x0004.
    /// For C103000046, this would be 0x0046.
    /// </summary>
    public Maybe<ushort> GetSequenceCounter()
    {
        return AdditionalData.Bind(data =>
        {
            switch (data.Length)
            {
                case 1:
                    // Single byte counter
                    return Maybe<ushort>.From(data[0]);
                case >= 2:
                {
                    // Two byte counter (big-endian)
                    var counter = (ushort)((data[data.Length - 2] << 8) | data[data.Length - 1]);
                    return Maybe<ushort>.From(counter);
                }
                default:
                    return Maybe<ushort>.None;
            }
        });
    }
    
    /// <summary>
    /// Formats the security domain status as a human-readable string.
    /// </summary>
    public override string ToString()
    {
        var sb = new StringBuilder();
        _ = sb.Append($"Security Domain Status: ");
        _ = sb.Append($"State={GetIsdState()}");
        
        if (IsPersonalized())
        {
            _ = sb.Append(" [Personalized]");
        }
        
        if (IsLocked())
        {
            _ = sb.Append(" [Locked]");
        }
        
        GetSequenceCounter().Match(
            Some: counter => sb.Append($", Sequence=0x{counter:X4}"),
            None: () => { }
        );
        
        return sb.ToString();
    }
    
    /// <summary>
    /// Gets a short description of the status.
    /// </summary>
    public string GetShortDescription()
    {
        var parts = new[]
        {
            GetIsdState().ToString(),
            IsPersonalized() ? "Personalized" : null,
            IsLocked() ? "Locked" : null,
            GetSequenceCounter().Match(c => $"Seq:0x{c:X4}", () => null)
        }.Where(p => p != null);
        
        return string.Join(", ", parts);
    }
}

/// <summary>
/// ISD (Issuer Security Domain) states.
/// </summary>
public enum IsdState : byte
{
    /// <summary>
    /// OP_READY state - normal operational state.
    /// </summary>
    OpReady = 0x01,
    
    /// <summary>
    /// INITIALIZED state.
    /// </summary>
    Initialized = 0x07,
    
    /// <summary>
    /// SECURED state.
    /// </summary>
    Secured = 0x0F,
    
    /// <summary>
    /// CARD_LOCKED state.
    /// </summary>
    CardLocked = 0x7F,
    
    /// <summary>
    /// TERMINATED state.
    /// </summary>
    Terminated = 0xFF,
    
    /// <summary>
    /// Unknown or invalid state.
    /// </summary>
    Unknown = 0x00
}