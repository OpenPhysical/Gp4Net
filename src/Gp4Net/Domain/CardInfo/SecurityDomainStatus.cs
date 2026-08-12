using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.DataObjects;

namespace Gp4Net.Domain.CardInfo;

/// <summary>
/// Security Domain Management Data (tag C1).
/// GP Card Specification v2.3.1, §11.3.2.1 defines its value as the default key
/// version's two- or three-byte sequence counter.
/// </summary>
public sealed class SecurityDomainStatus
{
    private SecurityDomainStatus(byte[] rawData, byte[] sequenceCounter)
    {
        RawData = (byte[])rawData.Clone();
        SequenceCounter = (byte[])sequenceCounter.Clone();
    }

    public byte[] RawData { get; }

    public byte[] SequenceCounter { get; }

    public static Result<SecurityDomainStatus, SmartCardError> Parse(Maybe<byte[]> data) =>
        data.Match(
            bytes =>
                SecurityDomainInfoCodec
                    .Decode(bytes)
                    .Map(info => new SecurityDomainStatus(bytes, info.SequenceCounter)),
            () =>
                Result.Failure<SecurityDomainStatus, SmartCardError>(
                    SmartCardError.InvalidData("Security domain management data cannot be absent")
                )
        );

    public static Result<SecurityDomainStatus, SmartCardError> Parse(byte[] data) =>
        Parse(Maybe<byte[]>.From(data));

    public Maybe<uint> GetSequenceCounter()
    {
        uint value = 0;
        foreach (byte current in SequenceCounter)
            value = value << 8 | current;
        return Maybe<uint>.From(value);
    }

    public override string ToString() =>
        $"Security Domain Sequence Counter: 0x{Convert.ToHexString(SequenceCounter)}";

    public string GetShortDescription() => $"Seq:0x{Convert.ToHexString(SequenceCounter)}";
}
