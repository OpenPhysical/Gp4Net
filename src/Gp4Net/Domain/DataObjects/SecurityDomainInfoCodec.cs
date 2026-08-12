// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;
using static Gp4Net.Services.TlvCodec;

namespace Gp4Net.Domain.DataObjects;

/// <summary>
/// Codec for the default Key Version Number Sequence Counter returned by GET DATA tag 'C1'.
/// </summary>
[PublicAPI]
public static class SecurityDomainInfoCodec
{
    public static Result<byte[], SmartCardError> Encode(SecurityDomainInfo info)
    {
        if (info is null)
            return SmartCardError.InvalidArgument("Security domain info cannot be null");

        Result validation = ValidateLength(info.SequenceCounter);
        if (validation.IsFailure)
            return SmartCardError.InvalidData(validation.Error);

        byte[] encoded = [0xC1, (byte)info.SequenceCounter.Length, .. info.SequenceCounter];
        return encoded;
    }

    public static Result<SecurityDomainInfo, SmartCardError> Decode(byte[] data)
    {
        if (data is null)
            return SmartCardError.InvalidArgument("Data cannot be null");

        return TlvParser
            .Parse([.. data])
            .Bind(tlv =>
                tlv.Tag.ToNumber()
                    .Bind(tag =>
                        tag == 0xC1
                            ? Result.Success<TlvObject, SmartCardError>(tlv)
                            : SmartCardError.InvalidData("Expected Sequence Counter tag C1")
                    )
            )
            .Bind(tlv =>
            {
                byte[] counter = tlv.TlvData.Bytes.ToArray();
                Result validation = ValidateLength(counter);
                return validation.IsSuccess
                    ? Result.Success<SecurityDomainInfo, SmartCardError>(
                        new SecurityDomainInfo { SequenceCounter = counter }
                    )
                    : Result.Failure<SecurityDomainInfo, SmartCardError>(
                        SmartCardError.InvalidData(validation.Error)
                    );
            });
    }

    private static Result ValidateLength(byte[] counter)
    {
        // GP Card Specification v2.3.1, section 11.3.2.1; Appendix E.5.1;
        // SCP03 Amendment D v1.2, section 7.1.1.6.
        return counter.Length is 2 or 3
            ? Result.Success()
            : Result.Failure("Sequence Counter must contain two or three bytes");
    }
}

/// <summary>
/// GP Card Specification v2.3.1, section 11.3.2.1: tag C1 is the Sequence Counter of the default Key Version Number.
/// </summary>
[PublicAPI]
public sealed record SecurityDomainInfo
{
    public byte[] SequenceCounter { get; init; } = [];

    public uint Value => SequenceCounter.Aggregate(0U, (value, octet) => value << 8 | octet);
}
