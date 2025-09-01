using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Services;
using static Gp4Net.Services.TlvService;
using Gp4Net.Domain.Protocol;

namespace Gp4Net.Domain.CardInfo;

/// <summary>
/// Parses SCP (Secure Channel Protocol) capabilities from card capability data.
/// This parser delegates to UnifiedTlvParser for TLV operations.
/// </summary>
[Obsolete("Use UnifiedTlvParser with domain-specific SCP parsing logic for new code. This class will be removed in a future version.")]
public static class ScpCapabilitiesParser
{
    /// <summary>
    /// Parses SCP capabilities from TLV-encoded card capability data.
    /// </summary>
    /// <param name="data">The raw capability data.</param>
    /// <returns>Comma-separated list of supported SCP protocols.</returns>
    public static string Parse(byte[] data)
    {
        ScpInformation info = ParseDetailed(data);
        return info.ToFormattedString(multiLine: false);
    }

    /// <summary>
    /// Parses SCP capabilities and returns detailed information.
    /// </summary>
    /// <param name="data">The raw capability data.</param>
    /// <returns>Structured SCP information.</returns>
    public static ScpInformation ParseDetailed(byte[] data)
    {
        if (data == null || data.Length == 0)
        {
            return new ScpInformation(new List<ScpProtocolInfo>());
        }

        Dictionary<byte, List<ScpImplementation>> protocols =
            new Dictionary<byte, List<ScpImplementation>>();

        try
        {
            // Use TlvParser which internally delegates to UnifiedTlvParser
            var parseResult = TlvParser.ParseMultiple(data.ToImmutableArray());
            if (parseResult.IsSuccess)
            {
                ParseElements(parseResult.Value.Objects, protocols);
            }
        }
        catch
        {
            // If TLV parsing fails, return empty information
            return new ScpInformation(new List<ScpProtocolInfo>());
        }

        // Convert to structured information
        List<ScpProtocolInfo> protocolList = [.. protocols
            .Select(kvp => new ScpProtocolInfo(kvp.Key, kvp.Value.Distinct().ToList()))
            .OrderBy(p => p.Version)];

        return new ScpInformation(protocolList);
    }

    /// <summary>
    /// Recursively parses TLV elements to extract SCP information.
    /// </summary>
    private static void ParseElements(
        ImmutableArray<TlvObject> elements,
        Dictionary<byte, List<ScpImplementation>> protocols
    )
    {
        var processedElements = elements
            .Select(element => element.Tag.ToNumber().Match(
                tagValue => ProcessElement(element, tagValue, protocols),
                error => UnitResult.Failure<SmartCardError>(error)
            ))
            .ToArray();
        
        // Force evaluation of the sequence to ensure side effects occur
        var _ = processedElements.Length;
    }

    /// <summary>
    /// Processes a single TLV element for SCP information.
    /// </summary>
    private static UnitResult<SmartCardError> ProcessElement(TlvObject element, uint tagValue, Dictionary<byte, List<ScpImplementation>> protocols)
    {
        switch (tagValue)
        {
            case 0xA0: // Constructed tag containing SCP information
                // Per GP Card Spec, A0 tag in capabilities contains nested TLV
                if (element.TlvData.Bytes.Length > 0)
                {
                    var innerParseResult = TlvParser.ParseMultiple(element.TlvData.Bytes);
                    if (innerParseResult.IsSuccess)
                    {
                        ParseA0Contents(innerParseResult.Value.Objects, protocols);
                    }
                }
                break;

            // Tags 80-87 outside A0 context are not SCP related per GP Card Spec Table H-5
            case 0x80: // Outside A0 context - not SCP related
            case 0x81: // Outside A0 context - privileges
            case 0x82: // Outside A0 context - privileges
            case 0x83: // Outside A0 context - privileges
            case 0x84: // Outside A0 context - privileges
            case 0x85: // Outside A0 context - privileges
            case 0x86: // Outside A0 context - privileges
            case 0x87: // Outside A0 context - privileges
                // These tags outside A0 are privilege/capability indicators, not SCP
                break;
        }
        
        return UnitResult.Success<SmartCardError>();
    }

    /// <summary>
    /// Parses A0 tag contents to extract SCP information per GP Card Spec Table H-5.
    /// </summary>
    private static void ParseA0Contents(
        ImmutableArray<TlvObject> elements,
        Dictionary<byte, List<ScpImplementation>> protocols
    )
    {
        var initialState = new A0ParsingState(Maybe<byte>.None, protocols);
        
        var finalState = elements
            .Select(element => element.Tag.ToNumber().Match(
                tagValue => new { Element = element, TagValue = Maybe<uint>.From(tagValue) },
                error => new { Element = element, TagValue = Maybe<uint>.None }
            ))
            .Where(x => x.TagValue.HasValue)
            .Aggregate(initialState, (state, x) => 
                x.TagValue.Match(
                    tagValue => ProcessA0Element(x.Element, tagValue, state),
                    () => state
                ));
    }

    /// <summary>
    /// State object for A0 parsing to maintain immutability.
    /// </summary>
    private record A0ParsingState(Maybe<byte> CurrentScpType, Dictionary<byte, List<ScpImplementation>> Protocols);

    /// <summary>
    /// Processes a single A0 element and returns updated state.
    /// </summary>
    private static A0ParsingState ProcessA0Element(TlvObject element, uint tagValue, A0ParsingState state)
    {
        return tagValue switch
        {
            0x80 => ProcessScpTypeTag(element, state),
            0x81 => ProcessScpOptionsTag(element, state),
            0x82 or 0x83 or 0x84 => state, // Additional SCP-specific options, handled in future versions
            _ => state
        };
    }

    /// <summary>
    /// Processes SCP type tag (0x80).
    /// </summary>
    private static A0ParsingState ProcessScpTypeTag(TlvObject element, A0ParsingState state)
    {
        if (element.TlvData.Bytes.Length == 0)
            return state;

        byte scpVersion = element.TlvData.Bytes[0];
        
        // Valid SCP versions per GP specification
        if (scpVersion is not (0x02 or 0x03 or 0x10 or 0x11 or 0x80 or 0x81))
            return state;

        if (!state.Protocols.ContainsKey(scpVersion))
        {
            state.Protocols[scpVersion] = [];
        }

        return state with { CurrentScpType = Maybe<byte>.From(scpVersion) };
    }

    /// <summary>
    /// Processes SCP options tag (0x81).
    /// </summary>
    private static A0ParsingState ProcessScpOptionsTag(TlvObject element, A0ParsingState state)
    {
        return state.CurrentScpType.Match(
            scpType => ProcessOptionsWithScpType(element, scpType, state),
            () => state
        );
    }

    /// <summary>
    /// Processes options when SCP type is available.
    /// </summary>
    private static A0ParsingState ProcessOptionsWithScpType(TlvObject element, byte scpType, A0ParsingState state)
    {
        var optionBytes = element.TlvData.Bytes.ToArray();
        
        if (optionBytes.Length == 0)
            return state;

        var validImplementations = optionBytes
            .Where(optionByte => Enum.IsDefined(typeof(ScpImplementation), optionByte))
            .Select(optionByte => (ScpImplementation)optionByte)
            .Where(impl => IsValidImplementationForScpType(impl, scpType))
            .ToList();

        // Create new protocols dictionary with added implementations
        var updatedProtocols = new Dictionary<byte, List<ScpImplementation>>(state.Protocols);
        var existingImplementations = updatedProtocols[scpType];
        updatedProtocols[scpType] = existingImplementations.Concat(validImplementations).Distinct().ToList();

        return state with { Protocols = updatedProtocols };
    }

    /// <summary>
    /// Determines if an implementation is valid for the given SCP type.
    /// </summary>
    private static bool IsValidImplementationForScpType(ScpImplementation impl, byte scpType)
    {
        return scpType switch
        {
            0x02 => impl.IsScp02(),
            0x03 => impl.IsScp03(),
            0x10 => true, // SCP10 implementation options
            _ => false
        };
    }
}
