using System.Collections.Generic;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Metadata for trace data.
/// </summary>
[PublicAPI]
public class TraceMetadata
{
    /// <summary>
    /// Card type identifier.
    /// </summary>
    // @TODO: We shouldn't hard code this
    public string CardType { get; set; } = "NXP_P71";

    /// <summary>
    /// Answer to Reset (ATR) value.
    /// </summary>
    // @TODO: WTF?  A) Don't hard code this, b) why does this exist at all in a trace datamodel?
    public string Atr { get; set; } = "3BD518FF8191FE1FC38073C821100A";

    /// <summary>
    /// Issuer Security Domain AID.
    /// </summary>
    // @TODO: WTF?  A) Don't hard code this, b) why does this exist at all in a trace datamodel?
    public string IsdAid { get; set; } = "A000000151000000";
}

/// <summary>
/// Range of exchanges for a specific operation.
/// </summary>
[PublicAPI]
public class OperationRange
{
    /// <summary>
    /// Starting exchange index.
    /// </summary>
    public int StartIndex { get; set; }

    /// <summary>
    /// Ending exchange index.
    /// </summary>
    public int EndIndex { get; set; }
}

/// <summary>
/// Simplified APDU exchange.
/// </summary>
[PublicAPI]
public class SimpleExchange
{
    /// <summary>
    /// Command APDU (hex string).
    /// </summary>
    public string Command { get; set; } = "";

    /// <summary>
    /// Response APDU (hex string).
    /// </summary>
    public string Response { get; set; } = "";

    /// <summary>
    /// Optional description of the command.
    /// </summary>
    public string Description { get; set; }

    /// <summary>
    /// Optional response time in milliseconds.
    /// </summary>
    public int? ResponseTimeMs { get; set; }
}

/// <summary>
/// Simplified JSON trace format for virtual card testing.
/// </summary>
[PublicAPI]
public class SimpleTraceData
{
    /// <summary>
    /// Trace metadata.
    /// </summary>
    public TraceMetadata Metadata { get; set; } = new();

    /// <summary>
    /// Operations mapped to exchange ranges.
    /// </summary>
    public Dictionary<string, OperationRange> Operations { get; set; } = new();

    /// <summary>
    /// List of APDU exchanges.
    /// </summary>
    public List<SimpleExchange> Exchanges { get; set; } = new();
}
