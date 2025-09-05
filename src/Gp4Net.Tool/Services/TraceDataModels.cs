using System.Collections.Generic;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Metadata for trace data.
/// All values are extracted from actual card traces, not hardcoded.
/// </summary>
[PublicAPI]
public class TraceMetadata
{
    /// <summary>
    /// Card type identifier extracted from trace data.
    /// </summary>
    public string CardType { get; set; } = "";

    /// <summary>
    /// Answer to Reset (ATR) value extracted from card session.
    /// </summary>
    public string Atr { get; set; } = "";

    /// <summary>
    /// Issuer Security Domain AID discovered during trace analysis.
    /// </summary>
    public string IsdAid { get; set; } = "";
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
