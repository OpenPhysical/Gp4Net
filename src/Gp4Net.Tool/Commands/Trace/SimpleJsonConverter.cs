using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Gp4Net.Tool.Services;

namespace Gp4Net.Tool.Commands.Trace;


/// <summary>
/// Simplified trace converter that produces minimal JSON.
/// </summary>
public class SimpleJsonConverter
{
    private static readonly Dictionary<string, string> CommandNames = new()
    {
        { "00A4", "SELECT" },
        { "80CA", "GET DATA" },
        { "80F2", "GET STATUS" },
        { "8050", "INITIALIZE UPDATE" },
        { "8482", "EXTERNAL AUTHENTICATE" },
        { "84E6", "INSTALL" },
        { "84E8", "LOAD" },
        { "84E4", "DELETE" }
    };

    public async Task<string> ConvertToSimpleJson(string inputFile, bool includeDescriptions = true)
    {
        List<(string Command, string Response, int ResponseTime)> exchanges = await ParseGpProTrace(inputFile);
        Dictionary<string, OperationRange> operations = DetectOperations(exchanges);

        SimpleTraceData traceData = new SimpleTraceData
        {
            Operations = operations,
            Exchanges = exchanges.Select((ex, idx) => new SimpleExchange
            {
                Command = ex.Command,
                Response = ex.Response,
                Description = includeDescriptions ? GetDescription(ex.Command) : null,
                ResponseTimeMs = ex.ResponseTime > 20 ? ex.ResponseTime : null // Only include if > 20ms
            }).ToList()
        };

        // Extract card info from exchanges
        ExtractCardInfo(traceData, exchanges);

        JsonSerializerOptions options = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };

        return JsonSerializer.Serialize(traceData, options);
    }

    private static async Task<List<(string Command, string Response, int ResponseTime)>> ParseGpProTrace(string filename)
    {
        List<(string Command, string Response, int ResponseTime)> exchanges = [];
        Regex commandPattern = new Regex(@"^A>> T=\d+ \([\d+]+\) ([0-9A-F\s]+)$");
        Regex responsePattern = new Regex(@"^A<< \([\d+]+\) \((\d+)ms\) ([0-9A-F\s]+)$");

        string currentCommand = null;
        string[] lines = await File.ReadAllLinesAsync(filename);

        foreach (string line in lines)
        {
            string trimmed = line.Trim();

            Match cmdMatch = commandPattern.Match(trimmed);
            if (cmdMatch.Success)
            {
                currentCommand = cmdMatch.Groups[1].Value.Replace(" ", "").ToUpper();
                continue;
            }

            Match respMatch = responsePattern.Match(trimmed);
            if (respMatch.Success && currentCommand != null)
            {
                int responseTime = int.Parse(respMatch.Groups[1].Value);
                string response = respMatch.Groups[2].Value.Replace(" ", "").ToUpper();
                exchanges.Add((currentCommand, response, responseTime));
                currentCommand = null;
            }
        }

        return exchanges;
    }

    private Dictionary<string, OperationRange> DetectOperations(List<(string Command, string Response, int ResponseTime)> exchanges)
    {
        Dictionary<string, OperationRange> operations = new Dictionary<string, OperationRange>();
        string currentOp = "";
        int opStart = 0;

        for (int i = 0; i < exchanges.Count; i++)
        {
            string desc = GetDescription(exchanges[i].Command);
            string newOp = DetectOperationType(desc);

            if (newOp != currentOp)
            {
                if (!string.IsNullOrEmpty(currentOp))
                {
                    operations[currentOp] = new OperationRange { StartIndex = opStart + 1, EndIndex = i };
                }
                currentOp = newOp;
                opStart = i;
            }
        }

        if (!string.IsNullOrEmpty(currentOp))
        {
            operations[currentOp] = new OperationRange { StartIndex = opStart + 1, EndIndex = exchanges.Count };
        }

        return operations;
    }

    private static string DetectOperationType(string description)
    {
        if (description.Contains("SELECT") || description.Contains("GET") && !description.Contains("STATUS"))
        {
            return "info";
        }

        if (description.Contains("INITIALIZE") || description.Contains("AUTHENTICATE"))
        {
            return "auth";
        }

        if (description.Contains("STATUS"))
        {
            return "list";
        }

        if (description.Contains("INSTALL") || description.Contains("LOAD"))
        {
            return "install";
        }

        if (description.Contains("DELETE"))
        {
            return "delete";
        }

        return "other";
    }

    private static string GetDescription(string command)
    {
        if (command.Length < 4)
        {
            return "";
        }

        string prefix = command.Substring(0, 4);
        if (CommandNames.TryGetValue(prefix, out string name))
        {
            // Special case for GET DATA
            if (prefix == "80CA" && command.Length >= 8)
            {
                string tag = command.Substring(4, 4);
                return tag switch
                {
                    "9F7F" => "GET CPLC",
                    "0066" => "GET CARD DATA",
                    "0067" => "GET CARD CAPS",
                    "00E0" => "GET KEY INFO",
                    _ => $"GET DATA {tag}"
                };
            }
            return name;
        }
        return "";
    }

    private static void ExtractCardInfo(SimpleTraceData data, List<(string Command, string Response, int ResponseTime)> exchanges)
    {
        foreach ((string Command, string Response, int ResponseTime) ex in exchanges)
        {
            // Extract ISD AID from SELECT response
            if (ex.Command.StartsWith("00A4") && ex.Response.Contains("A000000151"))
            {
                data.Metadata.IsdAid = "A000000151000000";
            }

            // Extract card type from CPLC
            if (ex.Command.StartsWith("80CA9F7F") && ex.Response.StartsWith("9F7F"))
            {
                if (ex.Response.Contains("4790"))
                {
                    data.Metadata.CardType = "NXP_P71";
                }
            }
        }
    }
}