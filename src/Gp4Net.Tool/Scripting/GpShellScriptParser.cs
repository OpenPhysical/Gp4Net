using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Scripting;

/// <summary>
/// Parser for GPShell script files.
/// Converts GPShell commands to Gp4Net Lua equivalents.
/// </summary>
[PublicAPI]
public class GpShellScriptParser
{
    private static readonly Dictionary<string, string> CommandMap =
        new()
        {
            ["print"] = "print",
            ["enable_trace"] = "gp.enable_trace()",
            ["disable_trace"] = "gp.disable_trace()",
            ["mode_201"] = "gp.set_mode('201')",
            ["mode_211"] = "gp.set_mode('211')",
            ["establish_context"] = "gp.establish_context()",
            ["release_context"] = "gp.release_context()",
            ["card_connect"] = "gp.connect()",
            ["card_disconnect"] = "gp.disconnect()",
            ["select"] = "gp.select",
            ["open_sc"] = "gp.open_secure_channel",
            ["send_apdu"] = "gp.send_apdu",
            ["put_sc_key"] = "gp.put_key",
            ["get_status"] = "gp.get_status",
            ["install"] = "gp.install",
            ["load"] = "gp.load",
            ["delete"] = "gp.delete",
        };

    /// <summary>
    /// Parses a GPShell script file and returns Lua script content.
    /// </summary>
    /// <param name="filePath">Path to the GPShell script file.</param>
    /// <returns>Lua script content.</returns>
    public static string ParseFile(string filePath)
    {
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"GPShell script file not found: {filePath}");
        }

        var lines = File.ReadAllLines(filePath);
        return ParseLines(lines);
    }

    /// <summary>
    /// Parses GPShell script lines and returns Lua script content.
    /// </summary>
    /// <param name="lines">GPShell script lines.</param>
    /// <returns>Lua script content.</returns>
    public static string ParseLines(string[] lines)
    {
        var luaLines = new List<string>
        {
            // Add header comment
            "-- Auto-generated from GPShell script",
            "-- Note: This is a best-effort conversion. Some commands may need manual adjustment.",
            ""
        };

        foreach (var line in lines)
        {
            var trimmedLine = line.Trim();

            // Skip empty lines and comments
            if (string.IsNullOrWhiteSpace(trimmedLine) || trimmedLine.StartsWith("#"))
            {
                if (trimmedLine.StartsWith("#"))
                {
                    luaLines.Add("--" + trimmedLine.Substring(1));
                }
                else
                {
                    luaLines.Add("");
                }
                continue;
            }

            // Parse the command
            var convertedLine = ParseCommand(trimmedLine);
            luaLines.Add(convertedLine);
        }

        return string.Join(Environment.NewLine, luaLines);
    }

    /// <summary>
    /// Parses a single GPShell command and returns the Lua equivalent.
    /// </summary>
    private static string ParseCommand(string command)
    {
        // Split command and arguments
        var parts = SplitCommand(command);
        if (parts.Count == 0)
        {
            return $"-- Unknown command: {command}";
        }

        var cmd = parts[0].ToLowerInvariant();

        // Handle print specially
        if (cmd == "print")
        {
            var message = command.Substring(5).Trim();
            return $"print(\"{EscapeString(message)}\")";
        }

        // Check if we have a mapping
        if (!CommandMap.TryGetValue(cmd, out var luaCmd))
        {
            return $"-- TODO: Unsupported command: {command}";
        }

        // Handle commands without parameters
        if (luaCmd.EndsWith("()"))
        {
            return luaCmd;
        }

        // Parse command-specific parameters
        var parameters = ParseParameters([.. parts.Skip(1)]);

        switch (cmd)
        {
            case "select":
                return ConvertSelect(parameters);
            case "open_sc":
                return ConvertOpenSecureChannel(parameters);
            case "send_apdu":
                return ConvertSendApdu(parameters);
            case "put_sc_key":
                return ConvertPutKey(parameters);
            default:
                return $"{luaCmd}({FormatParameters(parameters)})";
        }
    }

    /// <summary>
    /// Splits a command line into parts, respecting quotes.
    /// </summary>
    private static List<string> SplitCommand(string command)
    {
        var parts = new List<string>();
        var regex = new Regex(@"[\""].+?[\""]|[^ ]+");
        var matches = regex.Matches(command);

        foreach (Match match in matches)
        {
            var value = match.Value;
            // Remove quotes if present
            if (value.StartsWith("\"") && value.EndsWith("\""))
            {
                value = value.Substring(1, value.Length - 2);
            }
            parts.Add(value);
        }

        return parts;
    }

    /// <summary>
    /// Parses command parameters into a dictionary.
    /// </summary>
    private static Dictionary<string, string> ParseParameters(List<string> args)
    {
        var parameters = new Dictionary<string, string>();

        for (var i = 0; i < args.Count; i++)
        {
            var arg = args[i];

            if (arg.StartsWith("-"))
            {
                var key = arg.TrimStart('-');
                var value =
                    i + 1 < args.Count && !args[i + 1].StartsWith("-") ? args[++i] : "true";
                parameters[key] = value;
            }
            else
            {
                // Positional argument
                parameters[$"arg{parameters.Count}"] = arg;
            }
        }

        return parameters;
    }

    /// <summary>
    /// Converts a SELECT command.
    /// </summary>
    private static string ConvertSelect(Dictionary<string, string> parameters)
    {
        if (parameters.TryGetValue("AID", out var aid))
        {
            return $"gp.select(\"{aid}\")";
        }
        return "gp.select()  -- ISD";
    }

    /// <summary>
    /// Converts an OPEN_SC command.
    /// </summary>
    private static string ConvertOpenSecureChannel(Dictionary<string, string> parameters)
    {
        var args = new List<string>();

        if (parameters.TryGetValue("security", out var security))
        {
            args.Add($"security_level = {security}");
        }

        if (parameters.TryGetValue("keyind", out var keyind))
        {
            args.Add($"key_id = {keyind}");
        }

        if (parameters.TryGetValue("keyver", out var keyver))
        {
            args.Add($"key_version = {keyver}");
        }

        if (parameters.TryGetValue("mac_key", out var macKey))
        {
            args.Add($"mac_key = \"{macKey}\"");
        }

        if (parameters.TryGetValue("enc_key", out var encKey))
        {
            args.Add($"enc_key = \"{encKey}\"");
        }

        if (
            parameters.TryGetValue("kek_key", out var kekKey)
            || parameters.TryGetValue("dek_key", out kekKey)
        )
        {
            args.Add($"dek_key = \"{kekKey}\"");
        }

        if (parameters.TryGetValue("scp", out var scp))
        {
            args.Add($"scp = {scp}");
        }

        if (parameters.TryGetValue("scpimpl", out var scpimpl))
        {
            args.Add($"scp_impl = 0x{scpimpl}");
        }

        return $"gp.open_secure_channel({{ {string.Join(", ", args)} }})";
    }

    /// <summary>
    /// Converts a SEND_APDU command.
    /// </summary>
    private static string ConvertSendApdu(Dictionary<string, string> parameters)
    {
        var args = new List<string>();

        if (parameters.TryGetValue("APDU", out var apdu))
        {
            args.Add($"\"{apdu}\"");
        }

        if (parameters.TryGetValue("sc", out var sc))
        {
            args.Add($"secure = {(sc == "1" ? "true" : "false")}");
        }

        return $"gp.send_apdu({string.Join(", ", args)})";
    }

    /// <summary>
    /// Converts a PUT_SC_KEY command.
    /// </summary>
    private static string ConvertPutKey(Dictionary<string, string> parameters)
    {
        var args = new List<string>();

        if (parameters.TryGetValue("keyver", out var keyver))
        {
            args.Add($"current_version = {keyver}");
        }

        if (parameters.TryGetValue("newkeyver", out var newkeyver))
        {
            args.Add($"new_version = {newkeyver}");
        }

        if (parameters.TryGetValue("mac_key", out var macKey))
        {
            args.Add($"mac_key = \"{macKey}\"");
        }

        if (parameters.TryGetValue("enc_key", out var encKey))
        {
            args.Add($"enc_key = \"{encKey}\"");
        }

        if (
            parameters.TryGetValue("kek_key", out var kekKey)
            || parameters.TryGetValue("dek_key", out kekKey)
        )
        {
            args.Add($"dek_key = \"{kekKey}\"");
        }

        return $"gp.put_key({{ {string.Join(", ", args)} }})";
    }

    /// <summary>
    /// Formats parameters for generic commands.
    /// </summary>
    private static string FormatParameters(Dictionary<string, string> parameters)
    {
        if (parameters.Count == 0)
        {
            return "";
        }

        var args = new List<string>();

        // Check for positional arguments first
        var i = 0;
        while (parameters.TryGetValue($"arg{i}", out var arg))
        {
            args.Add($"\"{arg}\"");
            i++;
        }

        // Then add named parameters
        foreach (var kvp in parameters.Where(p => !p.Key.StartsWith("arg")))
        {
            var value =
                kvp.Value == "true" || kvp.Value == "false" ? kvp.Value : $"\"{kvp.Value}\"";
            args.Add($"{kvp.Key} = {value}");
        }

        return string.Join(", ", args);
    }

    /// <summary>
    /// Escapes a string for Lua.
    /// </summary>
    private static string EscapeString(string str)
    {
        return str.Replace("\\", "\\\\")
            .Replace("\"", "\\\"")
            .Replace("\n", "\\n")
            .Replace("\r", "\\r")
            .Replace("\t", "\\t");
    }
}