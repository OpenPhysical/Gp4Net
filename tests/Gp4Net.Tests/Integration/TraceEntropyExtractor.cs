using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Core;

namespace Gp4Net.Tests.Integration;

/// <summary>
/// Utility for extracting entropy from trace data to create deterministic cryptographic services.
/// Enables exact reproduction of cryptographic operations from captured traces.
/// </summary>
public static class TraceEntropyExtractor
{
    /// <summary>
    /// Extracts entropy data from trace exchanges to enable deterministic cryptographic operations.
    /// </summary>
    /// <param name="trace">The trace data containing exchanges with challenges and responses.</param>
    /// <returns>Combined entropy from all trace exchanges.</returns>
    public static Result<byte[], SmartCardError> ExtractEntropyFromTrace(TraceData trace)
    {
        if (trace?.Exchanges == null || !trace.Exchanges.Any())
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidData("Trace has no exchanges to extract entropy from"));
        }

        try
        {
            // Extract all challenges and responses from the trace
            var allEntropy = trace.Exchanges
                .Where(exchange => !string.IsNullOrEmpty(exchange.Command) && 
                                  !string.IsNullOrEmpty(exchange.Response))
                .SelectMany(exchange => new[]
                {
                    // Extract entropy from command data (if present)
                    ExtractEntropyFromHex(exchange.Command),
                    // Extract entropy from response data  
                    ExtractEntropyFromHex(exchange.Response)
                })
                .Where(entropy => entropy.Length > 0)
                .SelectMany(entropy => entropy)
                .ToArray();

            if (allEntropy.Length == 0)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidData("No entropy could be extracted from trace"));
            }

            return Result.Success<byte[], SmartCardError>(allEntropy);
        }
        catch (Exception ex)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.UnexpectedError($"Failed to extract entropy from trace: {ex.Message}", Maybe<Exception>.From(ex)));
        }
    }

    /// <summary>
    /// Creates a deterministic RNG service from trace entropy.
    /// </summary>
    /// <param name="trace">The trace data to extract entropy from.</param>
    /// <returns>A PreloadedRngService with trace entropy.</returns>
    public static Result<PreloadedRngService, SmartCardError> CreateDeterministicRngFromTrace(TraceData trace)
    {
        return ExtractEntropyFromTrace(trace)
            .Bind(entropy => PreloadedRngService.Create(entropy));
    }

    /// <summary>
    /// Creates a deterministic cryptographic service from trace entropy.
    /// </summary>
    /// <param name="trace">The trace data to extract entropy from.</param>
    /// <returns>A CryptographicService with deterministic entropy.</returns>
    public static Result<CryptographicService, SmartCardError> CreateDeterministicCryptoServiceFromTrace(TraceData trace)
    {
        return CreateDeterministicRngFromTrace(trace)
            .Map(rng => (CryptographicService)new CryptographicService(rng));
    }

    /// <summary>
    /// Extracts specific challenges from trace sessions for replay testing.
    /// </summary>
    /// <param name="trace">The trace data containing session information.</param>
    /// <returns>Collection of challenges from all sessions.</returns>
    public static Result<byte[][], SmartCardError> ExtractChallengesFromTrace(TraceData trace)
    {
        if (trace?.Sessions == null || !trace.Sessions.Any())
        {
            return Result.Failure<byte[][], SmartCardError>(
                SmartCardError.InvalidData("Trace has no session data to extract challenges from"));
        }

        try
        {
            var challenges = trace.Sessions.Values
                .Where(session => !string.IsNullOrEmpty(session.HostChallenge) && 
                                 !string.IsNullOrEmpty(session.CardChallenge))
                .SelectMany(session => new[]
                {
                    Convert.FromHexString(session.HostChallenge),
                    Convert.FromHexString(session.CardChallenge)
                })
                .ToArray();

            if (challenges.Length == 0)
            {
                return Result.Failure<byte[][], SmartCardError>(
                    SmartCardError.InvalidData("No challenges found in trace sessions"));
            }

            return Result.Success<byte[][], SmartCardError>(challenges);
        }
        catch (Exception ex)
        {
            return Result.Failure<byte[][], SmartCardError>(
                SmartCardError.UnexpectedError($"Failed to extract challenges from trace: {ex.Message}", Maybe<Exception>.From(ex)));
        }
    }

    /// <summary>
    /// Extracts host challenges from INITIALIZE UPDATE commands in trace exchanges.
    /// Per GP 2.3.1 Section 11.1.1: Host challenge is the 8-byte data field of INITIALIZE UPDATE.
    /// </summary>
    /// <param name="trace">The trace data containing INITIALIZE UPDATE exchanges.</param>
    /// <returns>Sequential host challenges extracted from trace.</returns>
    public static Result<byte[][], SmartCardError> ExtractHostChallengesFromTrace(TraceData trace)
    {
        if (trace?.Exchanges == null || !trace.Exchanges.Any())
        {
            return Result.Failure<byte[][], SmartCardError>(
                SmartCardError.InvalidData("Trace has no exchanges to extract host challenges from"));
        }

        try
        {
            var hostChallenges = trace.Exchanges
                .Where(exchange => IsInitializeUpdateCommand(exchange.Command))
                .Select(exchange => ExtractHostChallengeFromInitUpdate(exchange.Command))
                .Where(challenge => challenge.Length == 8) // GP spec: host challenge is always 8 bytes
                .ToArray();

            if (hostChallenges.Length == 0)
            {
                return Result.Failure<byte[][], SmartCardError>(
                    SmartCardError.InvalidData("No INITIALIZE UPDATE commands found in trace"));
            }

            return Result.Success<byte[][], SmartCardError>(hostChallenges);
        }
        catch (Exception ex)
        {
            return Result.Failure<byte[][], SmartCardError>(
                SmartCardError.UnexpectedError($"Failed to extract host challenges from trace: {ex.Message}", Maybe<Exception>.From(ex)));
        }
    }

    /// <summary>
    /// Extracts card challenges from INITIALIZE UPDATE responses in trace exchanges.
    /// Per GP 2.3.1 Section 11.1.1: Card challenge is bytes 12-19 of INITIALIZE UPDATE response.
    /// </summary>
    /// <param name="trace">The trace data containing INITIALIZE UPDATE response exchanges.</param>
    /// <returns>Sequential card challenges extracted from trace.</returns>
    public static Result<byte[][], SmartCardError> ExtractCardChallengesFromTrace(TraceData trace)
    {
        if (trace?.Exchanges == null || !trace.Exchanges.Any())
        {
            return Result.Failure<byte[][], SmartCardError>(
                SmartCardError.InvalidData("Trace has no exchanges to extract card challenges from"));
        }

        try
        {
            var cardChallenges = trace.Exchanges
                .Where(exchange => IsInitializeUpdateCommand(exchange.Command) && 
                                 IsSuccessfulResponse(exchange.Response))
                .Select(exchange => ExtractCardChallengeFromInitUpdateResponse(exchange.Response))
                .Where(challenge => challenge.Length == 8) // GP spec: card challenge is always 8 bytes
                .ToArray();

            if (cardChallenges.Length == 0)
            {
                return Result.Failure<byte[][], SmartCardError>(
                    SmartCardError.InvalidData("No successful INITIALIZE UPDATE responses found in trace"));
            }

            return Result.Success<byte[][], SmartCardError>(cardChallenges);
        }
        catch (Exception ex)
        {
            return Result.Failure<byte[][], SmartCardError>(
                SmartCardError.UnexpectedError($"Failed to extract card challenges from trace: {ex.Message}", Maybe<Exception>.From(ex)));
        }
    }

    /// <summary>
    /// Creates separate deterministic RNG services for host and card challenges from trace data.
    /// Enables proper entropy coordination where each side uses its own deterministic sequence.
    /// </summary>
    /// <param name="trace">The trace data to extract challenges from.</param>
    /// <returns>Tuple of (hostRng, cardRng) for independent entropy streams.</returns>
    public static Result<(PreloadedRngService hostRng, PreloadedRngService cardRng), SmartCardError> CreateSeparatedRngServicesFromTrace(TraceData trace)
    {
        return ExtractHostChallengesFromTrace(trace)
            .Bind(hostChallenges => ExtractCardChallengesFromTrace(trace)
                .Bind(cardChallenges => 
                {
                    return PreloadedRngService.FromTraceChallenges(hostChallenges)
                        .Bind(hostRng => PreloadedRngService.FromTraceChallenges(cardChallenges)
                            .Map(cardRng => (hostRng, cardRng)));
                }));
    }

    /// <summary>
    /// Creates a PreloadedRngService specifically from trace challenges.
    /// </summary>
    /// <param name="trace">The trace data containing challenge information.</param>
    /// <returns>A PreloadedRngService initialized with challenge entropy.</returns>
    public static Result<PreloadedRngService, SmartCardError> CreateRngFromTraceChallenges(TraceData trace)
    {
        return ExtractChallengesFromTrace(trace)
            .Bind(challenges => PreloadedRngService.FromTraceChallenges(challenges));
    }

    /// <summary>
    /// Checks if a command hex string is an INITIALIZE UPDATE command.
    /// Per GP 2.3.1 Section 11.1.1: INITIALIZE UPDATE has CLA=80 and INS=50.
    /// </summary>
    /// <param name="commandHex">Command APDU as hex string.</param>
    /// <returns>True if this is an INITIALIZE UPDATE command.</returns>
    private static bool IsInitializeUpdateCommand(string commandHex)
    {
        if (string.IsNullOrEmpty(commandHex) || commandHex.Length < 4)
        {
            return false;
        }

        try
        {
            var bytes = Convert.FromHexString(commandHex);
            return bytes.Length >= 2 && bytes[0] == 0x80 && bytes[1] == 0x50;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Checks if a response hex string indicates success (SW = 9000).
    /// </summary>
    /// <param name="responseHex">Response APDU as hex string.</param>
    /// <returns>True if response status word is 9000.</returns>
    private static bool IsSuccessfulResponse(string responseHex)
    {
        if (string.IsNullOrEmpty(responseHex) || responseHex.Length < 4)
        {
            return false;
        }

        try
        {
            var bytes = Convert.FromHexString(responseHex);
            return bytes.Length >= 2 && 
                   bytes[bytes.Length - 2] == 0x90 && 
                   bytes[bytes.Length - 1] == 0x00;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Extracts host challenge from INITIALIZE UPDATE command data field.
    /// Per GP 2.3.1 Section 11.1.1: Host challenge is the 8-byte data field.
    /// Format: CLA INS P1 P2 LC [8-byte host challenge] [Le]
    /// </summary>
    /// <param name="commandHex">INITIALIZE UPDATE command as hex string.</param>
    /// <returns>8-byte host challenge or empty array if not found.</returns>
    private static byte[] ExtractHostChallengeFromInitUpdate(string commandHex)
    {
        if (string.IsNullOrEmpty(commandHex))
        {
            return Array.Empty<byte>();
        }

        try
        {
            var bytes = Convert.FromHexString(commandHex);
            
            // Validate INITIALIZE UPDATE structure: CLA INS P1 P2 LC [8 bytes] [Le]
            if (bytes.Length < 13 || bytes[0] != 0x80 || bytes[1] != 0x50)
            {
                return Array.Empty<byte>();
            }

            var lc = bytes[4];
            if (lc != 8 || bytes.Length < 5 + lc)
            {
                return Array.Empty<byte>();
            }

            // Extract 8-byte host challenge from data field
            return bytes.Skip(5).Take(8).ToArray();
        }
        catch
        {
            return Array.Empty<byte>();
        }
    }

    /// <summary>
    /// Extracts card challenge from INITIALIZE UPDATE response data.
    /// Per GP 2.3.1 Section 11.1.1: Card challenge is bytes 12-19 of response data.
    /// SCP02 format: [10 bytes diversification] [1 byte key version] [1 byte SCP ID] [1 byte impl] [8 bytes card challenge] [8 bytes cryptogram] [2 bytes seq] SW
    /// SCP03 format: [10 bytes diversification] [1 byte key version] [1 byte SCP ID] [1 byte impl] [8 bytes card challenge] [8 bytes cryptogram] [3 bytes seq] SW
    /// </summary>
    /// <param name="responseHex">INITIALIZE UPDATE response as hex string.</param>
    /// <returns>8-byte card challenge or empty array if not found.</returns>
    private static byte[] ExtractCardChallengeFromInitUpdateResponse(string responseHex)
    {
        if (string.IsNullOrEmpty(responseHex))
        {
            return Array.Empty<byte>();
        }

        try
        {
            var bytes = Convert.FromHexString(responseHex);
            
            // Remove status word (last 2 bytes) to get response data
            if (bytes.Length < 4) // At minimum need data + SW
            {
                return Array.Empty<byte>();
            }
            
            var responseData = bytes.Take(bytes.Length - 2).ToArray();
            
            // Per GP 2.3.1: Card challenge starts at byte 12 (0-indexed) and is 8 bytes
            if (responseData.Length < 20) // Need at least 12 + 8 bytes for challenge
            {
                return Array.Empty<byte>();
            }

            // Extract 8-byte card challenge from bytes 12-19
            return responseData.Skip(12).Take(8).ToArray();
        }
        catch
        {
            return Array.Empty<byte>();
        }
    }

    /// <summary>
    /// Extracts entropy bytes from a hex string, filtering out structural elements.
    /// </summary>
    /// <param name="hexString">Hex string to extract entropy from.</param>
    /// <returns>Entropy bytes extracted from the hex string.</returns>
    private static byte[] ExtractEntropyFromHex(string hexString)
    {
        if (string.IsNullOrEmpty(hexString) || hexString.Length < 4)
        {
            return Array.Empty<byte>();
        }

        try
        {
            var allBytes = Convert.FromHexString(hexString);
            
            // For APDU commands, skip the header (CLA INS P1 P2) and extract data
            if (allBytes.Length > 4)
            {
                // Skip APDU header and length bytes, extract actual data
                var dataStart = 4;
                if (allBytes.Length > 5)
                {
                    var lc = allBytes[4];
                    if (lc > 0 && allBytes.Length >= 5 + lc)
                    {
                        dataStart = 5;
                        return allBytes.Skip(dataStart).Take(lc).ToArray();
                    }
                }
                
                // If no data field, use what we can from the command
                return allBytes.Skip(dataStart).ToArray();
            }

            return allBytes;
        }
        catch
        {
            return Array.Empty<byte>();
        }
    }
}