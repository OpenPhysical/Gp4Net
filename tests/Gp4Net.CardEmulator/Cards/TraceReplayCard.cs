using System;
using System.Collections.Generic;
using System.Linq;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Trace;
using ApduResponse = Gp4Net.CardEmulator.Core.ApduResponse;

namespace Gp4Net.CardEmulator.Cards
{
    /// <summary>
    /// Virtual card that replays responses from an APDU trace.
    /// </summary>
    public class TraceReplayCard : IVirtualCard
    {
        private readonly ApduTrace _trace;
        private readonly Dictionary<string, ApduResponse> _exactMatches;
        private readonly Dictionary<string, List<ApduResponse>> _patternMatches;
        private readonly List<ApduExchange> _executedExchanges;
        private readonly bool _strictMode;
        private int _exchangeIndex;

        /// <summary>
        /// Gets whether the card is selected.
        /// </summary>
        public bool IsSelected { get; private set; }

        /// <summary>
        /// Gets whether a secure channel is established.
        /// </summary>
        public bool IsSecureChannelEstablished { get; private set; }

        /// <summary>
        /// Gets the executed exchanges for verification.
        /// </summary>
        public IReadOnlyList<ApduExchange> ExecutedExchanges => _executedExchanges.AsReadOnly();

        /// <summary>
        /// Initializes a new instance of the TraceReplayCard class.
        /// </summary>
        /// <param name="trace">The APDU trace to replay.</param>
        /// <param name="strictMode">If true, requires exact command matches. If false, allows pattern matching.</param>
        public TraceReplayCard(ApduTrace trace, bool strictMode = false)
        {
            _trace = trace ?? throw new ArgumentNullException(nameof(trace));
            _exactMatches = new Dictionary<string, ApduResponse>(StringComparer.OrdinalIgnoreCase);
            _patternMatches = new Dictionary<string, List<ApduResponse>>(
                StringComparer.OrdinalIgnoreCase
            );
            _executedExchanges = new List<ApduExchange>();
            _strictMode = strictMode;
            _exchangeIndex = 0;

            BuildResponseMappings();
        }

        /// <inheritdoc />
        public byte[] GetAtr()
        {
            // Return ATR from trace if available, otherwise default JavaCard ATR
            return _trace.Atr ?? Convert.FromHexString("3B7D94000080318065B08311AC83009000");
        }

        /// <inheritdoc />
        public ApduResponse ProcessCommand(byte[] command)
        {
            if (command == null || command.Length < 4)
            {
                var errorResponse = ApduResponse.Error(0x6700); // Wrong length
                RecordExchange(command ?? Array.Empty<byte>(), errorResponse);
                return errorResponse;
            }

            ApduResponse? response = null;

            // Try sequential replay first (if enabled)
            if (!_strictMode && _exchangeIndex < _trace.Exchanges.Count)
            {
                var expectedExchange = _trace.Exchanges[_exchangeIndex];
                if (CommandsMatch(command, expectedExchange.Command, allowDynamicData: true))
                {
                    response = expectedExchange.Response;
                    _exchangeIndex++;
                }
            }

            // Try exact match
            if (response == null)
            {
                var exactKey = GetExactKey(command);
                if (_exactMatches.TryGetValue(exactKey, out var exactResponse))
                {
                    response = exactResponse;
                }
            }

            // Try pattern match if not in strict mode
            if (response == null && !_strictMode)
            {
                response = FindPatternMatch(command);
            }

            // Return error if no match found
            if (response == null)
            {
                response = ApduResponse.Error(0x6D00); // INS not supported
            }

            // Update card state
            UpdateCardState(command, response);

            // Record the exchange
            RecordExchange(command, response);

            return response;
        }

        /// <inheritdoc />
        public void Reset()
        {
            IsSelected = false;
            IsSecureChannelEstablished = false;
            _executedExchanges.Clear();
            _exchangeIndex = 0;
        }

        private void BuildResponseMappings()
        {
            foreach (var exchange in _trace.Exchanges)
            {
                if (exchange.Response == null || exchange.Command.Length < 4)
                    continue;

                // Store exact match
                var exactKey = GetExactKey(exchange.Command);
                _exactMatches[exactKey] = exchange.Response;

                // Store pattern match (CLA+INS+P1+P2)
                var patternKey = GetPatternKey(exchange.Command);
                if (!_patternMatches.ContainsKey(patternKey))
                {
                    _patternMatches[patternKey] = new List<ApduResponse>();
                }
                _patternMatches[patternKey].Add(exchange.Response);
            }
        }

        private string GetExactKey(byte[] command)
        {
            return BitConverter.ToString(command);
        }

        private string GetPatternKey(byte[] command)
        {
            if (command.Length < 4)
                return string.Empty;

            return $"{command[0]:X2}-{command[1]:X2}-{command[2]:X2}-{command[3]:X2}";
        }

        private ApduResponse? FindPatternMatch(byte[] command)
        {
            if (command.Length < 4)
                return null;

            var ins = command[1];

            // Special handling for commands with dynamic data
            switch (ins)
            {
                case 0x50: // INITIALIZE UPDATE - has random host challenge
                    return FindInitializeUpdateResponse(command);

                case 0x82: // EXTERNAL AUTHENTICATE - has cryptogram
                    return FindExternalAuthResponse(command);

                case 0xE6: // INSTALL - may have variable data
                    return FindInstallResponse(command);

                default:
                    // Try pattern key match
                    var patternKey = GetPatternKey(command);
                    if (
                        _patternMatches.TryGetValue(patternKey, out var responses)
                        && responses.Count > 0
                    )
                    {
                        // Return first matching response
                        // Could be enhanced to cycle through responses for repeated commands
                        return responses[0];
                    }
                    break;
            }

            return null;
        }

        private ApduResponse? FindInitializeUpdateResponse(byte[] command)
        {
            // INITIALIZE UPDATE: CLA=80/84 INS=50 P1=key_version P2=key_id Lc=08 Data=host_challenge Le=00
            var exchanges = _trace.FindExchanges(ins: 0x50).ToList();

            if (exchanges.Count > 0 && exchanges[0].Response != null)
            {
                return exchanges[0].Response;
            }

            return null;
        }

        private ApduResponse? FindExternalAuthResponse(byte[] command)
        {
            // EXTERNAL AUTHENTICATE: CLA=84 INS=82 P1=security_level P2=00 Lc=10 Data=cryptogram Le=00
            var exchanges = _trace.FindExchanges(ins: 0x82).ToList();

            if (exchanges.Count > 0 && exchanges[0].Response != null)
            {
                // Check if we can match the security level
                var p1 = command[2];
                var matchingExchange = exchanges.FirstOrDefault(ex => ex.Command[2] == p1);
                if (matchingExchange?.Response != null)
                {
                    return matchingExchange.Response;
                }

                // Otherwise return first response
                return exchanges[0].Response;
            }

            return null;
        }

        private ApduResponse? FindInstallResponse(byte[] command)
        {
            // INSTALL commands have variable data but same P1 indicates same operation type
            var p1 = command[2];
            var exchanges = _trace.FindExchanges(ins: 0xE6, p1: p1).ToList();

            if (exchanges.Count > 0 && exchanges[0].Response != null)
            {
                return exchanges[0].Response;
            }

            return null;
        }

        private bool CommandsMatch(byte[] actual, byte[] expected, bool allowDynamicData)
        {
            if (actual.Length != expected.Length)
                return false;

            // Always check header
            if (actual.Length < 4)
                return false;

            // CLA might differ by secure messaging bit
            var claMask = allowDynamicData ? 0xFC : 0xFF; // Ignore SM bits if dynamic
            if ((actual[0] & claMask) != (expected[0] & claMask))
                return false;

            // INS, P1, P2 must match
            if (actual[1] != expected[1] || actual[2] != expected[2] || actual[3] != expected[3])
                return false;

            if (!allowDynamicData)
            {
                // Exact match required
                for (int i = 4; i < actual.Length; i++)
                {
                    if (actual[i] != expected[i])
                        return false;
                }
            }

            return true;
        }

        private void UpdateCardState(byte[] command, ApduResponse response)
        {
            if (command.Length < 4 || !response.IsSuccessful)
                return;

            var ins = command[1];

            switch (ins)
            {
                case 0xA4: // SELECT
                    IsSelected = true;
                    break;

                case 0x50: // INITIALIZE UPDATE
                    // Don't set secure channel until EXTERNAL AUTHENTICATE succeeds
                    break;

                case 0x82: // EXTERNAL AUTHENTICATE
                    if (response.IsSuccessful)
                    {
                        IsSecureChannelEstablished = true;
                    }
                    break;
            }
        }

        private void RecordExchange(byte[] command, ApduResponse response)
        {
            var exchange = new ApduExchange(command, response);
            _executedExchanges.Add(exchange);
        }
    }

    /// <summary>
    /// Options for trace replay behavior.
    /// </summary>
    public class TraceReplayOptions
    {
        /// <summary>
        /// Gets or sets whether to require exact command matches.
        /// </summary>
        public bool StrictMode { get; set; }

        /// <summary>
        /// Gets or sets whether to follow trace order sequentially.
        /// </summary>
        public bool SequentialMode { get; set; } = true;

        /// <summary>
        /// Gets or sets whether to update card state based on commands.
        /// </summary>
        public bool TrackState { get; set; } = true;
    }
}
