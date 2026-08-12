using System;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Pipeline;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using static Gp4Net.Pipeline.CommandProcessing;

namespace Gp4Net.Tests.Integration;

[TestFixture]
[Category("Integration")]
[Category("Pipeline")]
public class PipelineSecureChannelIntegrationTest
{
    private static readonly byte[] SEnc = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
    private static readonly byte[] SMac = Convert.FromHexString("0102030405060708090A0B0C0D0E0F10");
    private static readonly byte[] SRMac = Convert.FromHexString(
        "102030405060708090A0B0C0D0E0F000"
    );
    private static readonly byte[] Chaining = Convert.FromHexString(
        "00112233445566778899AABBCCDDEEFF"
    );

    [Test]
    public async Task Pipeline_Should_Decrypt_And_Verify_Golden_Scp03_Response()
    {
        SecureChannelState state = SecureChannelState
            .Create(
                new SessionKeys(SEnc, SMac, SRMac),
                SecurityLevel.CDecryption | SecurityLevel.RMac | SecurityLevel.REncryption,
                CryptoOperations.ScpVersion.Scp03,
                Chaining,
                (byte)ScpImplementation.Scp03I70
            )
            .Value with
        {
            EncryptionCounter = 1,
        };
        // Fixed SCP03 R-ENC + R-MAC vector for plaintext 0102039000 and the keys above.
        byte[] goldenResponse = Convert.FromHexString(
            "6DAF1A05635B84438939EDC1FE2E57EB9E0688B245337A859000"
        );
        var channel = new FixedChannel();
        var transport = new FixedResponseTransport(goldenResponse);
        var environment = new CommandEnvironment(
            channel,
            transport,
            Maybe<SecureChannelState>.From(state),
            NullLogger.Instance,
            CommandOptions.Default
        );
        var command = SelectCommand.CreateForIssuerSecurityDomain().Value;

        var result = await CommandProcessors.ExecuteTransport(command, environment);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Data.Should().Equal(0x01, 0x02, 0x03);
        _ = ((ushort)result.Value.StatusWord).Should().Be(0x9000);
        _ = result.Value.Metadata.SecureChannelUnwrapped.Should().BeTrue();
        _ = transport.TransmissionCount.Should().Be(1);
    }

    private sealed class FixedChannel : ICardChannel
    {
        public TransportProtocol Protocol => TransportProtocol.T1;
        public bool IsOpen => true;

        public Task<Result<ChannelExchange, SmartCardError>> TransmitAsync(
            byte[] command,
            CancellationToken cancellationToken = default
        ) =>
            Task.FromResult(
                Result.Success<ChannelExchange, SmartCardError>(new ChannelExchange([], this))
            );
    }

    private sealed class FixedResponseTransport(byte[] response) : IApduTransport
    {
        public TransportProtocol Protocol => TransportProtocol.T1;
        public int MaxCommandDataLength => 255;
        public int MaxResponseDataLength => 256;
        public bool SupportsExtendedLength => false;
        public int TransmissionCount { get; private set; }

        public Task<Result<TransportExchange, SmartCardError>> TransmitAsync(
            IApduCommand command,
            ICardChannel channel,
            CancellationToken cancellationToken = default
        )
        {
            TransmissionCount++;
            ushort statusWord = (ushort)(response[^2] << 8 | response[^1]);
            var apduResponse = new ApduResponse(response[..^2], statusWord);
            return Task.FromResult(
                Result.Success<TransportExchange, SmartCardError>(
                    new TransportExchange(apduResponse, channel)
                )
            );
        }
    }
}
