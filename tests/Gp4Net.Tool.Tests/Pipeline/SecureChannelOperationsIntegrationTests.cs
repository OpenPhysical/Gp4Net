using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Services.GlobalPlatform;
using Gp4Net.Tool.Services;
using Gp4Net.Tool.Tests.Support;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Gp4Net.Tool.Tests.Pipeline;

public class SecureChannelOperationsIntegrationTests
{
    [Test]
    public async Task Should_Match_Card_Cryptogram_With_Host_Computation()
    {
        var profilePath = Path.Combine(
            SecurityTestData.RepositoryRoot,
            "src",
            "Gp4Net.CardEmulator",
            "Profiles",
            "p71_card_1.json"
        );

        var readerSpec = $"virtual:{profilePath}";
        var serviceResult = await VirtualCardConnections.CreateServiceAsync(
            readerSpec,
            NullLogger<Gp4Net.Services.CardSessionCommands>.Instance,
            CancellationToken.None
        );

        if (serviceResult.IsFailure)
        {
            Assert.Fail($"Failed to create virtual card service: {serviceResult.Error}");
        }

        using var cardService = serviceResult.Value;

        // select ISD first
        var selectCommand = Gp4Net
            .Services.GlobalPlatform.Commands.CreateSelectIsdCommand()
            .Bind(cmd => cmd.ToCommandApdu())
            .Map(apdu => apdu.ToBytes());

        Assert.That(
            selectCommand.IsSuccess,
            Is.True,
            selectCommand.IsFailure ? selectCommand.Error.ToString() : string.Empty
        );
        // Intentionally skip sending SELECT for diagnostic purposes
        // _ = await cardService.SendCommandAsync(selectCommand.Value, CancellationToken.None);

        // Emulate QueryCardCapabilities from ScpOperations
        var getDataCommand = GetDataCommand
            .Create(GetDataCommand.DataObjects.CardData)
            .Bind(cmd => cmd.ToCommandApdu())
            .Map(apdu => apdu.ToBytes());

        Assert.That(
            getDataCommand.IsSuccess,
            Is.True,
            getDataCommand.IsFailure ? getDataCommand.Error.ToString() : string.Empty
        );
        _ = await cardService.SendCommandAsync(getDataCommand.Value, CancellationToken.None);

        var hostChallenge = Convert.FromHexString("0102030405060708");
        var initUpdateResult = InitializeUpdateCommand
            .Create(0x01, 0x01, hostChallenge)
            .Bind(cmd => cmd.ToCommandApdu())
            .Map(apdu => apdu.ToBytes());

        Assert.That(
            initUpdateResult.IsSuccess,
            Is.True,
            initUpdateResult.IsFailure ? initUpdateResult.Error.ToString() : string.Empty
        );

        var responseResult = await cardService.SendCommandAsync(
            initUpdateResult.Value,
            CancellationToken.None
        );

        Assert.That(
            responseResult.IsSuccess,
            Is.True,
            responseResult.IsFailure ? responseResult.Error.ToString() : string.Empty
        );

        var response = InitializeUpdateResponse.Parse(responseResult.Value.Data);
        Assert.That(
            response.IsSuccess,
            Is.True,
            response.IsFailure ? response.Error.ToString() : string.Empty
        );

        var parsed = response.Value;

        var keySetResult = Scp02KeySet.Create(
            (byte[])GpTestKeys.GpTestKey.Clone(),
            (byte[])GpTestKeys.GpTestKey.Clone(),
            (byte[])GpTestKeys.GpTestKey.Clone(),
            parsed.KeyVersion
        );
        Assert.That(
            keySetResult.IsSuccess,
            Is.True,
            keySetResult.IsFailure ? keySetResult.Error.ToString() : string.Empty
        );

        var sessionContextResult = Gp4Net.Domain.Keys.KeyDerivationContext.CreateForScp02(
            keySetResult.Value,
            hostChallenge,
            parsed.CardChallenge,
            parsed.SequenceCounter,
            (Gp4Net.Constants.ScpImplementation)parsed.ImplementationParameter
        );

        Assert.That(
            sessionContextResult.IsSuccess,
            Is.True,
            sessionContextResult.IsFailure ? sessionContextResult.Error.ToString() : string.Empty
        );

        var sessionKeysResult =
            Gp4Net.Cryptography.CryptoOperations.KeyDerivation.DeriveSessionKeys(
                sessionContextResult.Value
            );

        Assert.That(
            sessionKeysResult.IsSuccess,
            Is.True,
            sessionKeysResult.IsFailure ? sessionKeysResult.Error.ToString() : string.Empty
        );

        var cardDataResult =
            Gp4Net.Cryptography.CryptoOperations.Cryptogram.BuildScp02CardCryptogramData(
                parsed,
                hostChallenge
            );
        Assert.That(
            cardDataResult.IsSuccess,
            Is.True,
            cardDataResult.IsFailure ? cardDataResult.Error.ToString() : string.Empty
        );

        var computedCryptogramResult =
            Gp4Net.Cryptography.CryptoOperations.ScpOperations.Scp02.CalculateCryptogram(
                sessionKeysResult.Value.SEnc,
                cardDataResult.Value
            );
        Assert.That(
            computedCryptogramResult.IsSuccess,
            Is.True,
            computedCryptogramResult.IsFailure
                ? computedCryptogramResult.Error.ToString()
                : string.Empty
        );

        Assert.That(
            Convert.ToHexString(parsed.CardCryptogram),
            Is.EqualTo(Convert.ToHexString(computedCryptogramResult.Value)),
            "Card cryptogram should match host computation"
        );

        var hostDataResult =
            Gp4Net.Cryptography.CryptoOperations.Cryptogram.BuildScp02HostCryptogramData(
                parsed,
                hostChallenge
            );
        Assert.That(
            hostDataResult.IsSuccess,
            Is.True,
            hostDataResult.IsFailure ? hostDataResult.Error.ToString() : string.Empty
        );

        var hostCryptogramResult =
            Gp4Net.Cryptography.CryptoOperations.ScpOperations.Scp02.CalculateCryptogram(
                sessionKeysResult.Value.SEnc,
                hostDataResult.Value
            );
        Assert.That(
            hostCryptogramResult.IsSuccess,
            Is.True,
            hostCryptogramResult.IsFailure ? hostCryptogramResult.Error.ToString() : string.Empty
        );

        var preliminaryCommandData = new byte[hostCryptogramResult.Value.Length + 1];
        Array.Copy(
            hostCryptogramResult.Value,
            preliminaryCommandData,
            hostCryptogramResult.Value.Length
        );
        preliminaryCommandData[^1] = (byte)SecurityLevel.CMac;

        var macHeader = new byte[]
        {
            Gp4Net.Domain.Commands.ExternalAuthenticateCommand.CLASS_BYTE,
            Gp4Net.Domain.Commands.ExternalAuthenticateCommand.INSTRUCTION_BYTE,
            (byte)SecurityLevel.CMac,
            0x00,
            (byte)preliminaryCommandData.Length,
        };

        var macBuffer = new byte[macHeader.Length + preliminaryCommandData.Length];
        Array.Copy(macHeader, macBuffer, macHeader.Length);
        Array.Copy(
            preliminaryCommandData,
            0,
            macBuffer,
            macHeader.Length,
            preliminaryCommandData.Length
        );

        var macResult =
            Gp4Net.Cryptography.CryptoOperations.ScpOperations.Scp02.CalculateCommandMac(
                macBuffer,
                sessionKeysResult.Value.SMac,
                Gp4Net.Constants.Constants.Scp.Common.ZeroChaining8
            );
        Assert.That(
            macResult.IsSuccess,
            Is.True,
            macResult.IsFailure ? macResult.Error.ToString() : string.Empty
        );

        var finalCommandResult = ExternalAuthenticateCommand.CreateWithMac(
            SecurityLevel.CMac,
            hostCryptogramResult.Value,
            macResult.Value
        );
        Assert.That(
            finalCommandResult.IsSuccess,
            Is.True,
            finalCommandResult.IsFailure ? finalCommandResult.Error.ToString() : string.Empty
        );

        var apduResult = finalCommandResult.Value.ToCommandApdu().Map(apdu => apdu.ToBytes());
        Assert.That(
            apduResult.IsSuccess,
            Is.True,
            apduResult.IsFailure ? apduResult.Error.ToString() : string.Empty
        );

        var externalAuthenticateResponse = await cardService.SendCommandAsync(
            apduResult.Value,
            CancellationToken.None
        );

        Assert.That(
            externalAuthenticateResponse.IsSuccess,
            Is.True,
            externalAuthenticateResponse.IsFailure
                ? externalAuthenticateResponse.Error.ToString()
                : string.Empty
        );

        var rawKeysetResult = Gp4Net.Domain.Keys.RawKeyset.Create(
            (byte[])GpTestKeys.GpTestKey.Clone(),
            (byte[])GpTestKeys.GpTestKey.Clone(),
            (byte[])GpTestKeys.GpTestKey.Clone(),
            0x00
        );
        Assert.That(
            rawKeysetResult.IsSuccess,
            Is.True,
            rawKeysetResult.IsFailure ? rawKeysetResult.Error.ToString() : string.Empty
        );

        var pipelineServiceResult = await VirtualCardConnections.CreateServiceAsync(
            readerSpec,
            NullLogger<Gp4Net.Services.CardSessionCommands>.Instance,
            CancellationToken.None
        );

        Assert.That(
            pipelineServiceResult.IsSuccess,
            Is.True,
            pipelineServiceResult.IsFailure ? pipelineServiceResult.Error.ToString() : string.Empty
        );

        using var recordingService = new RecordingSmartCardService(pipelineServiceResult.Value);

        var pipelineEstablishmentResult =
            await Gp4Net.Services.ScpOperations.Establishment.EstablishAsync(
                recordingService.SendCommandAsync,
                rawKeysetResult.Value,
                SecurityLevel.CMac,
                CancellationToken.None
            );

        if (pipelineEstablishmentResult.IsFailure)
        {
            foreach (var record in recordingService.Records)
            {
                var command = record.Command;
                var result = record.Result;
                TestContext.Out.WriteLine(
                    $"Recorded command CLA={command[0]:X2} INS={command[1]:X2} DATA={Convert.ToHexString(command[5..])}"
                );
                if (result.IsSuccess)
                {
                    TestContext.Out.WriteLine(
                        $"Response SW={result.Value.StatusWord} DATA={Convert.ToHexString(result.Value.Data ?? Array.Empty<byte>())}"
                    );
                }
                else
                {
                    TestContext.Out.WriteLine($"Response Error={result.Error}");
                }
            }

            var initializeUpdateRecord = recordingService.Records.Find(record =>
                record.Command.Length >= 13 && record.Command[1] == 0x50
            );
            Assert.That(
                initializeUpdateRecord.Command,
                Is.Not.Null,
                "INITIALIZE UPDATE command not captured"
            );

            var hostChallengeFromPipeline = initializeUpdateRecord.Command[5..13];

            Assert.That(
                initializeUpdateRecord.Result.IsSuccess,
                Is.True,
                initializeUpdateRecord.Result.IsFailure
                    ? initializeUpdateRecord.Result.Error.ToString()
                    : string.Empty
            );

            var initializeUpdateResponseBytes =
                initializeUpdateRecord.Result.Value.Data ?? Array.Empty<byte>();

            TestContext.Out.WriteLine(
                $"Pipeline host challenge: {Convert.ToHexString(hostChallengeFromPipeline)}"
            );
            TestContext.Out.WriteLine(
                $"Pipeline response data: {Convert.ToHexString(initializeUpdateResponseBytes)}"
            );

            var parsedResponseResult = InitializeUpdateResponse.Parse(
                initializeUpdateResponseBytes
            );
            Assert.That(
                parsedResponseResult.IsSuccess,
                Is.True,
                parsedResponseResult.IsFailure
                    ? parsedResponseResult.Error.ToString()
                    : string.Empty
            );
            var parsedResponse = parsedResponseResult.Value;

            var cryptoDataResult =
                Gp4Net.Cryptography.CryptoOperations.Cryptogram.BuildScp02CardCryptogramData(
                    parsedResponse,
                    hostChallengeFromPipeline
                );
            Assert.That(
                cryptoDataResult.IsSuccess,
                Is.True,
                cryptoDataResult.IsFailure ? cryptoDataResult.Error.ToString() : string.Empty
            );

            var expectedCryptogramResult =
                Gp4Net.Cryptography.CryptoOperations.ScpOperations.Scp02.CalculateCryptogram(
                    GpTestKeys.GpTestKey,
                    cryptoDataResult.Value
                );
            Assert.That(
                expectedCryptogramResult.IsSuccess,
                Is.True,
                expectedCryptogramResult.IsFailure
                    ? expectedCryptogramResult.Error.ToString()
                    : string.Empty
            );

            var typedKeysetResult = rawKeysetResult.Value.ToScp02KeySet();
            Assert.That(
                typedKeysetResult.IsSuccess,
                Is.True,
                typedKeysetResult.IsFailure ? typedKeysetResult.Error.ToString() : string.Empty
            );

            var contextResult = Gp4Net.Domain.Keys.KeyDerivationContext.CreateForScp02(
                typedKeysetResult.Value,
                hostChallengeFromPipeline,
                parsedResponse.CardChallenge,
                parsedResponse.SequenceCounter,
                (Gp4Net.Constants.ScpImplementation)parsedResponse.ImplementationParameter
            );
            Assert.That(
                contextResult.IsSuccess,
                Is.True,
                contextResult.IsFailure ? contextResult.Error.ToString() : string.Empty
            );

            var pipelineSessionKeysResult =
                Gp4Net.Cryptography.CryptoOperations.KeyDerivation.DeriveSessionKeys(
                    contextResult.Value
                );
            Assert.That(
                pipelineSessionKeysResult.IsSuccess,
                Is.True,
                pipelineSessionKeysResult.IsFailure
                    ? pipelineSessionKeysResult.Error.ToString()
                    : string.Empty
            );

            var sessionComputedResult =
                Gp4Net.Cryptography.CryptoOperations.ScpOperations.Scp02.CalculateCryptogram(
                    pipelineSessionKeysResult.Value.SEnc,
                    cryptoDataResult.Value
                );
            Assert.That(
                sessionComputedResult.IsSuccess,
                Is.True,
                sessionComputedResult.IsFailure
                    ? sessionComputedResult.Error.ToString()
                    : string.Empty
            );

            TestContext.Out.WriteLine(
                $"Card cryptogram: {Convert.ToHexString(parsedResponse.CardCryptogram)}"
            );
            TestContext.Out.WriteLine(
                $"Computed cryptogram: {Convert.ToHexString(expectedCryptogramResult.Value)}"
            );
            TestContext.Out.WriteLine(
                $"Session cryptogram: {Convert.ToHexString(sessionComputedResult.Value)}"
            );

            Assert.That(
                Convert.ToHexString(parsedResponse.CardCryptogram),
                Is.EqualTo(Convert.ToHexString(expectedCryptogramResult.Value)),
                "Pipeline cryptogram mismatch"
            );

            var externalAuthenticateRecord = recordingService.Records.Find(record =>
                record.Command.Length >= 21 && record.Command[1] == 0x82
            );
            if (externalAuthenticateRecord.Command is not null)
            {
                var hostCryptogramSent = externalAuthenticateRecord.Command[5..13];
                var macSent = externalAuthenticateRecord.Command[13..21];

                var hostDataForMac =
                    Gp4Net.Cryptography.CryptoOperations.Cryptogram.BuildScp02HostCryptogramData(
                        parsedResponse,
                        hostChallengeFromPipeline
                    );

                if (hostDataForMac.IsSuccess)
                {
                    var expectedHostCryptogram =
                        Gp4Net.Cryptography.CryptoOperations.ScpOperations.Scp02.CalculateCryptogram(
                            GpTestKeys.GpTestKey,
                            hostDataForMac.Value
                        );

                    if (expectedHostCryptogram.IsSuccess)
                    {
                        TestContext.Out.WriteLine(
                            $"Expected host cryptogram (static): {Convert.ToHexString(expectedHostCryptogram.Value)}"
                        );
                    }
                }

                var macInput = new byte[5 + hostCryptogramSent.Length];
                macInput[0] = Gp4Net.Constants.Constants.GlobalPlatform.Cla.SECURED;
                macInput[1] = Gp4Net.Constants.Apdu.Instructions.EXTERNAL_AUTHENTICATE;
                macInput[2] = (byte)SecurityLevel.CMac;
                macInput[3] = 0x00;
                macInput[4] = 0x10;
                Array.Copy(hostCryptogramSent, 0, macInput, 5, hostCryptogramSent.Length);

                var expectedMacResult =
                    Gp4Net.Cryptography.CryptoOperations.ScpOperations.Scp02.CalculateCommandMac(
                        macInput,
                        pipelineSessionKeysResult.Value.SMac,
                        Gp4Net.Constants.Constants.Scp.Common.ZeroChaining8
                    );

                if (expectedMacResult.IsSuccess)
                {
                    TestContext.Out.WriteLine(
                        $"Expected MAC (session): {Convert.ToHexString(expectedMacResult.Value)}"
                    );
                }

                TestContext.Out.WriteLine(
                    $"Host cryptogram sent: {Convert.ToHexString(hostCryptogramSent)}"
                );
                TestContext.Out.WriteLine($"MAC sent: {Convert.ToHexString(macSent)}");
            }
        }

        Assert.That(
            pipelineEstablishmentResult.IsSuccess,
            Is.True,
            pipelineEstablishmentResult.IsFailure
                ? pipelineEstablishmentResult.Error.ToString()
                : string.Empty
        );
    }
}
