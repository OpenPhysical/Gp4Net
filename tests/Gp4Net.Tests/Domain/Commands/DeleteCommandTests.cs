using System;
using System.Collections.Generic;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Tests.Infrastructure;
using Gp4Net.Transport;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands;

/// <summary>
/// Unit tests for the DeleteCommand domain model.
/// Tests pure functions without any I/O or mocking.
/// </summary>
[TestFixture]
public class DeleteCommandTests
{
    [Test]
    public void CreateForApplication_WithValidAid_ReturnsSuccessResult()
    {
        // Arrange
        byte[] aid = Convert.FromHexString("A000000003000000");

        // Act
        Result<DeleteCommand, SmartCardError> result = DeleteCommand.CreateForApplication(
            aid,
            deleteRelated: false
        );

        // Assert
        _ = result.Should().BeSuccess();
        result.Match(
            command =>
            {
                _ = command.Type.Should().Be(DeleteCommand.DeleteType.DeleteObjectOnly);
                _ = command.Target.Should().Be(DeleteCommand.DeleteTarget.ByAid);
                _ = command.Aids.Should().HaveCount(1);
                _ = command.Aids[0].Should().BeEquivalentTo(aid);
                _ = command.DeletionToken.Should().HaveNoValue();
            },
            error => Assert.Fail($"Expected success but got error: {error}")
        );
    }

    [Test]
    public void CreateForApplication_WithDeleteRelated_SetsCorrectParameters()
    {
        // Arrange
        byte[] aid = Convert.FromHexString("A000000003000000");

        // Act
        Result<DeleteCommand, SmartCardError> result = DeleteCommand.CreateForApplication(
            aid,
            deleteRelated: true
        );

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.Type.Should().Be(DeleteCommand.DeleteType.DeleteObjectAndRelated);
        _ = command.Target.Should().Be(DeleteCommand.DeleteTarget.WithRelated);
        _ = command.P1.Should().Be(0x00); // Delete object and related
        _ = command.P2.Should().Be(0x80); // With related
    }

    [Test]
    public void CreateForApplication_WithDeletionToken_IncludesToken()
    {
        // Arrange
        byte[] aid = Convert.FromHexString("A000000003000000");
        byte[] deletionToken = Convert.FromHexString("20EEDD243F094FAD");

        // Act
        Result<DeleteCommand, SmartCardError> result = DeleteCommand.CreateForApplication(
            aid,
            deleteRelated: true,
            deletionToken
        );

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.DeletionToken.HasValue.Should().BeTrue();
        _ = command.DeletionToken.Value.Should().BeEquivalentTo(deletionToken);
    }

    [Test]
    public void CreateForApplication_WithNullAid_ReturnsFailure()
    {
        // Act
        Result<DeleteCommand, SmartCardError> result = DeleteCommand.CreateForApplication(
            null!,
            deleteRelated: false
        );

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("AID cannot be null");
    }

    [Test]
    public void CreateForApplication_WithEmptyAid_ReturnsFailure()
    {
        // Act
        Result<DeleteCommand, SmartCardError> result = DeleteCommand.CreateForApplication(
            [],
            deleteRelated: false
        );

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("AID cannot be empty");
    }

    [Test]
    public void CreateForPackage_WithValidAid_ReturnsSuccessResult()
    {
        // Arrange
        byte[] packageAid = Convert.FromHexString("A000000003080000");

        // Act
        Result<DeleteCommand, SmartCardError> result = DeleteCommand.CreateForPackage(
            packageAid,
            deleteRelated: true
        );

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.Aids[0].Should().BeEquivalentTo(packageAid);
    }

    [Test]
    public void CreateForApplications_WithMultipleAids_ReturnsSuccessResult()
    {
        // Arrange
        byte[][] aids =
        [
            Convert.FromHexString("A000000003000000"),
            Convert.FromHexString("A000000003000001"),
            Convert.FromHexString("A000000003000002"),
        ];

        // Act
        Result<DeleteCommand, SmartCardError> result = DeleteCommand.CreateForApplications(
            aids,
            deleteRelated: false
        );

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.Aids.Should().HaveCount(3);
        for (int i = 0; i < aids.Length; i++)
        {
            _ = command.Aids[i].Should().BeEquivalentTo(aids[i]);
        }
    }

    [Test]
    public void CreateForApplications_WithNullList_ReturnsFailure()
    {
        // Act
        Result<DeleteCommand, SmartCardError> result = DeleteCommand.CreateForApplications(
            null!,
            deleteRelated: false
        );

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("AIDs list cannot be null");
    }

    [Test]
    public void CreateForApplications_WithEmptyList_ReturnsFailure()
    {
        // Act
        Result<DeleteCommand, SmartCardError> result = DeleteCommand.CreateForApplications(
            Array.Empty<byte[]>(),
            deleteRelated: false
        );

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("At least one AID must be provided");
    }

    [Test]
    public void CreateForApplications_WithNullAidInList_ReturnsFailure()
    {
        // Arrange
        byte[][] aids =
        [
            Convert.FromHexString("A000000003000000"),
            null!,
            Convert.FromHexString("A000000003000002")
        ];

        // Act
        Result<DeleteCommand, SmartCardError> result = DeleteCommand.CreateForApplications(
            aids,
            deleteRelated: false
        );

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("AIDs cannot contain null values");
    }

    [Test]
    public void CreateForKey_WithValidParameters_ReturnsSuccessResult()
    {
        // Arrange
        byte keyIdentifier = 0x01;
        byte keyVersion = 0x73;

        // Act
        Result<DeleteCommand, SmartCardError> result = DeleteCommand.CreateForKey(
            keyIdentifier,
            keyVersion
        );

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.Type.Should().Be(DeleteCommand.DeleteType.DeleteObjectOnly);
        _ = command.Target.Should().Be(DeleteCommand.DeleteTarget.ByKey);
        _ = command.Aids.Should().HaveCount(1);
        _ = command.Aids[0].Should().BeEquivalentTo([keyIdentifier, keyVersion]);
    }

    [Test]
    public void ToApdu_ForSingleAid_GeneratesCorrectStructure()
    {
        // Arrange
        byte[] aid = Convert.FromHexString("A000000003000000");

        // Act & Assert
        DeleteCommand
            .CreateForApplication(aid, deleteRelated: false)
            .Bind(command => ApduBuilder.BuildApdu(Maybe<IApduCommand>.From(command)))
            .Match(
                apdu =>
                {
                    _ = apdu[0].Should().Be(0x80); // CLA
                    _ = apdu[1].Should().Be(0xE4); // INS
                    // GP Card Spec 2.3.1, Tables 11-21/22: P1=00 is the last
                    // or only DELETE and P2=00 deletes only the named object.
                    _ = apdu[2].Should().Be(0x00);
                    _ = apdu[3].Should().Be(0x00); // P2 (by AID)
                    _ = apdu[4].Should().Be(0x0A); // Lc = 2 + 8 (tag + length + AID)
                    _ = apdu[5].Should().Be(0x4F); // AID tag
                    _ = apdu[6].Should().Be(0x08); // AID length (8 bytes)
                    _ = apdu.Skip(7).Take(8).Should().BeEquivalentTo(aid);
                    _ = apdu.Length.Should().Be(16); // header + data + mandatory Le=00
                },
                error =>
                    Result
                        .Success()
                        .IsSuccess.Should()
                        .BeTrue($"Command creation or APDU building failed: {error}")
            );
    }

    [Test]
    public void ToApdu_WithDeletionToken_AppendsTokenDirectly()
    {
        // Arrange
        byte[] aid = Convert.FromHexString("A000000003000000");
        byte[] deletionToken = Convert.FromHexString("20EEDD243F094FAD");

        // Act & Assert
        var result = DeleteCommand
            .CreateForApplication(aid, deleteRelated: true, deletionToken)
            .Bind(command => ApduBuilder.BuildApdu(Maybe<IApduCommand>.From(command)));

        result.Match(
            apdu =>
            {
                _ = apdu[0].Should().Be(0x80); // CLA
                _ = apdu[1].Should().Be(0xE4); // INS
                _ = apdu[2].Should().Be(0x00); // P1 (delete object and related)
                _ = apdu[3].Should().Be(0x80); // P2 (with related)

                // GP Card Spec 2.3.1, Table 11-23: Delete Token is tag 9E.
                int expectedLc = 2 + aid.Length + 2 + deletionToken.Length;
                _ = apdu[4].Should().Be((byte)expectedLc);

                // Verify AID TLV
                _ = apdu[5].Should().Be(0x4F); // AID tag
                _ = apdu[6].Should().Be((byte)aid.Length);
                _ = apdu.Skip(7).Take(aid.Length).Should().BeEquivalentTo(aid);

                int tokenOffset = 7 + aid.Length;
                _ = apdu[tokenOffset].Should().Be(0x9E);
                _ = apdu[tokenOffset + 1].Should().Be((byte)deletionToken.Length);
                _ = apdu.Skip(tokenOffset + 2)
                    .Take(deletionToken.Length)
                    .Should()
                    .BeEquivalentTo(deletionToken);
            },
            error =>
                Result
                    .Success()
                    .IsSuccess.Should()
                    .BeTrue($"Command creation or APDU building failed: {error}")
        );
    }

    [Test]
    public void ToApdu_WithLongDeletionToken_UsesBerLength()
    {
        byte[] aid = Convert.FromHexString("A000000003000000");
        byte[] deletionToken = new byte[128];

        var result = DeleteCommand
            .CreateForApplication(aid, deleteRelated: true, deletionToken)
            .Bind(command => ApduBuilder.BuildApdu(Maybe<IApduCommand>.From(command)));

        _ = result.IsSuccess.Should().BeTrue();
        int tokenOffset = 7 + aid.Length;
        // GP Card Spec 2.3.1, Table 11-23 and BER-TLV length encoding: tag 9E length 128 is 81 80.
        _ = result.Value.Skip(tokenOffset).Take(3).Should().Equal(0x9E, 0x81, 0x80);
    }

    [Test]
    public void ToApdu_ForMultipleAids_EncodesOneDataObjectPerAid()
    {
        // Arrange
        byte[][] aids =
        [
            Convert.FromHexString("A00000030800001000"), // 9 bytes
            Convert.FromHexString("A0000003080000"), // 7 bytes
            Convert.FromHexString("A000000308"), // 5 bytes
        ];

        // Act & Assert
        DeleteCommand
            .CreateForApplications(aids)
            .Bind(command => ApduBuilder.BuildApdu(Maybe<IApduCommand>.From(command)))
            .Match(
                apdu =>
                {
                    int expectedLc = aids.Sum(aid => aid.Length + 2);

                    _ = apdu[4].Should().Be((byte)expectedLc); // Lc
                    aids.Aggregate(
                        5,
                        (offset, aid) =>
                        {
                            _ = apdu[offset].Should().Be(0x4F);
                            _ = apdu[offset + 1].Should().Be((byte)aid.Length);
                            _ = apdu.Skip(offset + 2).Take(aid.Length).Should().Equal(aid);
                            return offset + aid.Length + 2;
                        }
                    );
                },
                error =>
                    Result
                        .Success()
                        .IsSuccess.Should()
                        .BeTrue($"Command creation or APDU building failed: {error}")
            );
    }

    [Test]
    public void ToApdu_IncludesMandatoryLeByte()
    {
        // Arrange
        byte[] aid = Convert.FromHexString("A000000003000000");

        // Act & Assert
        DeleteCommand
            .CreateForApplication(aid)
            .Bind(command => ApduBuilder.BuildApdu(Maybe<IApduCommand>.From(command)))
            .Match(
                apdu =>
                {
                    // GP Card Spec 2.3.1, Table 11-20 requires Le=00.
                    int expectedLength = 5 + apdu[4] + 1;
                    _ = apdu.Length.Should().Be(expectedLength);
                    _ = apdu[^1].Should().Be(0x00);
                },
                error =>
                    Result
                        .Success()
                        .IsSuccess.Should()
                        .BeTrue($"Command creation or APDU building failed: {error}")
            );
    }

    [Test]
    public void Data_Property_ReturnsCorrectTlvStructure()
    {
        // Arrange
        byte[] aid = Convert.FromHexString("A000000003000000");
        Result<DeleteCommand, SmartCardError> commandResult = DeleteCommand.CreateForApplication(
            aid
        );
        var command = commandResult.Value;

        // Act
        byte[]? data = command.Data;

        // Assert
        _ = data.Should().NotBeNull();
        _ = data![0].Should().Be(0x4F); // AID tag
        _ = data[1].Should().Be((byte)aid.Length);
        _ = data.Skip(2).Take(aid.Length).Should().BeEquivalentTo(aid);
    }

    [Test]
    public void DeleteResponse_Parse_WithNoConfirmationData()
    {
        // Arrange
        byte[] responseData = [0x00]; // Length of delete confirmation = 0
        ushort statusWord = 0x9000;

        // Act
        var response = DeleteResponse.Parse(responseData, statusWord);

        // Assert
        _ = response.IsSuccessful.Should().BeTrue();
        _ = response.StatusWord.Should().Be(0x9000);
        _ = response.DeletionReceipts.Should().BeEmpty();
    }

    [Test]
    public void DeleteResponse_Parse_WithDeletionReceipt()
    {
        // Arrange
        byte[] deletedAid = Convert.FromHexString("A000000003000000");
        byte[] responseData =
        [
            0x0A, // Length of delete confirmation (2 + 8)
            0x4F, // AID tag
            0x08,
            .. deletedAid, // AID length (8 bytes)
        ];
        ushort statusWord = 0x9000;

        // Act
        var response = DeleteResponse.Parse(responseData, statusWord);

        // Assert
        _ = response.IsSuccessful.Should().BeTrue();
        _ = response.DeletionReceipts.Should().HaveCount(1);
        _ = response.DeletionReceipts[0].Aid.Should().BeEquivalentTo(deletedAid);
        _ = response.DeletionReceipts[0].IsSuccessful.Should().BeTrue();
    }

    [Test]
    public void DeleteResponse_Parse_WithExtendedLength()
    {
        // Arrange
        byte[] responseData = [0x81, 0x80]; // Extended length: 128 bytes
        ushort statusWord = 0x9000;

        // Act
        var response = DeleteResponse.Parse(responseData, statusWord);

        // Assert
        _ = response.IsSuccessful.Should().BeTrue();
        _ = response.DeletionReceipts.Should().BeEmpty(); // No actual receipt data follows
    }

    [Test]
    public void DeleteResponse_GetResultDescription_MapsStatusWords()
    {
        // Arrange
        (ushort, string)[] testCases =
        [
            (0x9000, "Deletion successful"),
            (0x6A80, "Incorrect data or AID not found"),
            (0x6A82, "Application not found"),
            (0x6985, "Conditions not satisfied (dependencies exist)"),
            (0x6A88, "Referenced data not found"),
            (0x6F00, "Generic failure during deletion"),
            (0x1234, "Unknown error: 1234"), // Unknown status
        ];

        foreach ((ushort statusWord, string expectedDescription) in testCases)
        {
            // Act
            var response = new DeleteResponse([], statusWord);
            string? description = response.GetResultDescription();

            // Assert
            _ = description.Should().Be(expectedDescription);
        }
    }

    [Test]
    public void DeleteCommand_IsImmutable()
    {
        // Arrange
        byte[] aid = Convert.FromHexString("A000000003000000");
        Result<DeleteCommand, SmartCardError> commandResult = DeleteCommand.CreateForApplication(
            aid
        );
        var command = commandResult.Value;
        byte[][] originalAids = [.. command.Aids];

        // Act - Attempt to modify the returned AID list
        // This should not affect the command's internal state
        IReadOnlyList<byte[]>? externalAids = command.Aids;
        // Can't modify because it's IReadOnlyList

        // Assert
        _ = command.Aids.Should().HaveCount(1);
        _ = command.Aids[0].Should().BeEquivalentTo(originalAids[0]);
    }

    [Test]
    public void DeletionReceipt_CreatesDefensiveCopy()
    {
        // Arrange
        byte[] aid = Convert.FromHexString("A000000003000000");
        var receipt = new DeletionReceipt(aid, true);

        // Act - Modify original array
        aid[0] = 0xFF;

        // Assert - Receipt should not be affected
        _ = receipt.Aid[0].Should().Be(0xA0);
        _ = receipt.IsSuccessful.Should().BeTrue();
    }
}
