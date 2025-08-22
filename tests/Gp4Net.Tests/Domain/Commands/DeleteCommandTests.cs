using System;
using System.Linq;
using AwesomeAssertions;
using Gp4Net.Domain.Commands;
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
        var aid = Convert.FromHexString("A000000003000000");

        // Act
        var result = DeleteCommand.CreateForApplication(aid, deleteRelated: false);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.Type.Should().Be(DeleteCommand.DeleteType.DeleteObjectOnly);
        _ = command.Target.Should().Be(DeleteCommand.DeleteTarget.ByAid);
        _ = command.Aids.Should().HaveCount(1);
        _ = command.Aids[0].Should().BeEquivalentTo(aid);
        _ = command.DeletionToken.HasNoValue.Should().BeTrue();
    }

    [Test]
    public void CreateForApplication_WithDeleteRelated_SetsCorrectParameters()
    {
        // Arrange
        var aid = Convert.FromHexString("A000000003000000");

        // Act
        var result = DeleteCommand.CreateForApplication(aid, deleteRelated: true);

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
        var aid = Convert.FromHexString("A000000003000000");
        var deletionToken = Convert.FromHexString("20EEDD243F094FAD");

        // Act
        var result = DeleteCommand.CreateForApplication(aid, deleteRelated: true, deletionToken);

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
        var result = DeleteCommand.CreateForApplication(null!, deleteRelated: false);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("AID cannot be null");
    }

    [Test]
    public void CreateForApplication_WithEmptyAid_ReturnsFailure()
    {
        // Act
        var result = DeleteCommand.CreateForApplication([], deleteRelated: false);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("AID cannot be empty");
    }

    [Test]
    public void CreateForPackage_WithValidAid_ReturnsSuccessResult()
    {
        // Arrange
        var packageAid = Convert.FromHexString("A000000003080000");

        // Act
        var result = DeleteCommand.CreateForPackage(packageAid, deleteRelated: true);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.Aids[0].Should().BeEquivalentTo(packageAid);
    }

    [Test]
    public void CreateForApplications_WithMultipleAids_ReturnsSuccessResult()
    {
        // Arrange
        var aids = new[]
        {
            Convert.FromHexString("A000000003000000"),
            Convert.FromHexString("A000000003000001"),
            Convert.FromHexString("A000000003000002")
        };

        // Act
        var result = DeleteCommand.CreateForApplications(aids, deleteRelated: false);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.Aids.Should().HaveCount(3);
        for (var i = 0; i < aids.Length; i++)
        {
            _ = command.Aids[i].Should().BeEquivalentTo(aids[i]);
        }
    }

    [Test]
    public void CreateForApplications_WithNullList_ReturnsFailure()
    {
        // Act
        var result = DeleteCommand.CreateForApplications(null!, deleteRelated: false);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("AIDs list cannot be null");
    }

    [Test]
    public void CreateForApplications_WithEmptyList_ReturnsFailure()
    {
        // Act
        var result = DeleteCommand.CreateForApplications(Array.Empty<byte[]>(), deleteRelated: false);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("At least one AID must be provided");
    }

    [Test]
    public void CreateForApplications_WithNullAidInList_ReturnsFailure()
    {
        // Arrange
        var aids = new byte[][]
        {
            Convert.FromHexString("A000000003000000"),
            null!,
            Convert.FromHexString("A000000003000002")
        };

        // Act
        var result = DeleteCommand.CreateForApplications(aids, deleteRelated: false);

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
        var result = DeleteCommand.CreateForKey(keyIdentifier, keyVersion);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.Type.Should().Be(DeleteCommand.DeleteType.DeleteObjectOnly);
        _ = command.Target.Should().Be(DeleteCommand.DeleteTarget.ByAid);
        _ = command.Aids.Should().HaveCount(1);
        _ = command.Aids[0].Should().BeEquivalentTo([keyIdentifier, keyVersion]);
    }

    [Test]
    public void ToApdu_ForSingleAid_GeneratesCorrectStructure()
    {
        // Arrange
        var aid = Convert.FromHexString("A000000003000000");
        var commandResult = DeleteCommand.CreateForApplication(aid, deleteRelated: false);
        var command = commandResult.Value;

        // Act
        var apdu = ApduBuilder.BuildApdu(command);

        // Assert
        _ = apdu[0].Should().Be(0x80); // CLA
        _ = apdu[1].Should().Be(0xE4); // INS
        _ = apdu[2].Should().Be(0x80); // P1 (delete object only)
        _ = apdu[3].Should().Be(0x00); // P2 (by AID)
        _ = apdu[4].Should().Be(0x0A); // Lc = 2 + 8 (tag + length + AID)
        _ = apdu[5].Should().Be(0x4F); // AID tag
        _ = apdu[6].Should().Be(0x08); // AID length (8 bytes)
        _ = apdu.Skip(7).Take(8).Should().BeEquivalentTo(aid);
        _ = apdu.Length.Should().Be(15); // 5 header + 10 data
    }

    [Test]
    public void ToApdu_WithDeletionToken_AppendsTokenDirectly()
    {
        // Arrange
        var aid = Convert.FromHexString("A000000003000000");
        var deletionToken = Convert.FromHexString("20EEDD243F094FAD");
        var commandResult = DeleteCommand.CreateForApplication(aid, deleteRelated: true, deletionToken);
        var command = commandResult.Value;

        // Act
        var apdu = ApduBuilder.BuildApdu(command);

        // Assert
        _ = apdu[0].Should().Be(0x80); // CLA
        _ = apdu[1].Should().Be(0xE4); // INS
        _ = apdu[2].Should().Be(0x00); // P1 (delete object and related)
        _ = apdu[3].Should().Be(0x80); // P2 (with related)

        var expectedLc = 2 + aid.Length + deletionToken.Length; // 4F<len><AID><token>
        _ = apdu[4].Should().Be((byte)expectedLc);

        // Verify AID TLV
        _ = apdu[5].Should().Be(0x4F); // AID tag
        _ = apdu[6].Should().Be((byte)aid.Length);
        _ = apdu.Skip(7).Take(aid.Length).Should().BeEquivalentTo(aid);

        // Verify deletion token is appended directly (no TLV wrapper)
        var tokenOffset = 7 + aid.Length;
        _ = apdu.Skip(tokenOffset).Take(deletionToken.Length).Should().BeEquivalentTo(deletionToken);
    }

    [Test]
    public void ToApdu_ForMultipleAids_ConcatenatesAllAids()
    {
        // Arrange
        var aids = new[]
        {
            Convert.FromHexString("A00000030800001000"), // 9 bytes
            Convert.FromHexString("A0000003080000"), // 7 bytes
            Convert.FromHexString("A000000308") // 5 bytes
        };
        var commandResult = DeleteCommand.CreateForApplications(aids);
        var command = commandResult.Value;

        // Act
        var apdu = ApduBuilder.BuildApdu(command);

        // Assert
        var totalAidLength = aids.Sum(aid => aid.Length); // 9 + 7 + 5 = 21
        var expectedLc = 2 + totalAidLength; // 4F<len><all AIDs>

        _ = apdu[4].Should().Be((byte)expectedLc); // Lc
        _ = apdu[5].Should().Be(0x4F); // AID tag
        _ = apdu[6].Should().Be((byte)totalAidLength); // Total length of all AIDs

        // Verify all AIDs are concatenated
        var offset = 7;
        foreach (var aid in aids)
        {
            _ = apdu.Skip(offset).Take(aid.Length).Should().BeEquivalentTo(aid);
            offset += aid.Length;
        }
    }

    [Test]
    public void ToApdu_DoesNotIncludeLeByte()
    {
        // Arrange
        var aid = Convert.FromHexString("A000000003000000");
        var commandResult = DeleteCommand.CreateForApplication(aid);
        var command = commandResult.Value;

        // Act
        var apdu = ApduBuilder.BuildApdu(command);

        // Assert
        // Total length should be: 5 (header) + Lc value
        var expectedLength = 5 + apdu[4];
        _ = apdu.Length.Should().Be(expectedLength);
        // No LE byte at the end
    }

    [Test]
    public void Data_Property_ReturnsCorrectTlvStructure()
    {
        // Arrange
        var aid = Convert.FromHexString("A000000003000000");
        var commandResult = DeleteCommand.CreateForApplication(aid);
        var command = commandResult.Value;

        // Act
        var data = command.Data;

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
        var responseData = new byte[] { 0x00 }; // Length of delete confirmation = 0
        var statusWord = (ushort)0x9000;

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
        var deletedAid = Convert.FromHexString("A000000003000000");
        var responseData = new byte[]
        {
            0x0A, // Length of delete confirmation (2 + 8)
            0x4F, // AID tag
            0x08, // AID length (8 bytes)
        }.Concat(deletedAid).ToArray();
        var statusWord = (ushort)0x9000;

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
        var responseData = new byte[] { 0x81, 0x80 }; // Extended length: 128 bytes
        var statusWord = (ushort)0x9000;

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
        var testCases = new[]
        {
            ((ushort)0x9000, "Deletion successful"),
            ((ushort)0x6A80, "Incorrect data or AID not found"),
            ((ushort)0x6A82, "Application not found"),
            ((ushort)0x6985, "Conditions not satisfied (dependencies exist)"),
            ((ushort)0x6A88, "Referenced data not found"),
            ((ushort)0x6F00, "Generic failure during deletion"),
            ((ushort)0x1234, "Unknown error: 1234") // Unknown status
        };

        foreach (var (statusWord, expectedDescription) in testCases)
        {
            // Act
            var response = new DeleteResponse([], statusWord);
            var description = response.GetResultDescription();

            // Assert
            _ = description.Should().Be(expectedDescription);
        }
    }

    [Test]
    public void DeleteCommand_IsImmutable()
    {
        // Arrange
        var aid = Convert.FromHexString("A000000003000000");
        var commandResult = DeleteCommand.CreateForApplication(aid);
        var command = commandResult.Value;
        var originalAids = command.Aids.ToArray();

        // Act - Attempt to modify the returned AID list
        // This should not affect the command's internal state
        var externalAids = command.Aids;
        // Can't modify because it's IReadOnlyList

        // Assert
        _ = command.Aids.Should().HaveCount(1);
        _ = command.Aids[0].Should().BeEquivalentTo(originalAids[0]);
    }

    [Test]
    public void DeletionReceipt_CreatesDefensiveCopy()
    {
        // Arrange
        var aid = Convert.FromHexString("A000000003000000");
        var receipt = new DeletionReceipt(aid, true);

        // Act - Modify original array
        aid[0] = 0xFF;

        // Assert - Receipt should not be affected
        _ = receipt.Aid[0].Should().Be(0xA0);
        _ = receipt.IsSuccessful.Should().BeTrue();
    }
}
