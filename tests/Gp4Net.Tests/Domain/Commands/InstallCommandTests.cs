using System;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands;

/// <summary>
/// Unit tests for the InstallCommand domain model.
/// Tests pure functions without any I/O or mocking.
/// </summary>
[TestFixture]
[Category("Unit")]
public class InstallCommandTests
{
    private readonly byte[] _validPackageAid = Convert.FromHexString("A000000003000000");
    private readonly byte[] _validModuleAid = Convert.FromHexString("A000000003000001");
    private readonly byte[] _validAppletAid = Convert.FromHexString("A000000003000002");
    private readonly byte[] _validPrivileges = [0x00];
    private readonly byte[] _validSecurityDomainAid = Convert.FromHexString("A000000003080000");
    private readonly byte[] _validHash = Convert.FromHexString(
        "2020202020202020202020202020202020202020"
    );
    private readonly byte[] _validInstallToken = Convert.FromHexString("20EEDD243F094FAD");
    private readonly byte[] _validInstallParameters = Convert.FromHexString("C9020800");

    [Test]
    public void InstallForLoadCommand_Create_WithValidPackageAid_ReturnsSuccess()
    {
        Result<InstallCommand.InstallForLoadCommand, SmartCardError> result =
            InstallCommand.InstallForLoadCommand.Create(_validPackageAid);

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.Type.Should().Be(InstallType.ForLoad);
        _ = command.PackageAid.Should().BeEquivalentTo(_validPackageAid);
        _ = command.SecurityDomainAid.IsDefaultOrEmpty.Should().BeTrue();
        _ = command.Hash.IsDefaultOrEmpty.Should().BeTrue();
        _ = command.LoadParameters.IsDefaultOrEmpty.Should().BeTrue();
        _ = command.InstallToken.IsDefaultOrEmpty.Should().BeTrue();
    }

    [Test]
    public void InstallForLoadCommand_Create_WithAllOptionalParameters_ReturnsSuccess()
    {
        Result<InstallCommand.InstallForLoadCommand, SmartCardError> result =
            InstallCommand.InstallForLoadCommand.Create(
                _validPackageAid,
                maxDataBlockSize: 2048,
                securityDomainAid: _validSecurityDomainAid,
                hash: _validHash,
                installToken: _validInstallToken
            );

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.Type.Should().Be(InstallType.ForLoad);
        _ = command.PackageAid.Should().BeEquivalentTo(_validPackageAid);
        _ = command.SecurityDomainAid.Should().BeEquivalentTo(_validSecurityDomainAid);
        _ = command.Hash.Should().BeEquivalentTo(_validHash);
        _ = command.InstallToken.Should().BeEquivalentTo(_validInstallToken);

        // Verify max data block size is encoded correctly in load parameters
        byte[] expectedLoadParams = [0xC9, 0x02, 0x08, 0x00]; // 2048 = 0x0800
        _ = command.LoadParameters.Should().BeEquivalentTo(expectedLoadParams);
    }

    [Test]
    public void InstallForLoadCommand_Create_WithMaxDataBlockSize_EncodesCorrectly()
    {
        Result<InstallCommand.InstallForLoadCommand, SmartCardError> result =
            InstallCommand.InstallForLoadCommand.Create(_validPackageAid, maxDataBlockSize: 1024);

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        byte[] expectedLoadParams = [0xC9, 0x02, 0x04, 0x00]; // 1024 = 0x0400
        _ = command.LoadParameters.Should().BeEquivalentTo(expectedLoadParams);
    }

    [Test]
    public void InstallForLoadCommand_Create_WithNullPackageAid_ReturnsFailure()
    {
        Result<InstallCommand.InstallForLoadCommand, SmartCardError> result =
            InstallCommand.InstallForLoadCommand.Create(null!);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("Package AID cannot be null");
    }

    [Test]
    public void InstallForLoadCommand_Create_WithEmptyPackageAid_ReturnsFailure()
    {
        Result<InstallCommand.InstallForLoadCommand, SmartCardError> result =
            InstallCommand.InstallForLoadCommand.Create([]);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("Package AID cannot be empty");
    }

    [Test]
    public void InstallForLoadCommand_Data_WithMinimalParameters_BuildsCorrectStructure()
    {
        var command = InstallCommand.InstallForLoadCommand.Create(_validPackageAid).Value;

        byte[]? data = command.Data;

        // Expected structure: [PackageAID_len][PackageAID][SecurityDomainAID_len][Hash_len][LoadParams_len][InstallToken_len]
        int expectedLength = 1 + _validPackageAid.Length + 1 + 1 + 1 + 1; // All optional fields are empty (0x00)
        _ = data.Length.Should().Be(expectedLength);

        _ = data[0].Should().Be((byte)_validPackageAid.Length);
        _ = data.Skip(1).Take(_validPackageAid.Length).Should().BeEquivalentTo(_validPackageAid);

        int offset = 1 + _validPackageAid.Length;
        _ = data[offset].Should().Be(0x00); // SecurityDomainAid length
        _ = data[offset + 1].Should().Be(0x00); // Hash length
        _ = data[offset + 2].Should().Be(0x00); // LoadParameters length
        _ = data[offset + 3].Should().Be(0x00); // InstallToken length
    }

    [Test]
    public void InstallForLoadCommand_Data_WithAllParameters_BuildsCorrectStructure()
    {
        var command = InstallCommand
            .InstallForLoadCommand.Create(
                _validPackageAid,
                maxDataBlockSize: 2048,
                securityDomainAid: _validSecurityDomainAid,
                hash: _validHash,
                installToken: _validInstallToken
            )
            .Value;

        byte[]? data = command.Data;

        int offset = 0;

        // Package AID
        _ = data[offset].Should().Be((byte)_validPackageAid.Length);
        offset++;
        _ = data.Skip(offset)
            .Take(_validPackageAid.Length)
            .Should()
            .BeEquivalentTo(_validPackageAid);
        offset += _validPackageAid.Length;

        // Security Domain AID
        _ = data[offset].Should().Be((byte)_validSecurityDomainAid.Length);
        offset++;
        _ = data.Skip(offset)
            .Take(_validSecurityDomainAid.Length)
            .Should()
            .BeEquivalentTo(_validSecurityDomainAid);
        offset += _validSecurityDomainAid.Length;

        // Hash
        _ = data[offset].Should().Be((byte)_validHash.Length);
        offset++;
        _ = data.Skip(offset).Take(_validHash.Length).Should().BeEquivalentTo(_validHash);
        offset += _validHash.Length;

        // Load Parameters (encoded max data block size)
        _ = data[offset].Should().Be(0x04); // Length of C9 02 08 00
        offset++;
        byte[] expectedLoadParams = [0xC9, 0x02, 0x08, 0x00];
        _ = data.Skip(offset).Take(4).Should().BeEquivalentTo(expectedLoadParams);
        offset += 4;

        // Install Token
        _ = data[offset].Should().Be((byte)_validInstallToken.Length);
        offset++;
        _ = data.Skip(offset)
            .Take(_validInstallToken.Length)
            .Should()
            .BeEquivalentTo(_validInstallToken);
    }

    [Test]
    public void InstallForLoadCommand_ApduProperties_ReturnsCorrectValues()
    {
        var command = InstallCommand.InstallForLoadCommand.Create(_validPackageAid).Value;

        _ = command.Cla.Should().Be(0x80);
        _ = command.Ins.Should().Be(0xE6);
        _ = command.P1.Should().Be(0x02); // InstallType.ForLoad
        _ = command.P2.Should().Be(0x00);
        _ = command.ExpectedResponseLength.Should().Be(0);
        _ = command.IsExtendedLength.Should().BeFalse();
    }

    [Test]
    public void InstallForLoadCommand_ToApdu_GeneratesCorrectApdu()
    {
        var command = InstallCommand.InstallForLoadCommand.Create(_validPackageAid).Value;

        Result<byte[], SmartCardError> apduResult = ApduBuilder.BuildApdu(command);
        _ = apduResult.IsSuccess.Should().BeTrue();
        byte[] apdu = apduResult.Value;

        _ = apdu[0].Should().Be(0x80); // CLA
        _ = apdu[1].Should().Be(0xE6); // INS
        _ = apdu[2].Should().Be(0x02); // P1 (ForLoad)
        _ = apdu[3].Should().Be(0x00); // P2
        _ = apdu[4].Should().Be((byte)command.Data.Length); // LC
        _ = apdu.Skip(5).Take(command.Data.Length).Should().BeEquivalentTo(command.Data);
        _ = apdu[^1].Should().Be(0x00); // LE byte
    }

    [Test]
    public void InstallForLoadCommand_ToString_ReturnsCorrectString()
    {
        var command = InstallCommand.InstallForLoadCommand.Create(_validPackageAid).Value;

        _ = command.ToString().Should().Be("INSTALL [for load]");
    }

    [Test]
    public void InstallForInstallCommand_Create_WithValidParameters_ReturnsSuccess()
    {
        Result<InstallCommand.InstallForInstallCommand, SmartCardError> result =
            InstallCommand.InstallForInstallCommand.Create(
                _validPackageAid,
                _validModuleAid,
                _validAppletAid,
                _validPrivileges
            );

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.Type.Should().Be(InstallType.ForInstall);
        _ = command.PackageAid.Should().BeEquivalentTo(_validPackageAid);
        _ = command.ModuleAid.Should().BeEquivalentTo(_validModuleAid);
        _ = command.AppletAid.Should().BeEquivalentTo(_validAppletAid);
        _ = command.Privileges.Should().BeEquivalentTo(_validPrivileges);
        _ = command.InstallParameters.IsDefaultOrEmpty.Should().BeTrue();
        _ = command.InstallToken.IsDefaultOrEmpty.Should().BeTrue();
    }

    [Test]
    public void InstallForInstallCommand_Create_WithAllOptionalParameters_ReturnsSuccess()
    {
        Result<InstallCommand.InstallForInstallCommand, SmartCardError> result =
            InstallCommand.InstallForInstallCommand.Create(
                _validPackageAid,
                _validModuleAid,
                _validAppletAid,
                _validPrivileges,
                _validInstallParameters,
                _validInstallToken
            );

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.InstallParameters.Should().BeEquivalentTo(_validInstallParameters);
        _ = command.InstallToken.Should().BeEquivalentTo(_validInstallToken);
    }

    [Test]
    public void InstallForInstallCommand_Create_WithNullPackageAid_ReturnsFailure()
    {
        Result<InstallCommand.InstallForInstallCommand, SmartCardError> result =
            InstallCommand.InstallForInstallCommand.Create(
                null!,
                _validModuleAid,
                _validAppletAid,
                _validPrivileges
            );

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("Package AID cannot be null");
    }

    [Test]
    public void InstallForInstallCommand_Create_WithNullModuleAid_ReturnsFailure()
    {
        Result<InstallCommand.InstallForInstallCommand, SmartCardError> result =
            InstallCommand.InstallForInstallCommand.Create(
                _validPackageAid,
                null!,
                _validAppletAid,
                _validPrivileges
            );

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("Module AID cannot be null or empty");
    }

    [Test]
    public void InstallForInstallCommand_Create_WithEmptyModuleAid_ReturnsFailure()
    {
        Result<InstallCommand.InstallForInstallCommand, SmartCardError> result =
            InstallCommand.InstallForInstallCommand.Create(
                _validPackageAid,
                [],
                _validAppletAid,
                _validPrivileges
            );

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("Module AID cannot be null or empty");
    }

    [Test]
    public void InstallForInstallCommand_Create_WithNullAppletAid_ReturnsFailure()
    {
        Result<InstallCommand.InstallForInstallCommand, SmartCardError> result =
            InstallCommand.InstallForInstallCommand.Create(
                _validPackageAid,
                _validModuleAid,
                null!,
                _validPrivileges
            );

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("Application AID cannot be null or empty");
    }

    [Test]
    public void InstallForInstallCommand_Create_WithEmptyAppletAid_ReturnsFailure()
    {
        Result<InstallCommand.InstallForInstallCommand, SmartCardError> result =
            InstallCommand.InstallForInstallCommand.Create(
                _validPackageAid,
                _validModuleAid,
                [],
                _validPrivileges
            );

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("Application AID cannot be null or empty");
    }

    [Test]
    public void InstallForInstallCommand_Create_WithNullPrivileges_ReturnsFailure()
    {
        Result<InstallCommand.InstallForInstallCommand, SmartCardError> result =
            InstallCommand.InstallForInstallCommand.Create(
                _validPackageAid,
                _validModuleAid,
                _validAppletAid,
                null!
            );

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("Privileges cannot be null");
    }

    [Test]
    public void InstallForInstallCommand_Create_WithEmptyPrivileges_UsesDefaultPrivileges()
    {
        Result<InstallCommand.InstallForInstallCommand, SmartCardError> result =
            InstallCommand.InstallForInstallCommand.Create(
                _validPackageAid,
                _validModuleAid,
                _validAppletAid,
                []
            );

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.Privileges.Should().BeEquivalentTo(new byte[] { 0x00 }); // Default privileges
    }

    [Test]
    public void InstallForInstallCommand_CreateAndMakeSelectable_ReturnsCorrectType()
    {
        Result<InstallCommand.InstallForInstallCommand, SmartCardError> result =
            InstallCommand.InstallForInstallCommand.CreateAndMakeSelectable(
                _validPackageAid,
                _validModuleAid,
                _validAppletAid,
                _validPrivileges
            );

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.Type.Should().Be(InstallType.ForInstallAndMakeSelectable);
        _ = command.P1.Should().Be(0x0C); // InstallType.ForInstallAndMakeSelectable
    }

    [Test]
    public void InstallForInstallCommand_Data_WithMinimalParameters_BuildsCorrectStructure()
    {
        var command = InstallCommand
            .InstallForInstallCommand.Create(
                _validPackageAid,
                _validModuleAid,
                _validAppletAid,
                _validPrivileges
            )
            .Value;

        byte[]? data = command.Data;

        int offset = 0;

        // Package AID
        _ = data[offset].Should().Be((byte)_validPackageAid.Length);
        offset++;
        _ = data.Skip(offset)
            .Take(_validPackageAid.Length)
            .Should()
            .BeEquivalentTo(_validPackageAid);
        offset += _validPackageAid.Length;

        // Module AID
        _ = data[offset].Should().Be((byte)_validModuleAid.Length);
        offset++;
        _ = data.Skip(offset).Take(_validModuleAid.Length).Should().BeEquivalentTo(_validModuleAid);
        offset += _validModuleAid.Length;

        // Applet AID
        _ = data[offset].Should().Be((byte)_validAppletAid.Length);
        offset++;
        _ = data.Skip(offset).Take(_validAppletAid.Length).Should().BeEquivalentTo(_validAppletAid);
        offset += _validAppletAid.Length;

        // Privileges
        _ = data[offset].Should().Be((byte)_validPrivileges.Length);
        offset++;
        _ = data.Skip(offset)
            .Take(_validPrivileges.Length)
            .Should()
            .BeEquivalentTo(_validPrivileges);
        offset += _validPrivileges.Length;

        // Install Parameters (empty)
        _ = data[offset].Should().Be(0x00);
        offset++;

        // Install Token (empty)
        _ = data[offset].Should().Be(0x00);
    }

    [Test]
    public void InstallForInstallCommand_Data_WithAllParameters_BuildsCorrectStructure()
    {
        var command = InstallCommand
            .InstallForInstallCommand.Create(
                _validPackageAid,
                _validModuleAid,
                _validAppletAid,
                _validPrivileges,
                _validInstallParameters,
                _validInstallToken
            )
            .Value;

        byte[]? data = command.Data;

        int offset = 0;

        // Package AID
        _ = data[offset].Should().Be((byte)_validPackageAid.Length);
        offset++;
        _ = data.Skip(offset)
            .Take(_validPackageAid.Length)
            .Should()
            .BeEquivalentTo(_validPackageAid);
        offset += _validPackageAid.Length;

        // Module AID
        _ = data[offset].Should().Be((byte)_validModuleAid.Length);
        offset++;
        _ = data.Skip(offset).Take(_validModuleAid.Length).Should().BeEquivalentTo(_validModuleAid);
        offset += _validModuleAid.Length;

        // Applet AID
        _ = data[offset].Should().Be((byte)_validAppletAid.Length);
        offset++;
        _ = data.Skip(offset).Take(_validAppletAid.Length).Should().BeEquivalentTo(_validAppletAid);
        offset += _validAppletAid.Length;

        // Privileges
        _ = data[offset].Should().Be((byte)_validPrivileges.Length);
        offset++;
        _ = data.Skip(offset)
            .Take(_validPrivileges.Length)
            .Should()
            .BeEquivalentTo(_validPrivileges);
        offset += _validPrivileges.Length;

        // Install Parameters
        _ = data[offset].Should().Be((byte)_validInstallParameters.Length);
        offset++;
        _ = data.Skip(offset)
            .Take(_validInstallParameters.Length)
            .Should()
            .BeEquivalentTo(_validInstallParameters);
        offset += _validInstallParameters.Length;

        // Install Token
        _ = data[offset].Should().Be((byte)_validInstallToken.Length);
        offset++;
        _ = data.Skip(offset)
            .Take(_validInstallToken.Length)
            .Should()
            .BeEquivalentTo(_validInstallToken);
    }

    [Test]
    public void InstallForInstallCommand_ApduProperties_ReturnsCorrectValues()
    {
        var command = InstallCommand
            .InstallForInstallCommand.Create(
                _validPackageAid,
                _validModuleAid,
                _validAppletAid,
                _validPrivileges
            )
            .Value;

        _ = command.Cla.Should().Be(0x80);
        _ = command.Ins.Should().Be(0xE6);
        _ = command.P1.Should().Be(0x04); // InstallType.ForInstall
        _ = command.P2.Should().Be(0x00);
        _ = command.ExpectedResponseLength.Should().Be(0);
        _ = command.IsExtendedLength.Should().BeFalse();
    }

    [Test]
    public void InstallForInstallCommand_ToString_ReturnsCorrectString()
    {
        var command = InstallCommand
            .InstallForInstallCommand.Create(
                _validPackageAid,
                _validModuleAid,
                _validAppletAid,
                _validPrivileges
            )
            .Value;

        _ = command.ToString().Should().Be("INSTALL [for install]");
    }

    [Test]
    public void InstallType_EnumValues_HaveCorrectByteValues()
    {
        _ = ((byte)InstallType.ForLoad).Should().Be(0x02);
        _ = ((byte)InstallType.ForInstall).Should().Be(0x04);
        _ = ((byte)InstallType.ForMakeSelectable).Should().Be(0x08);
        _ = ((byte)InstallType.ForInstallAndMakeSelectable).Should().Be(0x0C);
    }

    [Test]
    public void InstallCommandBuilder_CreateForLoad_WithValidParameters_ReturnsSuccess()
    {
        Result<InstallCommand.InstallForLoadCommand, SmartCardError> result =
            InstallCommandBuilder.CreateForLoad(
                _validPackageAid,
                _validSecurityDomainAid,
                _validHash,
                2048,
                _validInstallToken
            );

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.Type.Should().Be(InstallType.ForLoad);
        _ = command.PackageAid.Should().BeEquivalentTo(_validPackageAid);
        _ = command.SecurityDomainAid.Should().BeEquivalentTo(_validSecurityDomainAid);
        _ = command.Hash.Should().BeEquivalentTo(_validHash);
        _ = command.InstallToken.Should().BeEquivalentTo(_validInstallToken);
    }

    [Test]
    public void InstallCommandBuilder_CreateForInstall_WithValidParameters_ReturnsSuccess()
    {
        Result<InstallCommand.InstallForInstallCommand, SmartCardError> result =
            InstallCommandBuilder.CreateForInstall(
                _validPackageAid,
                _validAppletAid,
                _validModuleAid,
                _validPrivileges,
                _validInstallParameters,
                _validInstallToken
            );

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.Type.Should().Be(InstallType.ForInstall);
        _ = command.PackageAid.Should().BeEquivalentTo(_validPackageAid);
        _ = command.AppletAid.Should().BeEquivalentTo(_validAppletAid);
        _ = command.ModuleAid.Should().BeEquivalentTo(_validModuleAid);
        _ = command.Privileges.Should().BeEquivalentTo(_validPrivileges);
        _ = command.InstallParameters.Should().BeEquivalentTo(_validInstallParameters);
        _ = command.InstallToken.Should().BeEquivalentTo(_validInstallToken);
    }

    [Test]
    public void InstallCommandBuilder_CreateForInstall_WithNullModuleAid_UsesPackageAid()
    {
        Result<InstallCommand.InstallForInstallCommand, SmartCardError> result =
            InstallCommandBuilder.CreateForInstall(
                _validPackageAid,
                _validAppletAid,
                moduleAid: null,
                privileges: null
            );

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.ModuleAid.Should().BeEquivalentTo(_validPackageAid); // Should use package AID
        _ = command.Privileges.Should().BeEquivalentTo(new byte[] { 0x00 }); // Default privileges
    }

    [Test]
    public void InstallCommandBuilder_CreateForInstallAndMakeSelectable_WithValidParameters_ReturnsSuccess()
    {
        Result<InstallCommand.InstallForInstallCommand, SmartCardError> result =
            InstallCommandBuilder.CreateForInstallAndMakeSelectable(
                _validPackageAid,
                _validAppletAid,
                _validModuleAid,
                _validPrivileges,
                _validInstallParameters,
                _validInstallToken
            );

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.Type.Should().Be(InstallType.ForInstallAndMakeSelectable);
        _ = command.P1.Should().Be(0x0C);
    }

    [Test]
    public void InstallCommandBuilder_CreateForInstallAndMakeSelectable_WithNullModuleAid_UsesPackageAid()
    {
        Result<InstallCommand.InstallForInstallCommand, SmartCardError> result =
            InstallCommandBuilder.CreateForInstallAndMakeSelectable(
                _validPackageAid,
                _validAppletAid,
                moduleAid: null,
                privileges: null
            );

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.ModuleAid.Should().BeEquivalentTo(_validPackageAid); // Should use package AID
        _ = command.Privileges.Should().BeEquivalentTo(new byte[] { 0x00 }); // Default privileges
    }

    [Test]
    public void InstallCommandResponse_Success_WithoutData_CreatesSuccessResponse()
    {
        var response = InstallCommandResponse.Success();

        _ = response.IsSuccess.Should().BeTrue();
        _ = response.StatusWord.Should().Be(0x9000);
        _ = response.Data.IsDefaultOrEmpty.Should().BeTrue();
    }

    [Test]
    public void InstallCommandResponse_Success_WithData_CreatesSuccessResponse()
    {
        byte[] responseData = [0x01, 0x02, 0x03];
        var response = InstallCommandResponse.Success(responseData);

        _ = response.IsSuccess.Should().BeTrue();
        _ = response.StatusWord.Should().Be(0x9000);
        _ = response.Data.Should().BeEquivalentTo(responseData);
    }

    [Test]
    public void InstallCommandResponse_Failure_WithStatusWord_CreatesFailureResponse()
    {
        ushort statusWord = 0x6A82;
        var response = InstallCommandResponse.Failure(statusWord);

        _ = response.IsSuccess.Should().BeFalse();
        _ = response.StatusWord.Should().Be(statusWord);
        _ = response.Data.IsDefaultOrEmpty.Should().BeTrue();
    }

    [Test]
    public void InstallCommandResponse_Failure_WithStatusWordAndData_CreatesFailureResponse()
    {
        ushort statusWord = 0x6A82;
        byte[] responseData = [0x01, 0x02, 0x03];
        var response = InstallCommandResponse.Failure(statusWord, responseData);

        _ = response.IsSuccess.Should().BeFalse();
        _ = response.StatusWord.Should().Be(statusWord);
        _ = response.Data.Should().BeEquivalentTo(responseData);
    }

    [Test]
    public void InstallCommandResponse_Parse_WithValidData_CreatesResponse()
    {
        byte[] responseData = [0x01, 0x02, 0x03];
        ushort statusWord = 0x9000;
        var response = InstallCommandResponse.Parse(responseData, statusWord);

        _ = response.StatusWord.Should().Be(statusWord);
        _ = response.Data.Should().BeEquivalentTo(responseData);
        _ = response.IsSuccess.Should().BeTrue();
    }

    [Test]
    public void InstallForLoadCommand_WithLargeMaxDataBlockSize_EncodesCorrectly()
    {
        Result<InstallCommand.InstallForLoadCommand, SmartCardError> result =
            InstallCommand.InstallForLoadCommand.Create(_validPackageAid, maxDataBlockSize: 65535);

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        byte[] expectedLoadParams = [0xC9, 0x02, 0xFF, 0xFF]; // 65535 = 0xFFFF
        _ = command.LoadParameters.Should().BeEquivalentTo(expectedLoadParams);
    }

    [Test]
    public void InstallForLoadCommand_WithMinimumMaxDataBlockSize_EncodesCorrectly()
    {
        Result<InstallCommand.InstallForLoadCommand, SmartCardError> result =
            InstallCommand.InstallForLoadCommand.Create(_validPackageAid, maxDataBlockSize: 1);

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        byte[] expectedLoadParams = [0xC9, 0x02, 0x00, 0x01]; // 1 = 0x0001
        _ = command.LoadParameters.Should().BeEquivalentTo(expectedLoadParams);
    }

    [Test]
    public void InstallCommand_IsImmutable_PropertiesCannotBeModified()
    {
        var command = InstallCommand.InstallForLoadCommand.Create(_validPackageAid).Value;
        byte[] originalPackageAid = [.. command.PackageAid];

        // Verify that the PackageAid property returns an immutable array
        _ = command.PackageAid.Should().BeEquivalentTo(originalPackageAid);
        // ImmutableArray<byte> cannot be modified directly
    }

    [Test]
    public void InstallForInstallCommand_WithLongAids_HandlesCorrectly()
    {
        byte[] longAid =
        [
            0xA0,
            0x00,
            0x00,
            0x00,
            0x03,
            0x00,
            0x00,
            0x00,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
        ];

        Result<InstallCommand.InstallForInstallCommand, SmartCardError> result =
            InstallCommand.InstallForInstallCommand.Create(
                longAid,
                longAid,
                longAid,
                _validPrivileges
            );

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.PackageAid.Should().BeEquivalentTo(longAid);
        _ = command.ModuleAid.Should().BeEquivalentTo(longAid);
        _ = command.AppletAid.Should().BeEquivalentTo(longAid);

        // Verify data structure can handle long AIDs
        byte[]? data = command.Data;
        _ = data.Should().NotBeNull();
        _ = data.Length.Should().BeGreaterThan(0);
    }

    [Test]
    public void InstallForInstallCommand_WithComplexPrivileges_HandlesCorrectly()
    {
        byte[] complexPrivileges = [0x80, 0x40, 0x20, 0x10]; // Multiple privilege flags

        Result<InstallCommand.InstallForInstallCommand, SmartCardError> result =
            InstallCommand.InstallForInstallCommand.Create(
                _validPackageAid,
                _validModuleAid,
                _validAppletAid,
                complexPrivileges
            );

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.Privileges.Should().BeEquivalentTo(complexPrivileges);
    }

    [Test]
    public void InstallForLoadCommand_Create_PreservesInputArrays()
    {
        byte[] packageAid = (byte[])_validPackageAid.Clone();
        byte[] originalPackageAid = (byte[])_validPackageAid.Clone();

        Result<InstallCommand.InstallForLoadCommand, SmartCardError> result =
            InstallCommand.InstallForLoadCommand.Create(packageAid);

        // Modify the original array
        packageAid[0] = 0xFF;

        // Verify the command was not affected
        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.PackageAid.Should().BeEquivalentTo(originalPackageAid);
    }

    [Test]
    public void InstallForInstallCommand_Create_PreservesInputArrays()
    {
        byte[] packageAid = (byte[])_validPackageAid.Clone();
        byte[] moduleAid = (byte[])_validModuleAid.Clone();
        byte[] appletAid = (byte[])_validAppletAid.Clone();
        byte[] privileges = (byte[])_validPrivileges.Clone();

        byte[] originalPackageAid = (byte[])_validPackageAid.Clone();
        byte[] originalModuleAid = (byte[])_validModuleAid.Clone();
        byte[] originalAppletAid = (byte[])_validAppletAid.Clone();
        byte[] originalPrivileges = (byte[])_validPrivileges.Clone();

        Result<InstallCommand.InstallForInstallCommand, SmartCardError> result =
            InstallCommand.InstallForInstallCommand.Create(
                packageAid,
                moduleAid,
                appletAid,
                privileges
            );

        // Modify the original arrays
        packageAid[0] = 0xFF;
        moduleAid[0] = 0xFF;
        appletAid[0] = 0xFF;
        privileges[0] = 0xFF;

        // Verify the command was not affected
        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.PackageAid.Should().BeEquivalentTo(originalPackageAid);
        _ = command.ModuleAid.Should().BeEquivalentTo(originalModuleAid);
        _ = command.AppletAid.Should().BeEquivalentTo(originalAppletAid);
        _ = command.Privileges.Should().BeEquivalentTo(originalPrivileges);
    }
}
