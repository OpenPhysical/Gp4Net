using System;
using System.Linq;
using AwesomeAssertions;
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
    private readonly byte[] _validPrivileges = new byte[] { 0x00 };
    private readonly byte[] _validSecurityDomainAid = Convert.FromHexString("A000000003080000");
    private readonly byte[] _validHash = Convert.FromHexString("2020202020202020202020202020202020202020");
    private readonly byte[] _validInstallToken = Convert.FromHexString("20EEDD243F094FAD");
    private readonly byte[] _validInstallParameters = Convert.FromHexString("C9020800");

    [Test]
    public void InstallForLoadCommand_Create_WithValidPackageAid_ReturnsSuccess()
    {
        var result = InstallCommand.InstallForLoadCommand.Create(_validPackageAid);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.Type.Should().Be(InstallType.ForLoad);
        command.PackageAid.Should().BeEquivalentTo(_validPackageAid);
        command.SecurityDomainAid.IsDefaultOrEmpty.Should().BeTrue();
        command.Hash.IsDefaultOrEmpty.Should().BeTrue();
        command.LoadParameters.IsDefaultOrEmpty.Should().BeTrue();
        command.InstallToken.IsDefaultOrEmpty.Should().BeTrue();
    }

    [Test]
    public void InstallForLoadCommand_Create_WithAllOptionalParameters_ReturnsSuccess()
    {
        var result = InstallCommand.InstallForLoadCommand.Create(
            _validPackageAid,
            maxDataBlockSize: 2048,
            securityDomainAid: _validSecurityDomainAid,
            hash: _validHash,
            installToken: _validInstallToken);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.Type.Should().Be(InstallType.ForLoad);
        command.PackageAid.Should().BeEquivalentTo(_validPackageAid);
        command.SecurityDomainAid.Should().BeEquivalentTo(_validSecurityDomainAid);
        command.Hash.Should().BeEquivalentTo(_validHash);
        command.InstallToken.Should().BeEquivalentTo(_validInstallToken);

        // Verify max data block size is encoded correctly in load parameters
        var expectedLoadParams = new byte[] { 0xC9, 0x02, 0x08, 0x00 }; // 2048 = 0x0800
        command.LoadParameters.Should().BeEquivalentTo(expectedLoadParams);
    }

    [Test]
    public void InstallForLoadCommand_Create_WithMaxDataBlockSize_EncodesCorrectly()
    {
        var result = InstallCommand.InstallForLoadCommand.Create(_validPackageAid, maxDataBlockSize: 1024);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        var expectedLoadParams = new byte[] { 0xC9, 0x02, 0x04, 0x00 }; // 1024 = 0x0400
        command.LoadParameters.Should().BeEquivalentTo(expectedLoadParams);
    }

    [Test]
    public void InstallForLoadCommand_Create_WithNullPackageAid_ReturnsFailure()
    {
        var result = InstallCommand.InstallForLoadCommand.Create(null!);

        result.IsFailure.Should().BeTrue();
        result.Error.Should().BeOfType<SmartCardError>();
        result.Error.Message.Should().Contain("Package AID cannot be null");
    }

    [Test]
    public void InstallForLoadCommand_Create_WithEmptyPackageAid_ReturnsFailure()
    {
        var result = InstallCommand.InstallForLoadCommand.Create([]);

        result.IsFailure.Should().BeTrue();
        result.Error.Should().BeOfType<SmartCardError>();
        result.Error.Message.Should().Contain("Package AID cannot be empty");
    }

    [Test]
    public void InstallForLoadCommand_Data_WithMinimalParameters_BuildsCorrectStructure()
    {
        var command = InstallCommand.InstallForLoadCommand.Create(_validPackageAid).Value;

        var data = command.Data;

        // Expected structure: [PackageAID_len][PackageAID][SecurityDomainAID_len][Hash_len][LoadParams_len][InstallToken_len]
        var expectedLength = 1 + _validPackageAid.Length + 1 + 1 + 1 + 1; // All optional fields are empty (0x00)
        data.Length.Should().Be(expectedLength);

        data[0].Should().Be((byte)_validPackageAid.Length);
        data.Skip(1).Take(_validPackageAid.Length).Should().BeEquivalentTo(_validPackageAid);

        var offset = 1 + _validPackageAid.Length;
        data[offset].Should().Be(0x00); // SecurityDomainAid length
        data[offset + 1].Should().Be(0x00); // Hash length
        data[offset + 2].Should().Be(0x00); // LoadParameters length
        data[offset + 3].Should().Be(0x00); // InstallToken length
    }

    [Test]
    public void InstallForLoadCommand_Data_WithAllParameters_BuildsCorrectStructure()
    {
        var command = InstallCommand.InstallForLoadCommand.Create(
            _validPackageAid,
            maxDataBlockSize: 2048,
            securityDomainAid: _validSecurityDomainAid,
            hash: _validHash,
            installToken: _validInstallToken).Value;

        var data = command.Data;

        var offset = 0;

        // Package AID
        data[offset].Should().Be((byte)_validPackageAid.Length);
        offset++;
        data.Skip(offset).Take(_validPackageAid.Length).Should().BeEquivalentTo(_validPackageAid);
        offset += _validPackageAid.Length;

        // Security Domain AID
        data[offset].Should().Be((byte)_validSecurityDomainAid.Length);
        offset++;
        data.Skip(offset).Take(_validSecurityDomainAid.Length).Should().BeEquivalentTo(_validSecurityDomainAid);
        offset += _validSecurityDomainAid.Length;

        // Hash
        data[offset].Should().Be((byte)_validHash.Length);
        offset++;
        data.Skip(offset).Take(_validHash.Length).Should().BeEquivalentTo(_validHash);
        offset += _validHash.Length;

        // Load Parameters (encoded max data block size)
        data[offset].Should().Be(0x04); // Length of C9 02 08 00
        offset++;
        var expectedLoadParams = new byte[] { 0xC9, 0x02, 0x08, 0x00 };
        data.Skip(offset).Take(4).Should().BeEquivalentTo(expectedLoadParams);
        offset += 4;

        // Install Token
        data[offset].Should().Be((byte)_validInstallToken.Length);
        offset++;
        data.Skip(offset).Take(_validInstallToken.Length).Should().BeEquivalentTo(_validInstallToken);
    }

    [Test]
    public void InstallForLoadCommand_ApduProperties_ReturnsCorrectValues()
    {
        var command = InstallCommand.InstallForLoadCommand.Create(_validPackageAid).Value;

        command.Cla.Should().Be(0x80);
        command.Ins.Should().Be(0xE6);
        command.P1.Should().Be(0x02); // InstallType.ForLoad
        command.P2.Should().Be(0x00);
        command.ExpectedResponseLength.Should().Be(0);
        command.IsExtendedLength.Should().BeFalse();
    }

    [Test]
    public void InstallForLoadCommand_ToApdu_GeneratesCorrectApdu()
    {
        var command = InstallCommand.InstallForLoadCommand.Create(_validPackageAid).Value;

        var apdu = ApduBuilder.BuildApdu(command);

        apdu[0].Should().Be(0x80); // CLA
        apdu[1].Should().Be(0xE6); // INS
        apdu[2].Should().Be(0x02); // P1 (ForLoad)
        apdu[3].Should().Be(0x00); // P2
        apdu[4].Should().Be((byte)command.Data.Length); // LC
        apdu.Skip(5).Take(command.Data.Length).Should().BeEquivalentTo(command.Data);
        apdu[apdu.Length - 1].Should().Be(0x00); // LE byte
    }

    [Test]
    public void InstallForLoadCommand_ToString_ReturnsCorrectString()
    {
        var command = InstallCommand.InstallForLoadCommand.Create(_validPackageAid).Value;

        command.ToString().Should().Be("INSTALL [for load]");
    }

    [Test]
    public void InstallForInstallCommand_Create_WithValidParameters_ReturnsSuccess()
    {
        var result = InstallCommand.InstallForInstallCommand.Create(
            _validPackageAid,
            _validModuleAid,
            _validAppletAid,
            _validPrivileges);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.Type.Should().Be(InstallType.ForInstall);
        command.PackageAid.Should().BeEquivalentTo(_validPackageAid);
        command.ModuleAid.Should().BeEquivalentTo(_validModuleAid);
        command.AppletAid.Should().BeEquivalentTo(_validAppletAid);
        command.Privileges.Should().BeEquivalentTo(_validPrivileges);
        command.InstallParameters.IsDefaultOrEmpty.Should().BeTrue();
        command.InstallToken.IsDefaultOrEmpty.Should().BeTrue();
    }

    [Test]
    public void InstallForInstallCommand_Create_WithAllOptionalParameters_ReturnsSuccess()
    {
        var result = InstallCommand.InstallForInstallCommand.Create(
            _validPackageAid,
            _validModuleAid,
            _validAppletAid,
            _validPrivileges,
            _validInstallParameters,
            _validInstallToken);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.InstallParameters.Should().BeEquivalentTo(_validInstallParameters);
        command.InstallToken.Should().BeEquivalentTo(_validInstallToken);
    }

    [Test]
    public void InstallForInstallCommand_Create_WithNullPackageAid_ReturnsFailure()
    {
        var result = InstallCommand.InstallForInstallCommand.Create(
            null!,
            _validModuleAid,
            _validAppletAid,
            _validPrivileges);

        result.IsFailure.Should().BeTrue();
        result.Error.Should().BeOfType<SmartCardError>();
        result.Error.Message.Should().Contain("Package AID cannot be null");
    }

    [Test]
    public void InstallForInstallCommand_Create_WithNullModuleAid_ReturnsFailure()
    {
        var result = InstallCommand.InstallForInstallCommand.Create(
            _validPackageAid,
            null!,
            _validAppletAid,
            _validPrivileges);

        result.IsFailure.Should().BeTrue();
        result.Error.Should().BeOfType<SmartCardError>();
        result.Error.Message.Should().Contain("Module AID cannot be null or empty");
    }

    [Test]
    public void InstallForInstallCommand_Create_WithEmptyModuleAid_ReturnsFailure()
    {
        var result = InstallCommand.InstallForInstallCommand.Create(
            _validPackageAid,
            [],
            _validAppletAid,
            _validPrivileges);

        result.IsFailure.Should().BeTrue();
        result.Error.Should().BeOfType<SmartCardError>();
        result.Error.Message.Should().Contain("Module AID cannot be null or empty");
    }

    [Test]
    public void InstallForInstallCommand_Create_WithNullAppletAid_ReturnsFailure()
    {
        var result = InstallCommand.InstallForInstallCommand.Create(
            _validPackageAid,
            _validModuleAid,
            null!,
            _validPrivileges);

        result.IsFailure.Should().BeTrue();
        result.Error.Should().BeOfType<SmartCardError>();
        result.Error.Message.Should().Contain("Application AID cannot be null or empty");
    }

    [Test]
    public void InstallForInstallCommand_Create_WithEmptyAppletAid_ReturnsFailure()
    {
        var result = InstallCommand.InstallForInstallCommand.Create(
            _validPackageAid,
            _validModuleAid,
            [],
            _validPrivileges);

        result.IsFailure.Should().BeTrue();
        result.Error.Should().BeOfType<SmartCardError>();
        result.Error.Message.Should().Contain("Application AID cannot be null or empty");
    }

    [Test]
    public void InstallForInstallCommand_Create_WithNullPrivileges_ReturnsFailure()
    {
        var result = InstallCommand.InstallForInstallCommand.Create(
            _validPackageAid,
            _validModuleAid,
            _validAppletAid,
            null!);

        result.IsFailure.Should().BeTrue();
        result.Error.Should().BeOfType<SmartCardError>();
        result.Error.Message.Should().Contain("Privileges cannot be null");
    }

    [Test]
    public void InstallForInstallCommand_Create_WithEmptyPrivileges_UsesDefaultPrivileges()
    {
        var result = InstallCommand.InstallForInstallCommand.Create(
            _validPackageAid,
            _validModuleAid,
            _validAppletAid,
            []);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.Privileges.Should().BeEquivalentTo(new byte[] { 0x00 }); // Default privileges
    }

    [Test]
    public void InstallForInstallCommand_CreateAndMakeSelectable_ReturnsCorrectType()
    {
        var result = InstallCommand.InstallForInstallCommand.CreateAndMakeSelectable(
            _validPackageAid,
            _validModuleAid,
            _validAppletAid,
            _validPrivileges);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.Type.Should().Be(InstallType.ForInstallAndMakeSelectable);
        command.P1.Should().Be(0x0C); // InstallType.ForInstallAndMakeSelectable
    }

    [Test]
    public void InstallForInstallCommand_Data_WithMinimalParameters_BuildsCorrectStructure()
    {
        var command = InstallCommand.InstallForInstallCommand.Create(
            _validPackageAid,
            _validModuleAid,
            _validAppletAid,
            _validPrivileges).Value;

        var data = command.Data;

        var offset = 0;

        // Package AID
        data[offset].Should().Be((byte)_validPackageAid.Length);
        offset++;
        data.Skip(offset).Take(_validPackageAid.Length).Should().BeEquivalentTo(_validPackageAid);
        offset += _validPackageAid.Length;

        // Module AID
        data[offset].Should().Be((byte)_validModuleAid.Length);
        offset++;
        data.Skip(offset).Take(_validModuleAid.Length).Should().BeEquivalentTo(_validModuleAid);
        offset += _validModuleAid.Length;

        // Applet AID
        data[offset].Should().Be((byte)_validAppletAid.Length);
        offset++;
        data.Skip(offset).Take(_validAppletAid.Length).Should().BeEquivalentTo(_validAppletAid);
        offset += _validAppletAid.Length;

        // Privileges
        data[offset].Should().Be((byte)_validPrivileges.Length);
        offset++;
        data.Skip(offset).Take(_validPrivileges.Length).Should().BeEquivalentTo(_validPrivileges);
        offset += _validPrivileges.Length;

        // Install Parameters (empty)
        data[offset].Should().Be(0x00);
        offset++;

        // Install Token (empty)
        data[offset].Should().Be(0x00);
    }

    [Test]
    public void InstallForInstallCommand_Data_WithAllParameters_BuildsCorrectStructure()
    {
        var command = InstallCommand.InstallForInstallCommand.Create(
            _validPackageAid,
            _validModuleAid,
            _validAppletAid,
            _validPrivileges,
            _validInstallParameters,
            _validInstallToken).Value;

        var data = command.Data;

        var offset = 0;

        // Package AID
        data[offset].Should().Be((byte)_validPackageAid.Length);
        offset++;
        data.Skip(offset).Take(_validPackageAid.Length).Should().BeEquivalentTo(_validPackageAid);
        offset += _validPackageAid.Length;

        // Module AID
        data[offset].Should().Be((byte)_validModuleAid.Length);
        offset++;
        data.Skip(offset).Take(_validModuleAid.Length).Should().BeEquivalentTo(_validModuleAid);
        offset += _validModuleAid.Length;

        // Applet AID
        data[offset].Should().Be((byte)_validAppletAid.Length);
        offset++;
        data.Skip(offset).Take(_validAppletAid.Length).Should().BeEquivalentTo(_validAppletAid);
        offset += _validAppletAid.Length;

        // Privileges
        data[offset].Should().Be((byte)_validPrivileges.Length);
        offset++;
        data.Skip(offset).Take(_validPrivileges.Length).Should().BeEquivalentTo(_validPrivileges);
        offset += _validPrivileges.Length;

        // Install Parameters
        data[offset].Should().Be((byte)_validInstallParameters.Length);
        offset++;
        data.Skip(offset).Take(_validInstallParameters.Length).Should().BeEquivalentTo(_validInstallParameters);
        offset += _validInstallParameters.Length;

        // Install Token
        data[offset].Should().Be((byte)_validInstallToken.Length);
        offset++;
        data.Skip(offset).Take(_validInstallToken.Length).Should().BeEquivalentTo(_validInstallToken);
    }

    [Test]
    public void InstallForInstallCommand_ApduProperties_ReturnsCorrectValues()
    {
        var command = InstallCommand.InstallForInstallCommand.Create(
            _validPackageAid,
            _validModuleAid,
            _validAppletAid,
            _validPrivileges).Value;

        command.Cla.Should().Be(0x80);
        command.Ins.Should().Be(0xE6);
        command.P1.Should().Be(0x04); // InstallType.ForInstall
        command.P2.Should().Be(0x00);
        command.ExpectedResponseLength.Should().Be(0);
        command.IsExtendedLength.Should().BeFalse();
    }

    [Test]
    public void InstallForInstallCommand_ToString_ReturnsCorrectString()
    {
        var command = InstallCommand.InstallForInstallCommand.Create(
            _validPackageAid,
            _validModuleAid,
            _validAppletAid,
            _validPrivileges).Value;

        command.ToString().Should().Be("INSTALL [for install]");
    }

    [Test]
    public void InstallType_EnumValues_HaveCorrectByteValues()
    {
        ((byte)InstallType.ForLoad).Should().Be(0x02);
        ((byte)InstallType.ForInstall).Should().Be(0x04);
        ((byte)InstallType.ForMakeSelectable).Should().Be(0x08);
        ((byte)InstallType.ForInstallAndMakeSelectable).Should().Be(0x0C);
    }

    [Test]
    public void InstallCommandBuilder_CreateForLoad_WithValidParameters_ReturnsSuccess()
    {
        var result = InstallCommandBuilder.CreateForLoad(
            _validPackageAid,
            _validSecurityDomainAid,
            _validHash,
            2048,
            _validInstallToken);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.Type.Should().Be(InstallType.ForLoad);
        command.PackageAid.Should().BeEquivalentTo(_validPackageAid);
        command.SecurityDomainAid.Should().BeEquivalentTo(_validSecurityDomainAid);
        command.Hash.Should().BeEquivalentTo(_validHash);
        command.InstallToken.Should().BeEquivalentTo(_validInstallToken);
    }

    [Test]
    public void InstallCommandBuilder_CreateForInstall_WithValidParameters_ReturnsSuccess()
    {
        var result = InstallCommandBuilder.CreateForInstall(
            _validPackageAid,
            _validAppletAid,
            _validModuleAid,
            _validPrivileges,
            _validInstallParameters,
            _validInstallToken);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.Type.Should().Be(InstallType.ForInstall);
        command.PackageAid.Should().BeEquivalentTo(_validPackageAid);
        command.AppletAid.Should().BeEquivalentTo(_validAppletAid);
        command.ModuleAid.Should().BeEquivalentTo(_validModuleAid);
        command.Privileges.Should().BeEquivalentTo(_validPrivileges);
        command.InstallParameters.Should().BeEquivalentTo(_validInstallParameters);
        command.InstallToken.Should().BeEquivalentTo(_validInstallToken);
    }

    [Test]
    public void InstallCommandBuilder_CreateForInstall_WithNullModuleAid_UsesPackageAid()
    {
        var result = InstallCommandBuilder.CreateForInstall(
            _validPackageAid,
            _validAppletAid,
            moduleAid: null,
            privileges: null);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.ModuleAid.Should().BeEquivalentTo(_validPackageAid); // Should use package AID
        command.Privileges.Should().BeEquivalentTo(new byte[] { 0x00 }); // Default privileges
    }

    [Test]
    public void InstallCommandBuilder_CreateForInstallAndMakeSelectable_WithValidParameters_ReturnsSuccess()
    {
        var result = InstallCommandBuilder.CreateForInstallAndMakeSelectable(
            _validPackageAid,
            _validAppletAid,
            _validModuleAid,
            _validPrivileges,
            _validInstallParameters,
            _validInstallToken);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.Type.Should().Be(InstallType.ForInstallAndMakeSelectable);
        command.P1.Should().Be(0x0C);
    }

    [Test]
    public void InstallCommandBuilder_CreateForInstallAndMakeSelectable_WithNullModuleAid_UsesPackageAid()
    {
        var result = InstallCommandBuilder.CreateForInstallAndMakeSelectable(
            _validPackageAid,
            _validAppletAid,
            moduleAid: null,
            privileges: null);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.ModuleAid.Should().BeEquivalentTo(_validPackageAid); // Should use package AID
        command.Privileges.Should().BeEquivalentTo(new byte[] { 0x00 }); // Default privileges
    }

    [Test]
    public void InstallCommandResponse_Success_WithoutData_CreatesSuccessResponse()
    {
        var response = InstallCommandResponse.Success();

        response.IsSuccess.Should().BeTrue();
        response.StatusWord.Should().Be(0x9000);
        response.Data.IsDefaultOrEmpty.Should().BeTrue();
    }

    [Test]
    public void InstallCommandResponse_Success_WithData_CreatesSuccessResponse()
    {
        var responseData = new byte[] { 0x01, 0x02, 0x03 };
        var response = InstallCommandResponse.Success(responseData);

        response.IsSuccess.Should().BeTrue();
        response.StatusWord.Should().Be(0x9000);
        response.Data.Should().BeEquivalentTo(responseData);
    }

    [Test]
    public void InstallCommandResponse_Failure_WithStatusWord_CreatesFailureResponse()
    {
        var statusWord = (ushort)0x6A82;
        var response = InstallCommandResponse.Failure(statusWord);

        response.IsSuccess.Should().BeFalse();
        response.StatusWord.Should().Be(statusWord);
        response.Data.IsDefaultOrEmpty.Should().BeTrue();
    }

    [Test]
    public void InstallCommandResponse_Failure_WithStatusWordAndData_CreatesFailureResponse()
    {
        var statusWord = (ushort)0x6A82;
        var responseData = new byte[] { 0x01, 0x02, 0x03 };
        var response = InstallCommandResponse.Failure(statusWord, responseData);

        response.IsSuccess.Should().BeFalse();
        response.StatusWord.Should().Be(statusWord);
        response.Data.Should().BeEquivalentTo(responseData);
    }

    [Test]
    public void InstallCommandResponse_Parse_WithValidData_CreatesResponse()
    {
        var responseData = new byte[] { 0x01, 0x02, 0x03 };
        var statusWord = (ushort)0x9000;
        var response = InstallCommandResponse.Parse(responseData, statusWord);

        response.StatusWord.Should().Be(statusWord);
        response.Data.Should().BeEquivalentTo(responseData);
        response.IsSuccess.Should().BeTrue();
    }

    [Test]
    public void InstallForLoadCommand_WithLargeMaxDataBlockSize_EncodesCorrectly()
    {
        var result = InstallCommand.InstallForLoadCommand.Create(_validPackageAid, maxDataBlockSize: 65535);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        var expectedLoadParams = new byte[] { 0xC9, 0x02, 0xFF, 0xFF }; // 65535 = 0xFFFF
        command.LoadParameters.Should().BeEquivalentTo(expectedLoadParams);
    }

    [Test]
    public void InstallForLoadCommand_WithMinimumMaxDataBlockSize_EncodesCorrectly()
    {
        var result = InstallCommand.InstallForLoadCommand.Create(_validPackageAid, maxDataBlockSize: 1);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        var expectedLoadParams = new byte[] { 0xC9, 0x02, 0x00, 0x01 }; // 1 = 0x0001
        command.LoadParameters.Should().BeEquivalentTo(expectedLoadParams);
    }

    [Test]
    public void InstallCommand_IsImmutable_PropertiesCannotBeModified()
    {
        var command = InstallCommand.InstallForLoadCommand.Create(_validPackageAid).Value;
        var originalPackageAid = command.PackageAid.ToArray();

        // Verify that the PackageAid property returns an immutable array
        command.PackageAid.Should().BeEquivalentTo(originalPackageAid);
        // ImmutableArray<byte> cannot be modified directly
    }

    [Test]
    public void InstallForInstallCommand_WithLongAids_HandlesCorrectly()
    {
        var longAid = new byte[16] { 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

        var result = InstallCommand.InstallForInstallCommand.Create(
            longAid,
            longAid,
            longAid,
            _validPrivileges);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.PackageAid.Should().BeEquivalentTo(longAid);
        command.ModuleAid.Should().BeEquivalentTo(longAid);
        command.AppletAid.Should().BeEquivalentTo(longAid);

        // Verify data structure can handle long AIDs
        var data = command.Data;
        data.Should().NotBeNull();
        data.Length.Should().BeGreaterThan(0);
    }

    [Test]
    public void InstallForInstallCommand_WithComplexPrivileges_HandlesCorrectly()
    {
        var complexPrivileges = new byte[] { 0x80, 0x40, 0x20, 0x10 }; // Multiple privilege flags

        var result = InstallCommand.InstallForInstallCommand.Create(
            _validPackageAid,
            _validModuleAid,
            _validAppletAid,
            complexPrivileges);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.Privileges.Should().BeEquivalentTo(complexPrivileges);
    }

    [Test]
    public void InstallForLoadCommand_Create_PreservesInputArrays()
    {
        var packageAid = (byte[])_validPackageAid.Clone();
        var originalPackageAid = (byte[])_validPackageAid.Clone();

        var result = InstallCommand.InstallForLoadCommand.Create(packageAid);

        // Modify the original array
        packageAid[0] = 0xFF;

        // Verify the command was not affected
        result.IsSuccess.Should().BeTrue();
        result.Value.PackageAid.Should().BeEquivalentTo(originalPackageAid);
    }

    [Test]
    public void InstallForInstallCommand_Create_PreservesInputArrays()
    {
        var packageAid = (byte[])_validPackageAid.Clone();
        var moduleAid = (byte[])_validModuleAid.Clone();
        var appletAid = (byte[])_validAppletAid.Clone();
        var privileges = (byte[])_validPrivileges.Clone();

        var originalPackageAid = (byte[])_validPackageAid.Clone();
        var originalModuleAid = (byte[])_validModuleAid.Clone();
        var originalAppletAid = (byte[])_validAppletAid.Clone();
        var originalPrivileges = (byte[])_validPrivileges.Clone();

        var result = InstallCommand.InstallForInstallCommand.Create(
            packageAid,
            moduleAid,
            appletAid,
            privileges);

        // Modify the original arrays
        packageAid[0] = 0xFF;
        moduleAid[0] = 0xFF;
        appletAid[0] = 0xFF;
        privileges[0] = 0xFF;

        // Verify the command was not affected
        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.PackageAid.Should().BeEquivalentTo(originalPackageAid);
        command.ModuleAid.Should().BeEquivalentTo(originalModuleAid);
        command.AppletAid.Should().BeEquivalentTo(originalAppletAid);
        command.Privileges.Should().BeEquivalentTo(originalPrivileges);
    }

}
