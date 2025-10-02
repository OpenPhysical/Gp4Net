using System;
using System.Linq;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Trace;
using NUnit.Framework;
using static Gp4Net.Cryptography.CryptoService;

namespace Gp4Net.Tests.Unit.Security;

/// <summary>
/// Unit tests for trace validation functionality.
/// Tests cryptographic validation operations with basic test vectors.
/// </summary>
[TestFixture]
[Category("Unit")]
[Category("Security")]
[Category("TraceValidation")]
public class TraceValidationTests
{
    // Standard GP test keys used in industry testing
    private static readonly byte[] TestMasterKey = Convert.FromHexString(
        "404142434445464748494A4B4C4D4E4F"
    );

    private IKeySet _scp02Keys;
    private IKeySet _scp03Keys;

    [SetUp]
    public void SetUp()
    {
        // Create test key sets for both protocols
        var scp02Result = Scp02KeySet.Create(TestMasterKey, TestMasterKey, TestMasterKey, 0x01);
        Assert.That(scp02Result.IsSuccess, Is.True, "SCP02 keyset creation should succeed");
        _scp02Keys = scp02Result.Value;

        var scp03Result = Scp03KeySet.Create(TestMasterKey, TestMasterKey, TestMasterKey, 0x01);
        Assert.That(scp03Result.IsSuccess, Is.True, "SCP03 keyset creation should succeed");
        _scp03Keys = scp03Result.Value;
    }

    [Test]
    public void TraceValidationState_Create_Should_Initialize_Correctly()
    {
        var state = TraceValidationState.Create(_scp02Keys);

        Assert.That(state.KeyMaterial.CurrentKeys, Is.EqualTo(_scp02Keys));
        Assert.That(state.KeyMaterial.MasterKeys, Is.EqualTo(_scp02Keys));
        Assert.That(state.KeyMaterial.Diversification.HasValue, Is.False);
        Assert.That(state.SessionKeys.HasValue, Is.False);
        Assert.That(state.CommandIcv.HasValue, Is.False);
        Assert.That(state.ResponseIcv.HasValue, Is.False);
        Assert.That(state.Results.Count, Is.EqualTo(0));
        Assert.That(state.SecurityLevel, Is.EqualTo(0x00));
        Assert.That(state.ScpVersion, Is.EqualTo(ScpVersion.Scp02));
    }

    [Test]
    public void ValidateExchange_Should_Reject_Empty_Command()
    {
        var state = TraceValidationState.Create(_scp02Keys);
        var emptyCommand = new byte[0];
        var response = Convert.FromHexString("9000");

        var result = TraceValidation.ValidateExchange(state, emptyCommand, response, 1);

        Assert.That(result.IsFailure, Is.True);
        Assert.That(result.Error.Message, Does.Contain("Command cannot be empty"));
    }

    [Test]
    public void ValidateExchange_Should_Validate_Simple_Select_Command()
    {
        var state = TraceValidationState.Create(_scp02Keys);
        var selectCommand = Convert.FromHexString("00A4040000");
        var selectResponse = Convert.FromHexString("6F108408A000000151000000A5049F6501FF9000");

        var result = TraceValidation.ValidateExchange(state, selectCommand, selectResponse, 1);

        Assert.That(result.IsSuccess, Is.True);

        if (result.IsSuccess)
        {
            var newState = result.Value;
            Assert.That(newState.Results.Count, Is.EqualTo(1));
            var validationResult = newState.Results.First();
            Assert.That(validationResult.IsValid, Is.True);
            Assert.That(validationResult.ValidationType, Is.EqualTo("STRUCTURE"));
            Assert.That(
                validationResult.Details,
                Does.Contain("Non-secure command structure validated")
            );
        }
    }

    [Test]
    public void ValidateExchange_Should_Handle_Command_Too_Short()
    {
        var state = TraceValidationState.Create(_scp02Keys);
        var shortCommand = Convert.FromHexString("00A4"); // Too short for proper APDU
        var response = Convert.FromHexString("9000");

        var result = TraceValidation.ValidateExchange(state, shortCommand, response, 1);

        Assert.That(result.IsSuccess, Is.True); // Should succeed but mark as invalid structure

        if (result.IsSuccess)
        {
            var newState = result.Value;
            Assert.That(newState.Results.Count, Is.EqualTo(1));
            var validationResult = newState.Results.First();
            Assert.That(validationResult.IsValid, Is.False);
            Assert.That(validationResult.ValidationType, Is.EqualTo("STRUCTURE"));
        }
    }

    [Test]
    public void ValidateExchange_Should_Handle_Secure_Command_Without_Session()
    {
        var state = TraceValidationState.Create(_scp02Keys).WithSecurityLevel(0x01); // C-MAC enabled but no session keys

        var secureCommand = Convert.FromHexString("84CA9F7F00081122334455667788"); // Secure command with MAC
        var response = Convert.FromHexString("9000");

        var result = TraceValidation.ValidateExchange(state, secureCommand, response, 1);

        Assert.That(result.IsSuccess, Is.True);

        if (result.IsSuccess)
        {
            var newState = result.Value;
            Assert.That(newState.Results.Count, Is.GreaterThan(0));
            var validationResult = newState.Results.First();
            // Should fail validation due to missing session keys
            Assert.That(validationResult.IsValid, Is.False);
            Assert.That(validationResult.ValidationType, Is.EqualTo("C-MAC"));
        }
    }


    [Test]
    public void ValidateExchange_Should_Handle_Error_Response()
    {
        var state = TraceValidationState.Create(_scp02Keys);
        var command = Convert.FromHexString("00A4040008A000000151000000");
        var errorResponse = Convert.FromHexString("6A82"); // File not found

        var result = TraceValidation.ValidateExchange(state, command, errorResponse, 1);

        Assert.That(result.IsSuccess, Is.True);

        if (result.IsSuccess)
        {
            var newState = result.Value;
            Assert.That(newState.Results.Count, Is.EqualTo(1));
            var validationResult = newState.Results.First();
            Assert.That(validationResult.IsValid, Is.True); // Error responses are structurally valid
            Assert.That(validationResult.ValidationType, Is.EqualTo("STRUCTURE"));
        }
    }

    [Test]
    public void TraceValidationState_WithMethods_Should_Update_State()
    {
        var state = TraceValidationState.Create(_scp02Keys);
        var newSecurityLevel = (byte)0x03;
        var newScpVersion = ScpVersion.Scp03;

        var updatedState = state.WithSecurityLevel(newSecurityLevel).WithScpVersion(newScpVersion);

        Assert.That(updatedState.SecurityLevel, Is.EqualTo(newSecurityLevel));
        Assert.That(updatedState.ScpVersion, Is.EqualTo(newScpVersion));
        // Original state should be immutable
        Assert.That(state.SecurityLevel, Is.EqualTo(0x00));
        Assert.That(state.ScpVersion, Is.EqualTo(ScpVersion.Scp02));
    }
}
