using System;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Protocol;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Protocol;

/// <summary>
/// Tests for pure SCP02 cryptographic functions using known values from GP Pro trace.
/// These tests help identify exactly which cryptographic operation differs from the specification.
/// </summary>
[TestFixture]
[Category("Cryptography")]
[Category("FailHard")]
public class Scp02CryptographyTests
{
    // Known values from working GP Pro trace (from scp02_CLR.log)
    private readonly byte[] _masterKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
    private readonly byte[] _kdd = Convert.FromHexString("00002345558083204839"); // Key Diversification Data
    private readonly byte[] _sequenceCounter = Convert.FromHexString("0011");
    private readonly byte[] _hostChallenge = Convert.FromHexString("719426F20E234840");
    private readonly byte[] _cardChallenge = Convert.FromHexString("C284EC19415D"); // 6 bytes only
    
    // Expected results from GP Pro CLR log
    private readonly byte[] _expectedSessionEnc = Convert.FromHexString("6DCE2A99BACB5207A7A96A92F114D66C");
    private readonly byte[] _expectedSessionMac = Convert.FromHexString("0D446132B168F75CD6F0A780693A4DD3");
    private readonly byte[] _expectedCardCryptogram = Convert.FromHexString("17F4198ADCD5102D");
    private readonly byte[] _expectedHostCryptogram = Convert.FromHexString("8E69F9E4D246FF36");

    [Test]
    public void DeriveScp02SessionKey_WithEncConstant_ShouldMatchGpPro()
    {
        // Arrange
        var encConstant = Convert.FromHexString("0182"); // SCP02 S-ENC constant

        // Act
        var result = Scp02Cryptography.DeriveScp02SessionKey(_masterKey, encConstant, _sequenceCounter);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var derivedKey = result.Value;
        
        TestContext.Out.WriteLine($"Master Key:       {Convert.ToHexString(_masterKey)}");
        TestContext.Out.WriteLine($"Derivation Const: {Convert.ToHexString(encConstant)}");
        TestContext.Out.WriteLine($"Sequence Counter: {Convert.ToHexString(_sequenceCounter)}");
        TestContext.Out.WriteLine($"Expected S-ENC:   {Convert.ToHexString(_expectedSessionEnc)}");
        TestContext.Out.WriteLine($"Actual S-ENC:     {Convert.ToHexString(derivedKey)}");

        _ = derivedKey.Should().Equal(_expectedSessionEnc);
    }

    [Test]
    public void DeriveScp02SessionKey_WithMacConstant_ShouldMatchGpPro()
    {
        // Arrange
        var macConstant = Convert.FromHexString("0101"); // SCP02 C-MAC constant

        // Act
        var result = Scp02Cryptography.DeriveScp02SessionKey(_masterKey, macConstant, _sequenceCounter);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var derivedKey = result.Value;
        
        TestContext.Out.WriteLine($"Master Key:       {Convert.ToHexString(_masterKey)}");
        TestContext.Out.WriteLine($"Derivation Const: {Convert.ToHexString(macConstant)}");
        TestContext.Out.WriteLine($"Sequence Counter: {Convert.ToHexString(_sequenceCounter)}");
        TestContext.Out.WriteLine($"Expected S-MAC:   {Convert.ToHexString(_expectedSessionMac)}");
        TestContext.Out.WriteLine($"Actual S-MAC:     {Convert.ToHexString(derivedKey)}");

        _ = derivedKey.Should().Equal(_expectedSessionMac);
    }

    [Test]
    public void BuildScp02CardCryptogramData_ShouldMatchSpecification()
    {
        // Act
        var result = Scp02Cryptography.BuildScp02CardCryptogramData(
            _hostChallenge, _sequenceCounter, _cardChallenge);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var cryptogramData = result.Value;

        // Expected: Host Challenge (8) || Sequence Counter (2) || Card Challenge (6) || Padding
        _ = cryptogramData.Length.Should().Be(24);

        // Verify structure
        _ = cryptogramData[..8].Should().Equal(_hostChallenge);
        _ = cryptogramData[8..10].Should().Equal(_sequenceCounter);
        _ = cryptogramData[10..16].Should().Equal(_cardChallenge);
        _ = cryptogramData[16].Should().Be(0x80); // ISO padding
        _ = cryptogramData[17..].Should().Equal(new byte[7]); // Zeros
        
        TestContext.Out.WriteLine($"Card Cryptogram Data: {Convert.ToHexString(cryptogramData)}");
    }

    [Test]
    public void CalculateScp02Mac_CardCryptogram_ShouldMatchGpPro()
    {
        // Arrange - Build card cryptogram data
        var cryptogramDataResult = Scp02Cryptography.BuildScp02CardCryptogramData(
            _hostChallenge, _sequenceCounter, _cardChallenge);
        _ = cryptogramDataResult.IsSuccess.Should().BeTrue();
        var cryptogramData = cryptogramDataResult.Value;

        // Act - Calculate cryptogram using S-ENC key (per SCP02 spec)
        var result = Scp02Cryptography.CalculateScp02Cryptogram(_expectedSessionEnc, cryptogramData);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var mac = result.Value;
        
        TestContext.Out.WriteLine($"Cryptogram Data:      {Convert.ToHexString(cryptogramData)}");
        TestContext.Out.WriteLine($"S-ENC Key:            {Convert.ToHexString(_expectedSessionEnc)}");
        TestContext.Out.WriteLine($"Expected Cryptogram:  {Convert.ToHexString(_expectedCardCryptogram)}");
        TestContext.Out.WriteLine($"Actual Cryptogram:    {Convert.ToHexString(mac)}");

        _ = mac.Should().Equal(_expectedCardCryptogram);
    }

    [Test]
    public void BuildScp02HostCryptogramData_ShouldMatchSpecification()
    {
        // Act
        var result = Scp02Cryptography.BuildScp02HostCryptogramData(
            _sequenceCounter, _cardChallenge, _hostChallenge);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var cryptogramData = result.Value;

        // Expected: Sequence Counter (2) || Card Challenge (6) || Host Challenge (8) || Padding
        _ = cryptogramData.Length.Should().Be(24);

        // Verify structure
        _ = cryptogramData[..2].Should().Equal(_sequenceCounter);
        _ = cryptogramData[2..8].Should().Equal(_cardChallenge);
        _ = cryptogramData[8..16].Should().Equal(_hostChallenge);
        _ = cryptogramData[16].Should().Be(0x80); // ISO padding
        _ = cryptogramData[17..].Should().Equal(new byte[7]); // Zeros
        
        TestContext.Out.WriteLine($"Host Cryptogram Data: {Convert.ToHexString(cryptogramData)}");
    }

    [Test]
    public void CalculateScp02Mac_HostCryptogram_ShouldMatchGpPro()
    {
        // Arrange - Build host cryptogram data
        var cryptogramDataResult = Scp02Cryptography.BuildScp02HostCryptogramData(
            _sequenceCounter, _cardChallenge, _hostChallenge);
        _ = cryptogramDataResult.IsSuccess.Should().BeTrue();
        var cryptogramData = cryptogramDataResult.Value;

        // Act - Calculate cryptogram using S-ENC key (per SCP02 spec)
        var result = Scp02Cryptography.CalculateScp02Cryptogram(_expectedSessionEnc, cryptogramData);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var mac = result.Value;
        
        TestContext.Out.WriteLine($"Cryptogram Data:      {Convert.ToHexString(cryptogramData)}");
        TestContext.Out.WriteLine($"S-ENC Key:            {Convert.ToHexString(_expectedSessionEnc)}");
        TestContext.Out.WriteLine($"Expected Cryptogram:  {Convert.ToHexString(_expectedHostCryptogram)}");
        TestContext.Out.WriteLine($"Actual Cryptogram:    {Convert.ToHexString(mac)}");

        _ = mac.Should().Equal(_expectedHostCryptogram);
    }

    [Test]
    public void Iso7816Padding_ShouldPadCorrectly()
    {
        // Arrange
        var data = new byte[] { 0x01, 0x02, 0x03 };

        // Act
        var paddedResult = Scp02Cryptography.ApplyIso7816Padding(data, 8);

        // Assert
        _ = paddedResult.IsSuccess.Should().BeTrue();
        var padded = paddedResult.Value;
        _ = padded.Length.Should().Be(8);
        _ = padded[0..3].Should().Equal(data);
        _ = padded[3].Should().Be(0x80);
        _ = padded[4..].Should().Equal(new byte[4]);
    }

    // Removed: DeriveScp02SessionKey_WithNullBaseKey_ShouldFailHard
    // NO NULLS rule - nulls should be converted to Result<T> at boundaries, not checked in domain

    // Removed: DeriveScp02SessionKey_WithNullDerivationConstant_ShouldFailHard
    // NO NULLS rule - nulls should be converted to Result<T> at boundaries, not checked in domain

    // Removed: DeriveScp02SessionKey_WithNullSequenceCounter_ShouldFailHard
    // NO NULLS rule - nulls should be converted to Result<T> at boundaries, not checked in domain

    [Test]
    public void DeriveScp02SessionKey_WithInvalidKeyLength_ShouldFailHard()
    {
        // Arrange
        var encConstant = Convert.FromHexString("0182");
        var testCases = new[]
        {
            ([], "Empty key"),
            (new byte[8], "8-byte key"),
            (new byte[12], "12-byte key"),
            (new byte[24], "24-byte key"),
            (new byte[32], "32-byte key")
        };
        
        foreach (var (invalidKey, description) in testCases)
        {
            // Act
            var result = Scp02Cryptography.DeriveScp02SessionKey(invalidKey, encConstant, _sequenceCounter);

            // Assert
            _ = result.IsFailure.Should().BeTrue($"{description} should be rejected");
            _ = result.Error.Should().BeOfType<InvalidLengthError>();
            var lengthError = (InvalidLengthError)result.Error;
            _ = lengthError.Expected.Should().Be(16);
            
            TestContext.Out.WriteLine($"✓ {description} correctly rejected: {result.Error.Message}");
        }
    }

    [Test]
    public void DeriveScp02SessionKey_WithInvalidDerivationConstantLength_ShouldFailHard()
    {
        // Arrange
        var testCases = new[]
        {
            ([], "Empty derivation constant"),
            (new byte[1], "1-byte derivation constant"),
            (new byte[3], "3-byte derivation constant"),
            (new byte[4], "4-byte derivation constant")
        };
        
        foreach (var (invalidConstant, description) in testCases)
        {
            // Act
            var result = Scp02Cryptography.DeriveScp02SessionKey(_masterKey, invalidConstant, _sequenceCounter);

            // Assert
            _ = result.IsFailure.Should().BeTrue($"{description} should be rejected");
            _ = result.Error.Should().BeOfType<InvalidLengthError>();
            var lengthError = (InvalidLengthError)result.Error;
            _ = lengthError.Expected.Should().Be(2);
            
            TestContext.Out.WriteLine($"✓ {description} correctly rejected: {result.Error.Message}");
        }
    }

    [Test]
    public void DeriveScp02SessionKey_WithInvalidSequenceCounterLength_ShouldFailHard()
    {
        // Arrange
        var encConstant = Convert.FromHexString("0182");
        var testCases = new[]
        {
            ([], "Empty sequence counter"),
            (new byte[1], "1-byte sequence counter"),
            (new byte[3], "3-byte sequence counter"),
            (new byte[4], "4-byte sequence counter")
        };
        
        foreach (var (invalidCounter, description) in testCases)
        {
            // Act
            var result = Scp02Cryptography.DeriveScp02SessionKey(_masterKey, encConstant, invalidCounter);

            // Assert
            _ = result.IsFailure.Should().BeTrue($"{description} should be rejected");
            _ = result.Error.Should().BeOfType<InvalidLengthError>();
            var lengthError = (InvalidLengthError)result.Error;
            _ = lengthError.Expected.Should().Be(2);
            
            TestContext.Out.WriteLine($"✓ {description} correctly rejected: {result.Error.Message}");
        }
    }

    [Test]
    public void CalculateScp02Mac_WithKnownValues_ShouldMatchGpPro()
    {
        // Arrange - From GP Pro trace CLR log
        var macKey = Convert.FromHexString("0D446132B168F75CD6F0A780693A4DD3");
        var commandData = Convert.FromHexString("84820000108E69F9E4D246FF36");
        var expectedMac = Convert.FromHexString("9F97E807B91F6318");

        // Act
        var result = Scp02Cryptography.CalculateScp02Mac(macKey, commandData);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var mac = result.Value;
        
        TestContext.Out.WriteLine($"Command Data: {Convert.ToHexString(commandData)}");
        TestContext.Out.WriteLine($"MAC Key:      {Convert.ToHexString(macKey)}");
        TestContext.Out.WriteLine($"Expected MAC: {Convert.ToHexString(expectedMac)}");
        TestContext.Out.WriteLine($"Actual MAC:   {Convert.ToHexString(mac)}");

        _ = mac.Should().Equal(expectedMac);
    }

    // Removed: BuildScp02CardCryptogramData_WithNullInputs_ShouldFailHard
    // NO NULLS rule - nulls should be converted to Result<T> at boundaries, not checked in domain

    [Test]
    public void BuildScp02CardCryptogramData_WithInvalidLengths_ShouldFailHard()
    {
        // Test invalid host challenge lengths
        var invalidHostChallenges = new[]
        {
            ([], "Empty host challenge"),
            (new byte[4], "4-byte host challenge"),
            (new byte[12], "12-byte host challenge")
        };
        
        foreach (var (invalidChallenge, description) in invalidHostChallenges)
        {
            var result = Scp02Cryptography.BuildScp02CardCryptogramData(
                invalidChallenge, _sequenceCounter, _cardChallenge);
            _ = result.IsFailure.Should().BeTrue($"{description} should be rejected");
            _ = result.Error.Should().BeOfType<InvalidLengthError>();
            _ = ((InvalidLengthError)result.Error).Expected.Should().Be(8);
            TestContext.Out.WriteLine($"✓ {description} correctly rejected: {result.Error.Message}");
        }
        
        // Test invalid sequence counter lengths
        var invalidSequenceCounters = new[]
        {
            ([], "Empty sequence counter"),
            (new byte[1], "1-byte sequence counter"),
            (new byte[4], "4-byte sequence counter")
        };
        
        foreach (var (invalidCounter, description) in invalidSequenceCounters)
        {
            var result = Scp02Cryptography.BuildScp02CardCryptogramData(
                _hostChallenge, invalidCounter, _cardChallenge);
            _ = result.IsFailure.Should().BeTrue($"{description} should be rejected");
            _ = result.Error.Should().BeOfType<InvalidLengthError>();
            _ = ((InvalidLengthError)result.Error).Expected.Should().Be(2);
            TestContext.Out.WriteLine($"✓ {description} correctly rejected: {result.Error.Message}");
        }
        
        // Test invalid card challenge lengths
        var invalidCardChallenges = new[]
        {
            ([], "Empty card challenge"),
            (new byte[4], "4-byte card challenge"),
            (new byte[8], "8-byte card challenge")
        };
        
        foreach (var (invalidChallenge, description) in invalidCardChallenges)
        {
            var result = Scp02Cryptography.BuildScp02CardCryptogramData(
                _hostChallenge, _sequenceCounter, invalidChallenge);
            _ = result.IsFailure.Should().BeTrue($"{description} should be rejected");
            _ = result.Error.Should().BeOfType<InvalidLengthError>();
            _ = ((InvalidLengthError)result.Error).Expected.Should().Be(6);
            TestContext.Out.WriteLine($"✓ {description} correctly rejected: {result.Error.Message}");
        }
    }

    // Removed: CalculateScp02Mac_WithNullInputs_ShouldFailHard
    // NO NULLS rule - nulls should be converted to Result<T> at boundaries, not checked in domain

    [Test]
    public void CalculateScp02Mac_WithInvalidKeyLength_ShouldFailHard()
    {
        // Arrange
        var testData = Convert.FromHexString("84820000108E69F9E4D246FF36");
        var testCases = new[]
        {
            ([], "Empty key"),
            (new byte[8], "8-byte key"),
            (new byte[12], "12-byte key"),
            (new byte[24], "24-byte key")
        };
        
        foreach (var (invalidKey, description) in testCases)
        {
            // Act
            var result = Scp02Cryptography.CalculateScp02Mac(invalidKey, testData);

            // Assert
            _ = result.IsFailure.Should().BeTrue($"{description} should be rejected");
            _ = result.Error.Should().BeOfType<InvalidLengthError>();
            var lengthError = (InvalidLengthError)result.Error;
            _ = lengthError.Expected.Should().Be(16);
            
            TestContext.Out.WriteLine($"✓ {description} correctly rejected: {result.Error.Message}");
        }
    }

    [Test]
    public void CalculateScp02Mac_WithEmptyData_ShouldFailHard()
    {
        // Arrange
        var emptyData = new byte[0];
        
        // Act
        var result = Scp02Cryptography.CalculateScp02Mac(_expectedSessionMac, emptyData);

        // Assert
        _ = result.IsFailure.Should().BeTrue("Empty data should be rejected");
        _ = result.Error.Should().BeOfType<EmptyDataError>();
        _ = result.Error.Message.Should().Contain("cannot be empty", "Error should identify empty data");
    }
}