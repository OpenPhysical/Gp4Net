using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using Gp4Net.Cryptography;
using Gp4Net.Extensions;
using NUnit.Framework;
using WSCT.ISO7816;

namespace Gp4Net.Tests.Trace;

/// <summary>
/// Tests that verify our encryption and MAC calculations match actual trace values.
/// These tests prove that the cryptographic validation is working correctly by:
/// 1. Taking known plaintext and keys from trace JSON files
/// 2. Calculating MAC/encryption
/// 3. Verifying the result matches actual values from traces
/// </summary>
[TestFixture]
public class TraceReconstructionTests
{
    private static string GetTraceFilePath(string protocol, string filename)
    {
        return Path.Combine(
            TestContext.CurrentContext.TestDirectory,
            "TestData",
            "Traces",
            "Protocol",
            protocol,
            filename
        );
    }

    [TestCase("SCP02", "gp_pro_scp02_mac.json")]
    [TestCase("SCP02", "gp_pro_scp02_clr.json")]
    public void Should_Verify_SCP02_MAC_Matches_Actual_Trace_Values(
        string protocol,
        string filename
    )
    {
        // Load the actual trace data from JSON
        var traceFile = GetTraceFilePath(protocol, filename);
        if (!File.Exists(traceFile))
        {
            Assert.Ignore($"Trace file not found: {filename}");
            return;
        }

        var json = File.ReadAllText(traceFile);
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        // Extract session data
        var session = root.GetProperty("metadata").GetProperty("sessions")[0];
        var hostChallenge = Convert.FromHexString(
            session.GetProperty("host_challenge").GetString()!
        );

        // Get INITIALIZE UPDATE response to extract card data
        var exchanges = root.GetProperty("exchanges").EnumerateArray().ToList();
        var initUpdateExchange = exchanges.First(e =>
            e.GetProperty("description").GetString() == "INITIALIZE UPDATE"
        );
        var initUpdateResponseHex = Convert.FromHexString(
            initUpdateExchange.GetProperty("response").GetString()!.Replace("9000", "")
        );

        // Parse INITIALIZE UPDATE response using domain parser
        var initUpdateResponseResult = Gp4Net.Domain.Commands.InitializeUpdateResponse.Parse(
            initUpdateResponseHex
        );
        Assert.That(
            initUpdateResponseResult.IsSuccess,
            Is.True,
            "Failed to parse INITIALIZE UPDATE response"
        );
        var initUpdateResponse = initUpdateResponseResult.Value;

        var cardChallenge = initUpdateResponse.CardChallenge;
        var cardCryptogram = initUpdateResponse.CardCryptogram;

        // Get EXTERNAL AUTHENTICATE to extract host cryptogram and its MAC
        var extAuthExchange = exchanges.First(e =>
            e.GetProperty("description").GetString() == "EXTERNAL AUTHENTICATE"
        );
        var extAuthCommandBytes = Convert.FromHexString(
            extAuthExchange.GetProperty("command").GetString()!
        );

        // Parse EXTERNAL AUTHENTICATE using WSCT CommandAPDU
        var extAuthCommand = new CommandAPDU(extAuthCommandBytes);

        // Extract MAC using the functional extension method
        // For EXTERNAL AUTHENTICATE, the data contains host cryptogram (8 bytes) + MAC (8 bytes)
        var extAuthMacInputResult = extAuthCommand.GetMacInput();
        Assert.That(
            extAuthMacInputResult.IsSuccess,
            Is.True,
            "Failed to extract MAC from EXTERNAL AUTHENTICATE"
        );
        var extAuthMac = extAuthMacInputResult.Value.ExtractedMac;

        // Use default test keys (404142434445464748494A4B4C4D4E4F)
        var masterKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");

        // Derive session MAC key for SCP02 using sequence counter from response
        var sMacResult = CryptoOperations.KeyDerivation.DeriveScp02SessionKey(
            masterKey,
            initUpdateResponse.SequenceCounter,
            [0x01, 0x01] // S-MAC derivation constant
        );

        Assert.That(sMacResult.IsSuccess, Is.True, "MAC key derivation should succeed");
        var sMacKey = sMacResult.Value;

        // First, validate EXTERNAL AUTHENTICATE MAC (always present)
        TestContext.Out.WriteLine($"Validating EXTERNAL AUTHENTICATE MAC...");

        // The MAC for EXTERNAL AUTHENTICATE should be calculated over the command
        // Build the MAC input for EXTERNAL AUTHENTICATE
        var extAuthMacInput = new byte[]
        {
            extAuthCommand.Cla,
            extAuthCommand.Ins,
            extAuthCommand.P1,
            extAuthCommand.P2,
            0x10 // Lc = 16 (8 bytes host cryptogram + 8 bytes MAC)
        }
            .Concat(extAuthCommand.Udc.Take(8))
            .ToArray(); // Just the host cryptogram

        // For EXTERNAL AUTHENTICATE, ICV is zeros (first command in secure channel)
        var extAuthIcv = new byte[8];

        // Calculate MAC for EXTERNAL AUTHENTICATE
        var extAuthMacResult = CryptoOperations.ScpOperations.Scp02.CalculateMac(
            sMacKey,
            extAuthMacInput,
            extAuthIcv
        );

        Assert.That(
            extAuthMacResult.IsSuccess,
            Is.True,
            "EXTERNAL AUTHENTICATE MAC calculation should succeed"
        );
        var calculatedExtAuthMac = extAuthMacResult.Value.Take(8).ToArray();

        TestContext.Out.WriteLine(
            $"EXTERNAL AUTHENTICATE Expected MAC: {Convert.ToHexString(extAuthMac)}"
        );
        TestContext.Out.WriteLine(
            $"EXTERNAL AUTHENTICATE Calculated MAC: {Convert.ToHexString(calculatedExtAuthMac)}"
        );

        Assert.That(
            calculatedExtAuthMac,
            Is.EqualTo(extAuthMac),
            $"EXTERNAL AUTHENTICATE MAC must match for {filename}"
        );

        // Try to find a secure GET STATUS command (may not exist in CLR traces)
        var secureGetStatusExchanges = exchanges
            .Where(e =>
                e.GetProperty("description").GetString() == "GET STATUS"
                && e.GetProperty("secure_messaging").GetBoolean()
            )
            .ToList();

        if (!secureGetStatusExchanges.Any())
        {
            TestContext.Out.WriteLine(
                $"No secure GET STATUS commands found in {filename} - skipping GET STATUS MAC validation"
            );
            Assert.Pass($"EXTERNAL AUTHENTICATE MAC validated successfully for {filename}");
            return;
        }

        // If we have secure GET STATUS, validate its MAC too
        var getStatusExchange = secureGetStatusExchanges.First();
        var getStatusCommandBytes = Convert.FromHexString(
            getStatusExchange.GetProperty("command").GetString()!
        );

        // Parse GET STATUS command using WSCT CommandAPDU
        var getStatusCommand = new CommandAPDU(getStatusCommandBytes);

        // Extract MAC and data using the functional extension method
        var macInputResult = getStatusCommand.GetMacInput();
        Assert.That(
            macInputResult.IsSuccess,
            Is.True,
            "Failed to extract MAC input from GET STATUS command"
        );
        var macInput = macInputResult.Value;

        var actualGetStatusMac = macInput.ExtractedMac;
        var getStatusDataWithoutMac = macInput.PlaintextData;

        // The ICV for the first command after EXTERNAL AUTHENTICATE
        // is the MAC from EXTERNAL AUTHENTICATE
        var initialIcv = extAuthMac;

        // GetMacInput extracts with the wrong Lc (doesn't adjust for MAC size)
        // We need to manually build the MAC input with Lc adjusted for MAC
        var macInputBytes = new byte[]
        {
            getStatusCommand.Cla,
            getStatusCommand.Ins,
            getStatusCommand.P1,
            getStatusCommand.P2,
            (byte)(getStatusDataWithoutMac.Length + 8) // Lc adjusted for 8-byte MAC
        }
            .Concat(getStatusDataWithoutMac)
            .ToArray();

        // For SCP02 with C-MAC enabled, the ICV must be encrypted before use
        // (except for EXTERNAL AUTHENTICATE which uses unencrypted ICV)
        // Since this is GET STATUS (INS=0xF2), we need to encrypt the ICV
        var encryptedIcvResult = CryptoOperations.Mac.EncryptScp02Icv(initialIcv, sMacKey);
        Assert.That(encryptedIcvResult.IsSuccess, Is.True, "ICV encryption should succeed");
        var encryptedIcv = encryptedIcvResult.Value;

        // For SCP02 with security level 01 (C-MAC only), calculate MAC with encrypted ICV
        var macResult = CryptoOperations.ScpOperations.Scp02.CalculateMac(
            sMacKey,
            macInputBytes,
            encryptedIcv
        );

        Assert.That(macResult.IsSuccess, Is.True, "MAC calculation should succeed");
        var calculatedMac = macResult.Value.Take(8).ToArray(); // Truncate to 8 bytes

        TestContext.Out.WriteLine($"Trace file: {filename}");
        TestContext.Out.WriteLine($"Host Challenge: {Convert.ToHexString(hostChallenge)}");
        TestContext.Out.WriteLine(
            $"Sequence Counter: {Convert.ToHexString(initUpdateResponse.SequenceCounter)}"
        );
        TestContext.Out.WriteLine($"Card Challenge: {Convert.ToHexString(cardChallenge)}");
        TestContext.Out.WriteLine($"Session MAC Key: {Convert.ToHexString(sMacKey)}");
        TestContext.Out.WriteLine(
            $"Initial ICV (from EXT AUTH): {Convert.ToHexString(initialIcv)}"
        );
        TestContext.Out.WriteLine(
            $"Encrypted ICV (for C-MAC): {Convert.ToHexString(encryptedIcv)}"
        );
        TestContext.Out.WriteLine($"MAC Input: {Convert.ToHexString(macInputBytes)}");
        TestContext.Out.WriteLine($"Data (no MAC): {Convert.ToHexString(getStatusDataWithoutMac)}");
        TestContext.Out.WriteLine(
            $"Expected MAC from trace: {Convert.ToHexString(actualGetStatusMac)}"
        );
        TestContext.Out.WriteLine($"Calculated MAC:          {Convert.ToHexString(calculatedMac)}");

        // This assertion verifies that our MAC calculation produces
        // the exact same value as in the actual trace
        Assert.That(
            calculatedMac,
            Is.EqualTo(actualGetStatusMac),
            $"Calculated MAC must match the actual MAC from {filename}"
        );
    }

    [TestCase("SCP02", "gp_pro_scp02_enc.json")]
    public void Should_Verify_SCP02_Encryption_With_Actual_Trace_Values(
        string protocol,
        string filename
    )
    {
        // Load the actual trace data from JSON with encryption
        var traceFile = GetTraceFilePath(protocol, filename);
        if (!File.Exists(traceFile))
        {
            Assert.Ignore($"Trace file not found: {filename}");
            return;
        }

        var json = File.ReadAllText(traceFile);
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        // Get INITIALIZE UPDATE response to extract sequence counter
        var exchanges = root.GetProperty("exchanges").EnumerateArray().ToList();
        var initUpdateExchange = exchanges.First(e =>
            e.GetProperty("description").GetString() == "INITIALIZE UPDATE"
        );
        var initUpdateResponseHex = Convert.FromHexString(
            initUpdateExchange.GetProperty("response").GetString()!.Replace("9000", "")
        );

        // Parse INITIALIZE UPDATE response using domain parser
        var initUpdateResponseResult = Gp4Net.Domain.Commands.InitializeUpdateResponse.Parse(
            initUpdateResponseHex
        );
        Assert.That(
            initUpdateResponseResult.IsSuccess,
            Is.True,
            "Failed to parse INITIALIZE UPDATE response"
        );
        var initUpdateResponse = initUpdateResponseResult.Value;

        // Find an encrypted command in the trace
        var encryptedExchanges = exchanges
            .Where(e =>
                e.TryGetProperty("secure_messaging", out var sm)
                && sm.GetBoolean()
                && e.TryGetProperty("scp_data", out var scpData)
                && scpData.TryGetProperty("encrypted_data", out _)
            )
            .ToList();

        if (!encryptedExchanges.Any())
        {
            Assert.Ignore($"No encrypted commands found in {filename}");
            return;
        }

        var encryptedExchange = encryptedExchanges.First();
        var encryptedCommand = Convert.FromHexString(
            encryptedExchange.GetProperty("command").GetString()!
        );
        var scpData = encryptedExchange.GetProperty("scp_data");
        var encryptedData = Convert.FromHexString(
            scpData.GetProperty("encrypted_data").GetString()!
        );
        var plaintextData = Convert.FromHexString(
            scpData.GetProperty("plaintext_data").GetString()!
        );
        // Parse encrypted APDU (SCP02) to allow future structural validations
        var encryptedCmd = new CommandAPDU(encryptedCommand);
        Assert.That(
            encryptedCmd.Udc.Length,
            Is.GreaterThanOrEqualTo(encryptedData.Length),
            "Encrypted APDU data must contain encrypted data (and possibly MAC)"
        );

        // Use default test keys
        var masterKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");

        // Derive S-ENC key for encryption using sequence counter from INITIALIZE UPDATE response
        var sEncResult = CryptoOperations.KeyDerivation.DeriveScp02SessionKey(
            masterKey,
            initUpdateResponse.SequenceCounter,
            [0x01, 0x82] // S-ENC derivation constant
        );

        Assert.That(sEncResult.IsSuccess, Is.True);
        var sEncKey = sEncResult.Value;

        // Apply padding
        var paddedLength = ((plaintextData.Length + 1 + 7) / 8) * 8; // 3DES block size is 8
        var paddedData = new byte[paddedLength];
        Array.Copy(plaintextData, paddedData, plaintextData.Length);
        paddedData[plaintextData.Length] = 0x80;

        // Encrypt with 3DES-CBC
        var encryptResult = CryptoOperations.Cipher.Encrypt3DesCbc(
            sEncKey,
            new byte[8], // Zero IV for SCP02
            paddedData
        );

        Assert.That(encryptResult.IsSuccess, Is.True);
        var calculatedEncrypted = encryptResult.Value;

        TestContext.Out.WriteLine($"Trace file: {filename}");
        TestContext.Out.WriteLine($"Plaintext:  {Convert.ToHexString(plaintextData)}");
        TestContext.Out.WriteLine($"Padded:     {Convert.ToHexString(paddedData)}");
        TestContext.Out.WriteLine($"S-ENC Key:  {Convert.ToHexString(sEncKey)}");
        TestContext.Out.WriteLine($"Expected Encrypted: {Convert.ToHexString(encryptedData)}");
        TestContext.Out.WriteLine(
            $"Calculated Encrypted: {Convert.ToHexString(calculatedEncrypted)}"
        );

        Assert.That(
            calculatedEncrypted,
            Is.EqualTo(encryptedData),
            $"Calculated encryption must match the actual encrypted data from {filename}"
        );
    }
}
