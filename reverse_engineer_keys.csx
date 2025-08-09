#!/usr/bin/env dotnet-script
#r "nuget: BouncyCastle.Cryptography, 2.4.0"

using System;
using System.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

Console.WriteLine("=== Reverse Engineering the Correct Keys ===\n");

// Known values from the log
var hostChallenge = "D23DB65BDA3AB572";
var sequenceCounter = "0005";  
var cardChallenge = "CE8E67158589";
var actualCardCryptogram = "63469C0EB1A6CC00"; // From debug output (this verification PASSES)
var sentHostCryptogram = "A311AB808F8BF83E";
var sentMac = "DF196923ACDE9B8F";

// Helper functions
static byte[] HexToBytes(string hex) => Convert.FromHexString(hex);
static string BytesToHex(byte[] bytes) => Convert.ToHexString(bytes);

// Common GP test key variations
var testKeys = new Dictionary<string, string>
{
    {"Default GP", "404142434445464748494A4B4C4D4E4F"},
    {"All zeros", "00000000000000000000000000000000"},
    {"All ones", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"},
    {"Test pattern 1", "0123456789ABCDEFFEDCBA9876543210"},
    {"Test pattern 2", "404142434445464748494A4B4C4D4E4F"}, // Same as default
    {"EMV test", "FFEEDDCCBBAA99887766554433221100"},
    {"GP spec example", "404142434445464748494A4B4C4D4E4F"} // Confirming default
};

var seqCounterBytes = HexToBytes(sequenceCounter);
var hostChallengeBytes = HexToBytes(hostChallenge);
var cardChallengeBytes = HexToBytes(cardChallenge);
var targetCardCrypto = HexToBytes(actualCardCryptogram);

Console.WriteLine($"Target card cryptogram: {actualCardCryptogram}");
Console.WriteLine($"Host challenge: {hostChallenge}");
Console.WriteLine($"Sequence counter: {sequenceCounter}");
Console.WriteLine($"Card challenge: {cardChallenge}");
Console.WriteLine();

// Test each key variation
foreach (var (keyName, keyHex) in testKeys)
{
    Console.WriteLine($"Testing {keyName}: {keyHex}");
    
    var baseKey = HexToBytes(keyHex);
    
    // Derive S-ENC session key  
    var sEncKey = DeriveScp02SessionKey(baseKey, new byte[] {0x01, 0x82}, seqCounterBytes);
    
    // Calculate card cryptogram data per SCP02 spec E.4.2.1:
    // Host Challenge (8) + Sequence Counter (2) + Card Challenge (6) + padding
    var cardCryptogramData = hostChallengeBytes
        .Concat(seqCounterBytes)
        .Concat(cardChallengeBytes)
        .Concat(new byte[] { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
        .ToArray();
    
    var calculatedCardCrypto = CalculateFull3DesMac(sEncKey, cardCryptogramData);
    
    Console.WriteLine($"  S-ENC session key: {BytesToHex(sEncKey)}");
    Console.WriteLine($"  Calculated card cryptogram: {BytesToHex(calculatedCardCrypto)}");
    
    bool matches = BytesToHex(calculatedCardCrypto) == actualCardCryptogram;
    Console.WriteLine($"  Matches target: {matches}");
    
    if (matches)
    {
        Console.WriteLine($"🎯 FOUND CORRECT BASE KEY: {keyName} = {keyHex}");
        
        // Now calculate what the host cryptogram should be
        var hostCryptogramData = seqCounterBytes
            .Concat(cardChallengeBytes)  
            .Concat(hostChallengeBytes)
            .Concat(new byte[] { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
            .ToArray();
        
        var correctHostCrypto = CalculateFull3DesMac(sEncKey, hostCryptogramData);
        Console.WriteLine($"  Correct host cryptogram should be: {BytesToHex(correctHostCrypto)}");
        Console.WriteLine($"  Actually sent: {sentHostCryptogram}");
        Console.WriteLine($"  Host crypto correct: {BytesToHex(correctHostCrypto) == sentHostCryptogram}");
        
        // Calculate correct MAC
        var sMacKey = DeriveScp02SessionKey(baseKey, new byte[] {0x01, 0x01}, seqCounterBytes);
        var extAuthCommand = HexToBytes("8482010010" + BytesToHex(correctHostCrypto));
        var paddedCommand = extAuthCommand.Concat(new byte[] { 0x80 }).ToArray();
        while (paddedCommand.Length % 8 != 0)
            paddedCommand = paddedCommand.Concat(new byte[] { 0x00 }).ToArray();
        
        var correctMac = CalculateRetailMac(sMacKey, paddedCommand);
        Console.WriteLine($"  Correct C-MAC should be: {BytesToHex(correctMac)}");
        Console.WriteLine($"  Actually sent: {sentMac}");
        Console.WriteLine($"  C-MAC correct: {BytesToHex(correctMac) == sentMac}");
    }
    
    Console.WriteLine();
}

Console.WriteLine("If no keys matched, the card might be using:");
Console.WriteLine("1. Diversified keys based on the key diversification data");
Console.WriteLine("2. A different set of test keys not in this list");
Console.WriteLine("3. Card-specific keys");

// Key derivation function matching the codebase
static byte[] DeriveScp02SessionKey(byte[] baseKey, byte[] derivationConstant, byte[] sequenceCounter)
{
    var derivationData = new byte[16];
    Array.Copy(derivationConstant, 0, derivationData, 0, 2);
    Array.Copy(sequenceCounter, 0, derivationData, 2, 2);
    
    var zeroIv = new byte[8];
    var cipher = new BufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()));
    cipher.Init(true, new ParametersWithIV(new KeyParameter(baseKey), zeroIv));

    var sessionKey = new byte[cipher.GetOutputSize(derivationData.Length)];
    var len = cipher.ProcessBytes(derivationData, 0, derivationData.Length, sessionKey, 0);
    cipher.DoFinal(sessionKey, len);
    
    return sessionKey;
}

static byte[] CalculateFull3DesMac(byte[] key, byte[] data)
{
    var expandedKey = key.Length == 16 ? key.Concat(key[0..8]).ToArray() : key;
    
    var cipher = new CbcBlockCipher(new DesEdeEngine());
    cipher.Init(true, new ParametersWithIV(new KeyParameter(expandedKey), new byte[8]));
    
    var currentBlock = new byte[8];
    for (int i = 0; i < data.Length; i += 8)
    {
        cipher.ProcessBlock(data, i, currentBlock, 0);
    }
    
    return currentBlock;
}

static byte[] CalculateRetailMac(byte[] key, byte[] data)
{
    var expandedKey = key.Length == 16 ? key.Concat(key[0..8]).ToArray() : key;
    
    var desKey = expandedKey[0..8];
    var desCipher = new CbcBlockCipher(new DesEngine());
    desCipher.Init(true, new ParametersWithIV(new KeyParameter(desKey), new byte[8]));
    
    var currentBlock = new byte[8];
    int numBlocks = data.Length / 8;
    
    for (int i = 0; i < numBlocks - 1; i++)
    {
        desCipher.ProcessBlock(data, i * 8, currentBlock, 0);
    }
    
    var tripleDesCipher = new CbcBlockCipher(new DesEdeEngine());
    tripleDesCipher.Init(true, new ParametersWithIV(new KeyParameter(expandedKey), currentBlock));
    
    var result = new byte[8];
    tripleDesCipher.ProcessBlock(data, (numBlocks - 1) * 8, result, 0);
    
    return result;
}