using System;
using Gp4Net.Constants;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Keys;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Kdf.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

class Program
{
    static void Main()
    {
        // Exact data from GP Pro trace
        var staticKeys = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var hostChallenge = Convert.FromHexString("FE0530CF61BAA9F3");
        var cardChallenge = Convert.FromHexString("83FA042C5C10F778");
        
        // Expected session keys from GP Pro
        var expectedSEnc = Convert.FromHexString("7392646744DF8721131C4A995A845BAE");
        var expectedSMac = Convert.FromHexString("CD9F750E543E0CF862B0EA73E3812113");
        var expectedSRMac = Convert.FromHexString("D1B695D89DE01992B6CB238BDFB006D9");
        
        Console.WriteLine("=== SCP03 KDF Structure Debug ===");
        Console.WriteLine($"Static keys: {Convert.ToHexString(staticKeys)}");
        Console.WriteLine($"Host challenge: {Convert.ToHexString(hostChallenge)}");
        Console.WriteLine($"Card challenge: {Convert.ToHexString(cardChallenge)}");
        Console.WriteLine();
        
        // Context is concatenation of host and card challenges
        var context = new byte[16];
        Array.Copy(hostChallenge, 0, context, 0, 8);
        Array.Copy(cardChallenge, 0, context, 8, 8);
        Console.WriteLine($"Context: {Convert.ToHexString(context)}");
        Console.WriteLine();
        
        // Build the fixed input for S-ENC derivation exactly as our implementation does
        var keyLengthBits = 128;
        var fixedInput = new byte[11 + 1 + 1 + 1 + 2 + context.Length]; // Total: 32 bytes
        var offset = 0;
        
        // Label (11 bytes of 0x00)
        Array.Copy(DerivationConstants.Scp03Label, 0, fixedInput, offset, 11);
        offset += 11;
        
        // Separator
        fixedInput[offset++] = 0x00;
        
        // Derivation constant for S-ENC
        fixedInput[offset++] = DerivationConstants.SEnc; // 0x04
        
        // Separator
        fixedInput[offset++] = 0x00;
        
        // L (length in bits as 2-byte big-endian)
        fixedInput[offset++] = (byte)(keyLengthBits >> 8);
        fixedInput[offset++] = (byte)keyLengthBits;
        
        // Context
        Array.Copy(context, 0, fixedInput, offset, context.Length);
        
        Console.WriteLine($"Fixed input for S-ENC: {Convert.ToHexString(fixedInput)}");
        Console.WriteLine($"Fixed input length: {fixedInput.Length} bytes");
        Console.WriteLine();
        
        // The full KDF input would be: 01 || fixedInput
        var fullKdfInput = new byte[1 + fixedInput.Length];
        fullKdfInput[0] = 0x01; // Counter
        Array.Copy(fixedInput, 0, fullKdfInput, 1, fixedInput.Length);
        Console.WriteLine($"Full KDF input (01 + fixed): {Convert.ToHexString(fullKdfInput)}");
        Console.WriteLine($"Full KDF input length: {fullKdfInput.Length} bytes");
        Console.WriteLine();
        
        // Now test with raw AES-CMAC to see what our KDF library produces
        Console.WriteLine("=== Testing Direct CMAC-AES ===");
        var cmac = new CMac(new AesEngine(), 128); // 128-bit MAC
        cmac.Init(new KeyParameter(staticKeys));
        cmac.BlockUpdate(fullKdfInput, 0, fullKdfInput.Length);
        
        var directMac = new byte[16];
        cmac.DoFinal(directMac, 0);
        Console.WriteLine($"Direct CMAC-AES result: {Convert.ToHexString(directMac)}");
        Console.WriteLine($"Expected S-ENC:        {Convert.ToHexString(expectedSEnc)}");
        Console.WriteLine($"Match: {Convert.ToHexString(directMac) == Convert.ToHexString(expectedSEnc)}");
        Console.WriteLine();
        
        // Test our actual KDF implementation
        Console.WriteLine("=== Testing Our KDF Implementation ===");
        var keySet = new Scp03KeySet(staticKeys, staticKeys, staticKeys, 1);
        var sessionKeys = KeyDerivation.DeriveScp03SessionKeys(keySet, hostChallenge, cardChallenge, 128);
        
        Console.WriteLine($"Our S-ENC:  {Convert.ToHexString(sessionKeys.SEnc)}");
        Console.WriteLine($"Expected:   {Convert.ToHexString(expectedSEnc)}");
        Console.WriteLine($"Match: {Convert.ToHexString(sessionKeys.SEnc) == Convert.ToHexString(expectedSEnc)}");
        Console.WriteLine();
        
        // Test with the Kdf108 library directly
        Console.WriteLine("=== Testing Kdf108 Library Directly ===");
        var kdfOptions = new KdfOptions(
            prfType: PrfType.CmacAes128,
            counterLengthBits: 8,
            useCounter: true,
            counterLocation: CounterLocation.BeforeFixed
        );
        
        var kdf = new CounterModeKdf();
        var kdfResult = kdf.DeriveWithSplitFixedInput(
            staticKeys,
            new byte[0],
            fixedInput,
            128,
            kdfOptions
        );
        
        Console.WriteLine($"Kdf108 result: {Convert.ToHexString(kdfResult)}");
        Console.WriteLine($"Expected:     {Convert.ToHexString(expectedSEnc)}");
        Console.WriteLine($"Match: {Convert.ToHexString(kdfResult) == Convert.ToHexString(expectedSEnc)}");
    }
}