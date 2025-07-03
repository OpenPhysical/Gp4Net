using System;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Keys;

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
        
        Console.WriteLine("=== SCP03 Key Derivation Debug ===");
        Console.WriteLine($"Static keys: {Convert.ToHexString(staticKeys)}");
        Console.WriteLine($"Host challenge: {Convert.ToHexString(hostChallenge)}");
        Console.WriteLine($"Card challenge: {Convert.ToHexString(cardChallenge)}");
        Console.WriteLine();
        
        // Create SCP03 key set
        var keySet = new Scp03KeySet(staticKeys, staticKeys, staticKeys, 1);
        
        // Derive session keys using our implementation
        var sessionKeys = KeyDerivation.DeriveScp03SessionKeys(keySet, hostChallenge, cardChallenge, 128);
        
        Console.WriteLine("Expected:");
        Console.WriteLine($"S-ENC:  {Convert.ToHexString(expectedSEnc)}");
        Console.WriteLine($"S-MAC:  {Convert.ToHexString(expectedSMac)}");
        Console.WriteLine($"S-RMAC: {Convert.ToHexString(expectedSRMac)}");
        Console.WriteLine();
        
        Console.WriteLine("Actual:");
        Console.WriteLine($"S-ENC:  {Convert.ToHexString(sessionKeys.SEnc)}");
        Console.WriteLine($"S-MAC:  {Convert.ToHexString(sessionKeys.SMac)}");
        Console.WriteLine($"S-RMAC: {Convert.ToHexString(sessionKeys.SRMac)}");
        Console.WriteLine();
        
        Console.WriteLine("Match:");
        Console.WriteLine($"S-ENC:  {Convert.ToHexString(sessionKeys.SEnc) == Convert.ToHexString(expectedSEnc)}");
        Console.WriteLine($"S-MAC:  {Convert.ToHexString(sessionKeys.SMac) == Convert.ToHexString(expectedSMac)}");
        Console.WriteLine($"S-RMAC: {Convert.ToHexString(sessionKeys.SRMac) == Convert.ToHexString(expectedSRMac)}");
    }
}