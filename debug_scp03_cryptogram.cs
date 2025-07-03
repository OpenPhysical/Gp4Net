using System;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Protocol;

class Program
{
    static void Main()
    {
        // Exact data from GP Pro trace
        var staticKeys = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var hostChallenge = Convert.FromHexString("FE0530CF61BAA9F3");
        var cardChallenge = Convert.FromHexString("83FA042C5C10F778");
        
        // Expected from GP Pro trace
        var expectedHostCryptogram = Convert.FromHexString("7B54E3B21E27DA5F");
        var expectedCardCryptogram = Convert.FromHexString("148C0CAF84B0E110");
        
        Console.WriteLine("=== SCP03 Cryptogram Debug ===");
        Console.WriteLine($"Host challenge: {Convert.ToHexString(hostChallenge)}");
        Console.WriteLine($"Card challenge: {Convert.ToHexString(cardChallenge)}");
        Console.WriteLine();
        
        // Create session keys (we know these are correct now)
        var keySet = new Scp03KeySet(staticKeys, staticKeys, staticKeys, 1);
        var sessionKeys = KeyDerivation.DeriveScp03SessionKeys(keySet, hostChallenge, cardChallenge, 128);
        
        Console.WriteLine("Session keys:");
        Console.WriteLine($"S-MAC: {Convert.ToHexString(sessionKeys.SMac)}");
        Console.WriteLine();
        
        // Create protocol and mock response
        var protocol = new Scp03Protocol(keySet, 0x70);
        
        // Parse the real response
        var initUpdateResponseBytes = Convert.FromHexString("0370000000000000000001037083FA042C5C10F778148C0CAF84B0E110000002");
        var response = InitializeUpdateResponse.Parse(initUpdateResponseBytes);
        
        // Calculate our host cryptogram
        var actualHostCryptogram = protocol.CalculateHostCryptogram(response, hostChallenge, sessionKeys);
        
        Console.WriteLine("Host cryptogram:");
        Console.WriteLine($"Expected: {Convert.ToHexString(expectedHostCryptogram)}");
        Console.WriteLine($"Actual:   {Convert.ToHexString(actualHostCryptogram)}");
        Console.WriteLine($"Match: {Convert.ToHexString(actualHostCryptogram) == Convert.ToHexString(expectedHostCryptogram)}");
        Console.WriteLine();
        
        // Verify card cryptogram
        var cardCryptogramValid = protocol.VerifyCardCryptogram(response, hostChallenge, sessionKeys);
        Console.WriteLine("Card cryptogram:");
        Console.WriteLine($"Expected: {Convert.ToHexString(expectedCardCryptogram)}");
        Console.WriteLine($"From card: {Convert.ToHexString(response.CardCryptogram)}");
        Console.WriteLine($"Valid: {cardCryptogramValid}");
    }
}