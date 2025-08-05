using System;
using System.Text.Json;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Security;
using Gp4Net.Constants;
using CSharpFunctionalExtensions;

class TestScp03Detailed
{
    static void Main()
    {
        // Load the same test vectors
        var jsonContent = System.IO.File.ReadAllText("../scripts/scp03_test_vectors.json");
        var document = JsonDocument.Parse(jsonContent);
        var vectors = document.RootElement.GetProperty("vectors");
        
        Console.WriteLine("Testing all SCP03 vectors in C#...\n");
        
        foreach (var vec in vectors.EnumerateArray())
        {
            var name = vec.GetProperty("name").GetString();
            Console.WriteLine($"Test: {name}");
            
            // Extract test data
            var baseMacKey = Convert.FromHexString(vec.GetProperty("static_keys").GetProperty("mac").GetString());
            var hostChallenge = Convert.FromHexString(vec.GetProperty("challenges").GetProperty("host").GetString());
            var cardChallenge = Convert.FromHexString(vec.GetProperty("challenges").GetProperty("card").GetString());
            var expectedSMac = Convert.FromHexString(vec.GetProperty("expected_session_keys").GetProperty("s_mac").GetString());
            var expectedCardCryptogram = Convert.FromHexString(vec.GetProperty("expected_cryptograms").GetProperty("card").GetString());
            
            var context = new byte[16];
            Array.Copy(hostChallenge, 0, context, 0, 8);
            Array.Copy(cardChallenge, 0, context, 8, 8);
            
            // Derive S-MAC using our KDF
            var kdfService = new KeyDerivationService();
            var sMacResult = kdfService.DeriveScp03Data(baseMacKey, DerivationConstants.SMac, context, 128);
            
            if (sMacResult.IsSuccess)
            {
                var sMacMatch = Convert.ToHexString(sMacResult.Value) == Convert.ToHexString(expectedSMac);
                Console.WriteLine($"  S-MAC match: {sMacMatch}");
                if (!sMacMatch)
                {
                    Console.WriteLine($"    Calculated: {Convert.ToHexString(sMacResult.Value)}");
                    Console.WriteLine($"    Expected:   {Convert.ToHexString(expectedSMac)}");
                }
                
                // Now calculate card cryptogram
                var cryptogramService = new Gp4Net.Domain.Security.CryptogramService();
                var cardCryptogramResult = cryptogramService.CalculateCardCryptogram(
                    sMacResult.Value,
                    hostChallenge,
                    cardChallenge,
                    Maybe<byte[]>.None,
                    ScpVersion.Scp03);
                    
                if (cardCryptogramResult.IsSuccess)
                {
                    var cryptogramMatch = Convert.ToHexString(cardCryptogramResult.Value) == Convert.ToHexString(expectedCardCryptogram);
                    Console.WriteLine($"  Card cryptogram match: {cryptogramMatch}");
                    if (!cryptogramMatch)
                    {
                        Console.WriteLine($"    Calculated: {Convert.ToHexString(cardCryptogramResult.Value)}");
                        Console.WriteLine($"    Expected:   {Convert.ToHexString(expectedCardCryptogram)}");
                    }
                }
                else
                {
                    Console.WriteLine($"  Card cryptogram failed: {cardCryptogramResult.Error.Message}");
                }
            }
            else
            {
                Console.WriteLine($"  S-MAC derivation failed: {sMacResult.Error.Message}");
            }
            
            Console.WriteLine();
        }
    }
}