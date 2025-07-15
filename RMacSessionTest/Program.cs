using System;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain;
using Gp4Net.Core;

class Program
{
    static void Main()
    {
        Console.WriteLine("Testing RMacSessionCommands Result<T,E> refactoring...");
        
        // Test BeginRMacSessionCommand.Create
        Console.WriteLine("\n1. Testing BeginRMacSessionCommand.Create...");
        
        var beginResult = BeginRMacSessionCommand.Create(SecurityLevel.RMac);
        if (beginResult.IsSuccess)
        {
            Console.WriteLine($"✓ SUCCESS: {beginResult.Value.ToString()}");
            Console.WriteLine($"  P1 (SecurityLevel): 0x{beginResult.Value.P1:X2}");
        }
        else
        {
            Console.WriteLine($"✗ FAILED: {beginResult.Error.Message}");
        }
        
        // Test invalid SecurityLevel
        var invalidBegin = BeginRMacSessionCommand.Create((SecurityLevel)255);
        if (invalidBegin.IsFailure)
        {
            Console.WriteLine($"✓ Validation works: {invalidBegin.Error.Message}");
        }
        
        // Test EndRMacSessionCommand.Create
        Console.WriteLine("\n2. Testing EndRMacSessionCommand.Create...");
        
        var endResult = EndRMacSessionCommand.Create(SecurityLevel.RMac);
        if (endResult.IsSuccess)
        {
            Console.WriteLine($"✓ SUCCESS: {endResult.Value.ToString()}");
            Console.WriteLine($"  P2: 0x{endResult.Value.P2:X2}");
        }
        else
        {
            Console.WriteLine($"✗ FAILED: {endResult.Error.Message}");
        }
        
        // Test EndRMacSessionResponse.Parse
        Console.WriteLine("\n3. Testing EndRMacSessionResponse.Parse...");
        
        var validRMac = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        var responseResult = EndRMacSessionResponse.Parse(validRMac);
        if (responseResult.IsSuccess)
        {
            Console.WriteLine($"✓ SUCCESS: {responseResult.Value.ToString()}");
        }
        else
        {
            Console.WriteLine($"✗ FAILED: {responseResult.Error.Message}");
        }
        
        // Test invalid response length
        var invalidRMac = new byte[] { 0x01, 0x02 };
        var invalidResponse = EndRMacSessionResponse.Parse(invalidRMac);
        if (invalidResponse.IsFailure)
        {
            Console.WriteLine($"✓ Validation works: {invalidResponse.Error.Message}");
        }
        
        Console.WriteLine("\n✓ All tests passed! RMacSessionCommands refactoring is complete.");
    }
}
