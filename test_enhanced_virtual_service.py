#!/usr/bin/env python3
"""
Quick test to verify the EnhancedVirtualCardService is working correctly.
This creates a simple test program that uses the enhanced service.
"""

csharp_test_code = '''
using System;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Domain.Keys;

namespace TestEnhancedService
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Testing EnhancedVirtualCardService...");
            
            try
            {
                // Create enhanced service with default cards
                using var service = new EnhancedVirtualCardService();
                
                // List available readers
                var readers = service.GetReaders();
                Console.WriteLine($"Available readers: {string.Join(", ", readers)}");
                
                // Connect to first reader
                if (readers.Count > 0)
                {
                    var connected = service.Connect(readers[0]);
                    Console.WriteLine($"Connected to {readers[0]}: {connected}");
                    
                    if (connected)
                    {
                        // Get ATR
                        var atr = service.GetAtr();
                        if (atr != null)
                        {
                            Console.WriteLine($"ATR: {Convert.ToHexString(atr)}");
                        }
                        
                        // Try to establish secure channel with test keys
                        var testKeys = new byte[] 
                        { 
                            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                            0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F 
                        };
                        
                        var secureChannelEstablished = service.EstablishSecureChannel(testKeys, 0x03);
                        Console.WriteLine($"Secure channel established: {secureChannelEstablished}");
                        Console.WriteLine($"Is secure channel active: {service.IsSecureChannelEstablished}");
                    }
                }
                
                Console.WriteLine("Test completed successfully!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Test failed: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
            }
        }
    }
}
'''

# Write test program to a temp file
with open('/tmp/TestEnhancedService.cs', 'w') as f:
    f.write(csharp_test_code)

print("Created test program at /tmp/TestEnhancedService.cs")
print("This tests the EnhancedVirtualCardService:")
print("1. Creates service with default cards")
print("2. Lists available readers")
print("3. Connects to first reader")
print("4. Gets ATR")
print("5. Attempts secure channel establishment")