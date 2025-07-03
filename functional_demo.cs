using System;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Constants;

// Demo program showing the functional virtual card architecture
namespace FunctionalDemo
{
    class Program
    {
        static void Main()
        {
            Console.WriteLine("Functional Virtual Card Architecture Demo");
            Console.WriteLine("=========================================");

            // 1. Create a P71 card using the test builder
            Console.WriteLine("\n1. Creating P71 Virtual Card...");
            var p71Card = VirtualCardTestBuilder.P71Card();
            Console.WriteLine($"   ATR: {Convert.ToHexString(p71Card.GetAtr())}");
            Console.WriteLine($"   Card Type: {p71Card.Configuration.CardType}");
            Console.WriteLine($"   Is Selected: {p71Card.IsSelected}");

            // 2. Test SELECT command
            Console.WriteLine("\n2. Testing SELECT Command...");
            var selectCmd = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 };
            var selectResponse = p71Card.ProcessCommand(selectCmd);
            Console.WriteLine($"   Response SW: {selectResponse.StatusWord:X4}");
            Console.WriteLine($"   Is Selected: {p71Card.IsSelected}");
            Console.WriteLine($"   Response Data Length: {selectResponse.Data.Length}");

            // 3. Test P71 IDENTIFY command
            Console.WriteLine("\n3. Testing P71 IDENTIFY Command...");
            var identifyCmd = new byte[] { 0x80, 0xCA, 0x00, 0xFE, 0x02, 0xDF, 0x28, 0x00 };
            var identifyResponse = p71Card.ProcessCommand(identifyCmd);
            Console.WriteLine($"   Response SW: {identifyResponse.StatusWord:X4}");
            Console.WriteLine($"   Response Data: {Convert.ToHexString(identifyResponse.Data)}");

            // 4. Test unsupported command
            Console.WriteLine("\n4. Testing Unsupported Command...");
            var unsupportedCmd = new byte[] { 0xFF, 0xFF, 0x00, 0x00 };
            var errorResponse = p71Card.ProcessCommand(unsupportedCmd);
            Console.WriteLine($"   Response SW: {errorResponse.StatusWord:X4} (Should be {StatusWords.INSTRUCTION_NOT_SUPPORTED:X4})");

            // 5. Test immutable state
            Console.WriteLine("\n5. Testing Immutable State...");
            var stateBefore = p71Card.CurrentState;
            Console.WriteLine($"   State before reset - Selected: {stateBefore.IsSelected}");
            
            p71Card.Reset();
            var stateAfter = p71Card.CurrentState;
            Console.WriteLine($"   State after reset - Selected: {stateAfter.IsSelected}");
            Console.WriteLine($"   States are different objects: {!ReferenceEquals(stateBefore, stateAfter)}");

            // 6. Test pure functional processing
            Console.WriteLine("\n6. Testing Pure Functional Processing...");
            var config = CardConfiguration.P71();
            var crypto = new TestCryptographicService();
            var initialState = CardState.Initial;
            
            var result1 = FunctionalVirtualCard.ProcessCommandFunctionally(selectCmd, initialState, config, crypto);
            var result2 = FunctionalVirtualCard.ProcessCommandFunctionally(selectCmd, initialState, config, crypto);
            
            Console.WriteLine($"   Pure function call 1 - Success: {result1.IsSuccess}");
            Console.WriteLine($"   Pure function call 2 - Success: {result2.IsSuccess}");
            Console.WriteLine($"   Results are identical: {result1.Value.Item1.StatusWord == result2.Value.Item1.StatusWord}");

            // 7. Test builder pattern
            Console.WriteLine("\n7. Testing Builder Pattern...");
            var customCard = VirtualCardTestBuilder.Builder()
                .AsP71()
                .WithScp(0x03, 0x70)
                .WithTestCrypto()
                .Build();
            
            Console.WriteLine($"   Custom card SCP version: {customCard.Configuration.DefaultScpVersion:X2}");
            Console.WriteLine($"   Custom card SCP implementation: {customCard.Configuration.DefaultScpImplementation:X2}");

            Console.WriteLine("\nDemo completed successfully!");
            Console.WriteLine("The functional architecture provides:");
            Console.WriteLine("- Pure functions that are easy to test");
            Console.WriteLine("- Immutable state for thread safety");
            Console.WriteLine("- Composable configuration");
            Console.WriteLine("- Testable error handling");
            Console.WriteLine("- P71-specific functionality");
        }
    }
}