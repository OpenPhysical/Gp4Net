using System;
using System.Linq;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Constants;

// Simple standalone test for the functional virtual card architecture
class FunctionalCardTest
{
    static void Main()
    {
        Console.WriteLine("🧪 Functional Virtual Card Architecture Test");
        Console.WriteLine("===========================================");
        
        var testsPassed = 0;
        var totalTests = 0;
        
        // Test 1: P71 Card Creation and ATR
        totalTests++;
        Console.WriteLine("\n1. Testing P71 Card ATR...");
        try
        {
            var card = VirtualCardTestBuilder.P71Card();
            var atr = card.GetAtr();
            var expectedAtr = Convert.FromHexString("3BD518FF8191FE1FC38073C821100A");
            
            if (atr.Length == expectedAtr.Length && 
                atr.SequenceEqual(expectedAtr))
            {
                Console.WriteLine("   ✅ PASS - ATR matches expected P71 ATR");
                testsPassed++;
            }
            else
            {
                Console.WriteLine($"   ❌ FAIL - ATR mismatch. Got: {Convert.ToHexString(atr)}, Expected: {Convert.ToHexString(expectedAtr)}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"   ❌ FAIL - Exception: {ex.Message}");
        }
        
        // Test 2: SELECT Command Processing
        totalTests++;
        Console.WriteLine("\n2. Testing SELECT Command...");
        try
        {
            var card = VirtualCardTestBuilder.P71Card();
            var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 }; // SELECT with no AID
            var response = card.ProcessCommand(selectCommand);
            
            if (response.StatusWord == StatusWords.SUCCESS && card.IsSelected)
            {
                Console.WriteLine("   ✅ PASS - SELECT command succeeded and card is selected");
                testsPassed++;
            }
            else
            {
                Console.WriteLine($"   ❌ FAIL - SELECT failed. SW: {response.StatusWord:X4}, IsSelected: {card.IsSelected}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"   ❌ FAIL - Exception: {ex.Message}");
        }
        
        // Test 3: P71 IDENTIFY Command
        totalTests++;
        Console.WriteLine("\n3. Testing P71 IDENTIFY Command...");
        try
        {
            var card = VirtualCardTestBuilder.P71Card();
            var identifyCommand = new byte[] { 0x80, 0xCA, 0x00, 0xFE, 0x02, 0xDF, 0x28, 0x00 };
            var response = card.ProcessCommand(identifyCommand);
            
            if (response.StatusWord == StatusWords.SUCCESS && response.Data.Length > 0)
            {
                Console.WriteLine($"   ✅ PASS - IDENTIFY command succeeded with {response.Data.Length} bytes");
                Console.WriteLine($"   Response data starts with: {Convert.ToHexString(response.Data.Take(Math.Min(8, response.Data.Length)).ToArray())}...");
                testsPassed++;
            }
            else
            {
                Console.WriteLine($"   ❌ FAIL - IDENTIFY failed. SW: {response.StatusWord:X4}, Data length: {response.Data.Length}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"   ❌ FAIL - Exception: {ex.Message}");
        }
        
        // Test 4: Unsupported Command
        totalTests++;
        Console.WriteLine("\n4. Testing Unsupported Command...");
        try
        {
            var card = VirtualCardTestBuilder.MinimalCard(); // Card with limited instruction support
            var unsupportedCommand = new byte[] { 0xFF, 0xFF, 0x00, 0x00 };
            var response = card.ProcessCommand(unsupportedCommand);
            
            if (response.StatusWord == StatusWords.INSTRUCTION_NOT_SUPPORTED)
            {
                Console.WriteLine("   ✅ PASS - Unsupported command correctly rejected");
                testsPassed++;
            }
            else
            {
                Console.WriteLine($"   ❌ FAIL - Expected {StatusWords.INSTRUCTION_NOT_SUPPORTED:X4}, got {response.StatusWord:X4}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"   ❌ FAIL - Exception: {ex.Message}");
        }
        
        // Test 5: Immutable State
        totalTests++;
        Console.WriteLine("\n5. Testing Immutable State...");
        try
        {
            var card = VirtualCardTestBuilder.P71Card();
            var initialState = card.CurrentState;
            var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 };
            
            card.ProcessCommand(selectCommand);
            var newState = card.CurrentState;
            
            if (!initialState.IsSelected && newState.IsSelected && !ReferenceEquals(initialState, newState))
            {
                Console.WriteLine("   ✅ PASS - State is properly immutable and updated");
                testsPassed++;
            }
            else
            {
                Console.WriteLine($"   ❌ FAIL - State immutability issue. Initial: {initialState.IsSelected}, New: {newState.IsSelected}, Same ref: {ReferenceEquals(initialState, newState)}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"   ❌ FAIL - Exception: {ex.Message}");
        }
        
        // Test 6: Builder Pattern
        totalTests++;
        Console.WriteLine("\n6. Testing Builder Pattern...");
        try
        {
            var customCard = VirtualCardTestBuilder.Builder()
                .AsP71()
                .WithScp(0x03, 0x70)
                .WithTestCrypto()
                .Build();
            
            if (customCard.Configuration.CardType.Contains("P71") && 
                customCard.Configuration.DefaultScpVersion == 0x03 &&
                customCard.Configuration.DefaultScpImplementation == 0x70)
            {
                Console.WriteLine("   ✅ PASS - Builder pattern works correctly");
                testsPassed++;
            }
            else
            {
                Console.WriteLine($"   ❌ FAIL - Builder pattern issue. Type: {customCard.Configuration.CardType}, SCP: {customCard.Configuration.DefaultScpVersion:X2}:{customCard.Configuration.DefaultScpImplementation:X2}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"   ❌ FAIL - Exception: {ex.Message}");
        }
        
        // Summary
        Console.WriteLine("\n📊 Test Summary");
        Console.WriteLine("===============");
        Console.WriteLine($"Tests Passed: {testsPassed}/{totalTests}");
        Console.WriteLine($"Success Rate: {(double)testsPassed / totalTests * 100:F1}%");
        
        if (testsPassed == totalTests)
        {
            Console.WriteLine("\n🎉 All tests passed! The functional virtual card architecture is working correctly.");
            Environment.Exit(0);
        }
        else
        {
            Console.WriteLine($"\n⚠️  {totalTests - testsPassed} test(s) failed. Please review the issues above.");
            Environment.Exit(1);
        }
    }
}