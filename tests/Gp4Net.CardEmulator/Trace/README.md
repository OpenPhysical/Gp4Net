# APDU Trace Replay System

This directory contains the APDU trace replay system for testing Gp4Net against known-good gpshell traces.

## Overview

The trace replay system allows you to:
1. Parse APDU traces from gpshell logs
2. Create virtual cards that replay responses from traces
3. Test Gp4Net commands against expected behavior
4. Debug protocol implementation differences

## Components

### Core Classes

- **`ApduTrace`** - Represents a complete APDU trace with exchanges
- **`GpShellTraceParser`** - Parses gpshell output into ApduTrace objects
- **`TraceReplayCard`** - Virtual card that replays responses from a trace
- **`TraceReplayCardService`** - Card service integration for testing

### Test Helpers

- **`TraceTestHelpers`** - Assertion methods and utilities for trace testing
- **`TraceDifference`** - Compares traces and reports differences

## Usage

### Basic Example

```csharp
// Load a gpshell trace
var traceService = new TraceReplayCardService();
traceService.LoadTraceFromFile("gpshell_trace.txt");

// Connect to virtual card
traceService.Connect("Trace Replay Reader");

// Execute commands - responses come from trace
var response = traceService.Transmit(selectCommand);
Assert.Equal(0x9000, response.StatusWord);
```

### Parsing Trace Files

```csharp
var parser = new GpShellTraceParser();
var trace = parser.ParseFile("session.log");

// Access parsed data
foreach (var exchange in trace.Exchanges)
{
    Console.WriteLine($"Command: {exchange.GetCommandString()}");
    Console.WriteLine($"Response: {exchange.GetResponseString()}");
}
```

### Comparing Execution with Original Trace

```csharp
// After running commands
var comparison = traceService.CompareWithOriginalTrace();
if (!comparison.AllMatched)
{
    Console.WriteLine(comparison.GenerateReport());
}
```

## Supported gpshell Formats

The parser recognizes various gpshell output formats:

```
# Format 1: Arrow notation
Command -> 00 A4 04 00 00
Response <- 6F 10 90 00

# Format 2: Chevron notation
=> 00 A4 04 00 00
<= 6F 10 90 00

# Format 3: Function notation
send_APDU() -> 00 A4 04 00 00
recv_APDU() <- 6F 10 90 00

# Format 4: APDU labels
C-APDU: 00 A4 04 00 00
R-APDU: 6F 10 90 00

# Format 5: Status word only
>>> 00 C0 00 00 00
<<< SW: 6A 82
```

## Trace Replay Modes

### Strict Mode
- Requires exact command matches
- Useful for regression testing
- Set with: `traceService.ReplayOptions.StrictMode = true`

### Flexible Mode (Default)
- Allows dynamic data in commands (e.g., random challenges)
- Pattern matches on CLA+INS+P1+P2
- Better for protocol testing

## Creating Test Traces

1. Run gpshell with debug output:
   ```bash
   gpshell -debug script.txt > trace.log
   ```

2. Clean up the trace (optional):
   - Remove non-APDU lines
   - Add comments with #
   - Include ATR and reader info

3. Use in tests:
   ```csharp
   [Fact]
   public void TestAgainstGpShellTrace()
   {
       var traceService = new TraceReplayCardService();
       traceService.LoadTraceFromFile("trace.log");
       // ... run test
   }
   ```

## Example Trace File

```
# Example gpshell trace for SCP02 session
Reader: ACS ACR122U 00 00
ATR: 3B 7D 94 00 00 80 31 80 65 B0 83 11 AC 83 00 90 00

# SELECT ISD
=> 00 A4 04 00 00
<= 6F 65 84 08 A0 00 00 00 03 00 00 00 A5 59 90 00

# INITIALIZE UPDATE
=> 80 50 00 00 08 01 02 03 04 05 06 07 08 00
<= 00 00 11 60 01 00 8A 79 0A F9 FF 02 00 11 79 11 36 5D 71 00 A5 A5 EC 63 BB DC 05 CC 90 00

# EXTERNAL AUTHENTICATE
=> 84 82 01 00 10 05 D3 6A 49 FB FB 93 E5 5C 28 DD 08 85 8D CC E5 00
<= 90 00

# GET STATUS
=> 84 F2 80 00 02 4F 00 C0
<= E3 18 4F 08 A0 00 00 00 03 00 00 00 9F 70 07 C5 01 41 9C 11 08 80 90 00
```

## Debugging Tips

1. **Enable flexible mode** for protocol testing with dynamic data
2. **Use strict mode** for exact regression testing
3. **Check the comparison report** to see which commands didn't match
4. **Examine executed exchanges** to see what was actually sent
5. **Parse traces incrementally** to debug parsing issues

## Integration with CI/CD

The trace replay system can be used in CI/CD pipelines:

```csharp
[Theory]
[InlineData("traces/scp02_gp_test_keys.txt")]
[InlineData("traces/scp03_session.txt")]
[InlineData("traces/install_openfips201.txt")]
public void VerifyAgainstKnownTraces(string traceFile)
{
    // Regression test against known-good traces
    var traceService = new TraceReplayCardService();
    traceService.LoadTraceFromFile(traceFile);
    
    // Run operations and verify they match trace
    // ...
}
```