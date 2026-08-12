# Research: Achieving High Test Coverage in C# .NET 9.0 with Functional Programming

> Historical note: this research targeted the former .NET 9 build. The active projects now target .NET 10.

**Project**: Gp4Net smart card library
**Current Coverage**: 32.73%
**Target**: >60% overall, 100% on security-critical paths
**Date**: 2025-10-15

## Executive Summary

This research addresses best practices for achieving high test coverage in a .NET 9.0 project that enforces strict functional programming principles (Result<T>, Maybe<T>, NO NULLS, NO EXCEPTIONS). The findings focus on five key areas: Coverlet XPlat configuration, async code testing, pure function extraction, property-based testing with FsCheck, and integration testing with real implementations.

---

## 1. Coverlet XPlat Code Coverage Configuration

### Decision: Use ExcludeFromCodeCoverage Attribute Instead of ExcludeByAttribute in .NET 9

**Rationale**:
- .NET 9 has a known bug where using `ExcludeByAttribute` with `GeneratedCodeAttribute` causes no coverage to be collected for the entire assembly
- The issue affects compiler-generated code (like logging methods) and can result in zero coverage for entire assemblies
- Using `[ExcludeFromCodeCoverage]` attribute on specific methods/classes provides granular control without triggering the .NET 9 bug

**Implementation**:

```xml
<!-- coverlet.runsettings -->
<?xml version="1.0" encoding="utf-8" ?>
<RunSettings>
  <DataCollectionRunSettings>
    <DataCollectors>
      <DataCollector friendlyName="XPlat code coverage">
        <Configuration>
          <Format>cobertura</Format>

          <!-- Exclude assemblies/namespaces, NOT attributes in .NET 9 -->
          <Exclude>[Gp4Net.Tool]*</Exclude>

          <!-- DO NOT use ExcludeByAttribute with GeneratedCodeAttribute in .NET 9 -->
          <!-- <ExcludeByAttribute>GeneratedCode</ExcludeByAttribute> -->

          <!-- Safe to exclude CompilerGenerated and ExcludeFromCodeCoverage -->
          <ExcludeByAttribute>ExcludeFromCodeCoverage</ExcludeByAttribute>

          <!-- Exclude build artifacts -->
          <ExcludeByFile>**/obj/**,**/bin/**</ExcludeByFile>
        </Configuration>
      </DataCollector>
    </DataCollectors>
  </DataCollectionRunSettings>
</RunSettings>
```

**For Gp4Net**:

```csharp
using System.Diagnostics.CodeAnalysis;

// Apply to methods you want to exclude
[ExcludeFromCodeCoverage]
private static void DebugLog(string message)
{
    Logger.LogDebug(message);
}

// Or entire classes (like CLI commands focused on display)
[ExcludeFromCodeCoverage]
public class DisplayOnlyCommand { }
```

**Alternatives Considered**:
1. **ExcludeByAttribute with GeneratedCodeAttribute** - Rejected due to .NET 9 bug causing zero coverage
2. **ExcludeByFile patterns** - Useful but doesn't help with compiler-generated state machines
3. **MSBuild integration with coverage filters** - More complex, but offers threshold enforcement

**References**:
- GitHub Issue #1756: .NET 9 generated logger methods with GeneratedCodeAttribute causes no coverage
- GitHub Issue #794: Async methods excluded from coverage after updating to 2.8.1

---

## 2. Testing Async-Heavy Code Without Testing State Machines

### Decision: Test Async Methods Directly; Exclude Async State Machine Branches from Coverage Metrics

**Rationale**:
- C# compiler transforms async methods into state machine classes with `[CompilerGenerated]` attribute
- Coverlet correctly simplifies async/await coverage by skipping compiler-generated branches
- Testing the async method itself (not the state machine) provides meaningful coverage
- Using `await Task.Yield()` in tests ensures proper async execution path coverage

**Implementation**:

```csharp
// Service method (async orchestration)
public static async Task<Result<SecureChannelSession, SmartCardError>> EstablishAsync(
    ISmartCardService cardService,
    IKeySet keySet,
    SecurityLevel securityLevel,
    CancellationToken cancellationToken = default)
{
    // Generate host challenge
    byte[] hostChallenge = new byte[8];
    Random.Shared.NextBytes(hostChallenge);

    // Orchestrate by calling pure functions
    return await SendInitializeUpdate(cardService, hostChallenge, cancellationToken)
        .Bind(async response => await ProcessInitializeUpdate(response, hostChallenge, keySet))
        .Bind(async context => await SendExternalAuthenticate(
            cardService, context, securityLevel, cancellationToken));
}

// Test approach
[Test]
public async Task Should_Establish_Secure_Channel_With_Valid_Keys()
{
    // Use real VirtualCardService (no mocks per constitutional requirement)
    var cardService = CreateVirtualCardService();
    var keySet = CreateTestKeySet();

    // Test the async method directly - state machine is compiler-generated
    var result = await ScpService.Establishment.EstablishAsync(
        cardService,
        keySet,
        SecurityLevel.CDecCMac,
        CancellationToken.None
    );

    result.Should().BeSuccess();
    result.Value.State.SecurityLevel.Should().Be(SecurityLevel.CDecCMac);
}
```

**Coverage Strategies**:
1. **Test async methods as units** - Don't worry about state machine coverage
2. **Use `Task.FromResult()` for pure functions** - Enables testing without async overhead
3. **Use `await Task.Yield()` to ensure async path** - Forces continuation scheduling for full coverage
4. **Extract pure logic from async methods** - Move business logic to synchronous pure functions

**Example Pattern from Gp4Net**:

```csharp
// Async orchestration (thin layer)
private static async Task<Result<InitializeUpdateResponse, SmartCardError>> SendInitializeUpdate(
    ISmartCardService cardService,
    byte[] hostChallenge,
    CancellationToken cancellationToken)
{
    // Pure function composition
    var command = InitializeUpdateCommand.Create(0x00, 0x00, hostChallenge);

    // Async I/O (only impure part)
    return await command
        .Bind(cmd => cmd.ToCommandApdu())
        .Map(apdu => apdu.ToBytes())
        .Bind(async bytes => await cardService.SendCommandAsync(bytes, cancellationToken))
        .Bind(response => InitializeUpdateResponse.Parse(response.Data)); // Pure parsing
}

// Pure function (easy to test synchronously)
private static Task<Result<SecureChannelContext, SmartCardError>> ProcessScp02InitializeUpdate(
    InitializeUpdateResponse response,
    byte[] hostChallenge,
    Scp02KeySet keySet)
{
    // All pure function calls, wrapped in Task for composition
    return Task.FromResult(
        CryptoService.KeyDerivation.DeriveSessionKeys(context)
            .Bind(sessionKeys => VerifyScp02CardCryptogram(response, hostChallenge, sessionKeys))
            .Bind(sessionKeys => SecureChannelContext.Create(...))
    );
}
```

**Alternatives Considered**:
1. **Synchronous wrappers around async code** - Creates unnecessary complexity
2. **Mocking async dependencies** - Violates constitutional "NO MOCKS" requirement
3. **Testing state machine internals** - Not recommended; test observable behavior

**References**:
- Microsoft Learn: Unit Testing Asynchronous Code (2014, still relevant)
- Coverlet PR #549: Fix and simplify async coverage
- Code Coverage with Async Await (dwayneneed.github.io)

---

## 3. Testing Pure Business Logic: Extracting Testable Functions from Services

### Decision: Apply "Functional Core, Imperative Shell" Pattern with Explicit Pure Function Extraction

**Rationale**:
- Pure functions are inherently testable (no mocks, no setup, deterministic)
- Async orchestration services should be thin wrappers around pure business logic
- Extracting pure functions increases coverage by making logic testable without I/O
- Gp4Net already follows this pattern in CryptoService (all pure functions)

**Pattern Implementation**:

```csharp
// BEFORE: Logic mixed with I/O (harder to test)
public async Task<Result<bool, Error>> ProcessCardCommand(string readerName)
{
    var reader = await FindReader(readerName); // I/O
    if (!reader.IsSuccess) return false;

    var data = await reader.Value.SendCommand(cmd); // I/O
    if (!data.IsSuccess) return false;

    var validated = ValidateResponse(data.Value); // Logic
    return validated;
}

// AFTER: Pure logic extracted (easy to test)
// PURE FUNCTION - 100% testable without I/O
public static Result<ResponseData, Error> ValidateAndProcessResponse(
    byte[] rawResponse,
    byte[] expectedPattern)
{
    return ParseResponse(rawResponse)
        .Bind(parsed => ValidateStructure(parsed))
        .Bind(valid => CheckPattern(valid, expectedPattern))
        .Map(result => new ResponseData(result));
}

// IMPERATIVE SHELL - Thin orchestration (integration test)
public async Task<Result<ResponseData, Error>> ProcessCardCommand(
    string readerName,
    byte[] expectedPattern)
{
    return await FindReader(readerName) // I/O
        .Bind(async reader => await reader.SendCommand(cmd)) // I/O
        .Bind(rawResponse => ValidateAndProcessResponse(rawResponse, expectedPattern)); // Pure
}
```

**Gp4Net Example (from ScpService.cs)**:

```csharp
// PURE FUNCTIONS (all in CryptoService) - 100% unit testable
public static class CryptoService.Cryptogram
{
    public static Result<byte[], SmartCardError> BuildScp02CardCryptogramData(
        InitializeUpdateResponse response,
        byte[] hostChallenge)
    {
        // Pure transformation, deterministic, easy to test
        byte[] data = [
            ..hostChallenge,
            ..response.SequenceCounter,
            ..response.CardChallenge
        ];
        return Result.Success<byte[], SmartCardError>(data);
    }
}

// ORCHESTRATION (in ScpService) - Integration testable with VirtualCardService
private static Result<SessionKeys, SmartCardError> VerifyScp02CardCryptogram(
    InitializeUpdateResponse response,
    byte[] hostChallenge,
    SessionKeys sessionKeys)
{
    // Compose pure functions
    return CryptoService.Cryptogram.BuildScp02CardCryptogramData(response, hostChallenge)
        .Bind(data => CryptoService.ScpOperations.Scp02.CalculateCryptogram(sessionKeys.SEnc, data))
        .Bind(calculated => CryptoService.Utils.CompareBytes(calculated, response.CardCryptogram)
            ? Result.Success<SessionKeys, SmartCardError>(sessionKeys)
            : Result.Failure<SessionKeys, SmartCardError>(
                SmartCardError.AuthenticationFailed("Card cryptogram verification failed")));
}
```

**Testing Approach**:

```csharp
// UNIT TEST: Pure function (fast, no dependencies)
[Test]
public void Should_Build_Scp02_Cryptogram_Data_In_Correct_Order()
{
    var response = CreateInitializeUpdateResponse(
        sequenceCounter: [0x00, 0x01],
        cardChallenge: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
    );
    var hostChallenge = new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

    var result = CryptoService.Cryptogram.BuildScp02CardCryptogramData(response, hostChallenge);

    result.Should().BeSuccess();
    result.Value.Should().Equal([
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // host challenge
        0x00, 0x01,                                      // sequence counter
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF              // card challenge
    ]);
}

// INTEGRATION TEST: Orchestration with real VirtualCardService
[Test]
public async Task Should_Establish_Scp02_Channel_With_Valid_Cryptogram()
{
    var virtualCard = new VirtualCardService();
    virtualCard.SetupTestEnvironment();
    var cardService = TestCardService.Create(virtualCard).Value;

    var result = await ScpService.Establishment.EstablishScp02Async(
        cardService,
        TestKeySet.DefaultScp02,
        SecurityLevel.CDecCMac,
        CancellationToken.None
    );

    result.Should().BeSuccess();
    result.Value.State.Protocol.Should().Be(CryptoService.ScpVersion.Scp02);
}
```

**Extraction Guidelines for Gp4Net**:

1. **Identify candidates**: Methods with complex logic that contain I/O operations
2. **Extract pure logic**: Move calculations, validations, transformations to static methods
3. **Keep I/O thin**: Async methods should orchestrate, not compute
4. **Use Result<T>**: All pure functions return Result for composability
5. **Test pure functions**: Unit tests for business logic (fast, comprehensive)
6. **Test orchestration**: Integration tests for I/O flow (fewer, focused on happy/error paths)

**Candidates in Gp4Net for Extraction** (based on grep results):
- AnalyzeCompatibility (if it exists) - extract compatibility logic from I/O
- CheckKeyInstallationCompatibility - extract validation rules
- DeriveCommandName - likely already pure, ensure it's in a testable location

**Alternatives Considered**:
1. **Test services as monoliths** - Lower coverage, slower tests, harder to maintain
2. **Extract to separate services** - Over-engineering; static pure functions sufficient
3. **Use language-ext effects wrapper** - Adds dependency, Gp4Net already uses CSharpFunctionalExtensions

**References**:
- "Functional core, imperative shell" (Kenneth Lange, MarsBased blog)
- "Testable Code with Pure Functions" (Mark Heath)
- Stack Overflow: Approach to functional core, imperative shell

---

## 4. Property-Based Testing with FsCheck for Cryptographic Invariants

### Decision: Use FsCheck.NUnit with Custom Generators for Cryptographic Property Testing

**Rationale**:
- Property-based testing excels at finding edge cases in cryptographic operations
- FsCheck generates hundreds of test cases automatically, testing invariants
- Cryptographic code has natural invariants (round-trip, size, determinism)
- Gp4Net already has FsCheck.NUnit infrastructure in place

**Common Cryptographic Properties**:

1. **Round-trip (Encryption/Decryption)**:
   ```
   ∀ plaintext, key: decrypt(encrypt(plaintext, key), key) == plaintext
   ```

2. **Determinism**:
   ```
   ∀ input, key: hash(input) == hash(input)  // Same input produces same output
   ```

3. **Size Invariants**:
   ```
   ∀ input: length(mac(input)) == MAC_SIZE  // Fixed output size
   ```

4. **Key Derivation Uniqueness**:
   ```
   ∀ key1, key2: key1 ≠ key2 => deriveSessionKey(key1) ≠ deriveSessionKey(key2)
   ```

5. **Commutative Operations**:
   ```
   ∀ a, b: xor(a, b) == xor(b, a)
   ```

**Implementation Example for Gp4Net**:

```csharp
using FsCheck;
using FsCheck.NUnit;
using NUnit.Framework;

[TestFixture]
public class Scp02CryptographicPropertyTests
{
    // Property: MAC always produces 8-byte output
    [Property(MaxTest = 200)]
    public bool Scp02_Mac_Always_Produces_8_Bytes(byte[] data)
    {
        if (data == null || data.Length == 0)
            return true; // Skip invalid inputs

        var key = GenerateValidScp02Key();
        var macResult = CryptoService.ScpOperations.Scp02.CalculateCommandMac(
            data,
            key,
            Constants.Scp.Common.ZeroChaining8
        );

        return macResult.IsSuccess && macResult.Value.Length == 8;
    }

    // Property: Encryption/Decryption round-trip
    [Property(MaxTest = 100)]
    public bool Scp02_Encryption_Roundtrip_Preserves_Data(NonEmptyArray<byte> plaintext)
    {
        var key = GenerateValidScp02Key();
        var iv = new byte[8]; // Zero IV for simplicity

        var encrypted = CryptoService.Cipher.EncryptDes3Cbc(plaintext.Get, key, iv);
        if (!encrypted.IsSuccess) return false;

        var decrypted = CryptoService.Cipher.DecryptDes3Cbc(encrypted.Value, key, iv);

        return decrypted.IsSuccess && decrypted.Value.SequenceEqual(plaintext.Get);
    }

    // Property: Same inputs produce same cryptogram
    [Property(MaxTest = 100)]
    public bool Scp02_Cryptogram_Is_Deterministic()
    {
        var key = GenerateValidScp02Key();
        var data = GenerateRandomBytes(16);

        var cryptogram1 = CryptoService.ScpOperations.Scp02.CalculateCryptogram(key, data);
        var cryptogram2 = CryptoService.ScpOperations.Scp02.CalculateCryptogram(key, data);

        return cryptogram1.IsSuccess
            && cryptogram2.IsSuccess
            && cryptogram1.Value.SequenceEqual(cryptogram2.Value);
    }

    // Property: Different keys produce different session keys
    [Property(MaxTest = 50)]
    public bool Scp03_Different_Master_Keys_Produce_Different_Session_Keys(
        NonEmptyArray<byte> hostChallenge,
        NonEmptyArray<byte> cardChallenge)
    {
        if (hostChallenge.Get.Length < 8 || cardChallenge.Get.Length < 8)
            return true; // Skip invalid

        var key1 = GenerateValidScp03Key();
        var key2 = GenerateValidScp03Key();

        var context1 = CreateScp03Context(key1, hostChallenge.Get, cardChallenge.Get);
        var context2 = CreateScp03Context(key2, hostChallenge.Get, cardChallenge.Get);

        var sessionKeys1 = CryptoService.KeyDerivation.DeriveSessionKeys(context1);
        var sessionKeys2 = CryptoService.KeyDerivation.DeriveSessionKeys(context2);

        return sessionKeys1.IsSuccess
            && sessionKeys2.IsSuccess
            && !sessionKeys1.Value.SEnc.SequenceEqual(sessionKeys2.Value.SEnc);
    }

    // Custom generator for valid 16-byte 3DES keys
    private static byte[] GenerateValidScp02Key()
    {
        var key = new byte[16];
        Random.Shared.NextBytes(key);
        return key;
    }

    private static byte[] GenerateRandomBytes(int length)
    {
        var bytes = new byte[length];
        Random.Shared.NextBytes(bytes);
        return bytes;
    }

    private static KeyDerivationContext CreateScp03Context(
        byte[] masterKey,
        byte[] hostChallenge,
        byte[] cardChallenge)
    {
        var keySet = Scp03KeySet.Create(masterKey, masterKey, masterKey, 0x01).Value;
        return KeyDerivationContext.CreateForScp03(
            keySet,
            hostChallenge[..8],
            cardChallenge[..8],
            Maybe<ScpImplementation>.From(ScpImplementation.Scp03I70)
        ).Value;
    }
}
```

**FsCheck Best Practices for Gp4Net**:

1. **Use NonEmptyArray<byte> for cryptographic data** - Prevents null/empty edge cases
2. **Set MaxTest appropriately** - 100-200 for expensive crypto operations
3. **Use QuietOnSuccess = true** - Reduces test output noise
4. **Create custom Arbitrary<T> for domain types** - Ensure generated data is valid
5. **Test invariants, not implementations** - Focus on "what" not "how"

**Property Ideas for Gp4Net Security-Critical Paths**:

```csharp
// SCP02 ICV encryption property
[Property]
public bool Scp02_ICV_Encryption_Produces_8_Byte_Output(NonEmptyArray<byte> mac)
{
    if (mac.Get.Length != 8) return true;
    var key = GenerateValidScp02Key();
    var encrypted = CryptoService.ScpOperations.Scp02.EncryptIcv(mac.Get, key);
    return encrypted.IsSuccess && encrypted.Value.Length == 8;
}

// Key diversification produces unique keys
[Property]
public bool Key_Diversification_Produces_Unique_Keys_For_Different_Data(
    NonEmptyArray<byte> divData1,
    NonEmptyArray<byte> divData2)
{
    if (divData1.Get.SequenceEqual(divData2.Get)) return true; // Skip same input

    var baseKey = GenerateValidScp02Key();
    var diversified1 = KeyDiversificationService.DiversifyKey(baseKey, divData1.Get);
    var diversified2 = KeyDiversificationService.DiversifyKey(baseKey, divData2.Get);

    return diversified1.IsSuccess
        && diversified2.IsSuccess
        && !diversified1.Value.SequenceEqual(diversified2.Value);
}

// C-MAC chaining property
[Property]
public bool Scp03_CMAC_Chaining_Updates_State(NonEmptyArray<byte> data1, NonEmptyArray<byte> data2)
{
    var key = GenerateValidScp03Key();
    var chaining1 = new byte[16]; // Initial

    var mac1 = CryptoService.ScpOperations.Scp03.CalculateCommandMac(data1.Get, key, chaining1);
    if (!mac1.IsSuccess) return false;

    var chaining2 = mac1.Value; // Chaining updated
    var mac2 = CryptoService.ScpOperations.Scp03.CalculateCommandMac(data2.Get, key, chaining2);

    // Property: Different chaining produces different MAC for same data
    var mac1Again = CryptoService.ScpOperations.Scp03.CalculateCommandMac(data2.Get, key, chaining1);

    return mac2.IsSuccess
        && mac1Again.IsSuccess
        && !mac2.Value.SequenceEqual(mac1Again.Value);
}
```

**Alternatives Considered**:
1. **Manually written example-based tests** - Miss edge cases, less comprehensive
2. **QuickCheck (Haskell port)** - FsCheck is native .NET solution
3. **Hypothesis (Python)** - Wrong ecosystem, not applicable to C#

**References**:
- FsCheck GitHub: fscheck/FsCheck
- "Property-Based Testing with C#" (Codit blog)
- "Choosing properties for property-based testing" (F# for fun and profit)
- GitHub Gist: akimboyko/10888729 (FsCheck samples)

---

## 5. VirtualCardService Integration Testing (NO MOCKS Pattern)

### Decision: Use Real VirtualCardService for All Integration Tests; Reserve Unit Tests for Pure Functions

**Rationale**:
- Gp4Net constitutional requirement: "NO MOCKS policy - Real implementations preferred, mocks only for hardware"
- VirtualCardService provides a real JavaCard emulator, not a mock
- Integration tests with real implementations catch more bugs than mocked tests
- Faster than physical card testing, more reliable than mocks

**Pattern Implementation**:

```csharp
// Integration test base class
public abstract class ScpIntegrationTestBase
{
    protected VirtualCardService VirtualCard { get; private set; }
    protected ISmartCardService CardService { get; private set; }

    [SetUp]
    public void SetUp()
    {
        // Real virtual card, not a mock
        VirtualCard = new VirtualCardService();
        VirtualCard.SetupTestEnvironment();

        // Real card service communicating with virtual card
        CardService = TestCardService.Create(VirtualCard).Value;
    }

    [TearDown]
    public void TearDown()
    {
        CardService?.Dispose();
        VirtualCard?.Dispose();
    }
}

// Integration test example
[TestFixture]
public class Scp02IntegrationTests : ScpIntegrationTestBase
{
    [Test]
    public async Task Should_Establish_Scp02_Channel_And_Execute_Secure_Commands()
    {
        // Real key set
        var keySet = Scp02KeySet.Create(
            TestKeys.DefaultEncKey,
            TestKeys.DefaultMacKey,
            TestKeys.DefaultKek,
            0x01
        ).Value;

        // Real secure channel establishment with virtual card
        var session = await ScpService.Establishment.EstablishScp02Async(
            CardService,
            keySet,
            SecurityLevel.CDecCMac,
            CancellationToken.None
        );

        session.Should().BeSuccess();

        // Execute real secure command
        var getDataCmd = GetDataCommand.Create(GetDataCommand.DataObjects.CardData).Value;
        var securedCmd = ScpService.Security.ApplyCommandSecurity(
            getDataCmd.ToCommandApdu().Value,
            session.Value.State
        );

        securedCmd.Should().BeSuccess();

        // Send to virtual card and verify response
        var response = await CardService.SendCommandAsync(
            securedCmd.Value.securedCommand.ToBytes(),
            CancellationToken.None
        );

        response.Should().BeSuccess();
        response.Value.IsSuccess.Should().BeTrue();
    }
}
```

**Testing Strategy**:

| Test Type | Use Case | Implementation | Coverage Target |
|-----------|----------|----------------|-----------------|
| **Unit Tests** | Pure functions (crypto, parsing, validation) | Direct function calls, no dependencies | 100% of pure logic |
| **Integration Tests** | I/O orchestration, protocol flows | VirtualCardService (real) | Happy path + error scenarios |
| **Property Tests** | Cryptographic invariants | FsCheck with real crypto functions | Edge cases, boundaries |
| **End-to-End Tests** | Complete workflows (install, authenticate) | VirtualCardService + full stack | Critical user scenarios |

**VirtualCardService Benefits**:

1. **Real JavaCard implementation** - Not a mock, actual card applet
2. **Deterministic** - Reproducible tests, no flaky behavior
3. **Fast** - No physical card communication overhead
4. **Flexible** - Can configure card state, keys, applets
5. **No hardware required** - Runs in CI/CD

**Example: Testing Security-Critical Path (100% Coverage Required)**:

```csharp
// Security-critical: Card cryptogram verification
[TestFixture]
public class Scp02CryptogramVerificationTests : ScpIntegrationTestBase
{
    [Test]
    public async Task Should_Reject_Invalid_Card_Cryptogram()
    {
        // Setup: Virtual card with known keys
        var keySet = Scp02KeySet.Create(
            TestKeys.DefaultEncKey,
            TestKeys.DefaultMacKey,
            TestKeys.DefaultKek,
            0x01
        ).Value;

        // Tamper with the virtual card's cryptogram response
        VirtualCard.TamperNextCryptogram(); // Simulates attack

        // Attempt to establish secure channel
        var result = await ScpService.Establishment.EstablishScp02Async(
            CardService,
            keySet,
            SecurityLevel.CDecCMac,
            CancellationToken.None
        );

        // Must fail secure: Invalid cryptogram must be rejected
        result.Should().BeFailure();
        result.Error.Code.Should().Be(ErrorCode.AuthenticationFailed);
        result.Error.Message.Should().Contain("cryptogram verification failed");
    }

    [Test]
    public async Task Should_Accept_Valid_Card_Cryptogram()
    {
        // Positive test: Valid cryptogram from virtual card
        var keySet = Scp02KeySet.Create(
            TestKeys.DefaultEncKey,
            TestKeys.DefaultMacKey,
            TestKeys.DefaultKek,
            0x01
        ).Value;

        var result = await ScpService.Establishment.EstablishScp02Async(
            CardService,
            keySet,
            SecurityLevel.CDecCMac,
            CancellationToken.None
        );

        result.Should().BeSuccess();
        result.Value.State.IsAuthenticated.Should().BeTrue();
    }

    [Test]
    public async Task Should_Fail_With_Wrong_Keys()
    {
        // Test with incorrect keys
        var wrongKeySet = Scp02KeySet.Create(
            new byte[16], // Wrong ENC key
            TestKeys.DefaultMacKey,
            TestKeys.DefaultKek,
            0x01
        ).Value;

        var result = await ScpService.Establishment.EstablishScp02Async(
            CardService,
            wrongKeySet,
            SecurityLevel.CDecCMac,
            CancellationToken.None
        );

        result.Should().BeFailure();
        result.Error.Code.Should().Be(ErrorCode.AuthenticationFailed);
    }
}
```

**Alternatives Considered**:
1. **Moq/NSubstitute mocks** - Violates constitutional requirement, less reliable
2. **Physical smart cards** - Too slow, not suitable for CI/CD, hardware dependency
3. **Fake implementations** - VirtualCardService IS a sophisticated fake/stub, preferred approach

**References**:
- Stack Overflow: "Favor real dependencies for unit testing"
- Microsoft Learn: "Integration tests in ASP.NET Core"
- Software Engineering Stack Exchange: "Is Functional Programming a viable alternative to DI patterns"

---

## 6. Coverage Thresholds and Enforcement

### Decision: Use MSBuild Integration with ReportGenerator for Solution-Wide Threshold Enforcement

**Rationale**:
- VSTest integration (current runsettings approach) does not support threshold validation
- MSBuild integration supports per-module and total/average threshold enforcement
- ReportGenerator can combine multiple coverage reports and enforce thresholds in CI/CD
- Allows different thresholds for different assemblies (e.g., 100% for CryptoService, 60% overall)

**Implementation**:

```xml
<!-- Directory.Build.props (solution root) -->
<Project>
  <PropertyGroup>
    <!-- Enable coverage collection -->
    <CollectCoverage>true</CollectCoverage>
    <CoverletOutputFormat>cobertura,json</CoverletOutputFormat>
    <CoverletOutput>$(MSBuildProjectDirectory)/TestResults/</CoverletOutput>

    <!-- Exclude Tool from coverage -->
    <ExcludeByFile>**/Gp4Net.Tool/**/*.cs</ExcludeByFile>

    <!-- Default thresholds (can be overridden per project) -->
    <Threshold>60</Threshold>
    <ThresholdType>line,branch</ThresholdType>
    <ThresholdStat>total</ThresholdStat>
  </PropertyGroup>
</Project>

<!-- tests/Gp4Net.Tests/Gp4Net.Tests.csproj -->
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net9.0</TargetFramework>

    <!-- Coverage for this test project -->
    <CollectCoverage>true</CollectCoverage>
    <CoverletOutputFormat>cobertura,json</CoverletOutputFormat>
    <CoverletOutput>../../TestResults/coverage.gp4net</CoverletOutput>

    <!-- Merge with previous results -->
    <MergeWith>../../TestResults/coverage.json</MergeWith>

    <!-- Per-assembly thresholds -->
    <Threshold>60</Threshold>
    <ThresholdType>line,branch</ThresholdType>
    <ThresholdStat>total</ThresholdStat>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="coverlet.msbuild" Version="6.0.2" />
    <!-- ... other packages ... -->
  </ItemGroup>
</Project>
```

**CI/CD Script (GitHub Actions example)**:

```yaml
name: Test Coverage

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup .NET 9
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '9.0.x'

      # Run all tests with coverage
      - name: Test with coverage
        run: |
          dotnet test \
            /p:CollectCoverage=true \
            /p:CoverletOutputFormat="cobertura,json" \
            /p:MergeWith="../TestResults/coverage.json" \
            /p:CoverletOutput="../TestResults/" \
            /p:Threshold=60 \
            /p:ThresholdType=line,branch \
            /p:ThresholdStat=total

      # Generate HTML report
      - name: Generate coverage report
        run: |
          dotnet tool install -g dotnet-reportgenerator-globaltool
          reportgenerator \
            -reports:**/TestResults/coverage.cobertura.xml \
            -targetdir:CoverageReport \
            -reporttypes:"Html;TextSummary;Cobertura"

      # Enforce thresholds (fails build if below)
      - name: Enforce coverage thresholds
        run: |
          reportgenerator \
            -reports:**/TestResults/coverage.cobertura.xml \
            -targetdir:CoverageReport \
            -reporttypes:TextSummary \
            "assemblyfilters:+Gp4Net;+Gp4Net.CardEmulator;-Gp4Net.Tool" \
            "classfilters:-*.Tests.*" \
            minimumCoverageThresholds:"lineCoverage=60;branchCoverage=55"

      # Upload coverage to Codecov (optional)
      - name: Upload to Codecov
        uses: codecov/codecov-action@v4
        with:
          files: ./CoverageReport/Cobertura.xml
          flags: unittests
          name: codecov-gp4net
```

**Per-Assembly Threshold Strategy**:

| Assembly | Line Coverage Target | Branch Coverage Target | Rationale |
|----------|---------------------|------------------------|-----------|
| **Gp4Net (Core)** | 70% | 65% | Contains critical crypto and protocol logic |
| **Gp4Net.CryptoService** | 100% | 100% | Security-critical, must have complete coverage |
| **Gp4Net.CardEmulator** | 80% | 75% | Test infrastructure, high coverage important |
| **Gp4Net.Tool** | Excluded | Excluded | CLI UI, difficult to test, low value |
| **Overall Solution** | 60% | 55% | Current: 32.73%, achievable target |

**Local Development Workflow**:

```bash
# Run tests with coverage locally
dotnet test \
  /p:CollectCoverage=true \
  /p:CoverletOutputFormat="cobertura,json" \
  /p:CoverletOutput="./TestResults/" \
  /p:Threshold=60 \
  /p:ThresholdType=line,branch

# Generate local HTML report
dotnet tool install -g dotnet-reportgenerator-globaltool
reportgenerator \
  -reports:tests/**/TestResults/coverage.cobertura.xml \
  -targetdir:CoverageReport \
  -reporttypes:Html

# Open in browser
open CoverageReport/index.html
```

**Alternatives Considered**:
1. **VSTest integration only** - Doesn't support thresholds, rejected
2. **Manual coverage analysis** - Not scalable, error-prone
3. **Third-party services only (Codecov)** - Should have local enforcement too

**References**:
- Coverlet MSBuild Integration documentation
- ReportGenerator GitHub (danielpalme/ReportGenerator)
- "Combining multiple code coverage results in Azure DevOps" (James Croft)

---

## 7. Roadmap to 60% Coverage

### Phase 1: Foundation (Weeks 1-2) - Target: 45%

**Tasks**:
1. Configure MSBuild coverage with thresholds (see section 6)
2. Set up ReportGenerator in CI/CD
3. Identify all pure functions in CryptoService (already mostly done)
4. Write unit tests for all CryptoService methods (100% coverage goal)
5. Add property-based tests for crypto invariants (10-15 properties)

**Expected Coverage Gain**: +12% (from 32.73% to ~45%)

**Focus Areas**:
- `CryptoService.*.cs` (all partial classes)
- `TlvService.cs` (parsing, encoding, validation)
- `KeyDiversificationService.cs`

### Phase 2: Business Logic Extraction (Weeks 3-4) - Target: 55%

**Tasks**:
1. Extract pure functions from `ScpService.cs` orchestration methods
2. Create unit tests for extracted validation/transformation logic
3. Add integration tests for ScpService using VirtualCardService
4. Extract and test pure functions from domain command classes

**Expected Coverage Gain**: +10% (from ~45% to ~55%)

**Focus Areas**:
- Extract from `ScpService.Establishment` methods
- Test all domain commands (`InitializeUpdateCommand`, `ExternalAuthenticateCommand`, etc.)
- Coverage for `SecureChannelState` transitions

### Phase 3: Security-Critical Paths (Weeks 5-6) - Target: 65%

**Tasks**:
1. Achieve 100% coverage on cryptogram verification methods
2. Achieve 100% coverage on MAC calculation/validation
3. Add comprehensive integration tests for SCP02/SCP03 flows
4. Test all error paths in security-critical code

**Expected Coverage Gain**: +10% (from ~55% to ~65%)

**Security-Critical Methods Requiring 100%**:
- `VerifyScp02CardCryptogram`
- `VerifyScp03CardCryptogram`
- `ApplyCommandSecurity`
- `ProcessResponseSecurity`
- All MAC calculation methods
- All cryptogram generation methods

### Phase 4: Integration and Edge Cases (Weeks 7-8) - Target: 70%

**Tasks**:
1. Add end-to-end integration tests for applet lifecycle
2. Test error recovery paths
3. Add property-based tests for protocol invariants
4. Increase coverage of transport and pipeline code

**Expected Coverage Gain**: +5% (from ~65% to ~70%)

**Focus Areas**:
- `SmartCardService.cs` integration tests
- Pipeline processors
- Transport layer (T0, CL)

---

## Appendix A: Tools and Dependencies

### Required NuGet Packages

```xml
<!-- Test projects -->
<ItemGroup>
  <PackageReference Include="coverlet.collector" Version="6.0.2" />
  <PackageReference Include="coverlet.msbuild" Version="6.0.2" />
  <PackageReference Include="FsCheck" Version="2.16.6" />
  <PackageReference Include="FsCheck.NUnit" Version="2.16.6" />
  <PackageReference Include="NUnit" Version="4.0.1" />
  <PackageReference Include="NUnit.Analyzers" Version="4.4.0" />
  <PackageReference Include="NUnit3TestAdapter" Version="4.6.0" />
  <PackageReference Include="AwesomeAssertions" Version="9.0.0" />
  <PackageReference Include="CSharpFunctionalExtensions.FluentAssertions" Version="1.1.0" />
  <PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.12.0" />
</ItemGroup>
```

### Global Tools

```bash
# Install ReportGenerator
dotnet tool install -g dotnet-reportgenerator-globaltool

# Install coverage tools (if using global tool approach)
dotnet tool install -g coverlet.console
```

---

## Appendix B: Key Metrics and Tracking

### Coverage Dashboard (Update Weekly)

| Metric | Current | Week 2 | Week 4 | Week 6 | Week 8 | Target |
|--------|---------|--------|--------|--------|--------|--------|
| **Overall Line Coverage** | 32.73% | 45% | 55% | 65% | 70% | 60% |
| **Overall Branch Coverage** | ? | 40% | 50% | 60% | 65% | 55% |
| **CryptoService Coverage** | ? | 100% | 100% | 100% | 100% | 100% |
| **Security-Critical Coverage** | ? | 80% | 90% | 100% | 100% | 100% |
| **Unit Tests** | ? | 200 | 350 | 500 | 600 | 500+ |
| **Property Tests** | 1 | 10 | 15 | 20 | 25 | 20+ |
| **Integration Tests** | ~20 | 30 | 45 | 60 | 70 | 60+ |

### High-Value Test Categories

1. **Pure Function Tests**: 300+ tests (fast, comprehensive)
2. **Property-Based Tests**: 20+ properties (edge cases, invariants)
3. **Integration Tests**: 60+ tests (real VirtualCardService)
4. **Security-Critical Tests**: 50+ tests (100% coverage required)

---

## Appendix C: Example Test Structure

```
tests/Gp4Net.Tests/
├── Unit/
│   ├── Cryptography/
│   │   ├── Scp02MacTests.cs              (Pure function tests)
│   │   ├── Scp03CryptogramTests.cs       (Pure function tests)
│   │   ├── KeyDerivationTests.cs         (Pure function tests)
│   │   └── PropertyTests/
│   │       ├── Scp02PropertyTests.cs     (FsCheck properties)
│   │       └── Scp03PropertyTests.cs     (FsCheck properties)
│   ├── Services/
│   │   ├── TlvParsingTests.cs            (Pure parsing logic)
│   │   └── KeyDiversificationTests.cs    (Pure diversification)
│   └── Domain/
│       ├── CommandTests/                 (Command creation, validation)
│       └── ValueObjectTests/             (Immutable types)
├── Integration/
│   ├── Scp02IntegrationTests.cs          (VirtualCardService)
│   ├── Scp03IntegrationTests.cs          (VirtualCardService)
│   ├── AppletLifecycleTests.cs           (End-to-end)
│   └── SecurityCriticalTests.cs          (100% coverage required)
└── TestData/
    ├── Traces/                           (Golden test data)
    └── Keys/                             (Test key sets)
```

---

## Summary of Decisions

| Area | Decision | Key Benefit |
|------|----------|-------------|
| **Coverage Configuration** | Use `[ExcludeFromCodeCoverage]` attribute, avoid `ExcludeByAttribute` in .NET 9 | Avoids .NET 9 bug, granular control |
| **Async Testing** | Test async methods directly, ignore state machine coverage | Focuses on observable behavior |
| **Pure Function Extraction** | Apply "Functional Core, Imperative Shell" pattern | Increases testability, coverage |
| **Property-Based Testing** | Use FsCheck.NUnit for cryptographic invariants | Finds edge cases, comprehensive testing |
| **Integration Testing** | Use real VirtualCardService, no mocks | Constitutional compliance, reliability |
| **Threshold Enforcement** | MSBuild integration + ReportGenerator | Solution-wide enforcement, CI/CD integration |

**Target Achievement**: Following this roadmap should increase coverage from 32.73% to 65-70% within 8 weeks, with 100% coverage on all security-critical paths.
