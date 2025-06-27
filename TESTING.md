# Testing Guide for Gp4Net

This document explains the testing approach and architecture for the Gp4Net project.

## Overview

The project uses a layered testing approach:
- **Unit Tests**: Fast, isolated tests that mock external dependencies
- **Integration Tests**: Tests that require real hardware (card readers and smart cards)
- **Test Builders**: Helper classes for creating test data

## Testing Stack

- **Framework**: NUnit 4.2.2
- **Mocking**: Moq 4.20.72
- **Test Runner**: NUnit3TestAdapter
- **Coverage**: Coverlet

## Architecture Changes for Testability

### Dependency Injection

The `WsctCardService` has been refactored to support dependency injection:

```csharp
// Before: Tightly coupled to WSCT implementation
public WsctCardService()
{
    _context = new CardContext();
}

// After: Accepts factory for creating WSCT objects
public WsctCardService(IWsctFactory wsctFactory)
{
    _wsctFactory = wsctFactory ?? throw new ArgumentNullException(nameof(wsctFactory));
    _context = _wsctFactory.CreateCardContext();
}
```

### Abstraction Layers

Created interfaces to wrap WSCT dependencies:
- `ICardContextWrapper`: Wraps WSCT `CardContext`
- `ICardChannelWrapper`: Wraps WSCT `CardChannel`
- `IWsctFactory`: Factory for creating WSCT objects

This allows mocking in unit tests while maintaining the same functionality.

## Unit Tests

Unit tests are located in `/tests/Gp4Net.Tests/Tool/Services/WsctCardServiceTests.cs`

### Key Testing Patterns

1. **Arrange-Act-Assert**: Clear test structure
2. **Mock Setup**: Configure expected behavior
3. **Verification**: Ensure methods were called correctly

### Example Unit Test

```csharp
[Test]
public void Connect_ValidReader_ReturnsTrue()
{
    // Arrange
    const string readerName = "TestReader";
    _mockContext.Setup(c => c.CreateCardChannel(readerName)).Returns(_mockChannel.Object);
    _mockChannel.Setup(ch => ch.Connect(ShareMode.Shared, Protocol.Any)).Returns(ErrorCode.Success);
    _service = new WsctCardService(_mockFactory.Object);

    // Act
    var result = _service.Connect(readerName);

    // Assert
    Assert.That(result, Is.True);
    _mockContext.Verify(c => c.CreateCardChannel(readerName), Times.Once);
    _mockChannel.Verify(ch => ch.Connect(ShareMode.Shared, Protocol.Any), Times.Once);
}
```

## Integration Tests

Integration tests are in `/tests/Gp4Net.Tests/Tool/Services/WsctCardServiceIntegrationTests.cs`

### Running Integration Tests

Integration tests are marked with `[Explicit]` and require:
1. A physical smart card reader connected
2. A smart card inserted
3. Manual execution

```bash
# Run integration tests explicitly
dotnet test --filter "Category=Integration" --logger "console;verbosity=detailed"
```

### Example Integration Test

```csharp
[Test]
[Explicit("Requires physical smart card reader and card")]
public void GetAtr_WithConnectedCard_ReturnsValidAtr()
{
    // Arrange
    ConnectToFirstAvailableCard();

    // Act
    var atr = _service.GetAtr();

    // Assert
    Assert.That(atr, Is.Not.Null);
    Assert.That(atr[0], Is.EqualTo(0x3B).Or.EqualTo(0x3F), "Invalid TS byte in ATR");
}
```

## Test Builders

Test builders provide a fluent API for creating test data:

```csharp
// Create a success response with data
var response = new CardResponseBuilder()
    .WithDataFromHex("6F 10 84 08 A0 00 00 01 51 00 00 00")
    .WithSuccessStatus()
    .Build();

// Create an error response
var errorResponse = new CardResponseBuilder()
    .WithSecurityNotSatisfied()
    .Build();
```

## Running Tests

### All Unit Tests
```bash
dotnet test --filter "Category!=Integration"
```

### Specific Test Class
```bash
dotnet test --filter "FullyQualifiedName~WsctCardServiceTests"
```

### With Coverage
```bash
dotnet test --collect:"XPlat Code Coverage" --filter "Category!=Integration"
```

## Best Practices

1. **Keep Tests Fast**: Unit tests should run in milliseconds
2. **Test One Thing**: Each test should verify a single behavior
3. **Use Descriptive Names**: Test names should describe what they test
4. **Mock External Dependencies**: Don't rely on hardware in unit tests
5. **Test Edge Cases**: Null values, exceptions, boundary conditions
6. **Maintain Test Code**: Refactor tests as you refactor production code

## Test Organization

```
tests/
├── Gp4Net.Tests/
│   ├── Tool/
│   │   └── Services/
│   │       ├── WsctCardServiceTests.cs          # Unit tests
│   │       └── WsctCardServiceIntegrationTests.cs # Integration tests
│   └── TestBuilders/
│       ├── CardResponseBuilder.cs               # Test data builder
│       └── CardResponseBuilderTests.cs          # Tests for the builder
└── Gp4Net.Tests.Emulator/
    └── (Emulator-based tests)
```

## Adding New Tests

1. **For new services**: Create interfaces for dependencies
2. **For new commands**: Test command parsing and validation
3. **For cryptography**: Use known test vectors
4. **For protocols**: Test state transitions and error handling

## Continuous Integration

Tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run Unit Tests
  run: dotnet test --filter "Category!=Integration" --logger trx --results-directory "TestResults"
  
- name: Upload Test Results
  uses: actions/upload-artifact@v3
  with:
    name: test-results
    path: TestResults
```

## Troubleshooting

### Common Issues

1. **"No card readers found"**: Ensure drivers are installed
2. **"Card not present"**: Insert a GlobalPlatform-compatible card
3. **Mock setup not working**: Check that all required methods are mocked
4. **Tests timing out**: Integration tests may need longer timeouts

### Debug Tips

- Use `TestContext.WriteLine()` for diagnostic output
- Set breakpoints in both test and production code
- Check mock invocation counts with `Verify()`
- Use `--verbosity detailed` for more test output