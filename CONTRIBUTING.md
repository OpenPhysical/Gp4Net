# Contributing to Gp4Net

Thank you for your interest in contributing to Gp4Net! This document provides guidelines and information for contributors.

## Bounded Collaboration Policy

Participation in this technical project is conditioned upon your abiding by our [Bounded Collaboration Policy](docs/BOUNDED_COLLABORATION_POLICY.md). All contributions and discussions must directly support the project's technical goals.

## Getting Started

### Prerequisites

- .NET 8.0 SDK or later
- Visual Studio 2022, VS Code, or JetBrains Rider
- Git

### Setting up the Development Environment

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/Gp4Net.git
   cd Gp4Net
   ```
3. Restore dependencies:
   ```bash
   dotnet restore
   ```
4. Build the solution:
   ```bash
   dotnet build
   ```
5. Run tests:
   ```bash
   dotnet test
   ```

## Architecture Principles

Gp4Net follows strict functional programming principles:

### Critical Rules

1. **NO NULLS** - Never use nullable types. Convert incoming nulls to `Result<T>` immediately. Use `Maybe<T>` for optional values.
2. **NO EXCEPTIONS** - Use `Result<T, SmartCardError>` for all errors.
3. **NO LANGUAGEEXT** - Use CSharpFunctionalExtensions only.
4. **NO SYSTEM.SECURITY.CRYPTOGRAPHY** - Use BouncyCastle exclusively.
5. **PURE FUNCTIONS** - Functional composition, no side effects in domain logic.
6. **IMMUTABILITY** - All data structures must be immutable.

### Code Style

- Follow the existing code patterns
- Add XML documentation for all public APIs
- Write inline comments explaining complex GP protocol logic
- Reference GP specifications in comments where applicable
- Use meaningful variable and method names

## Testing

### Unit Tests

- Write comprehensive unit tests for all new functionality
- Use AwesomeAssertions (not FluentAssertions)
- Follow the existing test patterns
- Aim for high code coverage (>90%)

### Test Structure

```csharp
[Test]
public void MethodName_Scenario_ExpectedBehavior()
{
    // Arrange
    var input = CreateTestData();
    
    // Act
    var result = ServiceUnderTest.MethodName(input);
    
    // Assert
    result.IsSuccess.Should().BeTrue();
    result.Value.Should().Be(expectedValue);
}
```

### Integration Tests

- Test against virtual cards when possible
- Use real GP traces for validation
- Test both SCP02 and SCP03 protocols

## Pull Request Process

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the coding standards

3. **Write tests** for your changes

4. **Run the full test suite**:
   ```bash
   dotnet test
   ```

5. **Format your code**:
   ```bash
   dotnet format
   ```

6. **Update documentation** if needed

7. **Commit your changes** with descriptive messages:
   ```bash
   git commit -m "Add SCP03 pseudo-random challenge generation"
   ```

8. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

9. **Create a Pull Request** with:
   - Clear description of the changes
   - Reference to any related issues
   - Screenshots or examples if applicable

### Pull Request Checklist

- [ ] Code follows the functional programming principles
- [ ] All tests pass
- [ ] New functionality is covered by tests
- [ ] Documentation is updated
- [ ] No compiler warnings
- [ ] No nullable types introduced
- [ ] XML documentation added for public APIs

## Development Workflow

### Functional Patterns

```csharp
// Good: Functional composition
return InitializeUpdate()
    .Bind(response => DeriveSessionKeys(keySet, response))
    .Bind(keys => ExternalAuthenticate(keys))
    .Map(keys => new SessionKeys(keys));

// Bad: Imperative style with exceptions
try
{
    var response = InitializeUpdate();
    var keys = DeriveSessionKeys(keySet, response);
    var auth = ExternalAuthenticate(keys);
    return new SessionKeys(auth);
}
catch (Exception ex)
{
    throw new SmartCardException(ex.Message);
}
```

### Error Handling

```csharp
// Good: Use Result<T, SmartCardError>
public Result<SessionKeys, SmartCardError> EstablishSecureChannel(IKeySet keySet)
{
    return keySet switch
    {
        null => SmartCardError.InvalidArgument("Key set cannot be null"),
        Scp03KeySet scp03 => EstablishScp03Channel(scp03),
        Scp02KeySet scp02 => EstablishScp02Channel(scp02),
        _ => SmartCardError.UnsupportedOperation($"Unsupported key set type: {keySet.GetType()}")
    };
}

// Bad: Exceptions and nulls
public SessionKeys EstablishSecureChannel(IKeySet keySet)
{
    if (keySet == null)
        throw new ArgumentNullException(nameof(keySet));
    
    // ... implementation
}
```

### Logging

```csharp
// Good: Structured logging with context
_logger.LogDebug("Processing {CommandName} for key version {KeyVersion}", 
    command.GetType().Name, keyVersion);

// Bad: Console.WriteLine or string interpolation
Console.WriteLine($"Processing {command.GetType().Name}");
```

## Submitting Issues

### Bug Reports

Include:
- Clear description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Environment details (.NET version, OS)
- Relevant logs or error messages

### Feature Requests

Include:
- Clear description of the proposed feature
- Use case and justification
- Proposed implementation approach
- Any breaking changes

## Security

- Never commit secrets, keys, or sensitive data
- Use test keys only (well-known test vectors)
- Follow secure coding practices
- Report security vulnerabilities privately

## Documentation

- Update README.md for user-facing changes
- Add XML documentation for all public APIs
- Update architecture documentation for significant changes
- Include code examples in documentation

## Release Process

Releases are automated through GitHub Actions:

1. Versions are managed by Nerdbank.GitVersioning
2. Pushing tags triggers release builds
3. NuGet packages are published automatically

## Getting Help

- Check existing issues and discussions
- Ask questions in pull request comments
- Review the GlobalPlatform specifications in `/docs/`
- Look at existing code patterns for guidance

## Recognition

Contributors will be recognized in:
- CHANGELOG.md
- GitHub contributors list
- Package acknowledgments

Thank you for contributing to Gp4Net!