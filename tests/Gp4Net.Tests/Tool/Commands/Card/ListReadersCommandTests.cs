// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

namespace Gp4Net.Tests.Tool.Commands.Card;

using System.Collections.Generic;
using System.Threading.Tasks;
using AwesomeAssertions;
using Gp4Net.Services;
using Gp4Net.Tool.Commands.Card;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Tool.Services;
using Moq;
using NUnit.Framework;
using CSharpFunctionalExtensions;

/// <summary>
/// Unit tests for the <see cref="ListReadersCommand"/> class.
/// </summary>
[TestFixture]
public class ListReadersCommandTests
{
    private Mock<IDisplayService> _mockDisplayService;
    private Mock<ICardService> _mockCardService;
    private Mock<IGlobalPlatformService> _mockGlobalPlatformService;
    private Mock<IKeysetResolver> _mockKeysetResolver;
    private MockCommandContext _mockContext;
    private ListReadersCommand _command;

    /// <summary>
    /// Sets up the test environment before each test.
    /// </summary>
    [SetUp]
    public void SetUp()
    {
        this._mockDisplayService = new Mock<IDisplayService>();
        this._mockCardService = new Mock<ICardService>();
        this._mockGlobalPlatformService = new Mock<IGlobalPlatformService>();
        this._mockKeysetResolver = new Mock<IKeysetResolver>();

        this._mockContext = new MockCommandContext(
            this._mockDisplayService.Object,
            this._mockCardService.Object,
            this._mockGlobalPlatformService.Object,
            this._mockKeysetResolver.Object
        );

        this._command = new ListReadersCommand();
    }

    /// <summary>
    /// Tests that the command can be constructed without dependencies.
    /// </summary>
    [Test]
    public void Constructor_WithNoDependencies_CreatesInstance()
    {
        // Act & Assert
        this._command.Should().NotBeNull();
    }

    /// <summary>
    /// Tests that the command executes successfully when readers are available.
    /// </summary>
    [Test]
    public async Task ExecuteAsync_WithAvailableReaders_ReturnsSuccess()
    {
        // Arrange
        var readers = new List<string> { "Reader 1", "Reader 2" }.AsReadOnly();
        _ = this._mockCardService.Setup(x => x.GetReaders()).Returns(readers);
        var settings = new ListReadersCommand.Settings();

        // Act
        var result = await this._command.ExecuteAsync(this._mockContext, settings);

        // Assert
        result.Should().Be(0);
        this._mockCardService.Verify(x => x.GetReaders(), Times.Once);
    }

    /// <summary>
    /// Tests that the command handles no readers gracefully.
    /// </summary>
    [Test]
    public async Task ExecuteAsync_WithNoReaders_ReturnsSuccess()
    {
        // Arrange
        var readers = new List<string>().AsReadOnly();
        _ = this._mockCardService.Setup(x => x.GetReaders()).Returns(readers);
        var settings = new ListReadersCommand.Settings();

        // Act
        var result = await this._command.ExecuteAsync(this._mockContext, settings);

        // Assert
        result.Should().Be(0);
        this._mockCardService.Verify(x => x.GetReaders(), Times.Once);
    }

    /// <summary>
    /// Tests that the command handles card service exceptions gracefully.
    /// </summary>
    [Test]
    public async Task ExecuteAsync_WithCardServiceException_ReturnsError()
    {
        // Arrange
        _ = this
            ._mockCardService.Setup(x => x.GetReaders())
            .Throws(new System.InvalidOperationException("Test exception"));
        var settings = new ListReadersCommand.Settings();

        // Act
        var result = await this._command.ExecuteAsync(this._mockContext, settings);

        // Assert
        result.Should().Be(1);
        this._mockCardService.Verify(x => x.GetReaders(), Times.Once);
    }
}
