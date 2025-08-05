using Gp4Net.Tool.Services;
using NUnit.Framework;

namespace Gp4Net.Tests.TestBuilders;

[TestFixture]
public class CardResponseBuilderTests
{
    [Test]
    public void Build_DefaultValues_CreatesSuccessResponse()
    {
        // Arrange & Act
        var response = new CardResponseBuilder().Build();

        Assert.Multiple(() =>
        {
            // Assert
            Assert.That(response.StatusWord, Is.EqualTo(0x9000));
            Assert.That(response.Data, Is.Empty);
        });
    }

    [Test]
    public void WithData_ByteArray_SetsData()
    {
        // Arrange & Act
        var response = new CardResponseBuilder().WithData(0x6F, 0x10, 0x84, 0x08).Build();

        // Assert
        Assert.That(response.Data, Is.EqualTo(new byte[] { 0x6F, 0x10, 0x84, 0x08 }));
    }

    [Test]
    public void WithDataFromHex_ValidHexString_SetsData()
    {
        // Arrange & Act
        var response = new CardResponseBuilder()
            .WithDataFromHex("6F 10 84 08 A0 00 00 01 51 00 00 00")
            .Build();

        // Assert
        Assert.That(
            response.Data,
            Is.EqualTo(
                new byte[]
                {
                    0x6F,
                    0x10,
                    0x84,
                    0x08,
                    0xA0,
                    0x00,
                    0x00,
                    0x01,
                    0x51,
                    0x00,
                    0x00,
                    0x00,
                }
            )
        );
    }

    [Test]
    public void WithStatusWord_SetsStatusWord()
    {
        // Arrange & Act
        var response = new CardResponseBuilder().WithStatusWord(0x6A82).Build();

        // Assert
        Assert.That(response.StatusWord, Is.EqualTo(0x6A82));
    }

    [Test]
    public void WithStatusBytes_SetsSW1AndSW2()
    {
        // Arrange & Act
        var response = new CardResponseBuilder().WithStatusBytes(0x61, 0x10).Build();

        // Assert
        Assert.That(response.StatusWord, Is.EqualTo(0x6110));
    }

    [Test]
    public void WithSecurityNotSatisfied_SetsCorrectStatus()
    {
        // Arrange & Act
        var response = new CardResponseBuilder().WithSecurityNotSatisfied().Build();

        // Assert
        Assert.That(response.StatusWord, Is.EqualTo(0x6982));
    }

    [Test]
    public void ImplicitConversion_WorksCorrectly()
    {
        // Arrange & Act
        CardResponse response = new CardResponseBuilder()
            .WithDataFromHex("90 00")
            .WithSuccessStatus();

        Assert.Multiple(() =>
        {
            // Assert
            Assert.That(response.StatusWord, Is.EqualTo(0x9000));
            Assert.That(response.Data, Is.EqualTo(new byte[] { 0x90, 0x00 }));
        });
    }

    [Test]
    public void FluentInterface_ChainsMethodsCorrectly()
    {
        // Arrange & Act
        var response = new CardResponseBuilder()
            .WithDataFromHex("6F 10")
            .WithMoreDataAvailable(0x20)
            .WithData(0xFF, 0xFE) // This should override the previous data
            .Build();

        Assert.Multiple(() =>
        {
            // Assert
            Assert.That(response.Data, Is.EqualTo(new byte[] { 0xFF, 0xFE }));
            Assert.That(response.StatusWord, Is.EqualTo(0x6120));
        });
    }
}