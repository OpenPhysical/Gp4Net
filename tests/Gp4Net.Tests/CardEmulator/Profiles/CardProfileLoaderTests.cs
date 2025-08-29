using System;
using System.IO;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.CardEmulator.Profiles;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using NUnit.Framework;

namespace Gp4Net.Tests.CardEmulator.Profiles;

/// <summary>
/// Unit tests for CardProfileLoader.
/// </summary>
public class CardProfileLoaderTests
{
    private const string SampleP71Profile = @"
    {
      ""cardProfile"": {
        ""name"": ""Test_P71_Card"",
        ""description"": ""Test P71D321 card""
      },
      ""chipInfo"": {
        ""manufacturer"": ""NXP"",
        ""platform"": ""SmartMX3"",
        ""model"": ""P71D321"",
        ""memoryConfig"": ""P71D351"",
        ""architecture"": ""IntegralSecurity 2.0""
      },
      ""cardData"": {
        ""atr"": ""3BD518FF8191FE1FC38073C821100A"",
        ""isdAid"": ""A000000151000000"",
        ""capabilities"": {
          ""scpSupport"": [
            {
              ""protocol"": ""0x02"",
              ""implementations"": [""0x15"", ""0x55""]
            }
          ]
        },
        ""keyInfo"": [
          {
            ""version"": 1,
            ""id"": 1,
            ""type"": ""DES3"",
            ""length"": 16
          }
        ]
      },
      ""staticKeys"": {
        ""1"": {
          ""version"": 1,
          ""type"": ""SCP02"",
          ""keys"": {
            ""enc"": ""404142434445464748494A4B4C4D4E4F"",
            ""mac"": ""404142434445464748494A4B4C4D4E4F"",
            ""dek"": ""404142434445464748494A4B4C4D4E4F""
          }
        }
      },
      ""dataObjects"": {
        ""0x9F7F"": ""9F7F2A4790D3214700000000002345558083204839000000000000000018648F35383038330000000000000000"",
        ""0x00C1"": ""C1020004""
      }
    }";

    [Test]
    public void LoadFromJson_WithValidP71Profile_ReturnsConfiguration()
    {
        // Act
        Result<CardConfiguration, SmartCardError> result = CardProfileLoader.LoadFromJson(SampleP71Profile);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        CardConfiguration? config = result.Value;

        // Basic properties
        _ = config.CardType.Should().Be("Test P71D321 card");
        _ = config.Atr.Should().BeEquivalentTo(Convert.FromHexString("3BD518FF8191FE1FC38073C821100A"));
        _ = config.IsdAid.Should().BeEquivalentTo(Convert.FromHexString("A000000151000000"));

        // SCP defaults
        _ = config.DefaultScpVersion.Should().Be(0x02);
        _ = config.DefaultScpImplementation.Should().Be(ScpImplementation.Scp02I15);

        // Keys
        _ = config.StaticKeys.Should().ContainKey((byte)1);
        IKeySet keySet = config.StaticKeys[1];
        _ = keySet.Should().BeOfType<Scp02KeySet>();

        // Data objects
        _ = config.DefaultDataObjects.Should().ContainKey((ushort)0x9F7F);
        _ = config.DefaultDataObjects.Should().ContainKey((ushort)0x00C1);
    }

    [Test]
    public void LoadFromJson_WithScp03Profile_DeterminesCorrectDefaults()
    {
        // Arrange
        string scp03Profile = @"
        {
          ""cardProfile"": {
            ""name"": ""SCP03_Card"",
            ""description"": ""Test SCP03 card""
          },
          ""cardData"": {
            ""atr"": ""3BD518FF8191FE1FC38073C821100A"",
            ""isdAid"": ""A000000151000000"",
            ""capabilities"": {
              ""scpSupport"": [
                {
                  ""protocol"": ""0x03"",
                  ""implementations"": [""0x60"", ""0x70""]
                }
              ]
            },
            ""keyInfo"": [
              {
                ""version"": 1,
                ""id"": 1,
                ""type"": ""AES"",
                ""length"": 16
              }
            ]
          },
          ""staticKeys"": {
            ""1"": {
              ""version"": 1,
              ""type"": ""SCP03"",
              ""keys"": {
                ""enc"": ""404142434445464748494A4B4C4D4E4F"",
                ""mac"": ""404142434445464748494A4B4C4D4E4F"",
                ""dek"": ""404142434445464748494A4B4C4D4E4F""
              }
            }
          }
        }";

        // Act
        Result<CardConfiguration, SmartCardError> result = CardProfileLoader.LoadFromJson(scp03Profile);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        CardConfiguration? config = result.Value;
        _ = config.DefaultScpVersion.Should().Be(0x03);
        _ = config.DefaultScpImplementation.Should().Be(ScpImplementation.Scp03I70);
        _ = config.StaticKeys[1].Should().BeOfType<Scp03KeySet>();
    }

    [Test]
    public void LoadFromJson_WithInvalidJson_ReturnsFailure()
    {
        // Arrange
        string invalidJson = "{ invalid json }";

        // Act
        Result<CardConfiguration, SmartCardError> result = CardProfileLoader.LoadFromJson(invalidJson);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("Invalid JSON format");
    }

    [Test]
    public void LoadFromJson_WithMissingRequiredFields_ReturnsFailure()
    {
        // Arrange
        string incompleteJson = @"
        {
          ""cardProfile"": {
            ""name"": ""Incomplete""
          }
        }";

        // Act
        Result<CardConfiguration, SmartCardError> result = CardProfileLoader.LoadFromJson(incompleteJson);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
    }

    [Test]
    public void LoadFromJson_WithInvalidHexString_ReturnsFailure()
    {
        // Arrange
        string badHexJson = @"
        {
          ""cardData"": {
            ""atr"": ""NOT_HEX"",
            ""isdAid"": ""A000000151000000""
          }
        }";

        // Act
        Result<CardConfiguration, SmartCardError> result = CardProfileLoader.LoadFromJson(badHexJson);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("ATR must have even number of hex digits");
    }

    [Test]
    public void LoadFromJson_WithInvalidKeyVersion_ReturnsFailure()
    {
        // Arrange
        string badKeyJson = @"
        {
          ""cardData"": {
            ""atr"": ""3BD518FF8191FE1FC38073C821100A"",
            ""isdAid"": ""A000000151000000""
          },
          ""staticKeys"": {
            ""not_a_number"": {
              ""version"": 1,
              ""type"": ""SCP02"",
              ""keys"": {
                ""enc"": ""404142434445464748494A4B4C4D4E4F"",
                ""mac"": ""404142434445464748494A4B4C4D4E4F"",
                ""dek"": ""404142434445464748494A4B4C4D4E4F""
              }
            }
          }
        }";

        // Act
        Result<CardConfiguration, SmartCardError> result = CardProfileLoader.LoadFromJson(badKeyJson);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("Invalid key version");
    }

    [Test]
    public void LoadFromJson_WithUnknownKeyType_ReturnsFailure()
    {
        // Arrange
        string unknownKeyTypeJson = @"
        {
          ""cardData"": {
            ""atr"": ""3BD518FF8191FE1FC38073C821100A"",
            ""isdAid"": ""A000000151000000""
          },
          ""staticKeys"": {
            ""1"": {
              ""version"": 1,
              ""type"": ""UNKNOWN_TYPE"",
              ""keys"": {
                ""enc"": ""404142434445464748494A4B4C4D4E4F"",
                ""mac"": ""404142434445464748494A4B4C4D4E4F"",
                ""dek"": ""404142434445464748494A4B4C4D4E4F""
              }
            }
          }
        }";

        // Act
        Result<CardConfiguration, SmartCardError> result = CardProfileLoader.LoadFromJson(unknownKeyTypeJson);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("Unknown key set type");
    }

    [Test]
    public void LoadFromFile_WithValidFile_ReturnsConfiguration()
    {
        // Arrange
        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, SampleP71Profile);

            // Act
            Result<CardConfiguration, SmartCardError> result = CardProfileLoader.LoadFromFile(tempFile);

            // Assert
            _ = result.IsSuccess.Should().BeTrue();
            CardConfiguration? config = result.Value;
            _ = config.CardType.Should().Be("Test P71D321 card");
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Test]
    public void LoadFromFile_WithNonExistentFile_ReturnsFailure()
    {
        // Arrange
        string nonExistentFile = Path.Combine(Path.GetTempPath(), "non_existent_profile.json");

        // Act
        Result<CardConfiguration, SmartCardError> result = CardProfileLoader.LoadFromFile(nonExistentFile);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("Profile file not found");
    }

    [Test]
    public void LoadFromFile_WithNullPath_ReturnsFailure()
    {
        // Act
        Result<CardConfiguration, SmartCardError> result = CardProfileLoader.LoadFromFile(null!);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("JSON path cannot be null or empty");
    }

    [Test]
    public void LoadFromJson_WithSpacesInHex_ParsesCorrectly()
    {
        // Arrange
        string jsonWithSpaces = @"
        {
          ""cardData"": {
            ""atr"": ""3B D5 18 FF 81 91 FE 1F C3 80 73 C8 21 10 0A"",
            ""isdAid"": ""A0 00 00 01 51 00 00 00""
          }
        }";

        // Act
        Result<CardConfiguration, SmartCardError> result = CardProfileLoader.LoadFromJson(jsonWithSpaces);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        CardConfiguration? config = result.Value;
        _ = config.Atr.Should().BeEquivalentTo(Convert.FromHexString("3BD518FF8191FE1FC38073C821100A"));
        _ = config.IsdAid.Should().BeEquivalentTo(Convert.FromHexString("A000000151000000"));
    }

    [Test]
    public void LoadFromJson_SupportedInstructions_ContainsStandardGpCommands()
    {
        // Act
        Result<CardConfiguration, SmartCardError> result = CardProfileLoader.LoadFromJson(SampleP71Profile);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        CardConfiguration? config = result.Value;
        _ = config.SupportedInstructions.Should().Contain(0xA4); // SELECT
        _ = config.SupportedInstructions.Should().Contain(0x50); // INITIALIZE UPDATE
        _ = config.SupportedInstructions.Should().Contain(0x82); // EXTERNAL AUTHENTICATE
        _ = config.SupportedInstructions.Should().Contain(0xCA); // GET DATA
        _ = config.SupportedInstructions.Should().Contain(0xF2); // GET STATUS
    }
}