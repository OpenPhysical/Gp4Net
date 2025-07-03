using System;
using System.Linq;
using Gp4Net.CardEmulator.Cards;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Xunit;

namespace Gp4Net.Tests.Integration
{
    /// <summary>
    /// Integration tests for SCP02 to SCP03 conversion process.
    /// </summary>
    public class ScpConversionIntegrationTests
    {
        private readonly byte[] _factoryEncKey = Convert.FromHexString(
            "AC2AD8C8E2E874A4C6B514D7ECD5FBE5"
        );
        private readonly byte[] _factoryMacKey = Convert.FromHexString(
            "86E6282CE0463C510FD4CB14D2A158EA"
        );
        private readonly byte[] _factoryDekKey = Convert.FromHexString(
            "7C290D97A5F4891F6C16ED7D2BB0A6E1"
        );
        private readonly byte[] _gpTestKey = Convert.FromHexString(
            "404142434445464748494A4B4C4D4E4F"
        );

        [Fact]
        public void FullScpConversion_FromScp02ToScp03_Succeeds()
        {
            // Arrange
            var card = new NxpP71Scp02Card();
            var hostChallenge = Convert.FromHexString("D71E77ACA51B72BC");

            // Step 1: Select ISD
            var isdAid = Convert.FromHexString("A000000151000000");
            var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, (byte)isdAid.Length };
            selectCommand = [.. selectCommand, .. isdAid];
            var response = card.ProcessCommand(selectCommand);
            Assert.True(response.IsSuccessful);
            Assert.True(card.IsSelected);

            // Step 2: Initialize Update with factory keys (KVN 255)
            var initUpdateCommand = new byte[] { 0x80, 0x50, 0xFF, 0x00, 0x08 };
            initUpdateCommand = [.. initUpdateCommand, .. hostChallenge];
            response = card.ProcessCommand(initUpdateCommand);
            Assert.True(response.IsSuccessful);

            // Verify SCP02 response
            Assert.Equal(0xFF, response.Data[10]); // Key version (factory)
            Assert.Equal(0x02, response.Data[11]); // SCP ID (SCP02)

            // Step 3: External Authenticate
            var extAuthCommand = new byte[] { 0x84, 0x82, 0x01, 0x00, 0x10 };
            var hostCryptogram = new byte[16]; // Simplified - real would calculate
            extAuthCommand = [.. extAuthCommand, .. hostCryptogram];
            response = card.ProcessCommand(extAuthCommand);
            Assert.True(response.IsSuccessful);
            Assert.True(card.IsSecureChannelEstablished);

            // Step 4: Store Data - Set SCP_ENABLE to SCP03 i=70 only
            var storeDataCommand = StoreDataCommand.CreateScpEnableCommand(0x0370);
            var storeDataApdu = new byte[]
            {
                0x80,
                0xE2,
                0x80,
                0x00,
                (byte)storeDataCommand.StoreData.Length
            };
            storeDataApdu = [.. storeDataApdu, .. storeDataCommand.StoreData];
            response = card.ProcessCommand(storeDataApdu);
            Assert.True(response.IsSuccessful);

            // Verify secure channel was closed
            Assert.False(card.IsSecureChannelEstablished);

            // Step 5: Re-authenticate with factory keys
            response = card.ProcessCommand(initUpdateCommand);
            Assert.True(response.IsSuccessful);

            // Verify now reporting SCP03
            Assert.Equal(0xFF, response.Data[10]); // Key version (factory)
            Assert.Equal(0x73, response.Data[11]); // SCP ID (03 | 70)

            // External auth again
            response = card.ProcessCommand(extAuthCommand);
            Assert.True(response.IsSuccessful);

            // Step 6: Check SCP configuration
            var getDataCommand = new byte[] { 0x84, 0xCA, 0x00, 0xCF, 0x00 };
            response = card.ProcessCommand(getDataCommand);
            Assert.True(response.IsSuccessful);

            // Step 7: Put Key - Install GP test keys as KVN 1
            var putKeyCommand = new byte[] { 0x84, 0xD8, 0x00, 0x81, 0x40 };
            putKeyCommand = [.. putKeyCommand, .. new byte[] { 0x01 }]; // New KVN

            // Add 3 AES keys (simplified - real would include proper formatting)
            for (int i = 0; i < 3; i++)
            {
                putKeyCommand = [.. putKeyCommand, .. new byte[] { 0x88, 0x10 }]; // AES-128 key type
                putKeyCommand = [.. putKeyCommand, .. _gpTestKey];
                putKeyCommand = [.. putKeyCommand, .. new byte[] { 0x50, 0x4A, 0x77 }]; // KCV
            }

            response = card.ProcessCommand(putKeyCommand);
            Assert.True(response.IsSuccessful);

            // Step 8: Set default key version to 1
            var setDefaultKvnCommand = StoreDataCommand.CreateDefaultKeyVersionCommand(0x01);
            storeDataApdu = new byte[]
            {
                0x80,
                0xE2,
                0x80,
                0x00,
                (byte)setDefaultKvnCommand.StoreData.Length
            };
            storeDataApdu = [.. storeDataApdu, .. setDefaultKvnCommand.StoreData];
            response = card.ProcessCommand(storeDataApdu);
            Assert.True(response.IsSuccessful);

            // Step 9: Reset card
            card.Reset();

            // Step 10: Select ISD again
            selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, (byte)isdAid.Length };
            selectCommand = [.. selectCommand, .. isdAid];
            response = card.ProcessCommand(selectCommand);
            Assert.True(response.IsSuccessful);

            // Step 11: Initialize Update with GP test keys (default KVN should be 1)
            initUpdateCommand = new byte[] { 0x80, 0x50, 0x00, 0x00, 0x08 };
            initUpdateCommand = [.. initUpdateCommand, .. hostChallenge];
            response = card.ProcessCommand(initUpdateCommand);
            Assert.True(response.IsSuccessful);

            // Verify SCP03 with KVN 1
            Assert.Equal(0x01, response.Data[10]); // Key version (GP test keys)
            Assert.Equal(0x73, response.Data[11]); // SCP ID (03 | 70)

            // Final verification: Card now uses SCP03 i=70 with GP test keys
            Assert.True(response.IsSuccessful);
        }

        [Fact]
        public void ScpEnable_WithMultipleProtocols_UpdatesConfiguration()
        {
            // Arrange
            var card = new NxpP71Scp02Card();
            EstablishSecureChannel(card);

            // Act - Set both SCP02 and SCP03 support
            var storeDataCommand = StoreDataCommand.CreateScpEnableCommand(0x0215, 0x0370);
            var storeDataApdu = new byte[]
            {
                0x80,
                0xE2,
                0x80,
                0x00,
                (byte)storeDataCommand.StoreData.Length
            };
            storeDataApdu = [.. storeDataApdu, .. storeDataCommand.StoreData];
            var response = card.ProcessCommand(storeDataApdu);

            // Assert
            if (!response.IsSuccessful)
            {
                throw new InvalidOperationException(
                    $"STORE DATA failed: SW={response.StatusWord:X4}"
                );
            }
            Assert.False(card.IsSecureChannelEstablished); // Should be closed

            // Verify configuration persists
            var isdAid = Convert.FromHexString("A000000151000000");
            var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, (byte)isdAid.Length };
            selectCommand = [.. selectCommand, .. isdAid];
            response = card.ProcessCommand(selectCommand);
            Assert.True(response.IsSuccessful);

            var initUpdateCommand = new byte[] { 0x80, 0x50, 0xFF, 0x00, 0x08 };
            initUpdateCommand = [.. initUpdateCommand, .. new byte[8]];
            response = card.ProcessCommand(initUpdateCommand);
            Assert.True(response.IsSuccessful);

            // Should still report first configured protocol (SCP02 i=15)
            Assert.Equal(0x02, response.Data[11] & 0x0F); // SCP version
        }

        [Fact]
        public void PutKey_WithAesKeys_InstallsSuccessfully()
        {
            // Arrange
            var card = new NxpP71Scp02Card();
            EstablishSecureChannel(card);

            // Act - Install AES keys
            var keyDataBlocks = new[]
            {
                KeyDataBlock.CreateAes128Key(_gpTestKey, new byte[] { 0x50, 0x4A, 0x77 }),
                KeyDataBlock.CreateAes128Key(_gpTestKey, new byte[] { 0x50, 0x4A, 0x77 }),
                KeyDataBlock.CreateAes128Key(_gpTestKey, new byte[] { 0x50, 0x4A, 0x77 })
            };

            var putKeyCommand = new PutKeyCommand(
                PutKeyCommand.KeyUsageQualifier.MultipleKeys,
                PutKeyCommand.KeyEncryptionKeyIdentifier.None,
                keyDataBlocks
            );

            // Build complete command with new key version
            var commandData = new byte[] { 0x01 }; // New KVN
            commandData = [.. commandData, .. putKeyCommand.Data ?? Array.Empty<byte>()];

            var apdu = new byte[] { 0x84, 0xD8, 0x00, 0x81, (byte)commandData.Length };
            apdu = [.. apdu, .. commandData];

            var response = card.ProcessCommand(apdu);

            // Assert
            Assert.True(response.IsSuccessful);
            Assert.Equal(0x01, response.Data[0]); // New key version
            Assert.Equal(10, response.Data.Length); // KVN + 3 KCVs
        }

        private void EstablishSecureChannel(NxpP71Scp02Card card)
        {
            // Select ISD - A000000151000000
            var isdAid = Convert.FromHexString("A000000151000000");
            var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, (byte)isdAid.Length };
            selectCommand = [.. selectCommand, .. isdAid];
            var response = card.ProcessCommand(selectCommand);
            if (!response.IsSuccessful)
            {
                throw new InvalidOperationException($"Select failed: SW={response.StatusWord:X4}");
            }

            // Initialize Update
            var initUpdateCommand = new byte[] { 0x80, 0x50, 0xFF, 0x00, 0x08 };
            initUpdateCommand = [.. initUpdateCommand, .. new byte[8]];
            response = card.ProcessCommand(initUpdateCommand);
            if (!response.IsSuccessful)
            {
                throw new InvalidOperationException(
                    $"Initialize Update failed: SW={response.StatusWord:X4}"
                );
            }

            // External Authenticate
            var extAuthCommand = new byte[] { 0x84, 0x82, 0x01, 0x00, 0x10 };
            extAuthCommand = [.. extAuthCommand, .. new byte[16]];
            response = card.ProcessCommand(extAuthCommand);
            if (!response.IsSuccessful)
            {
                throw new InvalidOperationException(
                    $"External Authenticate failed: SW={response.StatusWord:X4}"
                );
            }
        }
    }
}
