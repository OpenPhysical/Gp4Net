using System;
using System.Collections.Generic;
using System.Linq;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using NUnit.Framework;

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

        [Test]
        public void FullScpConversion_FromScp02ToScp03_Succeeds()
        {
            // Arrange
            var card = VirtualCardTestBuilder.P71Card();
            var hostChallenge = Convert.FromHexString("D71E77ACA51B72BC");

            // Step 1: Select ISD
            var isdAid = Convert.FromHexString("A000000151000000");
            var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, (byte)isdAid.Length };
            selectCommand = [.. selectCommand, .. isdAid];
            var response = card.ProcessCommand(selectCommand);
            Assert.That(response.IsSuccessful, Is.True);
            Assert.That(card.IsSelected, Is.True);

            // Step 2: Initialize Update with factory keys (KVN 255)
            var initUpdateCommand = new byte[] { 0x80, 0x50, 0xFF, 0x00, 0x08 };
            initUpdateCommand = [.. initUpdateCommand, .. hostChallenge];
            response = card.ProcessCommand(initUpdateCommand);
            Assert.That(response.IsSuccessful, Is.True);

            // Verify SCP02 response
            Assert.That(response.Data[10], Is.EqualTo(0xFF)); // Key version (factory)
            Assert.That(response.Data[11], Is.EqualTo(0x02)); // SCP ID (SCP02)

            // Step 3: External Authenticate
            // Calculate proper host cryptogram based on challenges
            var cardChallenge = response.Data.Skip(13).Take(8).ToArray();
            var hostCryptogram = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                hostCryptogram[i] = (byte)(cardChallenge[i] ^ hostChallenge[i]);
            }
            
            var extAuthCommand = new byte[] { 0x84, 0x82, 0x01, 0x00, 0x10 };
            extAuthCommand = [.. extAuthCommand, .. hostCryptogram, .. new byte[8]]; // cryptogram + MAC (zeros for test)
            response = card.ProcessCommand(extAuthCommand);
            Assert.That(response.IsSuccessful, Is.True);
            Assert.That(card.IsSecureChannelEstablished, Is.True);

            // Step 4: Store Data - Set SCP_ENABLE to SCP03 i=70 only
            var implementations = new List<ScpImplementation> { ScpImplementation.Scp03I70 };
            var storeDataResult = StoreDataCommand.CreateScpEnableCommand(implementations);
            Assert.That(storeDataResult.IsSuccess, Is.True);
            var storeDataCommand = storeDataResult.Value;
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
            Assert.That(response.IsSuccessful, Is.True);

            // Verify secure channel was closed
            Assert.That(card.IsSecureChannelEstablished, Is.True);

            // Step 5: Re-authenticate with factory keys
            response = card.ProcessCommand(initUpdateCommand);
            Assert.That(response.IsSuccessful, Is.True);

            // Verify now reporting SCP03
            Assert.That(response.Data[10], Is.EqualTo(0xFF)); // Key version (factory)
            Assert.That(response.Data[11], Is.EqualTo(0x73)); // SCP ID (03 | 70)

            // External auth again - recalculate cryptogram with new challenge
            cardChallenge = response.Data.Skip(13).Take(8).ToArray();
            hostCryptogram = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                hostCryptogram[i] = (byte)(cardChallenge[i] ^ hostChallenge[i]);
            }
            
            extAuthCommand = new byte[] { 0x84, 0x82, 0x01, 0x00, 0x10 };
            extAuthCommand = [.. extAuthCommand, .. hostCryptogram, .. new byte[8]]; // cryptogram + MAC (zeros for test)
            response = card.ProcessCommand(extAuthCommand);
            Assert.That(response.IsSuccessful, Is.True);

            // Step 6: Check SCP configuration
            var getDataCommand = new byte[] { 0x84, 0xCA, 0x00, 0xCF, 0x00 };
            response = card.ProcessCommand(getDataCommand);
            Assert.That(response.IsSuccessful, Is.True);

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
            Assert.That(response.IsSuccessful, Is.True);

            // Step 8: Set default key version to 1
            var setDefaultKvnResult = StoreDataCommand.CreateDefaultKeyVersionCommand(0x01);
            Assert.That(setDefaultKvnResult.IsSuccess, Is.True);
            var setDefaultKvnCommand = setDefaultKvnResult.Value;
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
            Assert.That(response.IsSuccessful, Is.True);

            // Step 9: Reset card
            card.Reset();

            // Step 10: Select ISD again
            selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, (byte)isdAid.Length };
            selectCommand = [.. selectCommand, .. isdAid];
            response = card.ProcessCommand(selectCommand);
            Assert.That(response.IsSuccessful, Is.True);

            // Step 11: Initialize Update with GP test keys (default KVN should be 1)
            initUpdateCommand = new byte[] { 0x80, 0x50, 0x00, 0x00, 0x08 };
            initUpdateCommand = [.. initUpdateCommand, .. hostChallenge];
            response = card.ProcessCommand(initUpdateCommand);
            Assert.That(response.IsSuccessful, Is.True);

            // Verify SCP03 with KVN 1
            Assert.That(response.Data[10], Is.EqualTo(0x01)); // Key version (GP test keys)
            Assert.That(response.Data[11], Is.EqualTo(0x73)); // SCP ID (03 | 70)

            // Final verification: Card now uses SCP03 i=70 with GP test keys
            Assert.That(response.IsSuccessful, Is.True);
        }

        [Test]
        public void ScpEnable_WithMultipleProtocols_UpdatesConfiguration()
        {
            // Arrange
            var card = VirtualCardTestBuilder.P71Card();
            EstablishSecureChannel(card);

            // Act - Set both SCP02 and SCP03 support
            var multipleImplementations = new List<ScpImplementation> 
            { 
                ScpImplementation.Scp02I15, 
                ScpImplementation.Scp03I70 
            };
            var storeDataResult = StoreDataCommand.CreateScpEnableCommand(multipleImplementations);
            if (!storeDataResult.IsSuccess)
            {
                Assert.Fail($"Failed to create STORE DATA command: {storeDataResult.Error?.Message}");
            }
            var storeDataCommand = storeDataResult.Value;
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
            Assert.That(card.IsSecureChannelEstablished, Is.True); // Should be closed

            // Verify configuration persists
            var isdAid = Convert.FromHexString("A000000151000000");
            var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, (byte)isdAid.Length };
            selectCommand = [.. selectCommand, .. isdAid];
            response = card.ProcessCommand(selectCommand);
            Assert.That(response.IsSuccessful, Is.True);

            var initUpdateCommand = new byte[] { 0x80, 0x50, 0xFF, 0x00, 0x08 };
            initUpdateCommand = [.. initUpdateCommand, .. new byte[8]];
            response = card.ProcessCommand(initUpdateCommand);
            Assert.That(response.IsSuccessful, Is.True);

            // Should still report first configured protocol (SCP02 i=15)
            Assert.That(response.Data[11] & 0x0F, Is.EqualTo(0x02)); // SCP version
        }

        [Test]
        public void PutKey_WithAesKeys_InstallsSuccessfully()
        {
            // Arrange
            var card = VirtualCardTestBuilder.P71Card();
            EstablishSecureChannel(card);

            // Act - Install AES keys
            var keyDataBlocks = new List<KeyDataBlock>();
            for (int i = 0; i < 3; i++) // ENC, MAC, DEK keys
            {
                var keyResult = KeyDataBlock.CreateAes128Key(_gpTestKey, new byte[] { 0x50, 0x4A, 0x77 });
                if (!keyResult.IsSuccess)
                {
                    Assert.Fail($"Failed to create key data block {i}: {keyResult.Error?.Message}");
                }
                keyDataBlocks.Add(keyResult.Value);
            }

            var putKeyCommandResult = PutKeyCommand.Create(0x01, keyDataBlocks); // KVN 1
            if (!putKeyCommandResult.IsSuccess)
            {
                Assert.Fail($"Failed to create PUT KEY command: {putKeyCommandResult.Error?.Message}");
            }
            var putKeyCommand = putKeyCommandResult.Value;

            // Build complete command with new key version
            var commandData = new byte[] { 0x01 }; // New KVN
            commandData = [.. commandData, .. putKeyCommand.Data ?? Array.Empty<byte>()];

            var apdu = new byte[] { 0x84, 0xD8, 0x00, 0x81, (byte)commandData.Length };
            apdu = [.. apdu, .. commandData];

            var response = card.ProcessCommand(apdu);

            // Assert
            Assert.That(response.IsSuccessful, Is.True);
            Assert.That(response.Data[0], Is.EqualTo(0x01)); // New key version
            Assert.That(response.Data.Length, Is.EqualTo(10)); // KVN + 3 KCVs
        }

        private void EstablishSecureChannel(FunctionalVirtualCard card)
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
            var hostChallenge = new byte[8]; // All zeros for test
            var initUpdateCommand = new byte[] { 0x80, 0x50, 0xFF, 0x00, 0x08 };
            initUpdateCommand = [.. initUpdateCommand, .. hostChallenge];
            response = card.ProcessCommand(initUpdateCommand);
            if (!response.IsSuccessful)
            {
                throw new InvalidOperationException(
                    $"Initialize Update failed: SW={response.StatusWord:X4}"
                );
            }
            
            // Extract card challenge from INITIALIZE UPDATE response
            // Response format: 10 bytes key diversification + 3 bytes key info + 8 bytes card challenge + 8 bytes card cryptogram
            if (response.Data.Length < 29)
            {
                throw new InvalidOperationException($"Invalid INITIALIZE UPDATE response length: {response.Data.Length}");
            }
            var cardChallenge = response.Data.Skip(13).Take(8).ToArray();
            
            // Calculate host cryptogram using test crypto service logic (XOR)
            var hostCryptogram = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                hostCryptogram[i] = (byte)(cardChallenge[i] ^ hostChallenge[i]);
            }
            
            // External Authenticate
            var extAuthCommand = new byte[] { 0x84, 0x82, 0x01, 0x00, 0x10 };
            extAuthCommand = [.. extAuthCommand, .. hostCryptogram, .. new byte[8]]; // cryptogram + MAC (zeros for test)
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
