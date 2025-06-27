using System;
using System.IO;
using System.Linq;
using Gp4Net.Domain.CapFile;
using Gp4Net.Utils;

namespace Gp4Net.Tests.Domain.CapFile
{
    /// <summary>
    /// Tests for the CapFileStructure class.
    /// </summary>
    [TestFixture]
    public class CapFileStructureTests
    {
        #region Test Data

        private static byte[] CreateMinimalCapFile()
        {
            // Create a minimal valid CAP file structure for testing
            var data = new MemoryStream();

            // Header component (tag 0x01)
            data.WriteByte(0x01); // Tag
            data.WriteByte(0x00); // Size high
            data.WriteByte(0x10); // Size low (16 bytes)
            
            // Header data (simplified)
            data.Write(new byte[] { 0xDE, 0xCA, 0xFF, 0xED }); // Magic
            data.WriteByte(0x01); // Flags
            data.WriteByte(0x08); // Package info (AID length = 8)
            data.Write(ConvertCompat.FromHexString("A000000062030100")); // Package AID
            data.WriteByte(0x01); // Major version
            data.WriteByte(0x00); // Minor version

            // Directory component (tag 0x02)
            data.WriteByte(0x02); // Tag
            data.WriteByte(0x00); // Size high
            data.WriteByte(0x08); // Size low (8 bytes)
            data.Write(new byte[8]); // Dummy directory data

            return data.ToArray();
        }

        private static byte[] CreateCapFileWithApplet()
        {
            var data = new MemoryStream();

            // Header component
            data.WriteByte(0x01); // Tag
            data.WriteByte(0x00); // Size high
            data.WriteByte(0x10); // Size low
            data.Write(new byte[] { 0xDE, 0xCA, 0xFF, 0xED }); // Magic
            data.WriteByte(0x01); // Flags
            data.WriteByte(0x08); // Package info
            data.Write(ConvertCompat.FromHexString("A000000062030100")); // Package AID
            data.WriteByte(0x01); // Major version
            data.WriteByte(0x00); // Minor version

            // Directory component
            data.WriteByte(0x02); // Tag
            data.WriteByte(0x00); // Size high
            data.WriteByte(0x08); // Size low
            data.Write(new byte[8]); // Dummy directory data

            // Applet component (tag 0x03)
            data.WriteByte(0x03); // Tag
            data.WriteByte(0x00); // Size high
            data.WriteByte(0x0D); // Size low (13 bytes)
            data.WriteByte(0x01); // Applet count
            data.WriteByte(0x09); // AID length
            data.Write(ConvertCompat.FromHexString("A00000006203010001")); // Applet AID
            data.WriteByte(0x00); // Install method offset high
            data.WriteByte(0x00); // Install method offset low

            return data.ToArray();
        }

        #endregion

        #region Parse Tests

        [Test]
        public void Parse_ValidMinimalCapFile_ReturnsStructure()
        {
            // Arrange
            var capData = CreateMinimalCapFile();

            // Act
            var result = CapFileStructure.Parse(capData);

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result.PackageAid, Is.EqualTo(ConvertCompat.FromHexString("A000000062030100")));
            Assert.That(result.PackageVersion.Major, Is.EqualTo(1));
            Assert.That(result.PackageVersion.Minor, Is.EqualTo(0));
            Assert.That(result.Components.Count, Is.EqualTo(2));
            Assert.That(result.Applets.Count, Is.EqualTo(0));
        }

        [Test]
        public void Parse_CapFileWithApplet_ParsesAppletInfo()
        {
            // Arrange
            var capData = CreateCapFileWithApplet();

            // Act
            var result = CapFileStructure.Parse(capData);

            // Assert
            Assert.That(result.Applets.Count, Is.EqualTo(1));
            Assert.That(result.Applets[0].Aid, Is.EqualTo(ConvertCompat.FromHexString("A00000006203010001")));
            Assert.That(result.Applets[0].InstallMethodOffset, Is.EqualTo(0));
        }

        [Test]
        public void Parse_NullData_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => CapFileStructure.Parse((byte[])null));
        }

        [Test]
        public void Parse_EmptyData_ThrowsInvalidDataException()
        {
            // Act & Assert
            Assert.Throws<InvalidDataException>(() => CapFileStructure.Parse(Array.Empty<byte>()));
        }

        [Test]
        public void Parse_InvalidData_ThrowsInvalidDataException()
        {
            // Arrange
            var invalidData = new byte[] { 0xFF, 0xFF, 0xFF };

            // Act & Assert
            Assert.Throws<InvalidDataException>(() => CapFileStructure.Parse(invalidData));
        }

        [Test]
        public void Parse_MissingHeaderComponent_ThrowsInvalidDataException()
        {
            // Arrange - create CAP file without header
            var data = new byte[] {
                0x02, 0x00, 0x08, // Directory component
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // Dummy data
            };

            // Act & Assert
            Assert.Throws<InvalidDataException>(() => CapFileStructure.Parse(data));
        }

        #endregion

        #region GetLoadingComponents Tests

        [Test]
        public void GetLoadingComponents_ValidCapFile_ReturnsComponentsInCorrectOrder()
        {
            // Arrange
            var capData = CreateMinimalCapFile();
            var capFile = CapFileStructure.Parse(capData);

            // Act
            var loadingComponents = capFile.GetLoadingComponents().ToList();

            // Assert
            Assert.That(loadingComponents.Count, Is.GreaterThan(0));
            Assert.That(loadingComponents[0].Tag, Is.EqualTo(CapFileStructure.ComponentTags.Header));
            
            // Directory should come after header if present
            if (loadingComponents.Count > 1)
            {
                Assert.That(loadingComponents[1].Tag, Is.EqualTo(CapFileStructure.ComponentTags.Directory));
            }
        }

        #endregion

        #region CreateLoadBlocks Tests

        [Test]
        public void CreateLoadBlocks_SmallCapFile_CreatesSingleBlock()
        {
            // Arrange
            var capData = CreateMinimalCapFile();
            var capFile = CapFileStructure.Parse(capData);

            // Act
            var blocks = capFile.CreateLoadBlocks(255);

            // Assert
            Assert.That(blocks.Count, Is.GreaterThan(0));
            Assert.That(blocks[^1].IsLastBlock, Is.True);
            
            // All blocks except possibly the last should be numbered sequentially
            for (int i = 0; i < blocks.Count; i++)
            {
                Assert.That(blocks[i].BlockNumber, Is.EqualTo(i));
            }
        }

        [Test]
        public void CreateLoadBlocks_LargeCapFile_CreatesMultipleBlocks()
        {
            // Arrange
            var capData = CreateMinimalCapFile();
            var capFile = CapFileStructure.Parse(capData);

            // Act with very small block size to force multiple blocks
            var blocks = capFile.CreateLoadBlocks(10);

            // Assert
            Assert.That(blocks.Count, Is.GreaterThan(1));
            
            // Only the last block should be marked as final
            for (int i = 0; i < blocks.Count - 1; i++)
            {
                Assert.That(blocks[i].IsLastBlock, Is.False);
            }
            Assert.That(blocks[^1].IsLastBlock, Is.True);
        }

        [Test]
        public void CreateLoadBlocks_ValidatesBlockSize()
        {
            // Arrange
            var capData = CreateMinimalCapFile();
            var capFile = CapFileStructure.Parse(capData);

            // Act
            var blocks = capFile.CreateLoadBlocks(50);

            // Assert
            foreach (var block in blocks)
            {
                Assert.That(block.Data.Length, Is.LessThanOrEqualTo(50));
                Assert.That(block.Data.Length, Is.GreaterThan(0));
            }
        }

        #endregion

        #region CapComponent Tests

        [Test]
        public void CapComponent_Parse_ValidComponent_ReturnsComponent()
        {
            // Arrange
            var data = new MemoryStream();
            data.WriteByte(0x01); // Tag
            data.WriteByte(0x00); // Size high
            data.WriteByte(0x04); // Size low
            data.Write(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }); // Component data
            data.Position = 0;

            // Act
            var component = CapComponent.Parse(data);

            // Assert
            Assert.That(component.Tag, Is.EqualTo(0x01));
            Assert.That(component.Size, Is.EqualTo(0x04));
            Assert.That(component.Data, Is.EqualTo(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }));
        }

        [Test]
        public void CapComponent_Parse_TruncatedData_ThrowsInvalidDataException()
        {
            // Arrange
            var data = new MemoryStream();
            data.WriteByte(0x01); // Tag
            data.WriteByte(0x00); // Size high
            data.WriteByte(0x04); // Size low (claims 4 bytes)
            data.Write(new byte[] { 0xAA, 0xBB }); // Only 2 bytes
            data.Position = 0;

            // Act & Assert
            Assert.Throws<InvalidDataException>(() => CapComponent.Parse(data));
        }

        #endregion

        #region CapVersion Tests

        [Test]
        public void CapVersion_ToString_ReturnsFormattedVersion()
        {
            // Arrange
            var version = new CapVersion(1, 2);

            // Act
            var result = version.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("1.2"));
        }

        [Test]
        public void CapVersion_Equality_WorksCorrectly()
        {
            // Arrange
            var version1 = new CapVersion(1, 0);
            var version2 = new CapVersion(1, 0);
            var version3 = new CapVersion(1, 1);

            // Act & Assert
            Assert.That(version1.Equals(version2), Is.True);
            Assert.That(version1.Equals(version3), Is.False);
        }

        #endregion

        #region AppletInfo Tests

        [Test]
        public void AppletInfo_Constructor_ClonesAid()
        {
            // Arrange
            var aid = ConvertCompat.FromHexString("A000000001");
            var originalAid = (byte[])aid.Clone();

            // Act
            var appletInfo = new AppletInfo(aid, 0x1234);
            aid[0] = 0xFF; // Modify original

            // Assert
            Assert.That(appletInfo.Aid, Is.EqualTo(originalAid));
            Assert.That(appletInfo.Aid, Is.Not.EqualTo(aid));
            Assert.That(appletInfo.InstallMethodOffset, Is.EqualTo(0x1234));
        }

        #endregion

        #region LoadBlock Tests

        [Test]
        public void LoadBlock_Constructor_ClonesData()
        {
            // Arrange
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            var originalData = (byte[])data.Clone();

            // Act
            var block = new LoadBlock(0, data, true);
            data[0] = 0xFF; // Modify original

            // Assert
            Assert.That(block.Data, Is.EqualTo(originalData));
            Assert.That(block.Data, Is.Not.EqualTo(data));
            Assert.That(block.BlockNumber, Is.EqualTo(0));
            Assert.That(block.IsLastBlock, Is.True);
        }

        #endregion
    }
}