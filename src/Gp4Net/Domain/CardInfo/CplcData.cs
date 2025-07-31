using System;
using System.Text;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.Domain.CardInfo
{
    /// <summary>
    /// Card Production Life Cycle (CPLC) data structure according to GlobalPlatform.
    /// Contains information about the card's manufacturing and personalization.
    /// </summary>
    public class CplcData
    {
        /// <summary>
        /// Gets or sets the IC fabricator ID (2 bytes).
        /// </summary>
        public ushort IcFabricator { get; set; }

        /// <summary>
        /// Gets or sets the IC type (2 bytes).
        /// </summary>
        public ushort IcType { get; set; }

        /// <summary>
        /// Gets or sets the operating system ID (2 bytes).
        /// </summary>
        public ushort OperatingSystemId { get; set; }

        /// <summary>
        /// Gets or sets the operating system release date (2 bytes).
        /// </summary>
        public ushort OperatingSystemReleaseDate { get; set; }

        /// <summary>
        /// Gets or sets the operating system release level (2 bytes).
        /// </summary>
        public ushort OperatingSystemReleaseLevel { get; set; }

        /// <summary>
        /// Gets or sets the IC fabrication date (2 bytes).
        /// </summary>
        public ushort IcFabricationDate { get; set; }

        /// <summary>
        /// Gets or sets the IC serial number (4 bytes).
        /// </summary>
        public uint IcSerialNumber { get; set; }

        /// <summary>
        /// Gets or sets the IC batch identifier (2 bytes).
        /// </summary>
        public ushort IcBatchIdentifier { get; set; }

        /// <summary>
        /// Gets or sets the IC module fabricator (2 bytes).
        /// </summary>
        public ushort IcModuleFabricator { get; set; }

        /// <summary>
        /// Gets or sets the IC module packaging date (2 bytes).
        /// </summary>
        public ushort IcModulePackagingDate { get; set; }

        /// <summary>
        /// Gets or sets the ICC manufacturer (2 bytes).
        /// </summary>
        public ushort IccManufacturer { get; set; }

        /// <summary>
        /// Gets or sets the IC embedding date (2 bytes).
        /// </summary>
        public ushort IcEmbeddingDate { get; set; }

        /// <summary>
        /// Gets or sets the IC pre-personalizer (2 bytes).
        /// </summary>
        public ushort IcPrePersonalizer { get; set; }

        /// <summary>
        /// Gets or sets the IC pre-personalization equipment date (2 bytes).
        /// </summary>
        public ushort IcPrePersonalizationEquipmentDate { get; set; }

        /// <summary>
        /// Gets or sets the IC pre-personalization equipment ID (4 bytes).
        /// </summary>
        public uint IcPrePersonalizationEquipmentId { get; set; }

        /// <summary>
        /// Gets or sets the IC personalizer (2 bytes).
        /// </summary>
        public ushort IcPersonalizer { get; set; }

        /// <summary>
        /// Gets or sets the IC personalization date (2 bytes).
        /// </summary>
        public ushort IcPersonalizationDate { get; set; }

        /// <summary>
        /// Gets or sets the IC personalization equipment ID (4 bytes).
        /// </summary>
        public uint IcPersonalizationEquipmentId { get; set; }

        /// <summary>
        /// Gets the raw CPLC data bytes.
        /// </summary>
        public byte[] RawData { get; private set; } = [];

        /// <summary>
        /// Parses CPLC data from a byte array.
        /// </summary>
        /// <param name="data">The CPLC data bytes (must be at least 42 bytes).</param>
        /// <returns>Parsed CPLC data.</returns>
        public static CplcData Parse(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);

            if (data.Length < 42)
            {
                throw new ArgumentException(
                    $"CPLC data must be at least 42 bytes, got {data.Length}",
                    nameof(data)
                );
            }

            var cplc = new CplcData { RawData = new byte[data.Length] };
            Array.Copy(data, cplc.RawData, data.Length);

            // Parse according to CPLC structure
            int offset = 0;
            cplc.IcFabricator = ReadUInt16(data, ref offset);
            cplc.IcType = ReadUInt16(data, ref offset);
            cplc.OperatingSystemId = ReadUInt16(data, ref offset);
            cplc.OperatingSystemReleaseDate = ReadUInt16(data, ref offset);
            cplc.OperatingSystemReleaseLevel = ReadUInt16(data, ref offset);
            cplc.IcFabricationDate = ReadUInt16(data, ref offset);
            cplc.IcSerialNumber = ReadUInt32(data, ref offset);
            cplc.IcBatchIdentifier = ReadUInt16(data, ref offset);
            cplc.IcModuleFabricator = ReadUInt16(data, ref offset);
            cplc.IcModulePackagingDate = ReadUInt16(data, ref offset);
            cplc.IccManufacturer = ReadUInt16(data, ref offset);
            cplc.IcEmbeddingDate = ReadUInt16(data, ref offset);
            cplc.IcPrePersonalizer = ReadUInt16(data, ref offset);
            cplc.IcPrePersonalizationEquipmentDate = ReadUInt16(data, ref offset);
            cplc.IcPrePersonalizationEquipmentId = ReadUInt32(data, ref offset);
            cplc.IcPersonalizer = ReadUInt16(data, ref offset);
            cplc.IcPersonalizationDate = ReadUInt16(data, ref offset);
            cplc.IcPersonalizationEquipmentId = ReadUInt32(data, ref offset);

            return cplc;
        }

        /// <summary>
        /// Attempts to parse CPLC data using functional error handling.
        /// </summary>
        /// <param name="data">The CPLC data bytes (must be at least 42 bytes).</param>
        /// <returns>A result containing the parsed CPLC data or an error.</returns>
        public static Result<CplcData, SmartCardError> TryParse(byte[] data)
        {
            if (data == null)
            {
                return Result.Failure<CplcData, SmartCardError>(
                    SmartCardError.InvalidData("CPLC data cannot be null"));
            }

            if (data.Length < 42)
            {
                return Result.Failure<CplcData, SmartCardError>(
                    SmartCardError.InvalidData($"CPLC data must be at least 42 bytes, got {data.Length}"));
            }

            try
            {
                var cplc = Parse(data);
                return Result.Success<CplcData, SmartCardError>(cplc);
            }
            catch (Exception ex)
            {
                return Result.Failure<CplcData, SmartCardError>(
                    SmartCardError.InvalidData($"Failed to parse CPLC data: {ex.Message}"));
            }
        }

        private static ushort ReadUInt16(byte[] data, ref int offset)
        {
            var value = (ushort)((data[offset] << 8) | data[offset + 1]);
            offset += 2;
            return value;
        }

        private static uint ReadUInt32(byte[] data, ref int offset)
        {
            var value = (uint)(
                (data[offset] << 24)
                | (data[offset + 1] << 16)
                | (data[offset + 2] << 8)
                | data[offset + 3]
            );
            offset += 4;
            return value;
        }

        /// <summary>
        /// Formats CPLC data as a human-readable string.
        /// </summary>
        public override string ToString()
        {
            var sb = new StringBuilder();
            _ = sb.AppendLine("CPLC Data:");
            _ = sb.AppendLine($"  IC Fabricator: {IcFabricator:X4}");
            _ = sb.AppendLine($"  IC Type: {IcType:X4}");
            _ = sb.AppendLine($"  Operating System ID: {OperatingSystemId:X4}");
            _ = sb.AppendLine($"  Operating System Release Date: {OperatingSystemReleaseDate:X4}");
            _ = sb.AppendLine(
                $"  Operating System Release Level: {OperatingSystemReleaseLevel:X4}"
            );
            _ = sb.AppendLine($"  IC Fabrication Date: {IcFabricationDate:X4}");
            _ = sb.AppendLine($"  IC Serial Number: {IcSerialNumber:X8}");
            _ = sb.AppendLine($"  IC Batch Identifier: {IcBatchIdentifier:X4}");
            _ = sb.AppendLine($"  IC Module Fabricator: {IcModuleFabricator:X4}");
            _ = sb.AppendLine($"  IC Module Packaging Date: {IcModulePackagingDate:X4}");
            _ = sb.AppendLine($"  ICC Manufacturer: {IccManufacturer:X4}");
            _ = sb.AppendLine($"  IC Embedding Date: {IcEmbeddingDate:X4}");
            _ = sb.AppendLine($"  IC Pre-Personalizer: {IcPrePersonalizer:X4}");
            _ = sb.AppendLine(
                $"  IC Pre-Personalization Equipment Date: {IcPrePersonalizationEquipmentDate:X4}"
            );
            _ = sb.AppendLine(
                $"  IC Pre-Personalization Equipment ID: {IcPrePersonalizationEquipmentId:X8}"
            );
            _ = sb.AppendLine($"  IC Personalizer: {IcPersonalizer:X4}");
            _ = sb.AppendLine($"  IC Personalization Date: {IcPersonalizationDate:X4}");
            _ = sb.AppendLine(
                $"  IC Personalization Equipment ID: {IcPersonalizationEquipmentId:X8}"
            );
            return sb.ToString();
        }

        /// <summary>
        /// Checks if a date value represents a valid date (not 0x0000 or 0xFFFF).
        /// </summary>
        public static bool IsValidDate(ushort dateValue)
        {
            return dateValue != 0x0000 && dateValue != 0xFFFF;
        }
    }
}
