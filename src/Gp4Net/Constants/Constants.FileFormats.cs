// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

namespace Gp4Net.Constants;

public static partial class Constants
{
    /// <summary>
    /// File format constants for various file types and their signatures.
    /// References: ZIP File Format Specification, PKware APPNOTE.TXT
    /// </summary>
    [PublicAPI]
    public static class FileFormats
    {
        /// <summary>
        /// ZIP/JAR file format signatures and constants.
        /// Reference: ZIP File Format Specification v6.3.9, Section 4.3.6
        /// </summary>
        public static class Zip
        {
            /// <summary>
            /// ZIP file local file header signature (0x504B0304).
            /// This is the "PK" signature followed by 0x03 0x04.
            /// Reference: ZIP File Format Specification, Section 4.3.7
            /// </summary>
            public static class LocalFileHeaderSignature
            {
                /// <summary>First byte of ZIP local file header signature (0x50 = 'P').</summary>
                public const byte BYTE1 = 0x50;

                /// <summary>Second byte of ZIP local file header signature (0x4B = 'K').</summary>
                public const byte BYTE2 = 0x4B;

                /// <summary>Third byte of ZIP local file header signature (0x03).</summary>
                public const byte BYTE3 = 0x03;

                /// <summary>Fourth byte of ZIP local file header signature (0x04).</summary>
                public const byte BYTE4 = 0x04;

                /// <summary>Complete ZIP local file header signature as 32-bit value (0x504B0304).</summary>
                public const uint COMPLETE = 0x504B0304;
            }

            /// <summary>
            /// Minimum ZIP file header size in bytes (4 bytes for signature).
            /// Reference: ZIP File Format Specification
            /// </summary>
            public const int MINIMUM_HEADER_SIZE = 4;

            /// <summary>
            /// JAR manifest file path within ZIP archive.
            /// Reference: JAR File Specification
            /// </summary>
            public const string MANIFEST_PATH = "META-INF/MANIFEST.MF";
        }
    }
}
