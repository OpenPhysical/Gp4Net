// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

namespace Gp4Net.Constants;

public static partial class Constants
{
    /// <summary>
    /// Java Card constants for CAP files, component structures, and runtime specifications.
    /// References: Java Card Virtual Machine Specification, Java Card Runtime Environment Specification
    /// </summary>
    [PublicAPI]
    public static class JavaCard
    {
        /// <summary>
        /// CAP file header component constants.
        /// Reference: Java Card Virtual Machine Specification, Section 6.3
        /// </summary>
        public static class CapHeader
        {
            /// <summary>
            /// CAP file magic number signature (0xDECAFFED).
            /// This signature appears at the start of CAP file header components.
            /// Reference: Java Card Virtual Machine Specification, Section 6.3.1
            /// </summary>
            public static class MagicNumber
            {
                /// <summary>First byte of CAP file magic number (0xDE).</summary>
                public const byte Byte1 = 0xDE;
                
                /// <summary>Second byte of CAP file magic number (0xCA).</summary>
                public const byte Byte2 = 0xCA;
                
                /// <summary>Third byte of CAP file magic number (0xFF).</summary>
                public const byte Byte3 = 0xFF;
                
                /// <summary>Fourth byte of CAP file magic number (0xED).</summary>
                public const byte Byte4 = 0xED;
                
                /// <summary>Complete CAP file magic number as 32-bit value (0xDECAFFED).</summary>
                public const uint Complete = 0xDECAFFED;
            }

            /// <summary>
            /// Minimum header component size in bytes (10 bytes without magic number).
            /// Reference: Java Card Virtual Machine Specification, Section 6.3
            /// </summary>
            public const int MinimumSize = 10;
        }

        /// <summary>
        /// CAP file component tags as defined in Java Card Virtual Machine Specification.
        /// Reference: Java Card Virtual Machine Specification, Section 6.2
        /// </summary>
        public static class ComponentTags
        {
            /// <summary>Header component tag (0x01).</summary>
            public const byte Header = 0x01;

            /// <summary>Directory component tag (0x02).</summary>
            public const byte Directory = 0x02;

            /// <summary>Applet component tag (0x03).</summary>
            public const byte Applet = 0x03;

            /// <summary>Import component tag (0x04).</summary>
            public const byte Import = 0x04;

            /// <summary>Constant Pool component tag (0x05).</summary>
            public const byte ConstantPool = 0x05;

            /// <summary>Class component tag (0x06).</summary>
            public const byte Class = 0x06;

            /// <summary>Method component tag (0x07).</summary>
            public const byte Method = 0x07;

            /// <summary>Static Field component tag (0x08).</summary>
            public const byte StaticField = 0x08;

            /// <summary>Reference Location component tag (0x09).</summary>
            public const byte ReferenceLocation = 0x09;

            /// <summary>Export component tag (0x0A).</summary>
            public const byte Export = 0x0A;

            /// <summary>Descriptor component tag (0x0B).</summary>
            public const byte Descriptor = 0x0B;

            /// <summary>Debug component tag (0x0C).</summary>
            public const byte Debug = 0x0C;
        }

        /// <summary>
        /// CAP file component filenames used in ZIP/JAR format CAP files.
        /// Reference: Java Card Virtual Machine Specification, Appendix A
        /// </summary>
        public static class ComponentFilenames
        {
            /// <summary>Header component filename.</summary>
            public const string Header = "Header.cap";

            /// <summary>Directory component filename.</summary>
            public const string Directory = "Directory.cap";

            /// <summary>Applet component filename.</summary>
            public const string Applet = "Applet.cap";

            /// <summary>Import component filename.</summary>
            public const string Import = "Import.cap";

            /// <summary>Constant Pool component filename.</summary>
            public const string ConstantPool = "ConstantPool.cap";

            /// <summary>Class component filename.</summary>
            public const string Class = "Class.cap";

            /// <summary>Method component filename.</summary>
            public const string Method = "Method.cap";

            /// <summary>Static Field component filename.</summary>
            public const string StaticField = "StaticField.cap";

            /// <summary>Reference Location component filename.</summary>
            public const string ReferenceLocation = "RefLocation.cap";

            /// <summary>Export component filename.</summary>
            public const string Export = "Export.cap";

            /// <summary>Descriptor component filename.</summary>
            public const string Descriptor = "Descriptor.cap";

            /// <summary>Debug component filename.</summary>
            public const string Debug = "Debug.cap";
        }

        /// <summary>
        /// Application Identifier (AID) length constraints per Java Card specification.
        /// Reference: Java Card Runtime Environment Specification, Section 4.2
        /// </summary>
        public static class AidConstraints
        {
            /// <summary>Minimum AID length in bytes (5 bytes).</summary>
            public const int MinLength = 5;

            /// <summary>Maximum AID length in bytes (16 bytes).</summary>
            public const int MaxLength = 16;
        }

        /// <summary>
        /// Default package version constants for CAP files.
        /// Reference: Java Card Virtual Machine Specification, Section 6.3.1
        /// </summary>
        public static class DefaultVersion
        {
            /// <summary>Default package major version (1).</summary>
            public const byte PackageMajor = 1;

            /// <summary>Default package minor version (0).</summary>
            public const byte PackageMinor = 0;
        }

        /// <summary>
        /// JAR manifest attributes specific to Java Card CAP files.
        /// Reference: Java Card Development Kit Documentation
        /// </summary>
        public static class ManifestAttributes
        {
            /// <summary>Java Card CAP file version attribute name.</summary>
            public const string CapFileVersion = "Java-Card-CAP-File-Version";

            /// <summary>Java Card converter version attribute name.</summary>
            public const string ConverterVersion = "Java-Card-Converter-Version";

            /// <summary>Java Card converter provider attribute name.</summary>
            public const string ConverterProvider = "Java-Card-Converter-Provider";

            /// <summary>Java Card CAP creation time attribute name.</summary>
            public const string CreationTime = "Java-Card-CAP-Creation-Time";

            /// <summary>Java Card package name attribute name.</summary>
            public const string PackageName = "Java-Card-Package-Name";

            /// <summary>Java Card integer support required attribute name.</summary>
            public const string IntegerSupportRequired = "Java-Card-Integer-Support-Required";

            /// <summary>Base attribute name for imported package AID (requires index suffix).</summary>
            public const string ImportedPackageAidBase = "Java-Card-Imported-Package-";

            /// <summary>AID suffix for imported package attributes.</summary>
            public const string ImportedPackageAidSuffix = "-AID";

            /// <summary>Version suffix for imported package attributes.</summary>
            public const string ImportedPackageVersionSuffix = "-Version";

            /// <summary>Value indicating integer support is required.</summary>
            public const string TrueValue = "TRUE";
        }

        /// <summary>
        /// Standard manifest header attributes to ignore during parsing.
        /// Reference: JAR File Specification
        /// </summary>
        public static class IgnoredManifestHeaders
        {
            /// <summary>Manifest version header.</summary>
            public const string ManifestVersion = "Manifest-Version";

            /// <summary>Name section header.</summary>
            public const string Name = "Name:";
        }
    }
}