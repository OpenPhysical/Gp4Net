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
                public const byte BYTE1 = 0xDE;

                /// <summary>Second byte of CAP file magic number (0xCA).</summary>
                public const byte BYTE2 = 0xCA;

                /// <summary>Third byte of CAP file magic number (0xFF).</summary>
                public const byte BYTE3 = 0xFF;

                /// <summary>Fourth byte of CAP file magic number (0xED).</summary>
                public const byte BYTE4 = 0xED;
            }

            /// <summary>
            /// Minimum header component size in bytes (10 bytes without magic number).
            /// Reference: Java Card Virtual Machine Specification, Section 6.3
            /// </summary>
            public const int MINIMUM_SIZE = 10;
        }

        /// <summary>
        /// CAP file component tags as defined in Java Card Virtual Machine Specification.
        /// Reference: Java Card Virtual Machine Specification, Section 6.2
        /// </summary>
        public static class ComponentTags
        {
            /// <summary>Header component tag (0x01).</summary>
            public const byte HEADER = 0x01;

            /// <summary>Directory component tag (0x02).</summary>
            public const byte DIRECTORY = 0x02;

            /// <summary>Applet component tag (0x03).</summary>
            public const byte APPLET = 0x03;

            /// <summary>Import component tag (0x04).</summary>
            public const byte IMPORT = 0x04;

            /// <summary>Constant Pool component tag (0x05).</summary>
            public const byte CONSTANT_POOL = 0x05;

            /// <summary>Class component tag (0x06).</summary>
            public const byte CLASS = 0x06;

            /// <summary>Method component tag (0x07).</summary>
            public const byte METHOD = 0x07;

            /// <summary>Static Field component tag (0x08).</summary>
            public const byte STATIC_FIELD = 0x08;

            /// <summary>Reference Location component tag (0x09).</summary>
            public const byte REFERENCE_LOCATION = 0x09;

            /// <summary>Export component tag (0x0A).</summary>
            public const byte EXPORT = 0x0A;

            /// <summary>Descriptor component tag (0x0B).</summary>
            public const byte DESCRIPTOR = 0x0B;

            /// <summary>Debug component tag (0x0C).</summary>
            public const byte DEBUG = 0x0C;
        }

        /// <summary>
        /// CAP file component filenames used in ZIP/JAR format CAP files.
        /// Reference: Java Card Virtual Machine Specification, Appendix A
        /// </summary>
        public static class ComponentFilenames
        {
            /// <summary>Header component filename.</summary>
            public const string HEADER = "Header.cap";

            /// <summary>Directory component filename.</summary>
            public const string DIRECTORY = "Directory.cap";

            /// <summary>Applet component filename.</summary>
            public const string APPLET = "Applet.cap";

            /// <summary>Import component filename.</summary>
            public const string IMPORT = "Import.cap";

            /// <summary>Constant Pool component filename.</summary>
            public const string CONSTANT_POOL = "ConstantPool.cap";

            /// <summary>Class component filename.</summary>
            public const string CLASS = "Class.cap";

            /// <summary>Method component filename.</summary>
            public const string METHOD = "Method.cap";

            /// <summary>Static Field component filename.</summary>
            public const string STATIC_FIELD = "StaticField.cap";

            /// <summary>Reference Location component filename.</summary>
            public const string REFERENCE_LOCATION = "RefLocation.cap";

            /// <summary>Export component filename.</summary>
            public const string EXPORT = "Export.cap";

            /// <summary>Descriptor component filename.</summary>
            public const string DESCRIPTOR = "Descriptor.cap";

            /// <summary>Debug component filename.</summary>
            public const string DEBUG = "Debug.cap";
        }

        /// <summary>
        /// Application Identifier (AID) length constraints per Java Card specification.
        /// Reference: Java Card Runtime Environment Specification, Section 4.2
        /// </summary>
        public static class AidConstraints
        {
            /// <summary>Minimum AID length in bytes (5 bytes).</summary>
            public const int MIN_LENGTH = 5;

            /// <summary>Maximum AID length in bytes (16 bytes).</summary>
            public const int MAX_LENGTH = 16;
        }

        /// <summary>
        /// Default package version constants for CAP files.
        /// Reference: Java Card Virtual Machine Specification, Section 6.3.1
        /// </summary>
        public static class DefaultVersion
        {
            /// <summary>Default package major version (1).</summary>
            public const byte PACKAGE_MAJOR = 1;

            /// <summary>Default package minor version (0).</summary>
            public const byte PACKAGE_MINOR = 0;
        }

        /// <summary>
        /// JAR manifest attributes specific to Java Card CAP files.
        /// Reference: Java Card Development Kit Documentation
        /// </summary>
        public static class ManifestAttributes
        {
            /// <summary>Java Card CAP file version attribute name.</summary>
            public const string CAP_FILE_VERSION = "Java-Card-CAP-File-Version";

            /// <summary>Java Card converter version attribute name.</summary>
            public const string CONVERTER_VERSION = "Java-Card-Converter-Version";

            /// <summary>Java Card converter provider attribute name.</summary>
            public const string CONVERTER_PROVIDER = "Java-Card-Converter-Provider";

            /// <summary>Java Card CAP creation time attribute name.</summary>
            public const string CREATION_TIME = "Java-Card-CAP-Creation-Time";

            /// <summary>Java Card package name attribute name.</summary>
            public const string PACKAGE_NAME = "Java-Card-Package-Name";

            /// <summary>Java Card integer support required attribute name.</summary>
            public const string INTEGER_SUPPORT_REQUIRED = "Java-Card-Integer-Support-Required";

            /// <summary>Base attribute name for imported package AID (requires index suffix).</summary>
            public const string IMPORTED_PACKAGE_AID_BASE = "Java-Card-Imported-Package-";

            /// <summary>AID suffix for imported package attributes.</summary>
            public const string IMPORTED_PACKAGE_AID_SUFFIX = "-AID";

            /// <summary>Version suffix for imported package attributes.</summary>
            public const string IMPORTED_PACKAGE_VERSION_SUFFIX = "-Version";

            /// <summary>Value indicating integer support is required.</summary>
            public const string TRUE_VALUE = "TRUE";
        }

        /// <summary>
        /// Standard manifest header attributes to ignore during parsing.
        /// Reference: JAR File Specification
        /// </summary>
        public static class IgnoredManifestHeaders
        {
            /// <summary>Manifest version header.</summary>
            public const string MANIFEST_VERSION = "Manifest-Version";

            /// <summary>Name section header.</summary>
            public const string NAME = "Name:";
        }
    }
}
