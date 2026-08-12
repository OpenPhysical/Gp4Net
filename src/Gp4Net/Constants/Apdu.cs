// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using JetBrains.Annotations;

namespace Gp4Net.Constants;

/// <summary>
/// APDU format constants and specifications as defined by ISO 7816-4.
/// Reference: ISO 7816-4 - Organization, security and commands for interchange
/// </summary>
[PublicAPI]
public static class Apdu
{
    /// <summary>
    /// APDU format length constants and limits.
    /// Reference: ISO 7816-4, Section 5.1
    /// </summary>
    public static class Formats
    {
        /// <summary>Maximum length for Lc field in short APDU format (255 bytes).</summary>
        public const int MAX_SHORT_LENGTH_LC = 255;

        /// <summary>Maximum length for extended APDU format (65536 bytes).</summary>
        public const int MAX_EXTENDED_LENGTH = 65536;

        /// <summary>Maximum data length for single APDU in extended format (65535 bytes).</summary>
        public const int MAX_APDU_DATA_LENGTH = 65535;

        /// <summary>Standard APDU header length - CLA, INS, P1, P2 (4 bytes).</summary>
        public const int APDU_HEADER_LENGTH = 4;
    }

    /// <summary>
    /// APDU class byte definitions for different command categories.
    /// Reference: ISO 7816-4, Section 5.4.1
    /// </summary>
    public static class Classes
    {
        /// <summary>Standard ISO 7816-4 class for basic interindustry commands (0x00).</summary>
        public const byte STANDARD = 0x00;

        /// <summary>First interindustry class (0x00-0x0F range).</summary>
        public const byte INTER_INDUSTRY_FIRST = 0x00;

        /// <summary>Last interindustry class (0x00-0x0F range).</summary>
        public const byte INTER_INDUSTRY_LAST = 0x0F;

        /// <summary>First proprietary class (0x80-0xFF range).</summary>
        public const byte PROPRIETARY_FIRST = 0x80;

        /// <summary>Last proprietary class (0x80-0xFF range).</summary>
        public const byte PROPRIETARY_LAST = 0xFF;
    }

    /// <summary>
    /// Standard instruction bytes as defined by ISO 7816-4.
    /// Reference: ISO 7816-4, Section 6
    /// </summary>
    public static class Instructions
    {
        /// <summary>SELECT instruction for file/application selection (0xA4).</summary>
        public const byte SELECT = 0xA4;

        /// <summary>READ BINARY instruction for transparent file reading (0xB0).</summary>
        public const byte READ_BINARY = 0xB0;

        /// <summary>WRITE BINARY instruction for transparent file writing (0xD0).</summary>
        public const byte WRITE_BINARY = 0xD0;

        /// <summary>READ RECORD instruction for record file reading (0xB2).</summary>
        public const byte READ_RECORD = 0xB2;

        /// <summary>WRITE RECORD instruction for record file writing (0xD2).</summary>
        public const byte WRITE_RECORD = 0xD2;

        /// <summary>GET DATA instruction for structured data retrieval (0xCA).</summary>
        public const byte GET_DATA = 0xCA;

        /// <summary>PUT DATA instruction for structured data storage (0xDA).</summary>
        public const byte PUT_DATA = 0xDA;

        /// <summary>VERIFY instruction for PIN/password verification (0x20).</summary>
        public const byte VERIFY = 0x20;

        /// <summary>CHANGE REFERENCE DATA instruction for PIN/password change (0x24).</summary>
        public const byte CHANGE_REFERENCE_DATA = 0x24;

        /// <summary>RESET RETRY COUNTER instruction (0x2C).</summary>
        public const byte RESET_RETRY_COUNTER = 0x2C;

        /// <summary>GET CHALLENGE instruction for random number generation (0x84).</summary>
        public const byte GET_CHALLENGE = 0x84;

        /// <summary>INTERNAL AUTHENTICATE instruction (0x88).</summary>
        public const byte INTERNAL_AUTHENTICATE = 0x88;

        /// <summary>EXTERNAL AUTHENTICATE instruction (0x82).</summary>
        public const byte EXTERNAL_AUTHENTICATE = 0x82;

        /// <summary>GET RESPONSE instruction for additional response data (0xC0).</summary>
        public const byte GET_RESPONSE = 0xC0;

        /// <summary>ENVELOPE instruction for command encapsulation (0xC2).</summary>
        public const byte ENVELOPE = 0xC2;

        /// <summary>MANAGE CHANNEL instruction for logical channel management (0x70).</summary>
        public const byte MANAGE_CHANNEL = 0x70;
    }

    /// <summary>
    /// SELECT command P1 parameter values.
    /// Reference: ISO 7816-4, Section 6.9.1
    /// </summary>
    public static class SelectP1
    {
        /// <summary>Select MF, DF or EF by file identifier (0x00).</summary>
        public const byte SELECT_BY_FILE_ID = 0x00;

        /// <summary>Select child DF by file identifier (0x01).</summary>
        public const byte SELECT_CHILD_DF = 0x01;

        /// <summary>Select EF under current DF by file identifier (0x02).</summary>
        public const byte SELECT_EF_UNDER_CURRENT_DF = 0x02;

        /// <summary>Select parent DF of current DF (0x03).</summary>
        public const byte SELECT_PARENT_DF = 0x03;

        /// <summary>Select by DF name (AID) (0x04).</summary>
        public const byte SELECT_BY_NAME = 0x04;

        /// <summary>Select from MF by path (0x08).</summary>
        public const byte SELECT_FROM_MF_BY_PATH = 0x08;

        /// <summary>Select from current DF by path (0x09).</summary>
        public const byte SELECT_FROM_CURRENT_DF_BY_PATH = 0x09;
    }

    /// <summary>
    /// SELECT command P2 parameter values.
    /// Reference: ISO 7816-4, Section 6.9.2
    /// </summary>
    public static class SelectP2
    {
        /// <summary>First record of file (0x00).</summary>
        public const byte FIRST_RECORD = 0x00;

        /// <summary>Last record of file (0x01).</summary>
        public const byte LAST_RECORD = 0x01;

        /// <summary>Next record of file (0x02).</summary>
        public const byte NEXT_RECORD = 0x02;

        /// <summary>Previous record of file (0x03).</summary>
        public const byte PREVIOUS_RECORD = 0x03;

        /// <summary>Return FCI template (0x00).</summary>
        public const byte RETURN_FCI = 0x00;

        /// <summary>Return FCP template (0x04).</summary>
        public const byte RETURN_FCP = 0x04;

        /// <summary>Return FMD template (0x08).</summary>
        public const byte RETURN_FMD = 0x08;

        /// <summary>No response data (0x0C).</summary>
        public const byte NO_RESPONSE_DATA = 0x0C;
    }
}
