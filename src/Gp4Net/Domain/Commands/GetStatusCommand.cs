using System;
using System.Collections.Generic;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Commands
{
    /// <summary>
    /// Represents the GET STATUS command for querying card content status.
    /// </summary>
    [PublicAPI]
    public class GetStatusCommand
    {
        /// <summary>
        /// The command class byte.
        /// </summary>
        public const byte Cla = 0x80;

        /// <summary>
        /// The command instruction byte.
        /// </summary>
        public const byte Ins = 0xF2;

        /// <summary>
        /// Get status subset values for P1.
        /// </summary>
        public enum StatusSubset : byte
        {
            /// <summary>
            /// Issuer Security Domain only.
            /// </summary>
            IssuerSecurityDomain = 0x80,
            
            /// <summary>
            /// Applications and Supplementary Security Domains only.
            /// </summary>
            ApplicationsAndSupplementaryDomains = 0x40,
            
            /// <summary>
            /// Executable Load Files only.
            /// </summary>
            ExecutableLoadFiles = 0x20,
            
            /// <summary>
            /// Executable Load Files and their Executable Modules.
            /// </summary>
            ExecutableLoadFilesAndModules = 0x10
        }

        /// <summary>
        /// Response format values for P2.
        /// </summary>
        public enum ResponseFormat : byte
        {
            /// <summary>
            /// No format specified.
            /// </summary>
            None = 0x00,
            
            /// <summary>
            /// Return data in TLV format.
            /// </summary>
            Tlv = 0x02
        }

        /// <summary>
        /// Gets the status subset to query.
        /// </summary>
        public StatusSubset Subset { get; }

        /// <summary>
        /// Gets the response format.
        /// </summary>
        public ResponseFormat Format { get; }

        /// <summary>
        /// Gets the search criteria (optional AID).
        /// </summary>
        public byte[]? SearchCriteria { get; }

        /// <summary>
        /// Initializes a new instance of the GetStatusCommand class.
        /// </summary>
        /// <param name="subset">The status subset to query.</param>
        /// <param name="format">The response format.</param>
        /// <param name="searchCriteria">Optional search criteria (AID).</param>
        public GetStatusCommand(StatusSubset subset, ResponseFormat format = ResponseFormat.None, byte[]? searchCriteria = null)
        {
            if (searchCriteria != null && (searchCriteria.Length < 5 || searchCriteria.Length > 16))
                throw new ArgumentException("Search criteria AID must be between 5 and 16 bytes.", nameof(searchCriteria));

            Subset = subset;
            Format = format;
            SearchCriteria = searchCriteria != null ? (byte[])searchCriteria.Clone() : null;
        }

        /// <summary>
        /// Converts this command to an APDU byte array.
        /// </summary>
        /// <returns>The APDU command bytes.</returns>
        public byte[] ToApdu()
        {
            var dataLength = SearchCriteria?.Length ?? 0;
            var apdu = new byte[5 + dataLength];

            apdu[0] = Cla;
            apdu[1] = Ins;
            apdu[2] = (byte)Subset;
            apdu[3] = (byte)Format;
            apdu[4] = (byte)dataLength;

            if (SearchCriteria != null)
            {
                Array.Copy(SearchCriteria, 0, apdu, 5, SearchCriteria.Length);
            }

            return apdu;
        }
    }

    /// <summary>
    /// Represents an application status entry from GET STATUS response.
    /// </summary>
    [PublicAPI]
    public class ApplicationStatusEntry
    {
        /// <summary>
        /// Application lifecycle states.
        /// </summary>
        public enum LifecycleState : byte
        {
            /// <summary>
            /// Application is installed.
            /// </summary>
            Installed = 0x03,
            
            /// <summary>
            /// Application is selectable.
            /// </summary>
            Selectable = 0x07,
            
            /// <summary>
            /// Application is personalized.
            /// </summary>
            Personalized = 0x0F,
            
            /// <summary>
            /// Application is blocked.
            /// </summary>
            Blocked = 0x83,
            
            /// <summary>
            /// Application is locked.
            /// </summary>
            Locked = 0x87
        }

        /// <summary>
        /// Gets the application AID.
        /// </summary>
        public byte[] Aid { get; }

        /// <summary>
        /// Gets the application lifecycle state.
        /// </summary>
        public LifecycleState State { get; }

        /// <summary>
        /// Gets the application privileges.
        /// </summary>
        public byte[] Privileges { get; }

        /// <summary>
        /// Initializes a new instance of the ApplicationStatusEntry class.
        /// </summary>
        /// <param name="aid">The application AID.</param>
        /// <param name="state">The lifecycle state.</param>
        /// <param name="privileges">The application privileges.</param>
        public ApplicationStatusEntry(byte[] aid, LifecycleState state, byte[] privileges)
        {
            Aid = (byte[])aid.Clone();
            State = state;
            Privileges = (byte[])privileges.Clone();
        }
    }

    /// <summary>
    /// Represents the response to a GET STATUS command.
    /// </summary>
    [PublicAPI]
    public class GetStatusResponse
    {
        /// <summary>
        /// Gets the list of application status entries.
        /// </summary>
        public IReadOnlyList<ApplicationStatusEntry> Applications { get; }

        /// <summary>
        /// Initializes a new instance of the GetStatusResponse class.
        /// </summary>
        /// <param name="applications">The list of applications.</param>
        public GetStatusResponse(IList<ApplicationStatusEntry> applications)
        {
            Applications = new List<ApplicationStatusEntry>(applications);
        }

        /// <summary>
        /// Parses a GET STATUS response.
        /// </summary>
        /// <param name="response">The response data (excluding status word).</param>
        /// <returns>The parsed response.</returns>
        public static GetStatusResponse Parse(byte[] response)
        {
            if (response == null)
                throw new ArgumentNullException(nameof(response));

            var applications = new List<ApplicationStatusEntry>();
            var offset = 0;

            while (offset < response.Length)
            {
                // Check if we have at least the minimum entry size
                if (offset + 3 >= response.Length)
                    break;

                // AID length
                var aidLength = response[offset++];
                if (aidLength == 0 || offset + aidLength >= response.Length)
                    break;

                // AID
                var aid = new byte[aidLength];
                Array.Copy(response, offset, aid, 0, aidLength);
                offset += aidLength;

                // Lifecycle state
                if (offset >= response.Length)
                    break;
                var state = (ApplicationStatusEntry.LifecycleState)response[offset++];

                // Privileges length
                if (offset >= response.Length)
                    break;
                var privilegesLength = response[offset++];

                // Privileges
                if (offset + privilegesLength > response.Length)
                    break;
                var privileges = new byte[privilegesLength];
                if (privilegesLength > 0)
                {
                    Array.Copy(response, offset, privileges, 0, privilegesLength);
                    offset += privilegesLength;
                }

                applications.Add(new ApplicationStatusEntry(aid, state, privileges));
            }

            return new GetStatusResponse(applications);
        }
    }
}