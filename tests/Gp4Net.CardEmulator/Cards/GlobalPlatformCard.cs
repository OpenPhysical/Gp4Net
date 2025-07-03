using System;
using System.Collections.Generic;
using System.Linq;
using Gp4Net.CardEmulator.Core;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Cards
{
    /// <summary>
    /// Base class for GlobalPlatform-compliant virtual cards.
    /// Provides common functionality for SELECT, INITIALIZE UPDATE, EXTERNAL AUTHENTICATE,
    /// GET DATA, GET STATUS, and other GP commands.
    /// </summary>
    [PublicAPI]
    public abstract class GlobalPlatformCard : IVirtualCard
    {
        // Standard GlobalPlatform response codes
        protected const ushort SW_SUCCESS = 0x9000;
        protected const ushort SW_FILE_NOT_FOUND = 0x6A82;
        protected const ushort SW_WRONG_LENGTH = 0x6700;
        protected const ushort SW_CONDITIONS_NOT_SATISFIED = 0x6985;
        protected const ushort SW_INCORRECT_P1P2 = 0x6A86;
        protected const ushort SW_INS_NOT_SUPPORTED = 0x6D00;
        protected const ushort SW_CLA_NOT_SUPPORTED = 0x6E00;
        protected const ushort SW_REFERENCED_DATA_NOT_FOUND = 0x6A88;
        protected const ushort SW_INCORRECT_PARAMETERS = 0x6A80;
        protected const ushort SW_GENERIC_ERROR = 0x6F00;

        // GlobalPlatform command instructions
        protected const byte INS_SELECT = 0xA4;
        protected const byte INS_INITIALIZE_UPDATE = 0x50;
        protected const byte INS_EXTERNAL_AUTHENTICATE = 0x82;
        protected const byte INS_GET_DATA = 0xCA;
        protected const byte INS_GET_STATUS = 0xF2;
        protected const byte INS_INSTALL = 0xE6;
        protected const byte INS_LOAD = 0xE8;
        protected const byte INS_DELETE = 0xE4;
        protected const byte INS_PUT_KEY = 0xD8;
        protected const byte INS_STORE_DATA = 0xE2;

        // Card state
        protected bool _isdSelected;
        protected bool _secureChannelEstablished;
        protected byte[] _hostChallenge = Array.Empty<byte>();
        protected byte[] _cardChallenge = Array.Empty<byte>();
        protected SessionKeys? _sessionKeys;
        protected byte _securityLevel;
        protected byte _scpVersion = 0x02; // Default to SCP02
        protected byte _scpImplementation = 0x15; // Default to i=15

        // Installed applications and load files
        protected readonly Dictionary<string, InstalledApplication> _installedApplications = new();
        protected readonly Dictionary<string, LoadFile> _loadFiles = new();
        protected readonly List<byte[]> _pendingCapData = new();
        protected string? _pendingPackageAid;

        // Data objects for GET DATA command
        protected readonly Dictionary<ushort, byte[]> _dataObjects = new();

        // Configuration data
        protected readonly Dictionary<ushort, byte[]> _configData = new();

        /// <inheritdoc />
        public bool IsSelected => _isdSelected;

        /// <inheritdoc />
        public bool IsSecureChannelEstablished => _secureChannelEstablished;

        /// <summary>
        /// Gets the ISD AID for this card.
        /// </summary>
        protected abstract byte[] IsdAid { get; }

        /// <summary>
        /// Gets the default static keys for this card.
        /// </summary>
        protected abstract Dictionary<byte, KeySet> StaticKeys { get; }

        /// <summary>
        /// Gets the current key version.
        /// </summary>
        protected abstract byte CurrentKeyVersion { get; }

        /// <summary>
        /// Initializes a new instance of the GlobalPlatformCard class.
        /// </summary>
        protected GlobalPlatformCard()
        {
            Reset();
            InitializeDefaultDataObjects();
        }

        /// <inheritdoc />
        public abstract byte[] GetAtr();

        /// <inheritdoc />
        public virtual void Reset()
        {
            _isdSelected = false;
            _secureChannelEstablished = false;
            _hostChallenge = Array.Empty<byte>();
            _cardChallenge = Array.Empty<byte>();
            _sessionKeys = null;
            _securityLevel = 0;
            _pendingCapData.Clear();
            _pendingPackageAid = null;
        }

        /// <inheritdoc />
        public virtual ApduResponse ProcessCommand(byte[] command)
        {
            try
            {
                var apdu = new ApduCommand(command);

                // Route command based on instruction
                return apdu.Ins switch
                {
                    INS_SELECT => ProcessSelect(apdu),
                    INS_INITIALIZE_UPDATE => ProcessInitializeUpdate(apdu),
                    INS_EXTERNAL_AUTHENTICATE => ProcessExternalAuthenticate(apdu),
                    INS_GET_DATA => ProcessGetData(apdu),
                    INS_GET_STATUS => ProcessGetStatus(apdu),
                    INS_INSTALL => ProcessInstall(apdu),
                    INS_LOAD => ProcessLoad(apdu),
                    INS_DELETE => ProcessDelete(apdu),
                    INS_PUT_KEY => ProcessPutKey(apdu),
                    INS_STORE_DATA => ProcessStoreData(apdu),
                    _ => ApduResponse.Error(SW_INS_NOT_SUPPORTED),
                };
            }
            catch (Exception)
            {
                return ApduResponse.Error(SW_GENERIC_ERROR);
            }
        }

        /// <summary>
        /// Processes a SELECT command.
        /// </summary>
        protected virtual ApduResponse ProcessSelect(ApduCommand apdu)
        {
            if (apdu.P1 != 0x04) // Select by name
                return ApduResponse.Error(SW_INCORRECT_P1P2);

            var aid = apdu.Data;

            if (aid.SequenceEqual(IsdAid))
            {
                _isdSelected = true;
                return GetSelectResponse();
            }

            // Check for installed applications
            var aidHex = Convert.ToHexString(aid);
            if (_installedApplications.ContainsKey(aidHex))
            {
                return ApduResponse.Success(); // Simple success for installed apps
            }

            return ApduResponse.Error(SW_FILE_NOT_FOUND);
        }

        /// <summary>
        /// Gets the SELECT response for the ISD.
        /// </summary>
        protected abstract ApduResponse GetSelectResponse();

        /// <summary>
        /// Processes an INITIALIZE UPDATE command.
        /// </summary>
        protected abstract ApduResponse ProcessInitializeUpdate(ApduCommand apdu);

        /// <summary>
        /// Processes an EXTERNAL AUTHENTICATE command.
        /// </summary>
        protected abstract ApduResponse ProcessExternalAuthenticate(ApduCommand apdu);

        /// <summary>
        /// Processes a GET DATA command.
        /// </summary>
        protected virtual ApduResponse ProcessGetData(ApduCommand apdu)
        {
            if (!_isdSelected)
                return ApduResponse.Error(SW_CONDITIONS_NOT_SATISFIED);

            // Construct data object identifier from P1 and P2
            var dataObjectId = (ushort)((apdu.P1 << 8) | apdu.P2);

            // Check if we have this data object
            if (_dataObjects.TryGetValue(dataObjectId, out var data))
            {
                return ApduResponse.Success(data);
            }

            // Check configuration data
            if (_configData.TryGetValue(dataObjectId, out var configData))
            {
                return ApduResponse.Success(configData);
            }

            return ApduResponse.Error(SW_REFERENCED_DATA_NOT_FOUND);
        }

        /// <summary>
        /// Processes a GET STATUS command.
        /// </summary>
        protected virtual ApduResponse ProcessGetStatus(ApduCommand apdu)
        {
            var response = new List<byte>();

            switch (apdu.P1)
            {
                case 0x80: // ISD only
                    response.AddRange(EncodeApplicationEntry(IsdAid, 0x07, GetIsdPrivileges()));
                    break;

                case 0x40: // Applications and SSDs
                    foreach (var app in _installedApplications.Values)
                    {
                        response.AddRange(
                            EncodeApplicationEntry(app.Aid, app.LifecycleState, app.Privileges)
                        );
                    }
                    break;

                case 0x20: // Load files
                    foreach (var loadFile in _loadFiles.Values)
                    {
                        var aid = Convert.FromHexString(loadFile.Aid);
                        response.AddRange(EncodeApplicationEntry(aid, 0x07, new byte[] { 0x00 }));
                    }
                    break;

                default:
                    return ApduResponse.Error(SW_INCORRECT_P1P2);
            }

            return ApduResponse.Success(response.ToArray());
        }

        /// <summary>
        /// Gets the ISD privileges.
        /// </summary>
        protected virtual byte[] GetIsdPrivileges()
        {
            return new byte[] { 0xC8 }; // Default ISD privileges
        }

        /// <summary>
        /// Processes an INSTALL command.
        /// </summary>
        protected virtual ApduResponse ProcessInstall(ApduCommand apdu)
        {
            if (!_secureChannelEstablished)
                return ApduResponse.Error(SW_CONDITIONS_NOT_SATISFIED);

            return apdu.P1 switch
            {
                0x02 => ProcessInstallForLoad(apdu),
                0x0C => ProcessInstallForInstall(apdu),
                _ => ApduResponse.Error(SW_INCORRECT_P1P2),
            };
        }

        /// <summary>
        /// Processes INSTALL [for load].
        /// </summary>
        protected virtual ApduResponse ProcessInstallForLoad(ApduCommand apdu)
        {
            var data = apdu.Data;
            if (data.Length < 1)
                return ApduResponse.Error(SW_WRONG_LENGTH);

            var offset = 0;

            // Parse package AID
            var packageAidLength = data[offset++];
            if (offset + packageAidLength > data.Length)
                return ApduResponse.Error(SW_WRONG_LENGTH);

            var packageAid = new byte[packageAidLength];
            Array.Copy(data, offset, packageAid, 0, packageAidLength);
            offset += packageAidLength;

            _pendingPackageAid = Convert.ToHexString(packageAid);
            _pendingCapData.Clear();

            return ApduResponse.Success(new byte[] { 0x00 });
        }

        /// <summary>
        /// Processes INSTALL [for install].
        /// </summary>
        protected virtual ApduResponse ProcessInstallForInstall(ApduCommand apdu)
        {
            var data = apdu.Data;
            if (data.Length < 3)
                return ApduResponse.Error(SW_WRONG_LENGTH);

            var offset = 0;

            // Parse package AID
            var packageAidLength = data[offset++];
            var packageAid = new byte[packageAidLength];
            Array.Copy(data, offset, packageAid, 0, packageAidLength);
            offset += packageAidLength;

            // Parse module AID
            var moduleAidLength = data[offset++];
            var moduleAid = new byte[moduleAidLength];
            Array.Copy(data, offset, moduleAid, 0, moduleAidLength);
            offset += moduleAidLength;

            // Parse application AID
            var appAidLength = data[offset++];
            var appAid = new byte[appAidLength];
            Array.Copy(data, offset, appAid, 0, appAidLength);
            offset += appAidLength;

            // Install the application
            var appAidHex = Convert.ToHexString(appAid);
            _installedApplications[appAidHex] = new InstalledApplication(
                appAid,
                0x07, // Selectable state
                new byte[] { 0x00 } // No privileges
            );

            return ApduResponse.Success(new byte[] { 0x00 });
        }

        /// <summary>
        /// Processes a LOAD command.
        /// </summary>
        protected virtual ApduResponse ProcessLoad(ApduCommand apdu)
        {
            if (!_secureChannelEstablished)
                return ApduResponse.Error(SW_CONDITIONS_NOT_SATISFIED);

            // Accumulate CAP file data
            _pendingCapData.Add((byte[])apdu.Data.Clone());

            if (apdu.P1 == 0x80) // Last block
            {
                // Simulate successful load
                if (_pendingPackageAid != null)
                {
                    var totalData = _pendingCapData.SelectMany(d => d).ToArray();
                    _loadFiles[_pendingPackageAid] = new LoadFile(_pendingPackageAid, totalData);
                }
            }

            return ApduResponse.Success(new byte[] { 0x00 });
        }

        /// <summary>
        /// Processes a DELETE command.
        /// </summary>
        protected virtual ApduResponse ProcessDelete(ApduCommand apdu)
        {
            if (!_secureChannelEstablished)
                return ApduResponse.Error(SW_CONDITIONS_NOT_SATISFIED);

            var data = apdu.Data;
            var offset = 0;

            while (offset < data.Length)
            {
                if (data[offset] != 0x4F) // AID tag
                    return ApduResponse.Error(SW_INCORRECT_PARAMETERS);

                offset++;
                var aidLength = data[offset++];
                var aid = new byte[aidLength];
                Array.Copy(data, offset, aid, 0, aidLength);
                offset += aidLength;

                var aidHex = Convert.ToHexString(aid);
                _installedApplications.Remove(aidHex);
                _loadFiles.Remove(aidHex);
            }

            return ApduResponse.Success(new byte[] { 0x00 });
        }

        /// <summary>
        /// Processes a PUT KEY command.
        /// </summary>
        protected abstract ApduResponse ProcessPutKey(ApduCommand apdu);

        /// <summary>
        /// Processes a STORE DATA command.
        /// </summary>
        protected virtual ApduResponse ProcessStoreData(ApduCommand apdu)
        {
            Console.WriteLine(
                $"Base ProcessStoreData called: SecureChannel={_secureChannelEstablished}"
            );

            if (!_secureChannelEstablished)
                return ApduResponse.Error(SW_CONDITIONS_NOT_SATISFIED);

            var structureFormat = apdu.P1;
            var data = apdu.Data;

            if (structureFormat == 0x80) // DGI format
            {
                return ProcessStoreDataDgi(data);
            }

            return ApduResponse.Error(SW_INCORRECT_P1P2);
        }

        /// <summary>
        /// Processes STORE DATA in DGI format.
        /// </summary>
        protected virtual ApduResponse ProcessStoreDataDgi(byte[] data)
        {
            Console.WriteLine(
                $"ProcessStoreDataDgi called with {data.Length} bytes: {Convert.ToHexString(data)}"
            );
            var offset = 0;

            while (offset < data.Length)
            {
                Console.WriteLine(
                    $"Processing at offset {offset}, remaining {data.Length - offset} bytes"
                );
                if (offset + 2 > data.Length)
                {
                    Console.WriteLine("Error: Not enough bytes for tag");
                    return ApduResponse.Error(SW_WRONG_LENGTH);
                }

                // Check for SET CONFIG ITEM format (DF2B)
                if (data[offset] == 0xDF && data[offset + 1] == 0x2B)
                {
                    Console.WriteLine("Found SET CONFIG ITEM (DF2B)");
                    offset += 2;
                    if (offset >= data.Length)
                    {
                        Console.WriteLine("Error: No length byte");
                        return ApduResponse.Error(SW_WRONG_LENGTH);
                    }

                    var length = data[offset++];
                    Console.WriteLine($"Length: {length}, offset now {offset}");
                    if (offset + length > data.Length)
                    {
                        Console.WriteLine(
                            $"Error: Not enough data. Need {length} more bytes but only have {data.Length - offset}"
                        );
                        return ApduResponse.Error(SW_WRONG_LENGTH);
                    }

                    // Process SET CONFIG ITEM
                    var result = ProcessSetConfigItem(data, offset, length);
                    if (!result.IsSuccessful)
                        return result;

                    offset += length;
                }
                else
                {
                    // Regular DGI format
                    var tag = (ushort)((data[offset] << 8) | data[offset + 1]);
                    offset += 2;

                    if (offset >= data.Length)
                        return ApduResponse.Error(SW_WRONG_LENGTH);

                    var length = data[offset++];
                    if (offset + length > data.Length)
                        return ApduResponse.Error(SW_WRONG_LENGTH);

                    var value = new byte[length];
                    Array.Copy(data, offset, value, 0, length);
                    offset += length;

                    // Store the configuration data
                    _configData[tag] = value;
                }
            }

            return ApduResponse.Success();
        }

        /// <summary>
        /// Processes a SET CONFIG ITEM command.
        /// </summary>
        protected virtual ApduResponse ProcessSetConfigItem(byte[] data, int offset, int length)
        {
            Console.WriteLine($"ProcessSetConfigItem: offset={offset}, length={length}");
            if (length < 3)
            {
                Console.WriteLine("Error: Length < 3");
                return ApduResponse.Error(SW_WRONG_LENGTH);
            }

            var tag = (ushort)((data[offset] << 8) | data[offset + 1]);
            var dataLength = data[offset + 2];
            Console.WriteLine($"Tag: 0x{tag:X4}, DataLength: {dataLength}");

            if (dataLength + 3 > length)
            {
                Console.WriteLine($"Error: dataLength + 3 ({dataLength + 3}) > length ({length})");
                return ApduResponse.Error(SW_WRONG_LENGTH);
            }

            var value = new byte[dataLength];
            Array.Copy(data, offset + 3, value, 0, dataLength);

            // Handle specific configuration items
            switch (tag)
            {
                case 0x1057: // SCP_ENABLE
                    return ProcessScpEnable(value);

                case 0x7F0D: // Default key version
                    if (value.Length != 1)
                        return ApduResponse.Error(SW_WRONG_LENGTH);
                    // Store default key version
                    _configData[tag] = value;
                    return ApduResponse.Success();

                default:
                    // Store generic configuration
                    _configData[tag] = value;
                    return ApduResponse.Success();
            }
        }

        /// <summary>
        /// Processes SCP_ENABLE configuration.
        /// </summary>
        protected virtual ApduResponse ProcessScpEnable(byte[] value)
        {
            // SCP_ENABLE format: up to 5 SCP implementation values (2 bytes each) = 10 bytes max
            if (value.Length % 2 != 0 || value.Length > 10)
                return ApduResponse.Error(SW_WRONG_LENGTH);

            // Parse SCP implementations
            var implementations = new List<ushort>();
            for (int i = 0; i < value.Length; i += 2)
            {
                var impl = (ushort)((value[i] << 8) | value[i + 1]);
                if (impl != 0x0000) // Skip empty slots
                {
                    implementations.Add(impl);
                }
            }

            // Update card SCP configuration based on first implementation
            if (implementations.Count > 0)
            {
                var firstImpl = implementations[0];
                _scpVersion = (byte)((firstImpl >> 8) & 0x0F);
                _scpImplementation = (byte)(firstImpl & 0xFF);
            }

            // Store configuration
            _configData[0x1057] = value;

            // Secure channel will be forcibly closed after SCP_ENABLE change
            _secureChannelEstablished = false;

            return ApduResponse.Success();
        }

        /// <summary>
        /// Initializes default data objects.
        /// </summary>
        protected virtual void InitializeDefaultDataObjects()
        {
            // Override in derived classes to set card-specific data objects
        }

        /// <summary>
        /// Sets a data object that can be retrieved via GET DATA.
        /// </summary>
        /// <param name="dataObjectId">The data object identifier.</param>
        /// <param name="data">The data to return.</param>
        public void SetDataObject(ushort dataObjectId, byte[] data)
        {
            _dataObjects[dataObjectId] = (byte[])data.Clone();
        }

        /// <summary>
        /// Encodes an application entry for GET STATUS response.
        /// </summary>
        protected static byte[] EncodeApplicationEntry(
            byte[] aid,
            byte lifecycleState,
            byte[] privileges
        )
        {
            var entry = new List<byte>();
            entry.Add((byte)aid.Length);
            entry.AddRange(aid);
            entry.Add(lifecycleState);
            entry.Add((byte)privileges.Length);
            entry.AddRange(privileges);
            return entry.ToArray();
        }

        /// <summary>
        /// Represents session keys for secure channel.
        /// </summary>
        protected class SessionKeys
        {
            public byte[] EncKey { get; set; } = Array.Empty<byte>();
            public byte[] MacKey { get; set; } = Array.Empty<byte>();
            public byte[] DekKey { get; set; } = Array.Empty<byte>();
            public byte[] SMac { get; set; } = Array.Empty<byte>(); // For SCP03
            public byte[] SEnc { get; set; } = Array.Empty<byte>(); // For SCP03
            public byte[] RMac { get; set; } = Array.Empty<byte>(); // For SCP03
        }

        /// <summary>
        /// Represents a static key set.
        /// </summary>
        protected class KeySet
        {
            public byte[] EncKey { get; set; } = Array.Empty<byte>();
            public byte[] MacKey { get; set; } = Array.Empty<byte>();
            public byte[] DekKey { get; set; } = Array.Empty<byte>();
        }

        /// <summary>
        /// Represents an installed application.
        /// </summary>
        protected class InstalledApplication
        {
            public byte[] Aid { get; }
            public byte LifecycleState { get; }
            public byte[] Privileges { get; }

            public InstalledApplication(byte[] aid, byte lifecycleState, byte[] privileges)
            {
                Aid = (byte[])aid.Clone();
                LifecycleState = lifecycleState;
                Privileges = (byte[])privileges.Clone();
            }
        }

        /// <summary>
        /// Represents a loaded CAP file.
        /// </summary>
        protected class LoadFile
        {
            public string Aid { get; }
            public byte[] Data { get; }

            public LoadFile(string aid, byte[] data)
            {
                Aid = aid;
                Data = (byte[])data.Clone();
            }
        }

        /// <summary>
        /// Simple APDU command parser.
        /// </summary>
        protected class ApduCommand
        {
            public byte Cla { get; }
            public byte Ins { get; }
            public byte P1 { get; }
            public byte P2 { get; }
            public byte[] Data { get; }
            public int Le { get; }

            public bool IsSelect => Ins == INS_SELECT;
            public bool IsInitializeUpdate => Ins == INS_INITIALIZE_UPDATE;
            public bool IsExternalAuthenticate => Ins == INS_EXTERNAL_AUTHENTICATE;
            public bool IsInstall => Ins == INS_INSTALL;
            public bool IsLoad => Ins == INS_LOAD;
            public bool IsGetStatus => Ins == INS_GET_STATUS;
            public bool IsDelete => Ins == INS_DELETE;
            public bool IsGetData => Ins == INS_GET_DATA;

            public ApduCommand(byte[] command)
            {
                if (command.Length < 4)
                    throw new ArgumentException("APDU too short");

                Cla = command[0];
                Ins = command[1];
                P1 = command[2];
                P2 = command[3];

                if (command.Length == 4)
                {
                    Data = Array.Empty<byte>();
                    Le = 0;
                }
                else if (command.Length == 5)
                {
                    Data = Array.Empty<byte>();
                    Le = command[4];
                }
                else
                {
                    var lc = command[4];
                    if (command.Length < 5 + lc)
                        throw new ArgumentException("APDU data length mismatch");

                    Data = new byte[lc];
                    Array.Copy(command, 5, Data, 0, lc);

                    if (command.Length == 5 + lc)
                    {
                        Le = 0;
                    }
                    else if (command.Length == 6 + lc)
                    {
                        Le = command[5 + lc];
                    }
                    else
                    {
                        throw new ArgumentException("Invalid APDU length");
                    }
                }
            }
        }
    }
}
