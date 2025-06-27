using System;
using System.Collections.Generic;
using System.Linq;
using Gp4Net.Tests.Emulator.Core;
using Gp4Net.Utils;
using JetBrains.Annotations;

namespace Gp4Net.Tests.Emulator.Cards
{
    /// <summary>
    /// Emulates an ACOSJ sample card as described in the installation manual.
    /// 
    /// Key specifications:
    /// - ISD AID: A000000151000000
    /// - Executable Load File AID: A011223344
    /// - Executable Module AID: A01122334401
    /// - SCP 02 option 55 support
    /// - Default keys: 404142434445464748494A4B4C4D4E4F (Key IDs 01, 02, 03, version 20)
    /// </summary>
    [PublicAPI]
    public class AcosJavaCard : IVirtualCard
    {
        // ACOS-specific constants from the manual
        private static readonly byte[] IsdAid = ConvertCompat.FromHexString("A000000151000000");
        private static readonly byte[] ExecutableLoadFileAid = ConvertCompat.FromHexString("A011223344");
        private static readonly byte[] ExecutableModuleAid = ConvertCompat.FromHexString("A01122334401");
        private static readonly byte[] DefaultKey = ConvertCompat.FromHexString("404142434445464748494A4B4C4D4E4F");
        
        // Standard ATR for JavaCard
        private static readonly byte[] CardAtr = ConvertCompat.FromHexString("3B68000030659000AF");

        // Card state
        private bool _isdSelected;
        private bool _secureChannelEstablished;
        private byte[] _hostChallenge = Array.Empty<byte>();
        private byte[] _cardChallenge = Array.Empty<byte>();
        private byte[] _sessionKeyEnc = Array.Empty<byte>();
        private byte[] _sessionKeyMac = Array.Empty<byte>();
        private byte[] _sessionKeyDek = Array.Empty<byte>();

        // Installed applications and load files
        private readonly Dictionary<string, InstalledApplication> _installedApplications = new();
        private readonly Dictionary<string, LoadFile> _loadFiles = new();
        private readonly List<byte[]> _pendingCapData = new();
        private string? _pendingPackageAid;

        /// <inheritdoc />
        public bool IsSelected => _isdSelected;

        /// <inheritdoc />
        public bool IsSecureChannelEstablished => _secureChannelEstablished;

        /// <summary>
        /// Initializes a new instance of the AcosJavaCard class.
        /// </summary>
        public AcosJavaCard()
        {
            // Initialize card state
            Reset();
        }

        /// <inheritdoc />
        public byte[] GetAtr()
        {
            return (byte[])CardAtr.Clone();
        }

        /// <inheritdoc />
        public void Reset()
        {
            _isdSelected = false;
            _secureChannelEstablished = false;
            _hostChallenge = Array.Empty<byte>();
            _cardChallenge = Array.Empty<byte>();
            _sessionKeyEnc = Array.Empty<byte>();
            _sessionKeyMac = Array.Empty<byte>();
            _sessionKeyDek = Array.Empty<byte>();
            _pendingCapData.Clear();
            _pendingPackageAid = null;
        }

        /// <inheritdoc />
        public ApduResponse ProcessCommand(byte[] command)
        {
            try
            {
                var apdu = new ApduCommand(command);
                
                // Route command based on instruction
                return apdu switch
                {
                    { IsSelect: true } => ProcessSelect(apdu),
                    { IsInitializeUpdate: true } => ProcessInitializeUpdate(apdu),
                    { IsExternalAuthenticate: true } => ProcessExternalAuthenticate(apdu),
                    { IsInstall: true } => ProcessInstall(apdu),
                    { IsLoad: true } => ProcessLoad(apdu),
                    { IsGetStatus: true } => ProcessGetStatus(apdu),
                    { IsDelete: true } => ProcessDelete(apdu),
                    { IsGetData: true } => ProcessGetData(apdu),
                    _ => ApduResponse.Error(0x6D00) // INS not supported
                };
            }
            catch (Exception)
            {
                return ApduResponse.Error(0x6F00); // Generic error
            }
        }

        private ApduResponse ProcessSelect(ApduCommand apdu)
        {
            if (apdu.P1 != 0x04) // Select by name
                return ApduResponse.Error(0x6A86); // Incorrect P1/P2

            var aid = apdu.Data;
            
            if (aid.SequenceEqual(IsdAid))
            {
                _isdSelected = true;
                
                // Return FCI response as shown in the manual
                var fciResponse = ConvertCompat.FromHexString(
                    "6F5C8408A000000151000000A550734A06072A864886FC6B01600C060A2A864886FC6B02020" +
                    "201630906072A864886FC6B03640B06092A864886FC6B040255650B06092A864886FC6B0201" +
                    "03660C060A2B060104012A026E01039F6501FF");
                    
                return ApduResponse.Success(fciResponse);
            }

            // Check for installed applications
            var aidHex = Convert.ToHexString(aid);
            if (_installedApplications.ContainsKey(aidHex))
            {
                return ApduResponse.Success(); // Simple success for installed apps
            }

            return ApduResponse.Error(0x6A82); // File not found
        }

        private ApduResponse ProcessInitializeUpdate(ApduCommand apdu)
        {
            if (!_isdSelected)
                return ApduResponse.Error(0x6985); // Conditions not satisfied

            if (apdu.Data.Length != 8)
                return ApduResponse.Error(0x6700); // Wrong length

            _hostChallenge = (byte[])apdu.Data.Clone();
            
            // Generate card challenge (example from manual)
            _cardChallenge = ConvertCompat.FromHexString("72BB2775E0D3");
            
            // Generate session keys using SCP02 derivation
            GenerateSessionKeys();
            
            // Response format from manual: Key diversification data + Key version + SCP ID + Challenge + Cryptogram
            var response = new List<byte>();
            response.AddRange(ConvertCompat.FromHexString("000002650183039536")); // Key diversification data
            response.AddRange(_cardChallenge); // 6 bytes card challenge  
            response.AddRange(ConvertCompat.FromHexString("2002")); // Key version (20) + SCP (02)
            response.AddRange(ConvertCompat.FromHexString("000A")); // Sequence counter
            response.AddRange(ConvertCompat.FromHexString("610D90424829CEB5")); // Card authentication cryptogram
            
            return ApduResponse.Success(response.ToArray());
        }

        private ApduResponse ProcessExternalAuthenticate(ApduCommand apdu)
        {
            if (!_isdSelected)
                return ApduResponse.Error(0x6985); // Conditions not satisfied

            if (apdu.Data.Length != 16)
                return ApduResponse.Error(0x6700); // Wrong length

            // For simplicity, we'll accept any authentication data
            // In real implementation, would verify host cryptogram and MAC
            _secureChannelEstablished = true;
            
            return ApduResponse.Success();
        }

        private ApduResponse ProcessInstall(ApduCommand apdu)
        {
            if (!_secureChannelEstablished)
                return ApduResponse.Error(0x6985); // Conditions not satisfied

            switch (apdu.P1)
            {
                case 0x02: // INSTALL [for load]
                    return ProcessInstallForLoad(apdu);
                case 0x0C: // INSTALL [for install]
                    return ProcessInstallForInstall(apdu);
                default:
                    return ApduResponse.Error(0x6A86); // Incorrect P1/P2
            }
        }

        private ApduResponse ProcessInstallForLoad(ApduCommand apdu)
        {
            var data = apdu.Data;
            if (data.Length < 1)
                return ApduResponse.Error(0x6700); // Wrong length

            var offset = 0;
            
            // Parse package AID
            var packageAidLength = data[offset++];
            if (offset + packageAidLength > data.Length)
                return ApduResponse.Error(0x6700);
                
            var packageAid = new byte[packageAidLength];
            Array.Copy(data, offset, packageAid, 0, packageAidLength);
            offset += packageAidLength;

            _pendingPackageAid = Convert.ToHexString(packageAid);
            _pendingCapData.Clear();

            return ApduResponse.Success(new byte[] { 0x00 }); // Response from manual
        }

        private ApduResponse ProcessInstallForInstall(ApduCommand apdu)
        {
            var data = apdu.Data;
            if (data.Length < 3)
                return ApduResponse.Error(0x6700);

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
                appAid, 0x07, new byte[] { 0x00 }); // Selectable state, no privileges

            return ApduResponse.Success(new byte[] { 0x00 });
        }

        private ApduResponse ProcessLoad(ApduCommand apdu)
        {
            if (!_secureChannelEstablished)
                return ApduResponse.Error(0x6985);

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

        private ApduResponse ProcessGetStatus(ApduCommand apdu)
        {
            var response = new List<byte>();

            switch (apdu.P1)
            {
                case 0x80: // ISD only
                    response.AddRange(EncodeApplicationEntry(IsdAid, 0x07, new byte[] { 0xC8 }));
                    break;
                    
                case 0x40: // Applications and SSDs
                    foreach (var app in _installedApplications.Values)
                    {
                        response.AddRange(EncodeApplicationEntry(app.Aid, app.LifecycleState, app.Privileges));
                    }
                    break;
                    
                case 0x20: // Load files
                    foreach (var loadFile in _loadFiles.Values)
                    {
                        var aid = ConvertCompat.FromHexString(loadFile.Aid);
                        response.AddRange(EncodeApplicationEntry(aid, 0x07, new byte[] { 0x00 }));
                    }
                    break;
                    
                default:
                    return ApduResponse.Error(0x6A86);
            }

            return ApduResponse.Success(response.ToArray());
        }

        private ApduResponse ProcessDelete(ApduCommand apdu)
        {
            if (!_secureChannelEstablished)
                return ApduResponse.Error(0x6985);

            var data = apdu.Data;
            var offset = 0;

            while (offset < data.Length)
            {
                if (data[offset] != 0x4F) // AID tag
                    return ApduResponse.Error(0x6A80);
                    
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

        private ApduResponse ProcessGetData(ApduCommand apdu)
        {
            // Simple GET DATA implementation
            return ApduResponse.Success(Array.Empty<byte>());
        }

        private void GenerateSessionKeys()
        {
            // Simplified session key generation for SCP02
            // In real implementation, would use proper cryptographic derivation
            _sessionKeyEnc = ConvertCompat.FromHexString("339F1D7F5D5841EB034F5CE234557894");
            _sessionKeyMac = ConvertCompat.FromHexString("C6713F31B8DC1F8905DFECB4065CB81E");
            _sessionKeyDek = ConvertCompat.FromHexString("06E72D52EEFBD1D8DB5C230C3F2B56E9");
        }

        private static byte[] EncodeApplicationEntry(byte[] aid, byte lifecycleState, byte[] privileges)
        {
            var entry = new List<byte>();
            entry.Add((byte)aid.Length);
            entry.AddRange(aid);
            entry.Add(lifecycleState);
            entry.Add((byte)privileges.Length);
            entry.AddRange(privileges);
            return entry.ToArray();
        }

        private class InstalledApplication
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

        private class LoadFile
        {
            public string Aid { get; }
            public byte[] Data { get; }

            public LoadFile(string aid, byte[] data)
            {
                Aid = aid;
                Data = (byte[])data.Clone();
            }
        }
    }
}