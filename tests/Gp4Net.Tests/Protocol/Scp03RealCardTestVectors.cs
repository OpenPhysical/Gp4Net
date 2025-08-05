// -----------------------------------------------------------------------------
// MIT License
//
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.  
// -----------------------------------------------------------------------------

using System;
using CSharpFunctionalExtensions;
using JetBrains.Annotations;

namespace Gp4Net.Tests.Protocol;

/// <summary>
/// Real-world SCP03 test vectors extracted from actual card traces.
/// These vectors provide validation against real card behavior rather than synthetic test data.
/// </summary>
[PublicAPI]
public static class Scp03RealCardTestVectors
{
    /// <summary>
    /// SCP03 test vector extracted from P71 card trace (gp_pro_p71_scp03.txt).
    /// This represents a real SCP03 i=70 session with key diversification.
    /// </summary>
    public static readonly Scp03RealCardTestVector P71_SCP03_Session = new()
    {
        Name = "P71 Card SCP03 i=70 Real Session",
        Description = "Real SCP03 session from P71 card with key diversification and i=70 implementation",
        
        // Card Information
        CardInfo = new CardInfo
        {
            ATR = Convert.FromHexString("3BD518FF8191FE1FC38073C821100A"),
            ISD_AID = Convert.FromHexString("A000000151000000"),
            CardType = "P71",
        },
        
        // Static Keys (GP test keys used in trace)
        StaticKeyEnc = Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
        StaticKeyMac = Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
        StaticKeyDek = Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
        
        // SCP03 Parameters
        ScpVersion = 0x03,
        ImplementationOption = 0x70, // i=70 from trace
        KeyVersion = 0x01,
        SecurityLevel = 0x01, // C-MAC only for INITIALIZE UPDATE
        
        // Key Diversification Data
        KDD = Convert.FromHexString("03700000000000000000"),
        SequenceCounter = Convert.FromHexString("000002"),
        
        // Session Challenges
        HostChallenge = Convert.FromHexString("FE0530CF61BAA9F3"),
        CardChallenge = Convert.FromHexString("83FA042C5C10F778"),
        
        // Expected Session Keys (from trace log)
        ExpectedSEnc = Convert.FromHexString("7392646744DF8721131C4A995A845BAE"),
        ExpectedSMac = Convert.FromHexString("CD9F750E543E0CF862B0EA73E3812113"),
        ExpectedSRMac = Convert.FromHexString("D1B695D89DE01992B6CB238BDFB006D9"),
        
        // Cryptograms (extracted from trace)
        ExpectedCardCryptogram = Convert.FromHexString("148C0CAF84B0E110"),
        ExpectedHostCryptogram = Convert.FromHexString("7B54E3B21E27DA5F"),
        
        // APDU Exchanges
        InitializeUpdateCommand = Convert.FromHexString("80500000 08 FE0530CF61BAA9F3 00".Replace(" ", "")),
        InitializeUpdateResponse = Convert.FromHexString("0370000000000000000001037083FA042C5C10F778148C0CAF84B0E1100000029000"),
        
        ExternalAuthenticateCommand = Convert.FromHexString("84820100 10 7B54E3B21E27DA5FFCA958062C7CA0C5".Replace(" ", "")),
        ExternalAuthenticateResponse = Convert.FromHexString("9000"),
        
        // Real Card Capabilities (from GET DATA responses in trace)
        SupportedSCPVersions = new[] { "SCP03 i=00", "i=10", "i=20", "i=60", "i=70" },
        SupportedKeyLengths = new[] { "AES-128", "AES-196", "AES-256" },
        SupportedPrivileges = new[] 
        {
            "SecurityDomain", "DAPVerification", "DelegatedManagement", 
            "CardReset", "MandatedDAPVerification", "TrustedPath", 
            "TokenVerification", "GlobalDelete", "GlobalLock", 
            "GlobalRegistry", "FinalApplication", "ReceiptGeneration",
            "CipheredLoadFileDataBlock"
        }
    };
    
    /// <summary>
    /// All available real-card test vectors.
    /// </summary>
    public static readonly Scp03RealCardTestVector[] AllVectors = { 
        P71_SCP03_Session
    };
}

/// <summary>
/// Represents a complete SCP03 test vector extracted from real card traces.
/// </summary>
[PublicAPI]
public record Scp03RealCardTestVector
{
    /// <summary>
    /// Descriptive name for this test vector.
    /// </summary>
    public required string Name { get; init; }
    
    /// <summary>
    /// Detailed description of the test scenario.
    /// </summary>
    public required string Description { get; init; }
    
    /// <summary>
    /// Card information from the trace.
    /// </summary>
    public required CardInfo CardInfo { get; init; }
    
    /// <summary>
    /// Static encryption key used in the session.
    /// </summary>
    public required byte[] StaticKeyEnc { get; init; }
    
    /// <summary>
    /// Static MAC key used in the session.
    /// </summary>
    public required byte[] StaticKeyMac { get; init; }
    
    /// <summary>
    /// Static Data Encryption Key used in the session.
    /// </summary>
    public required byte[] StaticKeyDek { get; init; }
    
    /// <summary>
    /// SCP version (should be 3 for SCP03).
    /// </summary>
    public required byte ScpVersion { get; init; }
    
    /// <summary>
    /// SCP03 implementation option (i parameter).
    /// </summary>
    public required byte ImplementationOption { get; init; }
    
    /// <summary>
    /// Key version identifier.
    /// </summary>
    public required byte KeyVersion { get; init; }
    
    /// <summary>
    /// Security level for INITIALIZE UPDATE.
    /// </summary>
    public required byte SecurityLevel { get; init; }
    
    /// <summary>
    /// Key Diversification Data from the card.
    /// </summary>
    public required byte[] KDD { get; init; }
    
    /// <summary>
    /// Sequence counter from INITIALIZE UPDATE response.
    /// </summary>
    public required byte[] SequenceCounter { get; init; }
    
    /// <summary>
    /// Host challenge sent in INITIALIZE UPDATE.
    /// </summary>
    public required byte[] HostChallenge { get; init; }
    
    /// <summary>
    /// Card challenge from INITIALIZE UPDATE response.
    /// </summary>
    public required byte[] CardChallenge { get; init; }
    
    /// <summary>
    /// Expected derived session encryption key.
    /// </summary>
    public required byte[] ExpectedSEnc { get; init; }
    
    /// <summary>
    /// Expected derived session MAC key.
    /// </summary>
    public required byte[] ExpectedSMac { get; init; }
    
    /// <summary>
    /// Expected derived session R-MAC key.
    /// </summary>
    public required byte[] ExpectedSRMac { get; init; }
    
    /// <summary>
    /// Expected card cryptogram from INITIALIZE UPDATE response.
    /// </summary>
    public required byte[] ExpectedCardCryptogram { get; init; }
    
    /// <summary>
    /// Expected host cryptogram for EXTERNAL AUTHENTICATE.
    /// </summary>
    public required byte[] ExpectedHostCryptogram { get; init; }
    
    /// <summary>
    /// Complete INITIALIZE UPDATE command from trace.
    /// </summary>
    public required byte[] InitializeUpdateCommand { get; init; }
    
    /// <summary>
    /// Complete INITIALIZE UPDATE response from trace.
    /// </summary>
    public required byte[] InitializeUpdateResponse { get; init; }
    
    /// <summary>
    /// Complete EXTERNAL AUTHENTICATE command from trace.
    /// </summary>
    public required byte[] ExternalAuthenticateCommand { get; init; }
    
    /// <summary>
    /// Complete EXTERNAL AUTHENTICATE response from trace.
    /// </summary>
    public required byte[] ExternalAuthenticateResponse { get; init; }
    
    /// <summary>
    /// SCP versions supported by the card.
    /// </summary>
    public required string[] SupportedSCPVersions { get; init; }
    
    /// <summary>
    /// Key lengths supported by the card.
    /// </summary>
    public required string[] SupportedKeyLengths { get; init; }
    
    /// <summary>
    /// Privileges supported by the card.
    /// </summary>
    public required string[] SupportedPrivileges { get; init; }
}

/// <summary>
/// Card information extracted from traces.
/// </summary>
[PublicAPI]
public record CardInfo
{
    /// <summary>
    /// Answer To Reset from the card.
    /// </summary>
    public required byte[] ATR { get; init; }
    
    /// <summary>
    /// Issuer Security Domain AID.
    /// </summary>
    public required byte[] ISD_AID { get; init; }
    
    /// <summary>
    /// Card type or model information.
    /// </summary>
    public required string CardType { get; init; }
}