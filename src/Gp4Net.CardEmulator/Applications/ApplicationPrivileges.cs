using System;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Applications;

/// <summary>
/// Application privileges per GlobalPlatform Card Specification Table 8-1.
/// Reference: GP Card Specification v2.3.1 Section 8.1
/// </summary>
[PublicAPI]
[Flags]
public enum ApplicationPrivileges : byte
{
    /// <summary>
    /// No privileges.
    /// </summary>
    None = 0x00,
    
    /// <summary>
    /// Security Domain privilege.
    /// Bit 8 (0x80) - Security Domain
    /// </summary>
    SecurityDomain = 0x80,
    
    /// <summary>
    /// DAP Verification privilege.
    /// Bit 7 (0x40) - DAP Verification
    /// </summary>
    DapVerification = 0x40,
    
    /// <summary>
    /// Delegated Management privilege.
    /// Bit 6 (0x20) - Delegated Management
    /// </summary>
    DelegatedManagement = 0x20,
    
    /// <summary>
    /// Card Lock privilege.
    /// Bit 5 (0x10) - Card Lock
    /// </summary>
    CardLock = 0x10,
    
    /// <summary>
    /// Card Terminate privilege.
    /// Bit 4 (0x08) - Card Terminate
    /// </summary>
    CardTerminate = 0x08,
    
    /// <summary>
    /// Card Reset privilege.
    /// Bit 3 (0x04) - Card Reset
    /// </summary>
    CardReset = 0x04,
    
    /// <summary>
    /// CVM Management privilege.
    /// Bit 2 (0x02) - CVM (Cardholder Verification Method) Management
    /// </summary>
    CvmManagement = 0x02,
    
    /// <summary>
    /// Mandated DAP Verification privilege.
    /// Bit 1 (0x01) - Mandated DAP Verification
    /// </summary>
    MandatedDapVerification = 0x01,
    
    /// <summary>
    /// Authorized Management privilege (second byte).
    /// This is typically represented in a second byte of privileges.
    /// For simplicity, we'll use a composite value.
    /// </summary>
    AuthorizedManagement = 0x80,
    
    /// <summary>
    /// Token Verification privilege.
    /// </summary>
    TokenVerification = 0x40,
    
    /// <summary>
    /// Global Delete privilege.
    /// </summary>
    GlobalDelete = 0x20,
    
    /// <summary>
    /// Global Lock privilege.
    /// </summary>
    GlobalLock = 0x10,
    
    /// <summary>
    /// Global Registry privilege.
    /// </summary>
    GlobalRegistry = 0x08,
    
    /// <summary>
    /// Final Application privilege.
    /// </summary>
    FinalApplication = 0x04,
    
    /// <summary>
    /// Global Service privilege.
    /// </summary>
    GlobalService = 0x02,
    
    /// <summary>
    /// Receipt Generation privilege.
    /// </summary>
    ReceiptGeneration = 0x01,
    
    /// <summary>
    /// Personalized - indicates the application is personalized.
    /// This is not technically a privilege but a state indicator.
    /// </summary>
    Personalized = 0x80
}