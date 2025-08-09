using System;

namespace Gp4Net.Domain;

/// <summary>
/// GlobalPlatform application lifecycle states.
/// </summary>
public enum LifecycleState : byte
{
    /// <summary>
    /// Loaded state - application loaded but not installed.
    /// </summary>
    Loaded = 0x01,

    /// <summary>
    /// Installed state - application installed but not selectable.
    /// </summary>
    Installed = 0x03,

    /// <summary>
    /// Selectable state - application can be selected.
    /// </summary>
    Selectable = 0x07,

    /// <summary>
    /// Personalized state - application is personalized.
    /// </summary>
    Personalized = 0x0F,

    /// <summary>
    /// Locked state - application is locked.
    /// </summary>
    Locked = 0x7F,
        
    /// <summary>
    /// Terminated state - application is terminated.
    /// </summary>
    Terminated = 0xFF,
        
    /// <summary>
    /// Unknown state.
    /// </summary>
    Unknown = 0x00
}

/// <summary>
/// GlobalPlatform privileges per GP Card Specification v2.3.1.
/// </summary>
[Flags]
public enum Privilege : uint
{
    /// <summary>
    /// No privileges.
    /// </summary>
    None = 0x000000,

    // First byte privileges (bits 7-0)
    /// <summary>
    /// Security domain privilege (bit 7).
    /// </summary>
    SecurityDomain = 0x800000,

    /// <summary>
    /// DAP verification privilege (bit 6).
    /// </summary>
    DapVerification = 0x400000,

    /// <summary>
    /// Delegated management privilege (bit 5).
    /// </summary>
    DelegatedManagement = 0x200000,

    /// <summary>
    /// Card lock privilege (bit 4).
    /// </summary>
    CardLock = 0x100000,

    /// <summary>
    /// Card terminate privilege (bit 3).
    /// </summary>
    CardTerminate = 0x080000,

    /// <summary>
    /// Card reset privilege (bit 2).
    /// </summary>
    CardReset = 0x040000,

    /// <summary>
    /// CVM management privilege (bit 1).
    /// </summary>
    CvmManagement = 0x020000,

    /// <summary>
    /// Trusted path privilege (bit 0).
    /// </summary>
    TrustedPath = 0x010000,

    // Second byte privileges (bits 15-8)
    /// <summary>
    /// Authorized management privilege (bit 15).
    /// </summary>
    AuthorizedManagement = 0x008000,

    /// <summary>
    /// Token verification privilege (bit 14).
    /// </summary>
    TokenVerification = 0x004000,

    /// <summary>
    /// Global delete privilege (bit 13).
    /// </summary>
    GlobalDelete = 0x002000,

    /// <summary>
    /// Global lock privilege (bit 12).
    /// </summary>
    GlobalLock = 0x001000,

    /// <summary>
    /// Global registry privilege (bit 11).
    /// </summary>
    GlobalRegistry = 0x000800,

    /// <summary>
    /// Final application privilege (bit 10).
    /// </summary>
    FinalApplication = 0x000400,

    /// <summary>
    /// Global service privilege (bit 9).
    /// </summary>
    GlobalService = 0x000200,

    /// <summary>
    /// Receipt generation privilege (bit 8).
    /// </summary>
    ReceiptGeneration = 0x000100,

    // Third byte privileges (bits 23-16) - reserved for application-specific
    /// <summary>
    /// Mandated DAP verification privilege.
    /// </summary>
    MandatedDapVerification = 0x000001
}


/// <summary>
/// Constants used throughout the GlobalPlatform implementation.
/// </summary>
public static class Constants
{
    // SecurityLevel enum has been moved to Domain/SecurityLevel.cs
}