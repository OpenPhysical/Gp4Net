using System;

namespace Gp4Net.Domain
{
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
        /// Blocked state - application is blocked.
        /// </summary>
        Blocked = 0x7F,

        /// <summary>
        /// Locked state - application is locked.
        /// </summary>
        Locked = 0xFF
    }

    /// <summary>
    /// GlobalPlatform privileges.
    /// </summary>
    [Flags]
    public enum Privilege : byte
    {
        /// <summary>
        /// No privileges.
        /// </summary>
        None = 0x00,

        /// <summary>
        /// Security domain privilege.
        /// </summary>
        SecurityDomain = 0x80,

        /// <summary>
        /// DAP verification privilege.
        /// </summary>
        DapVerification = 0x40,

        /// <summary>
        /// Delegated management privilege.
        /// </summary>
        DelegatedManagement = 0x20,

        /// <summary>
        /// Card lock privilege.
        /// </summary>
        CardLock = 0x10,

        /// <summary>
        /// Card terminate privilege.
        /// </summary>
        CardTerminate = 0x08,

        /// <summary>
        /// Card reset privilege.
        /// </summary>
        CardReset = 0x04,

        /// <summary>
        /// CVM management privilege.
        /// </summary>
        CvmManagement = 0x02,

        /// <summary>
        /// Mandated DAP verification privilege.
        /// </summary>
        MandatedDapVerification = 0x01
    }

    /// <summary>
    /// Constants used throughout the GlobalPlatform implementation.
    /// </summary>
    public static class Constants
    {
        // SecurityLevel enum has been moved to Domain/SecurityLevel.cs
    }
}