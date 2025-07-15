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
    /// Represents a Secure Channel Protocol (SCP) implementation.
    /// </summary>
    /// <param name="Version">The SCP version (e.g., 0x02 for SCP02, 0x03 for SCP03).</param>
    /// <param name="Implementation">The implementation ID (e.g., 0x15, 0x70).</param>
    public record ScpImplementation(byte Version, byte Implementation)
    {
        /// <summary>
        /// Converts the SCP implementation to a ushort value.
        /// </summary>
        /// <returns>A ushort with version in high byte and implementation in low byte.</returns>
        public ushort ToUShort() => (ushort)((Version << 8) | Implementation);

        /// <summary>
        /// Creates an SCP implementation from a ushort value.
        /// </summary>
        /// <param name="value">The ushort value with version in high byte and implementation in low byte.</param>
        /// <returns>A new ScpImplementation instance.</returns>
        public static ScpImplementation FromUShort(ushort value) => 
            new((byte)(value >> 8), (byte)(value & 0xFF));

        /// <summary>
        /// SCP02 with implementation ID 0x15.
        /// </summary>
        public static ScpImplementation Scp02I15 => new(0x02, 0x15);

        /// <summary>
        /// SCP03 with implementation ID 0x70.
        /// </summary>
        public static ScpImplementation Scp03I70 => new(0x03, 0x70);

        /// <summary>
        /// Returns a string representation of the SCP implementation.
        /// </summary>
        public override string ToString() => $"SCP{Version:X2} i={Implementation:X2}";
    }

    /// <summary>
    /// Constants used throughout the GlobalPlatform implementation.
    /// </summary>
    public static class Constants
    {
        // SecurityLevel enum has been moved to Domain/SecurityLevel.cs
    }
}