namespace Gp4Net.Domain;

/// <summary>GP Card Spec 2.3.1, Table 11-3.</summary>
public enum ExecutableLoadFileLifecycleState : byte
{
    Loaded = 0x01,
}

/// <summary>GP Card Spec 2.3.1, Table 11-4.</summary>
public enum ApplicationLifecycleState : byte
{
    Installed = 0x03,
    Selectable = 0x07,
}

/// <summary>GP Card Spec 2.3.1, Table 11-5.</summary>
public enum SecurityDomainLifecycleState : byte
{
    Installed = 0x03,
    Selectable = 0x07,
    Personalized = 0x0F,
}

/// <summary>GP Card Spec 2.3.1, Table 11-6.</summary>
public enum CardLifecycleState : byte
{
    OpReady = 0x01,
    Initialized = 0x07,
    Secured = 0x0F,
    CardLocked = 0x7F,
    Terminated = 0xFF,
}

public static class GlobalPlatformLifecycle
{
    public static bool IsExecutableLoadFileState(byte value) => value == 0x01;

    public static bool IsApplicationState(byte value) =>
        value == 0x03 || (value & 0x87) == 0x07 || (value & 0x83) == 0x83;

    public static bool IsSecurityDomainState(byte value) =>
        value is 0x03 or 0x07 or 0x0F || (value & 0x83) == 0x83;

    public static bool IsCardState(byte value) => value is 0x01 or 0x07 or 0x0F or 0x7F or 0xFF;

    public static bool IsRegistryState(byte value) =>
        IsExecutableLoadFileState(value)
        || IsApplicationState(value)
        || IsSecurityDomainState(value)
        || IsCardState(value);
}
