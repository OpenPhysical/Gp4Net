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
    // GP Card Specification v2.3.1, Tables 11-3 through 11-6.
    public static bool IsExecutableLoadFileState(byte value) => value == 0x01;

    public static bool IsApplicationState(byte value) =>
        value == 0x03 || (value & 0x87) == 0x07 || (value & 0x83) == 0x83;

    public static bool IsSecurityDomainState(byte value) =>
        value is 0x03 or 0x07 or 0x0F || (value & 0xE3) == 0x83;

    public static bool IsCardState(byte value) => value is 0x01 or 0x07 or 0x0F or 0x7F or 0xFF;

    /// <summary>GP Card Specification v2.3.1, Figure 5-1.</summary>
    public static bool CanTransitionCard(CardLifecycleState from, CardLifecycleState to) =>
        (from, to) switch
        {
            (CardLifecycleState.OpReady, CardLifecycleState.Initialized) => true,
            (CardLifecycleState.Initialized, CardLifecycleState.Secured) => true,
            (CardLifecycleState.Secured, CardLifecycleState.CardLocked) => true,
            (CardLifecycleState.CardLocked, CardLifecycleState.Secured) => true,
            (_, CardLifecycleState.Terminated) when from != CardLifecycleState.Terminated => true,
            _ => false,
        };

    public static bool IsRegistryState(byte value) =>
        IsExecutableLoadFileState(value)
        || IsApplicationState(value)
        || IsSecurityDomainState(value)
        || IsCardState(value);

    public static string DescribeApplicationState(byte value) =>
        value switch
        {
            0x03 => nameof(ApplicationLifecycleState.Installed),
            0x07 => nameof(ApplicationLifecycleState.Selectable),
            _ when (value & 0x83) == 0x83 => "Locked",
            _ when (value & 0x87) == 0x07 => $"ApplicationSpecific(0x{value:X2})",
            _ => $"Unknown(0x{value:X2})",
        };

    public static string DescribeSecurityDomainState(byte value) =>
        value switch
        {
            0x03 => nameof(SecurityDomainLifecycleState.Installed),
            0x07 => nameof(SecurityDomainLifecycleState.Selectable),
            0x0F => nameof(SecurityDomainLifecycleState.Personalized),
            _ when (value & 0xE3) == 0x83 => "Locked",
            _ => $"Unknown(0x{value:X2})",
        };

    public static string DescribeCardState(byte value) =>
        value switch
        {
            0x01 => nameof(CardLifecycleState.OpReady),
            0x07 => nameof(CardLifecycleState.Initialized),
            0x0F => nameof(CardLifecycleState.Secured),
            0x7F => nameof(CardLifecycleState.CardLocked),
            0xFF => nameof(CardLifecycleState.Terminated),
            _ => $"Unknown(0x{value:X2})",
        };
}
