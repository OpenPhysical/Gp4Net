using Gp4Net.CardEmulator.Core;
using Gp4Net.Domain;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Requirements for executing a command.
/// </summary>
public record CommandPrivilegeRequirements(
    ApplicationPrivileges RequiredPrivileges,
    SecurityLevel MinimumSecurityLevel,
    bool RequiresSecureChannel
)
{
    /// <summary>
    /// Creates a new instance of the CommandPrivilegeRequirements class with the specified parameters.
    /// </summary>
    /// <param name="privileges">The required application privileges for the command.</param>
    /// <param name="securityLevel">The minimum security level required for executing the command.</param>
    /// <param name="requiresSecureChannel">Indicates whether a secure channel is required.</param>
    /// <returns>A new instance of the CommandPrivilegeRequirements class.</returns>
    public static CommandPrivilegeRequirements Create(
        ApplicationPrivileges privileges,
        SecurityLevel securityLevel,
        bool requiresSecureChannel
    )
    {
        return new CommandPrivilegeRequirements(privileges, securityLevel, requiresSecureChannel);
    }
}
