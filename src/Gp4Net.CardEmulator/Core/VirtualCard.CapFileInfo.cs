using System.Collections.Immutable;
using Gp4Net.CardEmulator.Functional;

namespace Gp4Net.CardEmulator.Core;

public partial class VirtualCard
{
    /// <summary>
    /// Represents parsed CAP file information.
    /// </summary>
    private record CapFileInfo(byte[] LoadFileAid, ImmutableList<ExecutableModule> Modules);
}
