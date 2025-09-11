using System.Collections.Immutable;
using Gp4Net.CardEmulator.Functional;

namespace Gp4Net.CardEmulator.Domain;

/// <summary>
/// Represents parsed CAP file information.
/// </summary>
/// <param name="LoadFileAid">The AID of the load file.</param>
/// <param name="Modules">The executable modules contained in the CAP file.</param>
public record CapFileInfo(byte[] LoadFileAid, ImmutableList<ExecutableModule> Modules);
