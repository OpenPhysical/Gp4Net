namespace Gp4Net.CardEmulator.Core;

public partial class VirtualCard
{
    private record ParsedCommand(byte Cla, byte Ins, byte P1, byte P2, byte[] FullCommand);
}
