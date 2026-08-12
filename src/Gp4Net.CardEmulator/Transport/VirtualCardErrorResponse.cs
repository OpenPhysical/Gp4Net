using Gp4Net.Core;

namespace Gp4Net.CardEmulator.Transport;

public static class VirtualCardErrorResponse
{
    // GP Card Specification v2.3.1, Section 11.1.3, Table 11-10.
    public static StatusWord GetStatusWord(SmartCardError error)
    {
        ushort value = error.StatusWord.GetValueOrDefault(0x6400);
        return new StatusWord((byte)(value >> 8), (byte)value);
    }

    public static byte[] ToBytes(SmartCardError error)
    {
        StatusWord statusWord = GetStatusWord(error);
        return [statusWord.Sw1, statusWord.Sw2];
    }
}
