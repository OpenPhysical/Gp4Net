using System;

namespace Gp4Net.Domain.Commands;

internal static class GlobalPlatformLengthEncoding
{
    public static byte[] EncodeBerLength(int length)
    {
        if (length is < 0 or > 0xFFFF)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        return length switch
        {
            < 0x80 => [(byte)length],
            <= 0xFF => [0x81, (byte)length],
            _ => [0x82, (byte)(length >> 8), (byte)length],
        };
    }
}
