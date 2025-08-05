using System;
using CSharpFunctionalExtensions;
using Gp4Net.Transport;

namespace Gp4Net.Tests.TestHelpers;

/// <summary>
/// Test implementation of IApduCommand for unit tests.
/// </summary>
public class TestApduCommand : IApduCommand
{
    /// <inheritdoc />
    public byte Cla { get; }

    /// <inheritdoc />
    public byte Ins { get; }

    /// <inheritdoc />
    public byte P1 { get; }

    /// <inheritdoc />
    public byte P2 { get; }

    /// <inheritdoc />
    public byte[]? Data { get; }

    /// <inheritdoc />
    public Maybe<int> ExpectedResponseLength { get; }

    /// <inheritdoc />
    public bool IsExtendedLength { get; }

    /// <summary>
    /// Initializes a new instance of the TestApduCommand class.
    /// </summary>
    /// <param name="cla">The class byte.</param>
    /// <param name="ins">The instruction byte.</param>
    /// <param name="p1">The parameter 1 byte.</param>
    /// <param name="p2">The parameter 2 byte.</param>
    /// <param name="data">The command data.</param>
    /// <param name="expectedResponseLength">The expected response length.</param>
    /// <param name="isExtendedLength">Whether this is an extended length command.</param>
    public TestApduCommand(
        byte cla,
        byte ins,
        byte p1,
        byte p2,
        byte[]? data = null,
        Maybe<int> expectedResponseLength = default,
        bool isExtendedLength = false)
    {
        Cla = cla;
        Ins = ins;
        P1 = p1;
        P2 = p2;
        Data = data;
        ExpectedResponseLength = expectedResponseLength;
        IsExtendedLength = isExtendedLength;
    }

    /// <summary>
    /// Creates a TestApduCommand from a byte array.
    /// </summary>
    /// <param name="apduBytes">The APDU bytes to parse.</param>
    /// <returns>A TestApduCommand instance.</returns>
    public static TestApduCommand FromBytes(byte[] apduBytes)
    {
        if (apduBytes == null || apduBytes.Length < 4)
        {
            throw new ArgumentException("APDU must be at least 4 bytes long", nameof(apduBytes));
        }

        var cla = apduBytes[0];
        var ins = apduBytes[1];
        var p1 = apduBytes[2];
        var p2 = apduBytes[3];

        byte[]? data = null;
        Maybe<int> expectedResponseLength = Maybe<int>.None;

        if (apduBytes.Length == 4)
        {
            // Case 1: No data, no Le
        }
        else if (apduBytes.Length == 5)
        {
            // Case 2: No data, Le present
            var le = apduBytes[4];
            expectedResponseLength = Maybe<int>.From(le == 0 ? 256 : le);
        }
        else
        {
            // Case 3 or 4: Data present
            var lc = apduBytes[4];

            if (apduBytes.Length == 5 + lc)
            {
                // Case 3: Data present, no Le
                data = new byte[lc];
                Array.Copy(apduBytes, 5, data, 0, lc);
            }
            else if (apduBytes.Length == 5 + lc + 1)
            {
                // Case 4: Data present, Le present
                data = new byte[lc];
                Array.Copy(apduBytes, 5, data, 0, lc);
                var le = apduBytes[5 + lc];
                expectedResponseLength = Maybe<int>.From(le == 0 ? 256 : le);
            }
            else
            {
                throw new ArgumentException("Invalid APDU format", nameof(apduBytes));
            }
        }

        return new TestApduCommand(cla, ins, p1, p2, data, expectedResponseLength);
    }
}