using System;
using System.Threading;
using System.Threading.Tasks;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Transport;
using CSharpFunctionalExtensions;

namespace Gp4Net.Tests.TestHelpers;

/// <summary>
/// Mock card channel for testing.
/// </summary>
public class MockCardChannel : ICardChannel
{
    public bool IsOpen { get; private set; } = true;
    public TransportProtocol Protocol => TransportProtocol.T1;

    public Task<byte[]> TransmitAsync(
        byte[] command,
        CancellationToken cancellationToken = default
    )
    {
        // Return a mock success response
        return Task.FromResult(new byte[] { 0x90, 0x00 });
    }

    public void Close()
    {
        IsOpen = false;
    }

    public void Dispose()
    {
        Close();
    }
}

/// <summary>
/// Mock APDU transport for testing.
/// </summary>
public class MockApduTransport : IApduTransport
{
    public TransportProtocol Protocol => TransportProtocol.T1;
    public int MaxCommandDataLength => 255;
    public int MaxResponseDataLength => 256;
    public bool SupportsExtendedLength => false;

    public Task<ApduResponse> TransmitAsync(
        IApduCommand command,
        ICardChannel channel,
        CancellationToken cancellationToken = default
    )
    {
        // Return a mock success response
        return Task.FromResult(new ApduResponse([], StatusWords.Success));
    }

    public static void Dispose()
    {
        // Nothing to dispose
    }
}