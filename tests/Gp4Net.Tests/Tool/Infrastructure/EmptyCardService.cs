using System.Collections.Generic;
using CSharpFunctionalExtensions;
using Gp4Net.Tool.Services;
using Gp4Net.Transport;

namespace Gp4Net.Tests.Tool.Infrastructure;

/// <summary>
/// Empty card service for testing error conditions.
/// </summary>
public class EmptyCardService : ICardService
{
    public bool IsSecureChannelEstablished => false;
    public bool IsConnected => false;

    public IReadOnlyList<string> GetReaders() => new List<string>().AsReadOnly();
    public byte[] GetAtr() => [];
    public bool Connect(string reader) => false;
    public void Disconnect() { }
    public CardResponse SendCommand(byte[] apdu) => new CardResponse([], 0x6F00);
    public CardResponse SendCommand(IApduCommand command) => new CardResponse([], 0x6F00);
    public bool EstablishSecureChannel(byte[] keys, byte securityLevel) => false;
    public void Dispose() { }
}