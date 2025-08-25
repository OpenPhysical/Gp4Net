using System.Collections.Generic;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Tests.TestHelpers;

/// <summary>
/// Test implementation of ICardService that wraps VirtualCardService.
/// Eliminates adapter casting issues by implementing the Tool's ICardService directly.
/// </summary>
[PublicAPI]
public class TestCardService : Gp4Net.Tool.Services.ICardService
{
    private readonly VirtualCardService _virtualCardService;
    
    public TestCardService(VirtualCardService virtualCardService)
    {
        _virtualCardService = virtualCardService;
        // Ensure connection to first reader for tests
        var readers = _virtualCardService.GetReaders();
        if (readers.Count > 0)
        {
            _virtualCardService.Connect(readers[0]);
        }
    }
    
    public IReadOnlyList<string> GetReaders() => _virtualCardService.GetReaders();
    
    public bool Connect(string readerName) => _virtualCardService.Connect(readerName);
    
    public void Disconnect() => _virtualCardService.Disconnect();
    
    public bool IsConnected => _virtualCardService.IsConnected;
    
    public byte[] GetAtr() => _virtualCardService.GetAtr() ?? [];
    
    public Gp4Net.Tool.Services.CardResponse SendCommand(byte[] command)
    {
        var response = _virtualCardService.SendCommand(command);
        return new Gp4Net.Tool.Services.CardResponse(response.Data, response.StatusWord);
    }
    
    public Gp4Net.Tool.Services.CardResponse SendCommand(IApduCommand command)
    {
        var response = _virtualCardService.SendCommand(command);
        return new Gp4Net.Tool.Services.CardResponse(response.Data, response.StatusWord);
    }
    
    public bool EstablishSecureChannel(byte[] keySet, byte securityLevel) =>
        _virtualCardService.EstablishSecureChannel(keySet, securityLevel);
    
    public bool IsSecureChannelEstablished => _virtualCardService.IsSecureChannelEstablished;
    
    public void Dispose() => _virtualCardService.Dispose();
}