using System;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Constants;

class TestWrapCommand
{
    static void Main()
    {
        Console.WriteLine("Testing SecureChannelSession.WrapCommand");
        
        // Create session keys
        var sessionKeys = new SessionKeys(
            new byte[16], // S-ENC
            new byte[16], // S-MAC  
            new byte[16]  // S-RMAC
        );
        
        // Create secure channel session with C-MAC
        var session = new SecureChannelSession(
            sessionKeys,
            SecurityLevel.CMac,
            ProtocolIdentifiers.Scp03,
            new byte[16] // MAC chaining value
        );
        
        // Create a GET DATA command (no data)
        var command = GetDataCommand.Create(0x9F7F).Value;
        
        Console.WriteLine($"Original command:");
        Console.WriteLine($"  CLA: 0x{command.Cla:X2}");
        Console.WriteLine($"  INS: 0x{command.Ins:X2}");
        Console.WriteLine($"  P1: 0x{command.P1:X2}");
        Console.WriteLine($"  P2: 0x{command.P2:X2}");
        Console.WriteLine($"  Data: {(command.Data == null ? "null" : $"{command.Data.Length} bytes")}");
        Console.WriteLine($"  ExpectedResponseLength: {command.ExpectedResponseLength}");
        
        // Wrap the command
        var result = session.WrapCommand(command);
        
        if (result.IsSuccess)
        {
            var (wrappedData, expectedResponseLength) = result.Value;
            Console.WriteLine($"\nWrapped command:");
            Console.WriteLine($"  Length: {wrappedData.Length} bytes");
            Console.WriteLine($"  Hex: {BitConverter.ToString(wrappedData)}");
            Console.WriteLine($"  ExpectedResponseLength: {expectedResponseLength}");
        }
        else
        {
            Console.WriteLine($"Error: {result.Error.Message}");
        }
    }
}