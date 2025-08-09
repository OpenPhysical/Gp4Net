#!/usr/bin/env dotnet-script

using System;

// Parse the INITIALIZE UPDATE command from the log
var commandData = "8050000008A98C7EBAF388B7971C";
var commandBytes = Convert.FromHexString(commandData);

Console.WriteLine("=== INITIALIZE UPDATE Command Analysis ===");
Console.WriteLine($"Full command: {commandData}");
Console.WriteLine($"Command length: {commandBytes.Length}");
Console.WriteLine();

// Parse APDU structure: CLA INS P1 P2 Lc DATA
if (commandBytes.Length >= 5)
{
    var cla = commandBytes[0];
    var ins = commandBytes[1];
    var p1 = commandBytes[2];
    var p2 = commandBytes[3];
    var lc = commandBytes[4];
    var data = commandBytes[5..];

    Console.WriteLine($"CLA: {cla:X2}");
    Console.WriteLine($"INS: {ins:X2}");
    Console.WriteLine($"P1 (Key Version): {p1:X2}");
    Console.WriteLine($"P2 (Key ID): {p2:X2}");
    Console.WriteLine($"Lc: {lc:X2}");
    Console.WriteLine($"Data: {Convert.ToHexString(data)}");
    
    if (data.Length >= 8)
    {
        var hostChallenge = data[0..8];
        Console.WriteLine($"Host Challenge: {Convert.ToHexString(hostChallenge)}");
        
        if (data.Length > 8)
        {
            var extra = data[8..];
            Console.WriteLine($"Extra data: {Convert.ToHexString(extra)}");
        }
    }
}