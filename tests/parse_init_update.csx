#!/usr/bin/env dotnet-script

using System;

// Parse the INITIALIZE UPDATE response from the log
var responseData = "000023455586442048390102000A72BB2775E0D3954017CA0267BBAB";
var responseBytes = Convert.FromHexString(responseData);

Console.WriteLine("=== INITIALIZE UPDATE Response Analysis ===");
Console.WriteLine($"Full response: {responseData}");
Console.WriteLine($"Response length: {responseBytes.Length}");
Console.WriteLine();

// Parse according to GP spec
if (responseBytes.Length >= 28)
{
    var keyDiversificationData = responseBytes[0..10];
    var keyInformation = responseBytes[10];
    var scpId = responseBytes[11];
    var scpParameter = responseBytes[12];
    var sequenceCounter = responseBytes[13..15];
    var cardChallenge = responseBytes[15..23];
    var cardCryptogram = responseBytes[23..];

    Console.WriteLine($"Key Diversification Data: {Convert.ToHexString(keyDiversificationData)}");
    Console.WriteLine($"Key Information: {keyInformation:X2}");
    Console.WriteLine($"SCP ID: {scpId:X2}");
    Console.WriteLine($"SCP Parameter: {scpParameter:X2}");
    Console.WriteLine($"Sequence Counter: {Convert.ToHexString(sequenceCounter)}");
    Console.WriteLine($"Card Challenge: {Convert.ToHexString(cardChallenge)}");
    Console.WriteLine($"Card Cryptogram: {Convert.ToHexString(cardCryptogram)}");
}

// Check if the sequence counter is actually 0102 instead of 0009
Console.WriteLine();
Console.WriteLine("=== Corrected Analysis ===");
var correctSequence = Convert.FromHexString("0102");
Console.WriteLine($"Using sequence counter: {Convert.ToHexString(correctSequence)}");