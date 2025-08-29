using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.CardEmulator.Core;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Functional processor for SELECT commands with proper application context switching.
/// Implements GlobalPlatform SELECT command according to GP specification.
/// </summary>
public static class ApplicationSelectionProcessor
{
    /// <summary>
    /// Processes a SELECT command functionally, returning updated card state.
    /// </summary>
    /// <param name="state">Current card state.</param>
    /// <param name="command">SELECT command bytes.</param>
    /// <returns>Updated card state with application selected or error.</returns>
    public static Result<(CardState NewState, byte[] Response), SmartCardError> ProcessSelect(
        CardState state,
        ImmutableArray<byte> command)
    {
        return ParseSelectCommand(command)
            .Bind(selectData => ProcessApplicationSelection(state, selectData))
            .Map(newState => (newState, GenerateSelectResponse(newState)));
    }

    /// <summary>
    /// Parses SELECT command to extract AID and selection parameters.
    /// </summary>
    private static Result<SelectCommandData, SmartCardError> ParseSelectCommand(ImmutableArray<byte> command)
    {
        if (command.Length < 5)
        {
            return Result.Failure<SelectCommandData, SmartCardError>(
                SmartCardError.WrongLength());
        }

        byte cla = command[0];
        byte ins = command[1];
        byte p1 = command[2];
        byte p2 = command[3];
        byte lc = command[4];

        // Validate CLA and INS
        if (ins != 0xA4)
        {
            return Result.Failure<SelectCommandData, SmartCardError>(
                SmartCardError.InstructionNotSupported());
        }

        // Validate P1 (selection control)
        SelectionControl selectionControl = (SelectionControl)(p1 & 0x03);
        if (!Enum.IsDefined(typeof(SelectionControl), selectionControl))
        {
            return Result.Failure<SelectCommandData, SmartCardError>(
                SmartCardError.IncorrectData());
        }

        // Extract AID data
        if (command.Length < 5 + lc)
        {
            return Result.Failure<SelectCommandData, SmartCardError>(
                SmartCardError.WrongLength());
        }

        ImmutableArray<byte> aid = lc == 0 
            ? ImmutableArray<byte>.Empty 
            : [..command.Skip(5).Take(lc)];

        return Result.Success<SelectCommandData, SmartCardError>(new SelectCommandData(
            aid,
            selectionControl,
            (FileControlInformation)(p2 & 0x0F),
            (p1 & 0x04) != 0 // File occurrence bit
        ));
    }

    /// <summary>
    /// Processes the application selection using functional state transitions.
    /// </summary>
    private static Result<CardState, SmartCardError> ProcessApplicationSelection(
        CardState state,
        SelectCommandData selectData)
    {
        return selectData.SelectionControl switch
        {
            SelectionControl.SelectByName => ProcessSelectByName(state, selectData.Aid),
            SelectionControl.SelectFirstOccurrence => ProcessSelectFirst(state, selectData.Aid),
            SelectionControl.SelectNextOccurrence => ProcessSelectNext(state, selectData.Aid),
            _ => Result.Failure<CardState, SmartCardError>(SmartCardError.IncorrectData())
        };
    }

    /// <summary>
    /// Processes SELECT by name (most common case).
    /// </summary>
    private static Result<CardState, SmartCardError> ProcessSelectByName(CardState state, ImmutableArray<byte> aid)
    {
        if (aid.IsEmpty)
        {
            // Empty AID selects ISD
            return state.ApplicationContext.SelectIsd()
                .Map(newContext => state.WithApplicationContext(newContext).WithSelected(true));
        }

        // Select specific application by AID
        return state.ApplicationContext.SelectApplication(aid)
            .Map(newContext => state.WithApplicationContext(newContext).WithSelected(true));
    }

    /// <summary>
    /// Processes SELECT first occurrence (for partial AID matching).
    /// </summary>
    private static Result<CardState, SmartCardError> ProcessSelectFirst(CardState state, ImmutableArray<byte> aid)
    {
        if (aid.IsEmpty)
        {
            return ProcessSelectByName(state, aid);
        }

        // Find first application with AID starting with the given partial AID
        string aidString = Convert.ToHexString(aid.ToArray());
        ImmutableList<VirtualApplication> candidates = state.ApplicationContext.Applications.Values
            .Where(app => !app.Aid.IsEmpty)
            .Where(app => Convert.ToHexString(app.Aid.ToArray()).StartsWith(aidString))
            .ToImmutableList();

        if (!candidates.Any())
        {
            return Result.Failure<CardState, SmartCardError>(SmartCardError.FileNotFound());
        }

        VirtualApplication matchingApp = candidates.First();
        return state.ApplicationContext.SelectApplication(matchingApp.Aid)
            .Map(newContext => state.WithApplicationContext(newContext).WithSelected(true));
    }

    /// <summary>
    /// Processes SELECT next occurrence using selection history tracking.
    /// </summary>
    private static Result<CardState, SmartCardError> ProcessSelectNext(CardState state, ImmutableArray<byte> aid)
    {
        if (aid.IsEmpty)
        {
            return ProcessSelectByName(state, aid);
        }

        string aidString = Convert.ToHexString(aid.ToArray());
        ImmutableList<VirtualApplication> candidates = state.ApplicationContext.Applications.Values
            .Where(app => !app.Aid.IsEmpty)
            .Where(app => Convert.ToHexString(app.Aid.ToArray()).StartsWith(aidString))
            .ToImmutableList();

        if (!candidates.Any())
        {
            return Result.Failure<CardState, SmartCardError>(SmartCardError.FileNotFound());
        }

        // Find next occurrence based on selection history
        string? lastSelected = state.ApplicationContext.SelectionHistory.LastOrDefault();
        if (lastSelected != null)
        {
            ImmutableList<string> candidateAids = candidates.Select(app => Convert.ToHexString(app.Aid.ToArray())).ToImmutableList();
            int currentIndex = candidateAids.IndexOf(lastSelected);
            if (currentIndex >= 0 && currentIndex + 1 < candidateAids.Count)
            {
                byte[] nextAid = Convert.FromHexString(candidateAids[currentIndex + 1]);
                return state.ApplicationContext.SelectApplication([..nextAid])
                    .Map(newContext => state.WithApplicationContext(newContext).WithSelected(true));
            }
        }

        // If no history or at end, select first
        VirtualApplication firstApp = candidates.First();
        return state.ApplicationContext.SelectApplication(firstApp.Aid)
            .Map(newContext => state.WithApplicationContext(newContext).WithSelected(true));
    }

    /// <summary>
    /// Generates appropriate SELECT response based on new card state.
    /// </summary>
    private static byte[] GenerateSelectResponse(CardState state)
    {
        return state.CurrentlySelectedApplication.Match(
            app => GenerateApplicationSelectResponse(app),
            () => GenerateIsdSelectResponse()
        );
    }

    /// <summary>
    /// Generates SELECT response for a specific application.
    /// </summary>
    private static byte[] GenerateApplicationSelectResponse(VirtualApplication app)
    {
        // Simple FCI (File Control Information) template
        ImmutableArray<byte>.Builder fciBuilder = ImmutableArray.CreateBuilder<byte>();
        
        // FCI Template tag (6F)
        fciBuilder.Add(0x6F);
        
        ImmutableArray<byte>.Builder contentBuilder = ImmutableArray.CreateBuilder<byte>();
        
        // Application AID (84)
        if (!app.Aid.IsEmpty)
        {
            contentBuilder.Add(0x84);
            contentBuilder.Add((byte)app.Aid.Length);
            contentBuilder.AddRange(app.Aid);
        }
        
        // Application name (50) - optional
        if (!string.IsNullOrEmpty(app.Name))
        {
            byte[] nameBytes = System.Text.Encoding.UTF8.GetBytes(app.Name);
            if (nameBytes.Length <= 16) // Reasonable limit
            {
                contentBuilder.Add(0x50);
                contentBuilder.Add((byte)nameBytes.Length);
                contentBuilder.AddRange(nameBytes);
            }
        }
        
        ImmutableArray<byte> content = contentBuilder.ToImmutable();
        fciBuilder.Add((byte)content.Length);
        fciBuilder.AddRange(content);
        
        return fciBuilder.ToImmutable().ToArray();
    }

    /// <summary>
    /// Generates SELECT response for ISD selection.
    /// </summary>
    private static byte[] GenerateIsdSelectResponse()
    {
        // Simple FCI for ISD - includes ISD-specific data
        return [0x6F, 0x00]; // Empty FCI template
    }

    /// <summary>
    /// Extension method to set IsSelected state functionally.
    /// </summary>
    private static CardState WithSelected(this CardState state, bool isSelected)
    {
        return state with { IsSelected = isSelected };
    }
}

/// <summary>
/// Data extracted from a SELECT command.
/// </summary>
internal record SelectCommandData(
    ImmutableArray<byte> Aid,
    SelectionControl SelectionControl,
    FileControlInformation Fci,
    bool FileOccurrence
);

/// <summary>
/// SELECT command P1 parameter values.
/// </summary>
internal enum SelectionControl : byte
{
    SelectByName = 0x04,
    SelectFirstOccurrence = 0x00,
    SelectNextOccurrence = 0x02
}

/// <summary>
/// SELECT command P2 parameter values for FCI.
/// </summary>
internal enum FileControlInformation : byte
{
    ReturnFci = 0x00,
    ReturnFcp = 0x04,
    ReturnFmd = 0x08,
    NoResponse = 0x0C
}