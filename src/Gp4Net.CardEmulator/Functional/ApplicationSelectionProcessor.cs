
using System;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Constants;
using static Gp4Net.Constants.Constants;
using Gp4Net.Core;
using static Gp4Net.Constants.Constants.GlobalPlatform;
using static Gp4Net.Services.TlvService;

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
        if (ins != Gp4Net.Constants.Constants.GlobalPlatform.Ins.Select)
        {
            return Result.Failure<SelectCommandData, SmartCardError>(
                SmartCardError.InstructionNotSupported());
        }

        // Validate P1 (selection control)
        byte selectionControl = (byte)(p1 & 0x03);
        if (selectionControl != Apdu.SelectP1.SelectByName && 
            selectionControl != Apdu.SelectP1.SelectByFileId && 
            selectionControl != Apdu.SelectP1.SelectEfUnderCurrentDf)
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
            (FileControlInformation)(p2 & Gp4Net.Constants.Constants.GlobalPlatform.CommonBytes.LowerNibbleMask),
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
            var ctrl when ctrl == Apdu.SelectP1.SelectByName => ProcessSelectByName(state, selectData.Aid),
            var ctrl when ctrl == Apdu.SelectP1.SelectByFileId => ProcessSelectFirst(state, selectData.Aid),
            var ctrl when ctrl == Apdu.SelectP1.SelectEfUnderCurrentDf => ProcessSelectNext(state, selectData.Aid),
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
                .Map(newContext => state.WithApplicationContext(newContext).WithSelected());
        }

        // Select specific application by AID
        return state.ApplicationContext.SelectApplication(aid)
            .Map(newContext => state.WithApplicationContext(newContext).WithSelected());
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
            .Map(newContext => state.WithApplicationContext(newContext).WithSelected());
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
                    .Map(newContext => state.WithApplicationContext(newContext).WithSelected());
            }
        }

        // If no history or at end, select first
        // GlobalPlatform Card Specification v2.3.1 Section 11.1.1.1 - SELECT command processing
        // When multiple applications match AID, select first registered application
        VirtualApplication firstApp = candidates.First();
        return state.ApplicationContext.SelectApplication(firstApp.Aid)
            .Map(newContext => state.WithApplicationContext(newContext).WithSelected());
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
            byte[] nameBytes = Encoding.UTF8.GetBytes(app.Name);
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
    /// Generates proper FCI response for ISD selection according to GP specification.
    /// Per GP 2.3.1 Table 11-82: FCI contains mandatory '6F' template with '84' (AID) and 'A5' (proprietary data).
    /// </summary>
    private static byte[] GenerateIsdSelectResponse()
    {
        // Standard GP ISD AID
        byte[] isdAid = Gp4Net.Constants.Constants.GlobalPlatform.Aids.IsdDefault;
        
        // Build FCI according to GP spec:
        // 6F (FCI Template)
        //   84 (DF Name/AID) - 8 bytes
        //   A5 (Proprietary data) - contains ISD-specific info
        //     9F70 (Life Cycle State) - 1 byte: 0x07 (INITIALIZED)
        
        byte[] proprietaryData = BuildProprietaryData();
        var aidTlvResult = TlvEncoder.EncodeSimple(0x84, isdAid.ToImmutableArray());
        var proprietaryTlvResult = TlvEncoder.EncodeSimple(0xA5, proprietaryData.ToImmutableArray());
        
        return aidTlvResult.Bind(aidTlv =>
            proprietaryTlvResult.Bind(proprietaryTlv =>
            {
                var fciContent = aidTlv.AddRange(proprietaryTlv);
                return TlvEncoder.EncodeSimple(0x6F, fciContent);
            }))
            .Match(
                success => success.ToArray(),
                error => [0x6F, 0x00] // Return minimal FCI on error
            );
    }

    /// <summary>
    /// Builds proprietary data section for ISD FCI.
    /// </summary>
    private static byte[] BuildProprietaryData()
    {
        // Life cycle state: SELECTABLE (INITIALIZED)
        byte[] lifecycleState = [Gp4Net.Constants.Constants.GlobalPlatform.LifecycleStates.Selectable];
        var lifecycleTlvResult = TlvEncoder.EncodeSimple(0x9F70, lifecycleState.ToImmutableArray());
        var lifecycleTlv = lifecycleTlvResult.Match(
            success => success.ToArray(),
            error => [0x9F, 0x70, 0x01, lifecycleState[0]] // Fallback to manual construction
        );
        
        return lifecycleTlv;
    }


    /// <summary>
    /// Extension method to set IsSelected state functionally.
    /// </summary>
    private static CardState WithSelected(this CardState state, bool isSelected)
    {
        return state with { IsSelected = isSelected };
    }
}
