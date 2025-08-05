using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Represents the DELETE command for removing applications and load files from the card.
/// </summary>
[PublicAPI]
public class DeleteCommand : IApduCommand
{
    /// <summary>
    /// The command class byte.
    /// </summary>
    public const byte Cla = 0x80;

    /// <summary>
    /// The command instruction byte.
    /// </summary>
    public const byte Ins = 0xE4;

    /// <summary>
    /// Delete operation types for P1 parameter.
    /// </summary>
    public enum DeleteType : byte
    {
        /// <summary>
        /// Delete object and related objects.
        /// </summary>
        DeleteObjectAndRelated = 0x00,

        /// <summary>
        /// Delete object only.
        /// </summary>
        DeleteObjectOnly = 0x80,
    }

    /// <summary>
    /// Delete target types for P2 parameter.
    /// </summary>
    public enum DeleteTarget : byte
    {
        /// <summary>
        /// Delete by object AID.
        /// </summary>
        ByAid = 0x00,

        /// <summary>
        /// Delete with related objects.
        /// </summary>
        WithRelated = 0x80,
    }

    /// <summary>
    /// Gets the delete type.
    /// </summary>
    public DeleteType Type { get; }

    /// <summary>
    /// Gets the delete target.
    /// </summary>
    public DeleteTarget Target { get; }

    /// <summary>
    /// Gets the list of AIDs to delete.
    /// </summary>
    public IReadOnlyList<byte[]> Aids { get; }

    /// <summary>
    /// Gets the deletion token (optional).
    /// </summary>
    public Maybe<byte[]> DeletionToken { get; }

    /// <summary>
    /// Optional Delete Token Key (for automatic token calculation).
    /// </summary>
    public Maybe<byte[]> DeleteTokenKey { get; }

    /// <summary>
    /// Gets the class byte.
    /// </summary>
    byte IApduCommand.Cla => Cla;

    /// <summary>
    /// Gets the instruction byte.
    /// </summary>
    byte IApduCommand.Ins => Ins;

    /// <summary>
    /// Gets the parameter 1 byte.
    /// </summary>
    public byte P1 => (byte)Type;

    /// <summary>
    /// Gets the parameter 2 byte.
    /// </summary>
    public byte P2 => (byte)Target;

    /// <summary>
    /// Gets the command data.
    /// </summary>
    public byte[]? Data => GetDeleteData().Match(
        onSuccess: data => data,
        onFailure: _ => null);

    /// <summary>
    /// Gets the expected response length. DELETE commands do not use LE byte per GP traces.
    /// </summary>
    public int? ExpectedResponseLength => null;

    /// <summary>
    /// Gets whether this command uses extended length.
    /// </summary>
    public bool IsExtendedLength => false;

    /// <summary>
    /// Gets the delete data for the IApduCommand interface.
    /// </summary>
    private Result<byte[], SmartCardError> GetDeleteData()
    {
        var data = new List<byte>();

        if (Target == DeleteTarget.ByAid || Target == DeleteTarget.WithRelated)
        {
            // For AID deletion, encode as TLV: 4F <len> <AIDs concatenated>
            var totalAidLength = Aids.Sum(aid => aid.Length);
            data.Add(0x4F); // Tag for AID
            data.Add((byte)totalAidLength);
            foreach (var aid in Aids)
            {
                data.AddRange(aid);
            }
            // If DeletionTokenKey or DeletionToken is present, emit TLV (calculated as needed)
            var tokenToUse = DeletionToken;
            
            // If no token but we have a key, compute the token
            if (!tokenToUse.HasValue && DeleteTokenKey.HasValue)
            {
                // Compute token (simple heuristic: assume single AID, package removal)
                if (Aids.Count != 1)
                    return SmartCardError.InvalidArgument("Delete token calculation requires exactly one AID.");
                // Compute token using the DeleteTokenCalculator
                try
                {
                    var computedToken = Gp4Net.Cryptography.DeleteTokenCalculator.ComputeDeleteToken(
                        DeleteTokenKey.Value, 
                        P1, 
                        P2, 
                        Aids[0], 
                        Maybe<byte[]>.None); // No optional TLV for now
                    tokenToUse = Maybe<byte[]>.From(computedToken);
                }
                catch (Exception ex)
                {
                    return SmartCardError.CryptographicError($"Failed to compute delete token: {ex.Message}");
                }
            }
            
            // Add token if present
            if (tokenToUse.HasValue && tokenToUse.Value.Length > 0)
            {
                // Based on trace analysis, deletion token is appended directly
                // without TLV wrapping: just the raw token bytes
                data.AddRange(tokenToUse.Value);
            }
        }
        else
        {
            // For key deletion, as TLV: D0 (keyId) + D2 (keyVer) per entry
            foreach (var keyRef in Aids)
            {
                if (keyRef.Length == 2)
                {
                    data.Add(0xD0); data.Add(1); data.Add(keyRef[0]);
                    data.Add(0xD2); data.Add(1); data.Add(keyRef[1]);
                }
                else if (keyRef.Length == 1)
                {
                    data.Add(0xD0); data.Add(1); data.Add(keyRef[0]);
                }
            }
        }

        return Result.Success<byte[], SmartCardError>([.. data]);
    }

    /// <summary>
    /// Initializes a new instance of the DeleteCommand class.
    /// </summary>
    /// <param name="type">The delete type.</param>
    /// <param name="target">The delete target.</param>
    /// <param name="aids">The list of AIDs to delete.</param>
    /// <param name="deletionToken">The deletion token (optional).</param>
    private DeleteCommand(
        DeleteType type,
        DeleteTarget target,
        IList<byte[]> aids,
        Maybe<byte[]> deletionToken = default,
        Maybe<byte[]> deleteTokenKey = default
    )
    {
        Type = type;
        Target = target;
        Aids = new List<byte[]>(aids.Select(aid => (byte[])aid.Clone()));
        DeletionToken = deletionToken.Map(token => (byte[])token.Clone());
        DeleteTokenKey = deleteTokenKey.Map(key => (byte[])key.Clone());
    }

    /// <summary>
    /// Creates a DELETE command for deleting a single application or load file.
    /// </summary>
    /// <param name="aid">The AID to delete.</param>
    /// <param name="deleteRelated">Whether to delete related objects.</param>
    /// <param name="deletionToken">The deletion token (optional).</param>
    /// <returns>A Result containing either a new DeleteCommand or an error.</returns>
    public static Result<DeleteCommand, SmartCardError> CreateForApplication(
        byte[] aid,
        bool deleteRelated = false,
        Maybe<byte[]> deletionToken = default
    )
    {
        if (aid == null)
            return SmartCardError.InvalidArgument("AID cannot be null.");
            
        if (aid.Length == 0)
            return SmartCardError.InvalidArgument("AID cannot be empty.");

        var type = deleteRelated
            ? DeleteType.DeleteObjectAndRelated
            : DeleteType.DeleteObjectOnly;
        var target = deleteRelated
            ? DeleteTarget.WithRelated
            : DeleteTarget.ByAid;
        return new DeleteCommand(type, target, new[] { aid }, deletionToken);
    }

    /// <summary>
    /// Creates a DELETE command for deleting a package.
    /// </summary>
    /// <param name="aid">The package AID to delete.</param>
    /// <param name="deleteRelated">Whether to delete related objects.</param>
    /// <param name="deletionToken">The deletion token (optional).</param>
    /// <returns>A Result containing either a new DeleteCommand or an error.</returns>
    public static Result<DeleteCommand, SmartCardError> CreateForPackage(
        byte[] aid,
        bool deleteRelated = false,
        Maybe<byte[]> deletionToken = default
    )
    {
        if (aid == null)
            return SmartCardError.InvalidArgument("Package AID cannot be null.");
            
        if (aid.Length == 0)
            return SmartCardError.InvalidArgument("Package AID cannot be empty.");

        var type = deleteRelated
            ? DeleteType.DeleteObjectAndRelated
            : DeleteType.DeleteObjectOnly;
        var target = deleteRelated
            ? DeleteTarget.WithRelated
            : DeleteTarget.ByAid;
        return new DeleteCommand(type, target, new[] { aid }, deletionToken);
    }

    /// <summary>
    /// Creates a DELETE command for deleting an executable load file.
    /// </summary>
    /// <param name="aid">The executable load file AID to delete.</param>
    /// <param name="deleteRelated">Whether to delete related objects.</param>
    /// <param name="deletionToken">The deletion token (optional).</param>
    /// <returns>A Result containing either a new DeleteCommand or an error.</returns>
    public static Result<DeleteCommand, SmartCardError> CreateForExecutableLoadFile(
        byte[] aid,
        bool deleteRelated = false,
        Maybe<byte[]> deletionToken = default
    )
    {
        if (aid == null)
            return SmartCardError.InvalidArgument("Executable load file AID cannot be null.");
            
        if (aid.Length == 0)
            return SmartCardError.InvalidArgument("Executable load file AID cannot be empty.");

        var type = deleteRelated
            ? DeleteType.DeleteObjectAndRelated
            : DeleteType.DeleteObjectOnly;
        var target = deleteRelated
            ? DeleteTarget.WithRelated
            : DeleteTarget.ByAid;
        return new DeleteCommand(type, target, new[] { aid }, deletionToken);
    }

    /// <summary>
    /// Creates a DELETE command for deleting multiple applications or load files.
    /// </summary>
    /// <param name="aids">The AIDs to delete.</param>
    /// <param name="deleteRelated">Whether to delete related objects.</param>
    /// <param name="deletionToken">The deletion token (optional).</param>
    /// <returns>A Result containing either a new DeleteCommand or an error.</returns>
    public static Result<DeleteCommand, SmartCardError> CreateForApplications(
        IList<byte[]> aids,
        bool deleteRelated = false,
        Maybe<byte[]> deletionToken = default
    )
    {
        if (aids == null)
            return SmartCardError.InvalidArgument("AIDs list cannot be null.");
                
        if (aids.Count == 0)
            return SmartCardError.InvalidArgument("At least one AID must be provided.");

        foreach (var aid in aids)
        {
            if (aid == null)
                return SmartCardError.InvalidArgument("AIDs cannot contain null values.");
                    
            if (aid.Length == 0)
                return SmartCardError.InvalidArgument("AIDs cannot be empty.");
        }

        var type = deleteRelated
            ? DeleteType.DeleteObjectAndRelated
            : DeleteType.DeleteObjectOnly;
        var target = deleteRelated
            ? DeleteTarget.WithRelated
            : DeleteTarget.ByAid;
        return new DeleteCommand(type, target, aids, deletionToken);
    }

    /// <summary>
    /// Creates a DELETE command for deleting a key.
    /// </summary>
    /// <param name="keyIdentifier">The key identifier.</param>
    /// <param name="keyVersion">The key version.</param>
    /// <param name="deletionToken">The deletion token (optional).</param>
    /// <returns>A Result containing either a new DeleteCommand or an error.</returns>
    public static Result<DeleteCommand, SmartCardError> CreateForKey(
        byte keyIdentifier,
        byte keyVersion,
        Maybe<byte[]> deletionToken = default
    )
    {
        var keyReference = new byte[] { keyIdentifier, keyVersion };
        return new DeleteCommand(
            DeleteType.DeleteObjectOnly,
            DeleteTarget.ByAid,
            new[] { keyReference },
            deletionToken
        );
    }

    /// <summary>
    /// Returns the string representation of this command.
    /// </summary>
    /// <returns>The string "DELETE".</returns>
    public override string ToString() => "DELETE";

    /// <summary>
    /// Converts this command to an APDU byte array.
    /// </summary>
    /// <returns>The APDU command bytes.</returns>
    public byte[] ToApdu()
    {
        var data = new List<byte>();

        if (Target == DeleteTarget.ByAid || Target == DeleteTarget.WithRelated)
        {
            // For AID deletion, encode as:
            // 4F <total_len> <AID1><AID2>... [<token_len> <token>]
            // Based on the trace: 4F09A000000308000010000
                
            // Calculate total length of all AIDs
            var totalAidLength = Aids.Sum(aid => aid.Length);
                
            data.Add(0x4F); // AID tag
            data.Add((byte)totalAidLength);
                
            // Add all AIDs concatenated
            foreach (var aid in Aids)
            {
                data.AddRange(aid);
            }
        }
        else
        {
            // For key deletion, the AID contains key identifier and version
            foreach (var keyRef in Aids)
            {
                data.AddRange(keyRef);
            }
        }

        // Add deletion token if present
        if (DeletionToken.HasValue && DeletionToken.Value.Length > 0)
        {
            // Based on trace analysis, deletion token is appended directly
            // without length prefix: just the raw token bytes
            data.AddRange(DeletionToken.Value);
        }

        // Build APDU
        var apdu = new List<byte>
        {
            Cla,
            Ins,
            (byte)Type,
            (byte)Target,
            (byte)data.Count, // Lc
        };

        apdu.AddRange(data);
            
        // DELETE commands do NOT use LE byte per GP Pro traces
        // Trace: 84E40080134F09A0000003080000100020EEDD243F094FAD (no LE)

        return [.. apdu];
    }
}

/// <summary>
/// Represents the response to a DELETE command.
/// </summary>
[PublicAPI]
public class DeleteResponse
{
    /// <summary>
    /// Gets the response data (if any).
    /// </summary>
    public byte[] Data { get; }

    /// <summary>
    /// Gets a value indicating whether the deletion was successful.
    /// </summary>
    public bool IsSuccessful { get; }

    /// <summary>
    /// Gets the status word from the response.
    /// </summary>
    public StatusWord StatusWord { get; }

    /// <summary>
    /// Gets the list of deletion receipts (if any).
    /// </summary>
    public IReadOnlyList<DeletionReceipt> DeletionReceipts { get; }

    /// <summary>
    /// Initializes a new instance of the DeleteResponse class.
    /// </summary>
    /// <param name="data">The response data.</param>
    /// <param name="statusWord">The status word.</param>
    /// <param name="deletionReceipts">The deletion receipts.</param>
    public DeleteResponse(
        byte[] data,
        StatusWord statusWord,
        Maybe<IList<DeletionReceipt>> deletionReceipts = default
    )
    {
        Data = data != null ? (byte[])data.Clone() : [];
        StatusWord = statusWord;
        IsSuccessful = statusWord == StatusWords.Success;
        DeletionReceipts = deletionReceipts
            .Map(receipts => (IReadOnlyList<DeletionReceipt>)new List<DeletionReceipt>(receipts))
            .GetValueOrDefault(Array.Empty<DeletionReceipt>());
    }

    /// <summary>
    /// Parses a DELETE response.
    /// </summary>
    /// <param name="response">The response data (excluding status word).</param>
    /// <param name="statusWord">The status word from the response.</param>
    /// <returns>The parsed response.</returns>
    public static DeleteResponse Parse(byte[] response, ushort statusWord)
    {
        var deletionReceipts = new List<DeletionReceipt>();

        if (response is { Length: > 0 })
        {
            // According to GP spec Table 11-25, DELETE response has:
            // - Length of delete confirmation (1-2 bytes): Mandatory
            // - Delete confirmation (0-n bytes): Conditional
                
            var offset = 0;
                
            // Read the length of delete confirmation
            if (offset < response.Length)
            {
                var confirmationLength = response[offset];
                offset++;
                    
                // Handle extended length encoding (81 80 - 81 FF)
                if (confirmationLength == 0x81 && offset < response.Length)
                {
                    confirmationLength = response[offset];
                    offset++;
                }
                    
                // Parse deletion confirmation if present
                if (confirmationLength > 0 && offset + confirmationLength <= response.Length)
                {
                    // Parse the deletion confirmation data
                    var confirmationEnd = offset + confirmationLength;
                    while (offset < confirmationEnd)
                    {
                        // Look for AID TLV (4F tag)
                        if (offset + 2 < confirmationEnd && response[offset] == 0x4F)
                        {
                            var aidLength = response[offset + 1];
                            if (offset + 2 + aidLength <= confirmationEnd)
                            {
                                var aid = new byte[aidLength];
                                Array.Copy(response, offset + 2, aid, 0, aidLength);
                                deletionReceipts.Add(new DeletionReceipt(aid, true));
                                offset += 2 + aidLength;
                            }
                            else
                            {
                                break;
                            }
                        }
                        else
                        {
                            // Skip unknown data
                            offset++;
                        }
                    }
                }
            }
        }

        return new DeleteResponse(
            response ?? [],
            statusWord,
            deletionReceipts.Count > 0 ? Maybe<IList<DeletionReceipt>>.From(deletionReceipts) : Maybe<IList<DeletionReceipt>>.None
        );
    }

    /// <summary>
    /// Gets a human-readable description of the delete result.
    /// </summary>
    /// <returns>The result description.</returns>
    public string GetResultDescription()
    {
        return StatusWord switch
        {
            var sw when sw == StatusWords.Success => "Deletion successful",
            var sw when sw == StatusWords.IncorrectData => "Incorrect data or AID not found",
            var sw when sw == StatusWords.FileNotFound => "Application not found",
            var sw when sw == StatusWords.ConditionsNotSatisfied => "Conditions not satisfied (dependencies exist)",
            var sw when sw == StatusWords.ReferencedDataNotFound => "Referenced data not found",
            var sw when sw == StatusWords.GenericFailure => "Generic failure during deletion",
            _ => $"Unknown error: {StatusWord.Value:X}",
        };
    }
}

/// <summary>
/// Represents a deletion receipt for a successfully deleted object.
/// </summary>
[PublicAPI]
public class DeletionReceipt
{
    /// <summary>
    /// Gets the AID of the deleted object.
    /// </summary>
    public byte[] Aid { get; }

    /// <summary>
    /// Gets a value indicating whether the deletion was successful.
    /// </summary>
    public bool IsSuccessful { get; }

    /// <summary>
    /// Initializes a new instance of the DeletionReceipt class.
    /// </summary>
    /// <param name="aid">The AID of the deleted object.</param>
    /// <param name="isSuccessful">Whether the deletion was successful.</param>
    public DeletionReceipt(byte[] aid, bool isSuccessful)
    {
        Aid = (byte[])aid.Clone();
        IsSuccessful = isSuccessful;
    }
}