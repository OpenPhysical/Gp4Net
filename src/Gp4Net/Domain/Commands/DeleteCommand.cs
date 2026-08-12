using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Transport;
using JetBrains.Annotations;
using WSCT.ISO7816;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Represents the DELETE command for removing applications and load files from the card.
/// </summary>
[PublicAPI]
public class DeleteCommand : IApduCommand
{
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
        DeleteObjectOnly = 0x00,
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

        /// <summary>Key-reference data; P2 is 00 per GP 2.3.1 Table 11-22.</summary>
        ByKey = 0x01,
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
    /// Optional Security Domain identifier for token verification (tag '42').
    /// </summary>
    public Maybe<byte[]> SecurityDomainIdentifier { get; }

    /// <summary>
    /// Optional Security Domain image number (tag '45').
    /// </summary>
    public Maybe<byte[]> SecurityDomainImageNumber { get; }

    /// <summary>
    /// Optional Application Provider identifier (tag '5F20').
    /// </summary>
    public Maybe<byte[]> ApplicationProviderIdentifier { get; }

    /// <summary>
    /// Optional Token identifier/number (tag '93').
    /// </summary>
    public Maybe<byte[]> TokenIdentifier { get; }

    /// <summary>
    /// Gets the class byte.
    /// </summary>
    public byte Cla => GlobalPlatform.Cla.GP_STANDARD;

    /// <summary>
    /// Gets the instruction byte.
    /// </summary>
    public byte Ins => GlobalPlatform.Ins.DELETE;

    /// <summary>
    /// Gets the parameter 1 byte.
    /// </summary>
    public byte P1
    {
        get { return (byte)Type; }
    }

    /// <summary>
    /// Gets the parameter 2 byte.
    /// </summary>
    public byte P2
    {
        get { return Target == DeleteTarget.WithRelated ? (byte)0x80 : (byte)0x00; }
    }

    /// <summary>
    /// Gets the command data.
    /// </summary>
    public byte[] Data
    {
        get { return GetDeleteData().Match(onSuccess: data => data, onFailure: _ => []); }
    }

    /// <summary>
    /// Gets the expected response length.
    /// </summary>
    public Maybe<int> ExpectedResponseLength
    {
        // GP Card Spec 2.3.1, Table 11-20: Le=00 is mandatory.
        get { return Maybe<int>.From(0); }
    }

    /// <summary>
    /// Gets whether this command uses extended length.
    /// </summary>
    public bool IsExtendedLength
    {
        get { return false; }
    }

    /// <summary>
    /// Creates a WSCT CommandAPDU from this DELETE command.
    /// </summary>
    /// <returns>A Result containing either the CommandAPDU or an error.</returns>
    public Result<CommandAPDU, SmartCardError> ToCommandApdu()
    {
        return GetDeleteData()
            .Map(data =>
                ExpectedResponseLength.Match(
                    Some: expectedLength => new CommandAPDU(
                        Cla,
                        Ins,
                        P1,
                        P2,
                        (uint)data.Length,
                        data,
                        (uint)expectedLength
                    ),
                    None: () => new CommandAPDU(Cla, Ins, P1, P2, (uint)data.Length, data)
                )
            );
    }

    /// <summary>
    /// Gets the delete data for the IApduCommand interface.
    /// </summary>
    private Result<byte[], SmartCardError> GetDeleteData()
    {
        List<byte> data = [];

        if (Target is DeleteTarget.ByAid or DeleteTarget.WithRelated)
        {
            // For AID deletion, encode as TLV: 4F <len> <AIDs concatenated>
            int totalAidLength = Aids.Sum(aid => aid.Length);
            data.Add(0x4F); // Tag for AID
            data.Add((byte)totalAidLength);
            foreach (byte[] aid in Aids)
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
                {
                    return SmartCardError.InvalidArgument(
                        "Delete token calculation requires exactly one AID."
                    );
                }

                // Build Control Reference Template for Digital Signature if needed
                var controlReferenceTemplate = BuildControlReferenceTemplate();

                // Compute token using the DeleteTokenCalculator
                var tokenResult = DeleteTokenKey.Match(
                    Some: key =>
                        CryptoService.Keys.ComputeDeleteToken(
                            key,
                            P1,
                            P2,
                            Aids[0],
                            controlReferenceTemplate
                        ),
                    None: () => SmartCardError.InvalidArgument("Delete token key is required")
                );

                if (tokenResult.IsFailure)
                {
                    return tokenResult.Error;
                }

                tokenToUse = Maybe<byte[]>.From(tokenResult.Value);
            }

            // Add token if present
            if (tokenToUse.HasValue && tokenToUse.Value.Length > 0)
            {
                // GP Card Spec 2.3.1, Table 11-23: the Delete Token is data object 9E.
                data.Add(0x9E);
                data.Add((byte)tokenToUse.Value.Length);
                data.AddRange(tokenToUse.Value);
            }
        }
        else
        {
            // For key deletion, as TLV: D0 (keyId) + D2 (keyVer) per entry
            foreach (byte[] keyRef in Aids)
            {
                switch (keyRef.Length)
                {
                    case 2:
                        data.Add(0xD0);
                        data.Add(1);
                        data.Add(keyRef[0]);
                        data.Add(0xD2);
                        data.Add(1);
                        data.Add(keyRef[1]);
                        break;
                    case 1:
                        data.Add(0xD0);
                        data.Add(1);
                        data.Add(keyRef[0]);
                        break;
                }
            }
        }

        return Result.Success<byte[], SmartCardError>([.. data]);
    }

    /// <summary>
    /// Represents a command to delete an object or application associated with specific AIDs on a smart card.
    /// </summary>
    private DeleteCommand(
        DeleteType type,
        DeleteTarget target,
        IList<byte[]> aids,
        Maybe<byte[]> deletionToken = default,
        Maybe<byte[]> deleteTokenKey = default,
        Maybe<byte[]> securityDomainIdentifier = default,
        Maybe<byte[]> securityDomainImageNumber = default,
        Maybe<byte[]> applicationProviderIdentifier = default,
        Maybe<byte[]> tokenIdentifier = default
    )
    {
        Type = type;
        Target = target;
        Aids = new List<byte[]>(aids.Select(aid => (byte[])aid.Clone()));
        DeletionToken = deletionToken.Map(token => (byte[])token.Clone());
        DeleteTokenKey = deleteTokenKey.Map(key => (byte[])key.Clone());
        SecurityDomainIdentifier = securityDomainIdentifier.Map(id => (byte[])id.Clone());
        SecurityDomainImageNumber = securityDomainImageNumber.Map(num => (byte[])num.Clone());
        ApplicationProviderIdentifier = applicationProviderIdentifier.Map(id => (byte[])id.Clone());
        TokenIdentifier = tokenIdentifier.Map(id => (byte[])id.Clone());
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
        return Maybe<byte[]>
            .From(aid)
            .Match(
                Some: aidValue =>
                    aidValue.Length == 0
                        ? SmartCardError.InvalidArgument("AID cannot be empty.")
                        : CreateApplicationDeleteCommand(aidValue, deleteRelated, deletionToken),
                None: () => SmartCardError.InvalidArgument("AID cannot be null.")
            );
    }

    /// <summary>
    /// Creates a DELETE command for deleting a single application or load file with full token parameters.
    /// </summary>
    /// <param name="aid">The AID to delete.</param>
    /// <param name="deleteRelated">Whether to delete related objects.</param>
    /// <param name="deletionToken">The deletion token (optional).</param>
    /// <param name="deleteTokenKey">The delete token key for automatic token calculation (optional).</param>
    /// <param name="securityDomainIdentifier">Security Domain identifier for token verification (tag '42').</param>
    /// <param name="securityDomainImageNumber">Security Domain image number (tag '45').</param>
    /// <param name="applicationProviderIdentifier">Application Provider identifier (tag '5F20').</param>
    /// <param name="tokenIdentifier">Token identifier/number (tag '93').</param>
    /// <returns>A Result containing either a new DeleteCommand or an error.</returns>
    public static Result<DeleteCommand, SmartCardError> CreateForApplicationWithTokenParams(
        byte[] aid,
        bool deleteRelated = false,
        Maybe<byte[]> deletionToken = default,
        Maybe<byte[]> deleteTokenKey = default,
        Maybe<byte[]> securityDomainIdentifier = default,
        Maybe<byte[]> securityDomainImageNumber = default,
        Maybe<byte[]> applicationProviderIdentifier = default,
        Maybe<byte[]> tokenIdentifier = default
    )
    {
        return Maybe<byte[]>
            .From(aid)
            .Match(
                Some: aidValue =>
                    aidValue.Length == 0
                        ? SmartCardError.InvalidArgument("AID cannot be empty.")
                        : CreateApplicationDeleteCommandWithTokenParams(
                            aidValue,
                            deleteRelated,
                            deletionToken,
                            deleteTokenKey,
                            securityDomainIdentifier,
                            securityDomainImageNumber,
                            applicationProviderIdentifier,
                            tokenIdentifier
                        ),
                None: () => SmartCardError.InvalidArgument("AID cannot be null.")
            );
    }

    private static Result<DeleteCommand, SmartCardError> CreateApplicationDeleteCommand(
        byte[] aid,
        bool deleteRelated,
        Maybe<byte[]> deletionToken
    )
    {
        var type = deleteRelated ? DeleteType.DeleteObjectAndRelated : DeleteType.DeleteObjectOnly;
        var target = deleteRelated ? DeleteTarget.WithRelated : DeleteTarget.ByAid;
        return new DeleteCommand(type, target, [aid], deletionToken);
    }

    private static Result<
        DeleteCommand,
        SmartCardError
    > CreateApplicationDeleteCommandWithTokenParams(
        byte[] aid,
        bool deleteRelated,
        Maybe<byte[]> deletionToken,
        Maybe<byte[]> deleteTokenKey,
        Maybe<byte[]> securityDomainIdentifier,
        Maybe<byte[]> securityDomainImageNumber,
        Maybe<byte[]> applicationProviderIdentifier,
        Maybe<byte[]> tokenIdentifier
    )
    {
        var type = deleteRelated ? DeleteType.DeleteObjectAndRelated : DeleteType.DeleteObjectOnly;
        var target = deleteRelated ? DeleteTarget.WithRelated : DeleteTarget.ByAid;
        return new DeleteCommand(
            type,
            target,
            [aid],
            deletionToken,
            deleteTokenKey,
            securityDomainIdentifier,
            securityDomainImageNumber,
            applicationProviderIdentifier,
            tokenIdentifier
        );
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
        return Maybe<byte[]>
            .From(aid)
            .Match(
                Some: aidValue =>
                    aidValue.Length == 0
                        ? SmartCardError.InvalidArgument("Package AID cannot be empty.")
                        : CreatePackageDeleteCommand(aidValue, deleteRelated, deletionToken),
                None: () => SmartCardError.InvalidArgument("Package AID cannot be null.")
            );
    }

    private static Result<DeleteCommand, SmartCardError> CreatePackageDeleteCommand(
        byte[] aid,
        bool deleteRelated,
        Maybe<byte[]> deletionToken
    )
    {
        var type = deleteRelated ? DeleteType.DeleteObjectAndRelated : DeleteType.DeleteObjectOnly;
        var target = deleteRelated ? DeleteTarget.WithRelated : DeleteTarget.ByAid;
        return new DeleteCommand(type, target, [aid], deletionToken);
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
        return Maybe<byte[]>
            .From(aid)
            .Match(
                Some: aidValue =>
                    aidValue.Length == 0
                        ? SmartCardError.InvalidArgument(
                            "Executable load file AID cannot be empty."
                        )
                        : CreateExecutableLoadFileDeleteCommand(
                            aidValue,
                            deleteRelated,
                            deletionToken
                        ),
                None: () =>
                    SmartCardError.InvalidArgument("Executable load file AID cannot be null.")
            );
    }

    private static Result<DeleteCommand, SmartCardError> CreateExecutableLoadFileDeleteCommand(
        byte[] aid,
        bool deleteRelated,
        Maybe<byte[]> deletionToken
    )
    {
        var type = deleteRelated ? DeleteType.DeleteObjectAndRelated : DeleteType.DeleteObjectOnly;
        var target = deleteRelated ? DeleteTarget.WithRelated : DeleteTarget.ByAid;
        return new DeleteCommand(type, target, [aid], deletionToken);
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
        return Maybe<IList<byte[]>>
            .From(aids)
            .Match(
                Some: aidsList =>
                    ValidateAndCreateMultipleDeleteCommand(aidsList, deleteRelated, deletionToken),
                None: () => SmartCardError.InvalidArgument("AIDs list cannot be null.")
            );
    }

    private static Result<DeleteCommand, SmartCardError> ValidateAndCreateMultipleDeleteCommand(
        IList<byte[]> aids,
        bool deleteRelated,
        Maybe<byte[]> deletionToken
    )
    {
        if (aids.Count == 0)
        {
            return SmartCardError.InvalidArgument("At least one AID must be provided.");
        }

        // Validate all AIDs - collect all validation results
        List<Maybe<SmartCardError>> validationErrors =
        [
            .. aids.Select(aid =>
                    Maybe<byte[]>
                        .From(aid)
                        .Match(
                            Some: aidValue =>
                                aidValue.Length == 0
                                    ? Maybe<SmartCardError>.From(
                                        SmartCardError.InvalidArgument("AIDs cannot be empty.")
                                    )
                                    : Maybe<SmartCardError>.None,
                            None: () =>
                                Maybe<SmartCardError>.From(
                                    SmartCardError.InvalidArgument(
                                        "AIDs cannot contain null values."
                                    )
                                )
                        )
                )
                .Where(error => error.HasValue),
        ];

        if (validationErrors.Any())
        {
            return validationErrors.First().Value; // Return first validation error
        }

        var type = deleteRelated ? DeleteType.DeleteObjectAndRelated : DeleteType.DeleteObjectOnly;
        var target = deleteRelated ? DeleteTarget.WithRelated : DeleteTarget.ByAid;
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
        byte[] keyReference = [keyIdentifier, keyVersion];
        return new DeleteCommand(
            DeleteType.DeleteObjectOnly,
            DeleteTarget.ByKey,
            [keyReference],
            deletionToken
        );
    }

    /// <summary>
    /// Returns the string representation of this command.
    /// </summary>
    /// <returns>The string "DELETE".</returns>
    public override string ToString()
    {
        return "DELETE";
    }

    /// <summary>
    /// Builds the Control Reference Template for Digital Signature (tag 'B6') containing optional TLV parameters.
    /// Per GP specification Table 11-23, this includes Security Domain identification,
    /// Application Provider identifier, and Token identifier/number.
    /// </summary>
    /// <returns>The encoded Control Reference Template, or None if no parameters are specified.</returns>
    private Maybe<byte[]> BuildControlReferenceTemplate()
    {
        // Build TLV components functionally
        var tlvComponents = new[]
        {
            // Security Domain identifier (tag '42')
            SecurityDomainIdentifier.Map(id =>
                new byte[] { 0x42, (byte)id.Length }
                    .Concat(id)
                    .ToArray()
            ),
            // Security Domain image number (tag '45')
            SecurityDomainImageNumber.Map(num =>
                new byte[] { 0x45, (byte)num.Length }
                    .Concat(num)
                    .ToArray()
            ),
            // Application Provider identifier (tag '5F20')
            ApplicationProviderIdentifier.Map(id =>
                new byte[] { 0x5F, 0x20, (byte)id.Length }
                    .Concat(id)
                    .ToArray()
            ),
            // Token identifier/number (tag '93')
            TokenIdentifier.Map(id =>
                new byte[] { 0x93, (byte)id.Length }
                    .Concat(id)
                    .ToArray()
            ),
        }.Where(maybeComponent => maybeComponent.HasValue).Select(component => component.Value);

        // If we have components, build the complete template
        if (tlvComponents.Any())
        {
            byte[] templateData = tlvComponents.SelectMany(component => component).ToArray();
            byte[] result = new byte[] { 0xB6, (byte)templateData.Length }
                .Concat(templateData)
                .ToArray();
            return Maybe<byte[]>.From(result);
        }

        return Maybe<byte[]>.None;
    }

    /// <inheritdoc />
    public CommandAPDU ToApdu()
    {
        return ToCommandApdu()
            .GetValueOrDefault(
                new CommandAPDU(
                    GlobalPlatform.Cla.GP_STANDARD,
                    GlobalPlatform.Ins.DELETE,
                    0x00,
                    0x00
                )
            );
    }

    /// <inheritdoc />
    public byte[] ToBytes()
    {
        // Store the command data when building the APDU
        return ToCommandApdu().Map(cmd => cmd.ToBytes()).GetValueOrDefault([]);
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
        Data = Maybe<byte[]>.From(data).Map(d => (byte[])d.Clone()).GetValueOrDefault([]);
        StatusWord = statusWord;
        IsSuccessful = statusWord == StatusWords.Legacy.Success;
        DeletionReceipts = deletionReceipts
            .Map(receipts => (IReadOnlyList<DeletionReceipt>)new List<DeletionReceipt>(receipts))
            .GetValueOrDefault([]);
    }

    /// <summary>
    /// Parses a DELETE response.
    /// </summary>
    /// <param name="response">The response data (excluding status word).</param>
    /// <param name="statusWord">The status word from the response.</param>
    /// <returns>The parsed response.</returns>
    public static DeleteResponse Parse(byte[] response, ushort statusWord)
    {
        List<DeletionReceipt> deletionReceipts = [];

        if (response is { Length: > 0 })
        {
            // According to GP spec Table 11-25, DELETE response has:
            // - Length of delete confirmation (1-2 bytes): Mandatory
            // - Delete confirmation (0-n bytes): Conditional

            int offset = 0;

            // Read the length of delete confirmation
            if (offset < response.Length)
            {
                byte confirmationLength = response[offset];
                offset++;

                // Handle extended length encoding (81 80 - 81 FF)
                if (confirmationLength == 0x81 && offset < response.Length)
                {
                    confirmationLength = response[offset];
                    offset++;
                }

                // Parse deletion confirmation if present
                if (confirmationLength <= 0 || offset + confirmationLength > response.Length)
                {
                    return new DeleteResponse(
                        Maybe<byte[]>.From(response).GetValueOrDefault([]),
                        statusWord,
                        deletionReceipts.Count > 0
                            ? Maybe<IList<DeletionReceipt>>.From(deletionReceipts)
                            : Maybe<IList<DeletionReceipt>>.None
                    );
                }

                // Parse the deletion confirmation data
                int confirmationEnd = offset + confirmationLength;
                while (offset < confirmationEnd)
                {
                    // Look for AID TLV (4F tag)
                    if (offset + 2 < confirmationEnd && response[offset] == 0x4F)
                    {
                        byte aidLength = response[offset + 1];
                        if (offset + 2 + aidLength <= confirmationEnd)
                        {
                            byte[] aid = new byte[aidLength];
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

        return new DeleteResponse(
            Maybe<byte[]>.From(response).GetValueOrDefault([]),
            statusWord,
            deletionReceipts.Count > 0
                ? Maybe<IList<DeletionReceipt>>.From(deletionReceipts)
                : Maybe<IList<DeletionReceipt>>.None
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
            _ when StatusWord == StatusWords.Legacy.Success => "Deletion successful",
            _ when StatusWord == StatusWords.Legacy.IncorrectData
                => "Incorrect data or AID not found",
            _ when StatusWord == StatusWords.Legacy.FileNotFound => "Application not found",
            _ when StatusWord == StatusWords.Legacy.ConditionsNotSatisfied
                => "Conditions not satisfied (dependencies exist)",
            _ when StatusWord == StatusWords.Legacy.ReferencedDataNotFound
                => "Referenced data not found",
            _ when StatusWord == StatusWords.Legacy.GenericFailure
                => "Generic failure during deletion",
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
