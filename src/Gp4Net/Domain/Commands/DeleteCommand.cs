using System;
using System.Collections.Generic;
using System.Linq;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Commands
{
    /// <summary>
    /// Represents the DELETE command for removing applications and load files from the card.
    /// </summary>
    [PublicAPI]
    public class DeleteCommand
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
            DeleteObjectOnly = 0x80
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
            /// Delete key or key component.
            /// </summary>
            Key = 0x80
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
        public byte[]? DeletionToken { get; }

        /// <summary>
        /// Initializes a new instance of the DeleteCommand class.
        /// </summary>
        /// <param name="type">The delete type.</param>
        /// <param name="target">The delete target.</param>
        /// <param name="aids">The list of AIDs to delete.</param>
        /// <param name="deletionToken">The deletion token (optional).</param>
        public DeleteCommand(
            DeleteType type,
            DeleteTarget target,
            IList<byte[]> aids,
            byte[]? deletionToken = null)
        {
            if (aids == null || aids.Count == 0)
                throw new ArgumentException("At least one AID must be provided.", nameof(aids));

            foreach (var aid in aids)
            {
                if (aid == null || aid.Length == 0)
                    throw new ArgumentException("AIDs cannot be null or empty.", nameof(aids));
            }

            Type = type;
            Target = target;
            Aids = new List<byte[]>(aids.Select(aid => (byte[])aid.Clone()));
            DeletionToken = deletionToken?.Clone() as byte[];
        }

        /// <summary>
        /// Creates a DELETE command for deleting a single application or load file.
        /// </summary>
        /// <param name="aid">The AID to delete.</param>
        /// <param name="deleteRelated">Whether to delete related objects.</param>
        /// <param name="deletionToken">The deletion token (optional).</param>
        /// <returns>A new DeleteCommand.</returns>
        public static DeleteCommand CreateForApplication(
            byte[] aid,
            bool deleteRelated = true,
            byte[]? deletionToken = null)
        {
            if (aid == null)
                throw new ArgumentNullException(nameof(aid));

            var type = deleteRelated ? DeleteType.DeleteObjectAndRelated : DeleteType.DeleteObjectOnly;
            return new DeleteCommand(type, DeleteTarget.ByAid, new[] { aid }, deletionToken);
        }

        /// <summary>
        /// Creates a DELETE command for deleting multiple applications or load files.
        /// </summary>
        /// <param name="aids">The AIDs to delete.</param>
        /// <param name="deleteRelated">Whether to delete related objects.</param>
        /// <param name="deletionToken">The deletion token (optional).</param>
        /// <returns>A new DeleteCommand.</returns>
        public static DeleteCommand CreateForApplications(
            IList<byte[]> aids,
            bool deleteRelated = true,
            byte[]? deletionToken = null)
        {
            var type = deleteRelated ? DeleteType.DeleteObjectAndRelated : DeleteType.DeleteObjectOnly;
            return new DeleteCommand(type, DeleteTarget.ByAid, aids, deletionToken);
        }

        /// <summary>
        /// Creates a DELETE command for deleting a key.
        /// </summary>
        /// <param name="keyIdentifier">The key identifier.</param>
        /// <param name="keyVersion">The key version.</param>
        /// <param name="deletionToken">The deletion token (optional).</param>
        /// <returns>A new DeleteCommand.</returns>
        public static DeleteCommand CreateForKey(
            byte keyIdentifier,
            byte keyVersion,
            byte[]? deletionToken = null)
        {
            var keyReference = new byte[] { keyIdentifier, keyVersion };
            return new DeleteCommand(DeleteType.DeleteObjectOnly, DeleteTarget.Key, new[] { keyReference }, deletionToken);
        }

        /// <summary>
        /// Converts this command to an APDU byte array.
        /// </summary>
        /// <returns>The APDU command bytes.</returns>
        public byte[] ToApdu()
        {
            var data = new List<byte>();

            if (Target == DeleteTarget.ByAid)
            {
                // For AID deletion, encode as:
                // 4F <len> <AID1> [4F <len> <AID2>] ... [<token_len> <token>]
                
                foreach (var aid in Aids)
                {
                    data.Add(0x4F); // AID tag
                    data.Add((byte)aid.Length);
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
            if (DeletionToken != null && DeletionToken.Length > 0)
            {
                data.Add((byte)DeletionToken.Length);
                data.AddRange(DeletionToken);
            }

            // Build APDU
            var apdu = new List<byte>
            {
                Cla,
                Ins,
                (byte)Type,
                (byte)Target,
                (byte)data.Count // Lc
            };

            apdu.AddRange(data);
            apdu.Add(0x00); // Le

            return apdu.ToArray();
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
        public ushort StatusWord { get; }

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
        public DeleteResponse(byte[] data, ushort statusWord, IList<DeletionReceipt>? deletionReceipts = null)
        {
            Data = data != null ? (byte[])data.Clone() : Array.Empty<byte>();
            StatusWord = statusWord;
            IsSuccessful = statusWord == 0x9000;
            DeletionReceipts = deletionReceipts != null ? 
                new List<DeletionReceipt>(deletionReceipts) : 
                Array.Empty<DeletionReceipt>();
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

            if (response != null && response.Length > 0)
            {
                // Parse deletion receipts if present
                var offset = 0;
                while (offset < response.Length)
                {
                    try
                    {
                        // Simple parsing - in practice this would need more sophisticated TLV parsing
                        if (offset + 2 < response.Length && response[offset] == 0x4F)
                        {
                            var aidLength = response[offset + 1];
                            if (offset + 2 + aidLength <= response.Length)
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
                            break;
                        }
                    }
                    catch
                    {
                        break;
                    }
                }
            }

            return new DeleteResponse(response ?? Array.Empty<byte>(), statusWord, deletionReceipts);
        }

        /// <summary>
        /// Gets a human-readable description of the delete result.
        /// </summary>
        /// <returns>The result description.</returns>
        public string GetResultDescription()
        {
            return StatusWord switch
            {
                0x9000 => "Deletion successful",
                0x6A80 => "Incorrect data or AID not found",
                0x6A82 => "Application not found",
                0x6985 => "Conditions not satisfied (dependencies exist)",
                0x6A88 => "Referenced data not found",
                0x6F00 => "Generic failure during deletion",
                _ => $"Unknown error: {StatusWord:X4}"
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
}