using System;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.Services.Helpers;

/// <summary>
/// Helper methods for converting GlobalPlatform privileges to/from wire format.
/// Handles both 1-byte (legacy) and 3-byte privilege formats per GP Card Specification v2.3.1.
/// </summary>
public static class PrivilegeHelpers
{
    /// <summary>
    /// Converts privileges to wire format bytes (always 3 bytes).
    /// Wire format: [Byte1][Byte2][Byte3] in little-endian order.
    /// </summary>
    /// <param name="privilege">The privilege flags to convert.</param>
    /// <returns>3-byte array representing privileges in wire format.</returns>
    public static byte[] ToBytes(this Privilege privilege)
    {
        uint value = (uint)privilege;
        // Direct mapping: enum value matches wire format exactly
        return new[]
        {
            (byte)(value & 0xFF),         // Byte 1 (LSB)
            (byte)((value >> 8) & 0xFF),  // Byte 2
            (byte)((value >> 16) & 0xFF)  // Byte 3 (MSB)
        };
    }

    /// <summary>
    /// Converts privileges to compact wire format (1 byte if possible, otherwise 3).
    /// Used for backward compatibility with older cards.
    /// </summary>
    /// <param name="privilege">The privilege flags to convert.</param>
    /// <returns>1 or 3 byte array representing privileges.</returns>
    public static byte[] ToBytesCompact(this Privilege privilege)
    {
        uint value = (uint)privilege;
        // If only byte 1 privileges are set, return 1 byte
        if ((value & 0xFFFFFF00) == 0)
        {
            return new[] { (byte)value };
        }

        // Otherwise return full 3 bytes
        return privilege.ToBytes();
    }

    /// <summary>
    /// Parses privileges from wire format bytes.
    /// Handles both 1-byte (legacy) and 3-byte formats per GP spec.
    /// </summary>
    /// <param name="bytes">1 or 3 byte array from wire format.</param>
    /// <returns>Success with parsed privileges or failure with error.</returns>
    public static Result<Privilege, SmartCardError> FromBytes(byte[] bytes)
    {
        // Validate array has content
        if (bytes.Length == 0)
        {
            return Result.Failure<Privilege, SmartCardError>(
                SmartCardError.InvalidArgument("Privilege bytes cannot be empty"));
        }

        return bytes.Length switch
        {
            1 => Result.Success<Privilege, SmartCardError>(
                // Legacy 1-byte format: only byte 1, bytes 2-3 are 0x00
                (Privilege)bytes[0]),
            
            3 => Result.Success<Privilege, SmartCardError>(
                // Full 3-byte format: direct mapping to enum
                (Privilege)(bytes[0] | (bytes[1] << 8) | (bytes[2] << 16))),
            
            _ => Result.Failure<Privilege, SmartCardError>(
                SmartCardError.InvalidArgument($"Invalid privilege byte length: {bytes.Length}. Expected 1 or 3 bytes."))
        };
    }

    /// <summary>
    /// Checks if the given privileges include Security Domain privilege.
    /// </summary>
    public static bool IsSecurityDomain(this Privilege privilege)
    {
        return privilege.HasFlag(Privilege.SecurityDomain);
    }

    /// <summary>
    /// Checks if the given privileges allow delegated management operations.
    /// Requires both SecurityDomain and DelegatedManagement privileges.
    /// </summary>
    public static bool CanPerformDelegatedManagement(this Privilege privilege)
    {
        return privilege.HasFlag(Privilege.SecurityDomain) &&
               privilege.HasFlag(Privilege.DelegatedManagement);
    }

    /// <summary>
    /// Checks if the given privileges allow authorized management operations.
    /// Requires both SecurityDomain and AuthorizedManagement privileges.
    /// </summary>
    public static bool CanPerformAuthorizedManagement(this Privilege privilege)
    {
        return privilege.HasFlag(Privilege.SecurityDomain) &&
               privilege.HasFlag(Privilege.AuthorizedManagement);
    }

    /// <summary>
    /// Checks if the given privileges allow DAP verification.
    /// Requires both SecurityDomain and DapVerification privileges.
    /// </summary>
    public static bool CanVerifyDap(this Privilege privilege)
    {
        return privilege.HasFlag(Privilege.SecurityDomain) &&
               privilege.HasFlag(Privilege.DapVerification);
    }

    /// <summary>
    /// Checks if the given privileges require mandatory DAP verification.
    /// Requires SecurityDomain, DapVerification, and MandatedDapVerification.
    /// </summary>
    public static bool RequiresDapVerification(this Privilege privilege)
    {
        return privilege.HasFlag(Privilege.SecurityDomain) &&
               privilege.HasFlag(Privilege.DapVerification) &&
               privilege.HasFlag(Privilege.MandatedDapVerification);
    }

    /// <summary>
    /// Validates that privilege combinations are valid per GP specification.
    /// </summary>
    public static Result<Privilege, SmartCardError> ValidatePrivilegeCombination(this Privilege privilege)
    {
        // DelegatedManagement requires SecurityDomain
        if (privilege.HasFlag(Privilege.DelegatedManagement) && !privilege.HasFlag(Privilege.SecurityDomain))
        {
            return Result.Failure<Privilege, SmartCardError>(
                SmartCardError.InvalidArgument("DelegatedManagement privilege requires SecurityDomain privilege"));
        }

        // AuthorizedManagement requires SecurityDomain
        if (privilege.HasFlag(Privilege.AuthorizedManagement) && !privilege.HasFlag(Privilege.SecurityDomain))
        {
            return Result.Failure<Privilege, SmartCardError>(
                SmartCardError.InvalidArgument("AuthorizedManagement privilege requires SecurityDomain privilege"));
        }

        // DapVerification requires SecurityDomain
        if (privilege.HasFlag(Privilege.DapVerification) && !privilege.HasFlag(Privilege.SecurityDomain))
        {
            return Result.Failure<Privilege, SmartCardError>(
                SmartCardError.InvalidArgument("DapVerification privilege requires SecurityDomain privilege"));
        }

        // MandatedDapVerification requires both SecurityDomain and DapVerification
        if (privilege.HasFlag(Privilege.MandatedDapVerification))
        {
            if (!privilege.HasFlag(Privilege.SecurityDomain) || !privilege.HasFlag(Privilege.DapVerification))
            {
                return Result.Failure<Privilege, SmartCardError>(
                    SmartCardError.InvalidArgument("MandatedDapVerification requires both SecurityDomain and DapVerification privileges"));
            }
        }

        return Result.Success<Privilege, SmartCardError>(privilege);
    }
}