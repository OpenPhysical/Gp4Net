// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Pure functional processor for DAP (Data Authentication Pattern) verification.
/// Handles cryptographic verification of CAP file signatures according to GlobalPlatform specification.
/// </summary>
[PublicAPI]
public static class DapProcessor
{
    /// <summary>
    /// Verifies the DAP signature in a CAP file if present.
    /// </summary>
    /// <param name="capFileData">The complete CAP file data.</param>
    /// <param name="config">Card configuration with DAP verification settings.</param>
    /// <returns>True if DAP verification passes or no DAP present, false otherwise.</returns>
    public static Result<bool, SmartCardError> VerifyDapSignature(
        byte[] capFileData,
        CardConfiguration config)
    {
        return ExtractDapBlock(capFileData)
            .Match(
                dapBlock => PerformDapVerification(dapBlock, capFileData, config),
                () => Result.Success<bool, SmartCardError>(true) // No DAP verification required when DAP not present
            );
    }

    /// <summary>
    /// Extracts the DAP block from CAP file data if present.
    /// </summary>
    /// <param name="capFileData">The CAP file data to search.</param>
    /// <returns>DAP block if found, None if not present.</returns>
    private static Maybe<DapBlock> ExtractDapBlock(byte[] capFileData)
    {
        return FindDapTag(capFileData, 0xE2) // DAP block tag
            .Match(
                onSuccess: tagPosition => Maybe<DapBlock>.From(CreateDapBlock(capFileData, tagPosition)),
                onFailure: _ => Maybe<DapBlock>.None
            );
    }

    /// <summary>
    /// Finds the position of a DAP tag in the CAP file data.
    /// </summary>
    /// <param name="data">The data to search.</param>
    /// <param name="dapTag">The DAP tag to find.</param>
    /// <returns>Position of the tag if found, error otherwise.</returns>
    private static Result<int, SmartCardError> FindDapTag(byte[] data, byte dapTag)
    {
        var tagPositions = data
            .Select((value, index) => new { Value = value, Index = index })
            .Where(item => item.Value == dapTag)
            .Select(item => item.Index);

        return tagPositions.Any()
            ? Result.Success<int, SmartCardError>(tagPositions.First())
            : Result.Failure<int, SmartCardError>(SmartCardError.ReferencedDataNotFound());
    }

    /// <summary>
    /// Creates a DAP block from CAP file data starting at the specified position.
    /// </summary>
    /// <param name="capFileData">The CAP file data.</param>
    /// <param name="tagPosition">The position of the DAP tag.</param>
    /// <returns>The created DAP block.</returns>
    private static DapBlock CreateDapBlock(byte[] capFileData, int tagPosition)
    {
        // Simplified DAP block extraction for emulation
        int blockLength = Math.Min(256, capFileData.Length - tagPosition);
        var blockData = ImmutableArray.Create(capFileData, tagPosition, blockLength);
        
        return new DapBlock(
            SecurityDomainAid: ImmutableArray<byte>.Empty,
            DapSignature: blockData[..Math.Min(64, blockData.Length)],
            CertificateChain: ImmutableArray<ImmutableArray<byte>>.Empty,
            SignatureAlgorithm: 0x01 // RSA-SHA1 for simplicity
        );
    }

    /// <summary>
    /// Performs complete DAP verification including algorithm validation, certificate chain, and signature.
    /// </summary>
    /// <param name="dapBlock">The DAP block to verify.</param>
    /// <param name="capFileData">The original CAP file data.</param>
    /// <param name="config">Card configuration.</param>
    /// <returns>True if verification passes, false otherwise.</returns>
    private static Result<bool, SmartCardError> PerformDapVerification(
        DapBlock dapBlock,
        byte[] capFileData,
        CardConfiguration config)
    {
        return ValidateDapAlgorithm(dapBlock)
            .Bind(validBlock => VerifyDapCertificateChain(validBlock, config))
            .Bind(certValidBlock => VerifyDapDataSignature(certValidBlock, capFileData))
            .Map(_ => true);
    }

    /// <summary>
    /// Validates that the DAP signature algorithm is supported.
    /// </summary>
    /// <param name="dapBlock">The DAP block to validate.</param>
    /// <returns>Validated DAP block or error.</returns>
    private static Result<DapBlock, SmartCardError> ValidateDapAlgorithm(DapBlock dapBlock)
    {
        return dapBlock.SignatureAlgorithm switch
        {
            0x01 => Result.Success<DapBlock, SmartCardError>(dapBlock), // RSA-SHA1
            0x02 => Result.Success<DapBlock, SmartCardError>(dapBlock), // RSA-SHA256
            0x03 => Result.Success<DapBlock, SmartCardError>(dapBlock), // ECDSA-SHA256
            _ => Result.Failure<DapBlock, SmartCardError>(SmartCardError.SecurityStatusNotSatisfied(
                $"Unsupported DAP algorithm: {dapBlock.SignatureAlgorithm:X2}"))
        };
    }

    /// <summary>
    /// Verifies the certificate chain in the DAP block.
    /// </summary>
    /// <param name="dapBlock">The DAP block with certificate chain.</param>
    /// <param name="config">Card configuration with trusted roots.</param>
    /// <returns>Verified DAP block or error.</returns>
    private static Result<DapBlock, SmartCardError> VerifyDapCertificateChain(
        DapBlock dapBlock,
        CardConfiguration config)
    {
        if (!dapBlock.CertificateChain.Any())
        {
            return Result.Failure<DapBlock, SmartCardError>(
                SmartCardError.SecurityStatusNotSatisfied("No certificate chain provided"));
        }
        
        // Validate the certificate chain and return the validated DAP block
        return CryptoService.Signature.ValidateCertificateChain(
            dapBlock.CertificateChain.Select(cert => cert.ToArray()).ToArray())
            .Map(_ => dapBlock);
    }

    /// <summary>
    /// Verifies the DAP signature against the signed data.
    /// </summary>
    /// <param name="dapBlock">The DAP block with signature.</param>
    /// <param name="capFileData">The CAP file data to verify.</param>
    /// <returns>Verified DAP block or error.</returns>
    private static Result<DapBlock, SmartCardError> VerifyDapDataSignature(
        DapBlock dapBlock,
        byte[] capFileData)
    {
        // First extract the public key from the validated certificate chain
        return CryptoService.Signature.ValidateCertificateChain(
            dapBlock.CertificateChain.Select(cert => cert.ToArray()).ToArray())
            .Bind(publicKey => ExtractSignedData(capFileData)
                .Bind(signedData => VerifySignature(
                    signedData, 
                    dapBlock.DapSignature.ToArray(), 
                    publicKey, 
                    dapBlock.SignatureAlgorithm)))
            .Map(_ => dapBlock);
    }

    /// <summary>
    /// Extracts the data that was signed for DAP verification.
    /// </summary>
    /// <param name="capFileData">The CAP file data.</param>
    /// <returns>The signed data portion.</returns>
    private static Result<byte[], SmartCardError> ExtractSignedData(byte[] capFileData)
    {
        // In a real implementation, this would extract the specific portions
        // of the CAP file that are covered by the DAP signature
        // For emulation, use the first portion of the file
        int signedDataLength = Math.Min(1024, capFileData.Length);
        return Result.Success<byte[], SmartCardError>(capFileData[..signedDataLength]);
    }

    /// <summary>
    /// Verifies a cryptographic signature against data.
    /// </summary>
    /// <param name="data">The data that was signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns>True if signature is valid, false otherwise.</returns>
    private static Result<bool, SmartCardError> VerifySignature(
        byte[] data, 
        byte[] signature, 
        byte[] publicKey,
        byte algorithm)
    {
        return algorithm switch
        {
            0x01 => CryptoService.Signature.VerifyRsaSha1(data, signature, publicKey),
            0x02 => CryptoService.Signature.VerifyRsaSha256(data, signature, publicKey),
            0x03 => CryptoService.Signature.VerifyEcdsaSha256(data, signature, publicKey),
            _ => Result.Failure<bool, SmartCardError>(
                SmartCardError.AlgorithmNotSupported())
        };
    }

    /// <summary>
    /// Immutable DAP (Data Authentication Pattern) block structure.
    /// </summary>
    /// <param name="SecurityDomainAid">AID of the Security Domain that created the DAP.</param>
    /// <param name="DapSignature">The cryptographic signature over the signed data.</param>
    /// <param name="CertificateChain">X.509 certificate chain for signature verification.</param>
    /// <param name="SignatureAlgorithm">Algorithm identifier for the signature.</param>
    public record DapBlock(
        ImmutableArray<byte> SecurityDomainAid,
        ImmutableArray<byte> DapSignature,
        ImmutableArray<ImmutableArray<byte>> CertificateChain,
        byte SignatureAlgorithm);
}