using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Gp4Net.Cryptography;

/// <summary>
/// Cryptographic service for digital signature operations.
/// </summary>
public static partial class CryptoService
{
    /// <summary>
    /// Signature verification operations following GlobalPlatform specifications.
    /// </summary>
    public static class Signature
    {
        /// <summary>
        /// Verifies an RSA-SHA1 signature according to GlobalPlatform DAP specifications.
        /// </summary>
        /// <param name="data">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKey">The RSA public key for verification.</param>
        /// <returns>True if signature is valid, false otherwise.</returns>
        public static Result<bool, SmartCardError> VerifyRsaSha1(
            byte[] data,
            byte[] signature,
            byte[] publicKey)
        {
            try
            {
                var signer = SignerUtilities.GetSigner("SHA1withRSA");
                var keyParameter = PublicKeyFactory.CreateKey(publicKey);
                
                signer.Init(false, keyParameter);
                signer.BlockUpdate(data, 0, data.Length);
                
                return Result.Success<bool, SmartCardError>(signer.VerifySignature(signature));
            }
            catch (Exception ex)
            {
                return Result.Failure<bool, SmartCardError>(
                    SmartCardError.CryptographicError($"RSA-SHA1 verification failed: {ex.Message}"));
            }
        }
        
        /// <summary>
        /// Verifies an RSA-SHA256 signature according to GlobalPlatform DAP specifications.
        /// </summary>
        /// <param name="data">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKey">The RSA public key for verification.</param>
        /// <returns>True if signature is valid, false otherwise.</returns>
        public static Result<bool, SmartCardError> VerifyRsaSha256(
            byte[] data,
            byte[] signature,
            byte[] publicKey)
        {
            try
            {
                var signer = SignerUtilities.GetSigner("SHA256withRSA");
                var keyParameter = PublicKeyFactory.CreateKey(publicKey);
                
                signer.Init(false, keyParameter);
                signer.BlockUpdate(data, 0, data.Length);
                
                return Result.Success<bool, SmartCardError>(signer.VerifySignature(signature));
            }
            catch (Exception ex)
            {
                return Result.Failure<bool, SmartCardError>(
                    SmartCardError.CryptographicError($"RSA-SHA256 verification failed: {ex.Message}"));
            }
        }
        
        /// <summary>
        /// Verifies an ECDSA-SHA256 signature according to GlobalPlatform DAP specifications.
        /// </summary>
        /// <param name="data">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKey">The EC public key for verification.</param>
        /// <returns>True if signature is valid, false otherwise.</returns>
        public static Result<bool, SmartCardError> VerifyEcdsaSha256(
            byte[] data,
            byte[] signature,
            byte[] publicKey)
        {
            try
            {
                var signer = SignerUtilities.GetSigner("SHA256withECDSA");
                var keyParameter = PublicKeyFactory.CreateKey(publicKey);
                
                signer.Init(false, keyParameter);
                signer.BlockUpdate(data, 0, data.Length);
                
                return Result.Success<bool, SmartCardError>(signer.VerifySignature(signature));
            }
            catch (Exception ex)
            {
                return Result.Failure<bool, SmartCardError>(
                    SmartCardError.CryptographicError($"ECDSA-SHA256 verification failed: {ex.Message}"));
            }
        }
        
        /// <summary>
        /// Validates a certificate chain according to X.509 standards.
        /// </summary>
        /// <param name="certificateChain">The certificate chain to validate, starting from end-entity.</param>
        /// <returns>The public key from the validated end-entity certificate.</returns>
        public static Result<byte[], SmartCardError> ValidateCertificateChain(byte[][] certificateChain)
        {
            if (certificateChain.Length == 0)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidData("Certificate chain is empty"));
            }
            
            try
            {
                var parser = new Org.BouncyCastle.X509.X509CertificateParser();
                var certificates = certificateChain
                    .Select(certBytes => parser.ReadCertificate(certBytes))
                    .ToArray();
                
                // Validate the end-entity certificate dates
                var endEntityCert = certificates[0];
                try
                {
                    endEntityCert.CheckValidity(DateTime.UtcNow);
                }
                catch
                {
                    return Result.Failure<byte[], SmartCardError>(
                        SmartCardError.SecurityError("Certificate is not valid at current time"));
                }
                
                // Validate certificate chain signatures using functional approach
                var validationResults = certificates
                    .Zip(certificates.Skip(1), (current, issuer) => new { Current = current, Issuer = issuer })
                    .Select((pair, index) =>
                    {
                        try
                        {
                            pair.Current.Verify(pair.Issuer.GetPublicKey());
                            return Result.Success<bool, SmartCardError>(true);
                        }
                        catch
                        {
                            return Result.Failure<bool, SmartCardError>(
                                SmartCardError.SecurityError($"Certificate {index} signature verification failed"));
                        }
                    })
                    .ToList();
                
                // Check all validations passed using functional aggregation
                var allValid = validationResults
                    .Aggregate(
                        Result.Success<bool, SmartCardError>(true),
                        (acc, result) => acc.IsFailure ? acc : result);
                
                if (allValid.IsFailure)
                {
                    return Result.Failure<byte[], SmartCardError>(allValid.Error);
                }
                
                // Extract and return the public key from end-entity certificate
                var publicKeyInfo = endEntityCert.GetPublicKey();
                var encoded = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory
                    .CreateSubjectPublicKeyInfo(publicKeyInfo)
                    .GetEncoded();
                
                return Result.Success<byte[], SmartCardError>(encoded);
            }
            catch (Exception ex)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.CryptographicError($"Certificate chain validation failed: {ex.Message}"));
            }
        }
    }
}