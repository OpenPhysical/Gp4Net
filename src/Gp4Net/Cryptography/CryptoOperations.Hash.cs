// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Org.BouncyCastle.Crypto.Digests;

namespace Gp4Net.Cryptography;

public static partial class CryptoOperations
{
    /// <summary>
    /// Hash operations using BouncyCastle cryptographic library.
    /// All methods are static, pure functional, and return Result&lt;T, SmartCardError&gt;.
    /// </summary>
    public static class Hash
    {
        /// <summary>
        /// Computes SHA-256 hash of input data.
        /// </summary>
        /// <param name="data">Data to hash.</param>
        /// <returns>SHA-256 hash or error.</returns>
        public static Result<byte[], SmartCardError> Sha256(byte[] data)
        {
            return Maybe<byte[]>
                .From(data)
                .ToResult(SmartCardError.InvalidArgument("Data cannot be null"))
                .Bind(input =>
                    Result.Try(
                        () =>
                        {
                            var digest = new Sha256Digest();
                            digest.BlockUpdate(input, 0, input.Length);

                            var hash = new byte[digest.GetDigestSize()];
                            digest.DoFinal(hash, 0);

                            return hash;
                        },
                        ex =>
                            SmartCardError.CryptographicError(
                                $"SHA-256 hash computation failed: {ex.Message}"
                            )
                    )
                );
        }

        /// <summary>
        /// Computes SHA-384 hash of input data.
        /// </summary>
        public static Result<byte[], SmartCardError> Sha384(byte[] data)
        {
            return Compute(data, new Sha384Digest(), "SHA-384");
        }

        /// <summary>
        /// Computes SHA-512 hash of input data.
        /// </summary>
        public static Result<byte[], SmartCardError> Sha512(byte[] data)
        {
            return Compute(data, new Sha512Digest(), "SHA-512");
        }

        /// <summary>
        /// Computes SHA-1 hash of input data.
        /// </summary>
        /// <param name="data">Data to hash.</param>
        /// <returns>SHA-1 hash or error.</returns>
        public static Result<byte[], SmartCardError> Sha1(byte[] data)
        {
            return Maybe<byte[]>
                .From(data)
                .ToResult(SmartCardError.InvalidArgument("Data cannot be null"))
                .Bind(input =>
                    Result.Try(
                        () =>
                        {
                            var digest = new Sha1Digest();
                            digest.BlockUpdate(input, 0, input.Length);

                            var hash = new byte[digest.GetDigestSize()];
                            digest.DoFinal(hash, 0);

                            return hash;
                        },
                        ex =>
                            SmartCardError.CryptographicError(
                                $"SHA-1 hash computation failed: {ex.Message}"
                            )
                    )
                );
        }

        /// <summary>
        /// Computes MD5 hash of input data.
        /// Note: MD5 is cryptographically weak and should only be used for legacy compatibility.
        /// </summary>
        /// <param name="data">Data to hash.</param>
        /// <returns>MD5 hash or error.</returns>
        public static Result<byte[], SmartCardError> Md5(byte[] data)
        {
            return Maybe<byte[]>
                .From(data)
                .ToResult(SmartCardError.InvalidArgument("Data cannot be null"))
                .Bind(input =>
                    Result.Try(
                        () =>
                        {
                            var digest = new MD5Digest();
                            digest.BlockUpdate(input, 0, input.Length);

                            var hash = new byte[digest.GetDigestSize()];
                            digest.DoFinal(hash, 0);

                            return hash;
                        },
                        ex =>
                            SmartCardError.CryptographicError(
                                $"MD5 hash computation failed: {ex.Message}"
                            )
                    )
                );
        }

        private static Result<byte[], SmartCardError> Compute(
            byte[] data,
            Org.BouncyCastle.Crypto.IDigest digest,
            string algorithm
        )
        {
            return Maybe<byte[]>
                .From(data)
                .ToResult(SmartCardError.InvalidArgument("Data cannot be null"))
                .Bind(input =>
                    Result.Try(
                        () =>
                        {
                            digest.BlockUpdate(input, 0, input.Length);
                            var hash = new byte[digest.GetDigestSize()];
                            digest.DoFinal(hash, 0);
                            return hash;
                        },
                        ex =>
                            SmartCardError.CryptographicError(
                                $"{algorithm} hash computation failed: {ex.Message}"
                            )
                    )
                );
        }
    }
}
