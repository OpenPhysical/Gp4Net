using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.Cryptography;

public static partial class CryptoService
{
    /// <summary>
    /// MAC (Message Authentication Code) operations for SCP02 and SCP03.
    /// Consolidates all MAC calculation methods from multiple classes.
    /// </summary>
    public static class Mac
    {
        /// <summary>
        /// Calculates SCP02 Command MAC using ISO 9797-1 Algorithm 3 (Retail MAC).
        /// Per GlobalPlatform Card Specification v2.3.1 Section B.1.2.2 "Single DES Plus Final Triple DES MAC".
        /// </summary>
        /// <param name="sMacKey">The S-MAC session key (16 or 24 bytes).</param>
        /// <param name="data">The data to authenticate.</param>
        /// <param name="icv">The Initial Chaining Value (8 bytes) for MAC chaining.</param>
        /// <returns>8-byte MAC or error.</returns>
        public static Result<byte[], SmartCardError> CalculateScp02CommandMac(
            byte[] sMacKey,
            byte[] data,
            byte[] icv
        )
        {
            return Validation
                .ValidateInputs(sMacKey, data, icv)
                .Bind(
                    () =>
                        Validation.ValidateKeyLength(
                            sMacKey,
                            [16, 24],
                            "SCP02 S-MAC key must be 16 or 24 bytes"
                        )
                )
                .Bind(() => Validation.ValidateExactLength(icv, 8, "ICV"))
                .Bind(
                    () =>
                        Result.Try(
                            () =>
                            {
                                // Expand 16-byte key to 24 bytes if needed (K1||K2 -> K1||K2||K1)
                                byte[] expandedKey =
                                    sMacKey.Length == 16
                                        ? Utils.ExpandTripleDesKey(sMacKey).Value
                                        : sMacKey;

                                // Set odd parity on the expanded key to match ScpVerification
                                DesParameters.SetOddParity(expandedKey);

                                // Use ISO9797Alg3Mac with ISO7816d4Padding
                                // Initialize with ICV using ParametersWithIV
                                var mac = new ISO9797Alg3Mac(
                                    new DesEngine(),
                                    64, // 64 bits output
                                    new ISO7816d4Padding()
                                );
                                mac.Init(new ParametersWithIV(new KeyParameter(expandedKey), icv));
                                mac.BlockUpdate(data, 0, data.Length);

                                byte[] result = new byte[8];
                                mac.DoFinal(result, 0);

                                return result;
                            },
                            static ex =>
                                SmartCardError.CryptographicError(
                                    $"SCP02 Command MAC calculation failed: {ex.Message}"
                                )
                        )
                );
        }

        /// <summary>
        /// Calculates SCP02 Response MAC using ISO 9797-1 Algorithm 3 (Retail MAC).
        /// Per GlobalPlatform Card Specification v2.3.1 Section B.1.2.2 - same algorithm as Command MAC.
        /// </summary>
        /// <param name="sMacKey">The S-MAC session key (16 or 24 bytes).</param>
        /// <param name="data">The data to authenticate.</param>
        /// <param name="icv">The Initial Chaining Value (8 bytes) for MAC chaining.</param>
        /// <returns>8-byte MAC or error.</returns>
        public static Result<byte[], SmartCardError> CalculateScp02ResponseMac(
            byte[] sMacKey,
            byte[] data,
            byte[] icv
        )
        {
            return Validation
                .ValidateInputs(sMacKey, data, icv)
                .Bind(
                    () =>
                        Validation.ValidateKeyLength(
                            sMacKey,
                            [16, 24],
                            "SCP02 S-MAC key must be 16 or 24 bytes"
                        )
                )
                .Bind(() => Validation.ValidateExactLength(icv, 8, "ICV"))
                .Bind(
                    () =>
                        Result.Try(
                            () =>
                            {
                                // Expand 16-byte key to 24 bytes if needed (K1||K2 -> K1||K2||K1)
                                byte[] expandedKey =
                                    sMacKey.Length == 16
                                        ? Utils.ExpandTripleDesKey(sMacKey).Value
                                        : sMacKey;

                                // Set odd parity on the expanded key to match ScpVerification
                                DesParameters.SetOddParity(expandedKey);

                                // Use ISO9797Alg3Mac with ISO7816d4Padding
                                // Initialize with ICV using ParametersWithIV
                                var mac = new ISO9797Alg3Mac(
                                    new DesEngine(),
                                    64, // 64 bits output
                                    new ISO7816d4Padding()
                                );
                                mac.Init(new ParametersWithIV(new KeyParameter(expandedKey), icv));
                                mac.BlockUpdate(data, 0, data.Length);

                                byte[] result = new byte[8];
                                mac.DoFinal(result, 0);

                                return result;
                            },
                            static ex =>
                                SmartCardError.CryptographicError(
                                    $"SCP02 Response MAC calculation failed: {ex.Message}"
                                )
                        )
                );
        }

        /// <summary>
        /// Calculates SCP03 Command MAC using AES-CMAC.
        /// Per GlobalPlatform SCP03 v1.1.1 Section 4.1.3 and 6.2.4.
        /// </summary>
        /// <param name="sMacKey">The S-MAC session key (16, 24, or 32 bytes).</param>
        /// <param name="data">The data to authenticate.</param>
        /// <returns>16-byte MAC or error.</returns>
        public static Result<byte[], SmartCardError> CalculateScp03CommandMac(
            byte[] sMacKey,
            byte[] data
        )
        {
            return CalculateScp03FullMac(sMacKey, data)
                .Map(fullMac => fullMac[..Scp.Scp03.MAC_SIZE]);
        }

        /// <summary>
        /// Calculates full 16-byte SCP03 MAC using AES-CMAC.
        /// Used for ICV chaining where the full MAC is required.
        /// Per GlobalPlatform SCP03 v1.1.1 Section 4.1.3.
        /// </summary>
        /// <param name="sMacKey">The S-MAC session key (16, 24, or 32 bytes).</param>
        /// <param name="data">The data to authenticate.</param>
        /// <returns>16-byte full MAC or error.</returns>
        public static Result<byte[], SmartCardError> CalculateScp03FullMac(
            byte[] sMacKey,
            byte[] data
        )
        {
            return Validation
                .ValidateInputs(sMacKey, data)
                .Bind(
                    () =>
                        Validation.ValidateKeyLength(
                            sMacKey,
                            [16, 24, 32],
                            "SCP03 S-MAC key must be 16, 24, or 32 bytes"
                        )
                )
                .Bind(
                    () =>
                        Result.Try(
                            () =>
                            {
                                var cmac = new CMac(
                                    new AesEngine(),
                                    Scp.Common.AES_CMAC_BLOCK_BITS
                                );
                                cmac.Init(new KeyParameter(sMacKey));
                                cmac.BlockUpdate(data, 0, data.Length);

                                byte[] fullMac = new byte[Scp.Scp03.FULL_MAC_SIZE];
                                cmac.DoFinal(fullMac, 0);

                                return fullMac;
                            },
                            ex =>
                                SmartCardError.CryptographicError(
                                    $"SCP03 MAC calculation failed: {ex.Message}"
                                )
                        )
                );
        }

        /// <summary>
        /// Calculates SCP03 Response MAC using AES-CMAC.
        /// Per GlobalPlatform SCP03 v1.1.1 Section 4.1.3 and 6.2.5.
        /// </summary>
        /// <param name="sMacKey">The S-MAC session key (16, 24, or 32 bytes).</param>
        /// <param name="data">The data to authenticate.</param>
        /// <returns>16-byte MAC or error.</returns>
        public static Result<byte[], SmartCardError> CalculateScp03ResponseMac(
            byte[] sMacKey,
            byte[] data
        )
        {
            return Validation
                .ValidateInputs(sMacKey, data)
                .Bind(
                    () =>
                        Validation.ValidateKeyLength(
                            sMacKey,
                            [16, 24, 32],
                            "SCP03 S-MAC key must be 16, 24, or 32 bytes"
                        )
                )
                .Bind(
                    () =>
                        Result.Try(
                            () =>
                            {
                                var cmac = new CMac(
                                    new AesEngine(),
                                    Scp.Common.AES_CMAC_BLOCK_BITS
                                );
                                cmac.Init(new KeyParameter(sMacKey));
                                cmac.BlockUpdate(data, 0, data.Length);

                                byte[] fullMac = new byte[Scp.Scp03.FULL_MAC_SIZE];
                                cmac.DoFinal(fullMac, 0);

                                return fullMac[..Scp.Scp03.MAC_SIZE];
                            },
                            ex =>
                                SmartCardError.CryptographicError(
                                    $"SCP03 Response MAC calculation failed: {ex.Message}"
                                )
                        )
                );
        }

        /// <summary>
        /// Encrypts ICV for SCP02 MAC chaining per GP Card Specification v2.3.1 Section E.3.4.
        /// "As an enhancement to the C-MAC mechanism, the ICV is encrypted before being applied
        /// to the calculation of the next C-MAC. The encryption mechanism used is single DES
        /// with the first half of the Secure Channel C-MAC session key."
        /// </summary>
        /// <param name="icv">The 8-byte ICV to encrypt.</param>
        /// <param name="sMacKey">The S-MAC session key (16 or 24 bytes).</param>
        /// <returns>8-byte encrypted ICV or error.</returns>
        public static Result<byte[], SmartCardError> EncryptScp02Icv(byte[] icv, byte[] sMacKey)
        {
            return Validation
                .ValidateInputs(icv, sMacKey)
                .Bind(() => Validation.ValidateExactLength(icv, 8, "ICV"))
                .Bind(
                    () =>
                        Validation.ValidateKeyLength(
                            sMacKey,
                            [16, 24],
                            "SCP02 S-MAC key must be 16 or 24 bytes"
                        )
                )
                .Bind(
                    () =>
                        Result.Try(
                            () =>
                            {
                                // Use single DES with first 8 bytes of MAC key
                                byte[] truncatedKey = sMacKey.Take(8).ToArray();
                                DesParameters.SetOddParity(truncatedKey);

                                // Use ECB mode for single block encryption (no IV needed)
                                var cipher = new DesEngine();
                                cipher.Init(true, new DesParameters(truncatedKey));

                                byte[] encryptedIcv = new byte[8];
                                cipher.ProcessBlock(icv, 0, encryptedIcv, 0);

                                return encryptedIcv;
                            },
                            ex =>
                                SmartCardError.CryptographicError(
                                    $"ICV encryption failed: {ex.Message}"
                                )
                        )
                );
        }

        /// <summary>
        /// Calculates the Initial Chaining Vector (ICV) from MAC over AID for implicit mode implementations.
        /// Per GP Section E.3.3: "When using implicit Secure Channel Session initiation, the ICV shall be
        /// a MAC computed on the AID of the selected Application."
        /// </summary>
        /// <param name="selectedAid">The AID of the selected application</param>
        /// <param name="cMacSessionKey">The 16-byte C-MAC session key</param>
        /// <param name="implementation">The SCP02 implementation parameter</param>
        /// <returns>Result containing the 8-byte ICV calculated from AID MAC</returns>
        public static Result<byte[], SmartCardError> CalculateIcvFromAidMac(
            byte[] selectedAid,
            byte[] cMacSessionKey,
            ScpImplementation implementation
        )
        {
            return Maybe<byte[]>
                .From(selectedAid)
                .ToResult(SmartCardError.InvalidArgument("Selected AID required"))
                .Bind(_ =>
                    Maybe<byte[]>
                        .From(cMacSessionKey)
                        .ToResult(SmartCardError.InvalidArgument("C-MAC session key required"))
                )
                .Bind(_ =>
                    cMacSessionKey.Length == 16
                        ? Result.Success<byte[], SmartCardError>(cMacSessionKey)
                        : Result.Failure<byte[], SmartCardError>(
                            SmartCardError.InvalidArgument(
                                "C-MAC session key must be 16 bytes for SCP02"
                            )
                        )
                )
                .Bind(_ =>
                    // This method is specifically for SCP02 MAC-over-AID calculation
                    // The caller must ensure this is used only with SCP02
                    implementation.HasMacOverAid()
                        ? Result.Success<ScpImplementation, SmartCardError>(implementation)
                        : Result.Failure<ScpImplementation, SmartCardError>(
                            SmartCardError.InvalidArgument(
                                "Implementation does not support MAC over AID (i-param bit 4)"
                            )
                        )
                )
                .Bind(_ => Utils.ApplyGpPadding(selectedAid))
                .Bind(paddedAid => CalculateMacOverPaddedData(paddedAid, cMacSessionKey));
        }

        /// <summary>
        /// Calculates 3DES MAC over the padded AID using ISO 9797-1 Algorithm 3.
        /// Uses zero ICV for the MAC calculation per GP specification.
        /// </summary>
        private static Result<byte[], SmartCardError> CalculateMacOverPaddedData(
            byte[] paddedData,
            byte[] macKey
        )
        {
            return Result.Try(
                () =>
                {
                    var engine = new DesEngine();
                    var desMac = new ISO9797Alg3Mac(engine);
                    desMac.Init(new KeyParameter(macKey));

                    desMac.BlockUpdate(paddedData, 0, paddedData.Length);

                    byte[] mac = new byte[8];
                    desMac.DoFinal(mac, 0);

                    return mac;
                },
                ex => SmartCardError.CryptographicError($"AID MAC calculation failed: {ex.Message}")
            );
        }
    }
}
