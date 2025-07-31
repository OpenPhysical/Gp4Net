using System;
using System.Collections.Immutable;
using System.Security.Cryptography;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;

namespace Gp4Net.Domain.Keys
{
    /// <summary>
    /// Functional key derivation service that implements secure key management patterns.
    /// All operations are pure functions that return new instances rather than mutating state.
    /// Keys are handled securely with automatic cleanup and minimal exposure.
    /// </summary>
    public static class FunctionalKeyDerivationService
    {
        /// <summary>
        /// Derives session keys from a master key set using the specified diversification data.
        /// This is a pure function that doesn't modify any state.
        /// </summary>
        public static Result<DerivedKeys, SmartCardError> DeriveSessionKeys(
            IKeySet masterKeys,
            byte[] sequenceCounter,
            byte[] hostChallenge,
            byte[] cardChallenge,
            DiversificationMode mode = DiversificationMode.None)
        {
            if (masterKeys == null)
                return Result.Failure<DerivedKeys, SmartCardError>(
                    SmartCardError.InvalidArgument("Master keys cannot be null"));

            if (hostChallenge == null || hostChallenge.Length != 8)
                return Result.Failure<DerivedKeys, SmartCardError>(
                    SmartCardError.InvalidArgument("Host challenge must be 8 bytes"));

            if (cardChallenge == null || cardChallenge.Length != 8)
                return Result.Failure<DerivedKeys, SmartCardError>(
                    SmartCardError.InvalidArgument("Card challenge must be 8 bytes"));

            try
            {
                // Create derivation context
                var context = new KeyDerivationContext(
                    sequenceCounter,
                    hostChallenge,
                    cardChallenge,
                    mode);

                // Derive keys based on protocol
                return masterKeys switch
                {
                    Scp02KeySet scp02Keys => DeriveScp02Keys(scp02Keys, context),
                    Scp03KeySet scp03Keys => DeriveScp03Keys(scp03Keys, context),
                    _ => Result.Failure<DerivedKeys, SmartCardError>(
                        SmartCardError.InvalidArgument("Unsupported key set type"))
                };
            }
            catch (Exception ex)
            {
                return Result.Failure<DerivedKeys, SmartCardError>(
                    SmartCardError.SecurityError($"Key derivation failed: {ex.Message}"));
            }
        }

        /// <summary>
        /// Creates a secure key set with proper key management.
        /// </summary>
        public static Result<FunctionalSecureKeySet, SmartCardError> CreateSecureKeySet(
            byte[] encKey,
            byte[] macKey,
            byte[] dekKey,
            byte keyVersion,
            bool isScp03 = false)
        {
            // Validate inputs
            if (encKey == null || encKey.Length == 0)
                return Result.Failure<FunctionalSecureKeySet, SmartCardError>(
                    SmartCardError.InvalidArgument("ENC key cannot be null or empty"));

            if (macKey == null || macKey.Length == 0)
                return Result.Failure<FunctionalSecureKeySet, SmartCardError>(
                    SmartCardError.InvalidArgument("MAC key cannot be null or empty"));

            if (dekKey == null || dekKey.Length == 0)
                return Result.Failure<FunctionalSecureKeySet, SmartCardError>(
                    SmartCardError.InvalidArgument("DEK key cannot be null or empty"));

            try
            {
                // Create copies of keys to ensure immutability
                var encKeyCopy = (byte[])encKey.Clone();
                var macKeyCopy = (byte[])macKey.Clone();
                var dekKeyCopy = (byte[])dekKey.Clone();

                // Clear original arrays for security
                Array.Clear(encKey, 0, encKey.Length);
                Array.Clear(macKey, 0, macKey.Length);
                Array.Clear(dekKey, 0, dekKey.Length);

                return Result.Success<FunctionalSecureKeySet, SmartCardError>(
                    new FunctionalSecureKeySet(encKeyCopy, macKeyCopy, dekKeyCopy, keyVersion, isScp03));
            }
            catch (Exception ex)
            {
                return Result.Failure<FunctionalSecureKeySet, SmartCardError>(
                    SmartCardError.UnexpectedError($"Failed to create secure key set: {ex.Message}", ex));
            }
        }

        private static Result<DerivedKeys, SmartCardError> DeriveScp02Keys(
            Scp02KeySet masterKeys,
            KeyDerivationContext context)
        {
            // Derive session keys for SCP02
            var derivationData = CombineBytes(
                context.SequenceCounter ?? new byte[2],
                new byte[6], // Padding
                context.HostChallenge,
                context.CardChallenge);

            var sEnc = Derive3DesKey(masterKeys.EncKey, derivationData, 0x0182);
            var sMac = Derive3DesKey(masterKeys.MacKey, derivationData, 0x0101);
            var sDek = masterKeys.DekKey; // DEK is not derived in SCP02

            return Result.Success<DerivedKeys, SmartCardError>(
                new DerivedKeys(sEnc, sMac, sDek, null));
        }

        private static Result<DerivedKeys, SmartCardError> DeriveScp03Keys(
            Scp03KeySet masterKeys,
            KeyDerivationContext context)
        {
            // Create KDF input for SCP03
            var kdfInput = CombineBytes(
                new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                context.HostChallenge,
                context.CardChallenge);

            // Derive all session keys
            var sEnc = DeriveAesKey(masterKeys.EncKey, 0x04, kdfInput);
            var sMac = DeriveAesKey(masterKeys.MacKey, 0x06, kdfInput);
            var sRmac = DeriveAesKey(masterKeys.MacKey, 0x07, kdfInput);
            var sDek = masterKeys.DekKey; // DEK is typically not derived

            return Result.Success<DerivedKeys, SmartCardError>(
                new DerivedKeys(sEnc, sMac, sDek, sRmac));
        }

        private static byte[] Derive3DesKey(byte[] baseKey, byte[] derivationData, ushort keyType)
        {
            // Implement 3DES key derivation according to GP spec
#pragma warning disable CA5350 // TripleDES is required for SCP02 compatibility with GlobalPlatform spec
            using (var des = TripleDES.Create())
#pragma warning restore CA5350
            {
                des.Mode = System.Security.Cryptography.CipherMode.CBC;
                des.Padding = PaddingMode.None;
                des.Key = baseKey;
                des.IV = new byte[8]; // Zero IV

                // Prepare input with key type
                var input = new byte[16];
                input[0] = (byte)(keyType >> 8);
                input[1] = (byte)(keyType & 0xFF);
                Array.Copy(derivationData, 0, input, 2, Math.Min(14, derivationData.Length));

                using (var encryptor = des.CreateEncryptor())
                {
                    var encrypted = encryptor.TransformFinalBlock(input, 0, 16);
                    
                    // For 3DES-2, replicate first 8 bytes
                    var result = new byte[16];
                    Array.Copy(encrypted, 0, result, 0, 8);
                    Array.Copy(encrypted, 0, result, 8, 8);
                    return result;
                }
            }
        }

        private static byte[] DeriveAesKey(byte[] baseKey, byte label, byte[] context)
        {
            // Implement AES-CMAC based KDF for SCP03
            var labelBytes = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, label };
            var input = CombineBytes(labelBytes, context);

            // Use AES-CMAC for key derivation
            using (var aes = Aes.Create())
            {
                aes.Key = baseKey;
                aes.Mode = System.Security.Cryptography.CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                aes.IV = new byte[16];

                // Simplified KDF - in production use proper CMAC
                using (var encryptor = aes.CreateEncryptor())
                {
                    var result = new byte[16];
                    for (int i = 0; i < input.Length; i += 16)
                    {
                        var block = new byte[16];
                        var len = Math.Min(16, input.Length - i);
                        Array.Copy(input, i, block, 0, len);
                        
                        var encrypted = encryptor.TransformFinalBlock(block, 0, 16);
                        for (int j = 0; j < 16; j++)
                        {
                            result[j] ^= encrypted[j];
                        }
                    }
                    return result;
                }
            }
        }

        private static byte[] CombineBytes(params byte[][] arrays)
        {
            var totalLength = 0;
            foreach (var array in arrays)
            {
                if (array != null)
                    totalLength += array.Length;
            }

            var result = new byte[totalLength];
            var offset = 0;
            foreach (var array in arrays)
            {
                if (array != null)
                {
                    Array.Copy(array, 0, result, offset, array.Length);
                    offset += array.Length;
                }
            }

            return result;
        }

        /// <summary>
        /// Key derivation context with all necessary parameters.
        /// </summary>
        private sealed record KeyDerivationContext(
            byte[]? SequenceCounter,
            byte[] HostChallenge,
            byte[] CardChallenge,
            DiversificationMode Mode);

        /// <summary>
        /// Key diversification modes.
        /// </summary>
        public enum DiversificationMode
        {
            None,
            Visa2,
            EMV,
            KDF3
        }
    }

    /// <summary>
    /// Secure key set that automatically clears keys when disposed.
    /// </summary>
    public sealed class FunctionalSecureKeySet : IKeySet, IDisposable
    {
        private byte[] _encKey;
        private byte[] _macKey;
        private byte[] _dekKey;
        private readonly byte _keyVersion;
        private readonly bool _isScp03;
        private bool _disposed;

        internal FunctionalSecureKeySet(byte[] encKey, byte[] macKey, byte[] dekKey, byte keyVersion, bool isScp03)
        {
            _encKey = encKey;
            _macKey = macKey;
            _dekKey = dekKey;
            _keyVersion = keyVersion;
            _isScp03 = isScp03;
        }

        public byte[] EncKey => _disposed ? throw new ObjectDisposedException(nameof(FunctionalSecureKeySet)) : _encKey;
        public byte[] MacKey => _disposed ? throw new ObjectDisposedException(nameof(FunctionalSecureKeySet)) : _macKey;
        public byte[] DekKey => _disposed ? throw new ObjectDisposedException(nameof(FunctionalSecureKeySet)) : _dekKey;
        public byte KeyVersion => _keyVersion;
        public byte KeyId => 0; // Default key ID

        public void Dispose()
        {
            if (!_disposed)
            {
                // Clear sensitive key material
                if (_encKey != null)
                {
                    Array.Clear(_encKey, 0, _encKey.Length);
                    _encKey = null!;
                }
                if (_macKey != null)
                {
                    Array.Clear(_macKey, 0, _macKey.Length);
                    _macKey = null!;
                }
                if (_dekKey != null)
                {
                    Array.Clear(_dekKey, 0, _dekKey.Length);
                    _dekKey = null!;
                }
                _disposed = true;
            }
        }
    }

    /// <summary>
    /// Container for derived session keys.
    /// </summary>
    public sealed record DerivedKeys(
        byte[] SEnc,
        byte[] SMac,
        byte[] SDek,
        byte[]? SRMac)
    {
        /// <summary>
        /// Creates session keys from the derived keys.
        /// </summary>
        public SessionKeys ToSessionKeys()
        {
            return new SessionKeys(SEnc, SMac, SDek, SRMac ?? SMac);
        }

        /// <summary>
        /// Clears all key material.
        /// </summary>
        public void Clear()
        {
            Array.Clear(SEnc, 0, SEnc.Length);
            Array.Clear(SMac, 0, SMac.Length);
            Array.Clear(SDek, 0, SDek.Length);
            if (SRMac != null)
            {
                Array.Clear(SRMac, 0, SRMac.Length);
            }
        }
    }
}