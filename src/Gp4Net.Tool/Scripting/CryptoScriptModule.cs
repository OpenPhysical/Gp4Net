using System;
using Gp4Net.Domain.Protocol;
using JetBrains.Annotations;
using MoonSharp.Interpreter;
using MoonSharp.Interpreter.Interop;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Gp4Net.Tool.Scripting;

/// <summary>
/// Provides cryptographic operations to Lua scripts.
/// </summary>
[PublicAPI]
[MoonSharpUserData]
public class CryptoScriptModule
{
    /// <summary>
    /// DES ECB encryption.
    /// </summary>
    [MoonSharpVisible(true)]
    public static byte[] DesEcb(byte[] key, byte[] data)
    {
        if (key.Length != 8)
        {
            throw new ArgumentException("DES key must be 8 bytes");
        }

        var engine = new DesEngine();
        engine.Init(true, new KeyParameter(key));

        var output = new byte[data.Length];
        for (var i = 0; i < data.Length; i += 8)
        {
            _ = engine.ProcessBlock(data, i, output, i);
        }

        return output;
    }

    /// <summary>
    /// DES CBC encryption.
    /// </summary>
    [MoonSharpVisible(true)]
    public static byte[] DesCbc(byte[] key, byte[] iv, byte[] data)
    {
        if (key.Length != 8)
        {
            throw new ArgumentException("DES key must be 8 bytes");
        }

        if (iv.Length != 8)
        {
            throw new ArgumentException("DES IV must be 8 bytes");
        }

        var cipher = new CbcBlockCipher(new DesEngine());
        cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

        var output = new byte[data.Length];
        for (var i = 0; i < data.Length; i += 8)
        {
            _ = cipher.ProcessBlock(data, i, output, i);
        }

        return output;
    }

    /// <summary>
    /// 3DES ECB encryption.
    /// </summary>
    [MoonSharpVisible(true)]
    public static byte[] Des3Ecb(byte[] key, byte[] data)
    {
        if (key.Length != 16 && key.Length != 24)
        {
            throw new ArgumentException("3DES key must be 16 or 24 bytes");
        }

        // Expand 16-byte key to 24 bytes if needed
        if (key.Length == 16)
        {
            key = CryptographicOperations.ExpandTripleDesKey(key);
        }

        var engine = new DesEdeEngine();
        engine.Init(true, new KeyParameter(key));

        var output = new byte[data.Length];
        for (var i = 0; i < data.Length; i += 8)
        {
            _ = engine.ProcessBlock(data, i, output, i);
        }

        return output;
    }

    /// <summary>
    /// 3DES CBC encryption.
    /// </summary>
    [MoonSharpVisible(true)]
    public static byte[] Des3Cbc(byte[] key, byte[] iv, byte[] data)
    {
        if (key.Length != 16 && key.Length != 24)
        {
            throw new ArgumentException("3DES key must be 16 or 24 bytes");
        }

        if (iv.Length != 8)
        {
            throw new ArgumentException("3DES IV must be 8 bytes");
        }

        // Expand 16-byte key to 24 bytes if needed
        if (key.Length == 16)
        {
            key = CryptographicOperations.ExpandTripleDesKey(key);
        }

        var cipher = new CbcBlockCipher(new DesEdeEngine());
        cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

        var output = new byte[data.Length];
        for (var i = 0; i < data.Length; i += 8)
        {
            _ = cipher.ProcessBlock(data, i, output, i);
        }

        return output;
    }

    /// <summary>
    /// AES ECB encryption.
    /// </summary>
    [MoonSharpVisible(true)]
    public static byte[] AesEcb(byte[] key, byte[] data)
    {
        if (key.Length != 16 && key.Length != 24 && key.Length != 32)
        {
            throw new ArgumentException("AES key must be 16, 24, or 32 bytes");
        }

        var engine = new AesEngine();
        engine.Init(true, new KeyParameter(key));

        var output = new byte[data.Length];
        for (var i = 0; i < data.Length; i += 16)
        {
            _ = engine.ProcessBlock(data, i, output, i);
        }

        return output;
    }

    /// <summary>
    /// AES CBC encryption.
    /// </summary>
    [MoonSharpVisible(true)]
    public static byte[] AesCbc(byte[] key, byte[] iv, byte[] data)
    {
        if (key.Length != 16 && key.Length != 24 && key.Length != 32)
        {
            throw new ArgumentException("AES key must be 16, 24, or 32 bytes");
        }

        if (iv.Length != 16)
        {
            throw new ArgumentException("AES IV must be 16 bytes");
        }

        var cipher = new CbcBlockCipher(new AesEngine());
        cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

        var output = new byte[data.Length];
        for (var i = 0; i < data.Length; i += 16)
        {
            _ = cipher.ProcessBlock(data, i, output, i);
        }

        return output;
    }

    /// <summary>
    /// CMAC with DES.
    /// </summary>
    [MoonSharpVisible(true)]
    public static byte[] CmacDes(byte[] key, byte[] data)
    {
        var mac = new CMac(new DesEngine(), 64);
        mac.Init(new KeyParameter(key));
        mac.BlockUpdate(data, 0, data.Length);

        var result = new byte[8];
        _ = mac.DoFinal(result, 0);

        return result;
    }

    /// <summary>
    /// CMAC with AES.
    /// </summary>
    [MoonSharpVisible(true)]
    public static byte[] CmacAes(byte[] key, byte[] data)
    {
        var mac = new CMac(new AesEngine(), 128);
        mac.Init(new KeyParameter(key));
        mac.BlockUpdate(data, 0, data.Length);

        var result = new byte[16];
        _ = mac.DoFinal(result, 0);

        return result;
    }

    /// <summary>
    /// ISO 9797-1 MAC Algorithm 3 (Retail MAC).
    /// </summary>
    [MoonSharpVisible(true)]
    public static byte[] Iso9797Mac(byte[] key, byte[] data)
    {
        // This is a simplified version - real implementation needs proper padding
        var engine = new DesEdeEngine();
        var mac = new ISO9797Alg3Mac(engine);
        mac.Init(new KeyParameter(key));
        mac.BlockUpdate(data, 0, data.Length);

        var result = new byte[8];
        _ = mac.DoFinal(result, 0);

        return result;
    }

    /// <summary>
    /// SHA-1 hash.
    /// </summary>
    [MoonSharpVisible(true)]
#pragma warning disable CA5350 // SHA1 required for legacy GlobalPlatform card compatibility
    public static byte[] Sha1(byte[] data)
    {
        var digest = new Sha1Digest();
        digest.BlockUpdate(data, 0, data.Length);
        var result = new byte[digest.GetDigestSize()];
        _ = digest.DoFinal(result, 0);
        return result;
    }
#pragma warning restore CA5350

    /// <summary>
    /// SHA-256 hash.
    /// </summary>
    [MoonSharpVisible(true)]
    public static byte[] Sha256(byte[] data)
    {
        var digest = new Sha256Digest();
        digest.BlockUpdate(data, 0, data.Length);
        var result = new byte[digest.GetDigestSize()];
        _ = digest.DoFinal(result, 0);
        return result;
    }

    /// <summary>
    /// SHA-384 hash.
    /// </summary>
    [MoonSharpVisible(true)]
    public static byte[] Sha384(byte[] data)
    {
        var digest = new Sha384Digest();
        digest.BlockUpdate(data, 0, data.Length);
        var result = new byte[digest.GetDigestSize()];
        _ = digest.DoFinal(result, 0);
        return result;
    }

    /// <summary>
    /// SHA-512 hash.
    /// </summary>
    [MoonSharpVisible(true)]
    public static byte[] Sha512(byte[] data)
    {
        var digest = new Sha512Digest();
        digest.BlockUpdate(data, 0, data.Length);
        var result = new byte[digest.GetDigestSize()];
        _ = digest.DoFinal(result, 0);
        return result;
    }

    /// <summary>
    /// Generate random bytes.
    /// </summary>
    [MoonSharpVisible(true)]
    public static byte[] RandomBytes(int length)
    {
        var random = new SecureRandom();
        var bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }
}