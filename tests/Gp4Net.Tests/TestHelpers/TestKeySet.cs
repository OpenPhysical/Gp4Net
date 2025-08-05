using System;
using Gp4Net.Domain.Keys;
using CSharpFunctionalExtensions;

namespace Gp4Net.Tests.TestHelpers;

/// <summary>
/// Simple concrete implementation of IKeySet for testing purposes.
/// </summary>
internal class TestKeySet : IKeySet
{
    private readonly byte[] _encKey;
    private readonly byte[] _macKey;
    private readonly byte[] _dekKey;

    public TestKeySet(byte[] encKey, byte[] macKey, byte[] dekKey, byte keyVersion, byte keyId = 0)
    {
        _encKey = (byte[])encKey.Clone();
        _macKey = (byte[])macKey.Clone();
        _dekKey = (byte[])dekKey.Clone();
        KeyVersion = keyVersion;
        KeyId = keyId;
    }

    public byte KeyVersion { get; }
    public byte KeyId { get; }
    public byte[] EncKey => (byte[])_encKey.Clone();
    public byte[] MacKey => (byte[])_macKey.Clone();
    public byte[] DekKey => (byte[])_dekKey.Clone();

    public void Dispose()
    {
        // Clear keys from memory
        Array.Clear(_encKey, 0, _encKey.Length);
        Array.Clear(_macKey, 0, _macKey.Length);
        Array.Clear(_dekKey, 0, _dekKey.Length);
    }
}