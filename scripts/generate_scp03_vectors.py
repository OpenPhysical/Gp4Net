#!/usr/bin/env python3
"""
Generate SCP03 test vectors from the reference implementation.
"""

from binascii import hexlify, unhexlify
from struct import pack
from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC as CryptoCMAC

# DDC constants from SCP03.py
class DDC:
    CardCrypto = 0x00
    HostCrypto = 0x01
    CardChallenge = 0x02
    S_ENC = 0x04
    S_MAC = 0x06
    S_RMAC = 0x07

def CMAC(key, data):
    """Calculate CMAC using AES"""
    if isinstance(data, str):
        data = data.encode('latin-1')
    
    cmac = CryptoCMAC.new(key, ciphermod=AES)
    cmac.update(data)
    return cmac.digest()

def KDF(key, const, L, context):
    """Key derivation scheme as defined in [GP AmD] 4.1.5"""
    nbl = (L + 127) // 128
    res = b''
    for i in range(1, nbl+1):
        # Build data exactly as in SCP03.py line 126
        data = b'\0'*11 + pack(">BBHB", const, 0, L, i) + context
        res += CMAC(key, data)
    BL = L // 8
    return res[:BL]

def generate_test_vector(name, static_enc, static_mac, static_dek, host_challenge, card_challenge):
    """Generate a complete test vector"""
    print(f"// {name}")
    print(f'StaticKeyEnc = Convert.FromHexString("{hexlify(static_enc).decode().upper()}");')
    print(f'StaticKeyMac = Convert.FromHexString("{hexlify(static_mac).decode().upper()}");')
    print(f'StaticKeyDek = Convert.FromHexString("{hexlify(static_dek).decode().upper()}");')
    print()
    print(f'HostChallenge = Convert.FromHexString("{hexlify(host_challenge).decode().upper()}");')
    print(f'CardChallenge = Convert.FromHexString("{hexlify(card_challenge).decode().upper()}");')
    print()
    
    # Context for all derivations
    context = host_challenge + card_challenge
    
    # Derive session keys
    s_enc = KDF(static_enc, DDC.S_ENC, 8*len(static_enc), context)
    s_mac = KDF(static_mac, DDC.S_MAC, 8*len(static_mac), context)
    s_rmac = KDF(static_mac, DDC.S_RMAC, 8*len(static_mac), context)
    
    print(f'ExpectedSEnc = Convert.FromHexString("{hexlify(s_enc).decode().upper()}");')
    print(f'ExpectedSMac = Convert.FromHexString("{hexlify(s_mac).decode().upper()}");')
    print(f'ExpectedSRMac = Convert.FromHexString("{hexlify(s_rmac).decode().upper()}");')
    print()
    
    # Derive cryptograms using S-MAC (not static MAC!)
    card_cryptogram = KDF(s_mac, DDC.CardCrypto, 64, context)
    host_cryptogram = KDF(s_mac, DDC.HostCrypto, 64, context)
    
    print(f'ExpectedCardCryptogram = Convert.FromHexString("{hexlify(card_cryptogram).decode().upper()}");')
    print(f'ExpectedHostCryptogram = Convert.FromHexString("{hexlify(host_cryptogram).decode().upper()}");')
    print()

def main():
    print("# SCP03 Test Vectors - Generated from reference implementation")
    print("# These match the Python SCP03.py implementation exactly")
    print()
    
    # Test Vector 1: Sequential Pattern Keys
    generate_test_vector(
        "Test Vector 1: Sequential Pattern Keys",
        static_enc=unhexlify("000102030405060708090A0B0C0D0E0F"),
        static_mac=unhexlify("101112131415161718191A1B1C1D1E1F"),
        static_dek=unhexlify("202122232425262728292A2B2C2D2E2F"),
        host_challenge=unhexlify("0001020304050607"),
        card_challenge=unhexlify("08090A0B0C0D0E0F")
    )
    
    # Test Vector 2: All-Zeros Baseline
    generate_test_vector(
        "Test Vector 2: All-Zeros Baseline", 
        static_enc=unhexlify("00000000000000000000000000000000"),
        static_mac=unhexlify("00000000000000000000000000000000"),
        static_dek=unhexlify("00000000000000000000000000000000"),
        host_challenge=unhexlify("0000000000000000"),
        card_challenge=unhexlify("0000000000000000")
    )
    
    # Test Vector 3: From test unit test 128
    generate_test_vector(
        "Test Vector 3: From SCP03.py Test128",
        static_enc=unhexlify("404142434445464748494A4B4C4D4E4F"), # '@ABCDEFGHIJKLMNO'
        static_mac=unhexlify("401122334445566748494A4B4C4D4E4F"), # 16 bytes
        static_dek=unhexlify("9876543210404142434445464748494A"), # Mixed
        host_challenge=unhexlify("0807060504030201"),
        card_challenge=unhexlify("A3F5F144D19BE66E")
    )

if __name__ == "__main__":
    main()