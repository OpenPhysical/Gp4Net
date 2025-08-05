#!/usr/bin/env python3
"""
Verify KDF structure matches between Python reference and C# implementation.
This helps catch off-by-one errors and structural mismatches.
"""

import sys
import os
from binascii import hexlify, unhexlify
from struct import pack, unpack

# We'll implement the KDF and CMAC functions directly here to avoid Python 2/3 issues
from Cryptodome.Cipher import AES

# DDC constants from SCP03.py
class DDC:
    CardCrypto = 0x00
    HostCrypto = 0x01
    CardChallenge = 0x02
    S_ENC = 0x04
    S_MAC = 0x06
    S_RMAC = 0x07

def CMAC(key, data):
    """Calculate CMAC using AES as underlaying cipher (Python 3 version)"""
    from Cryptodome.Hash import CMAC as CryptoCMAC
    from Cryptodome.Cipher import AES
    
    if isinstance(data, str):
        data = data.encode('latin-1')
    
    cmac = CryptoCMAC.new(key, ciphermod=AES)
    cmac.update(data)
    return cmac.digest()

def KDF(key, const, L, context):
    """Key derivation scheme as defined in [GP AmD] 4.1.5 (Python 3 version)"""
    nbl = (L + 127) // 128
    res = b''
    for i in range(1, nbl+1):
        # Build data exactly as in SCP03.py line 126
        data = b'\0'*11 + pack(">BBHB", const, 0, L, i) + context
        res += CMAC(key, data)
    BL = L // 8
    return res[:BL]

def print_hex(label, data):
    """Print hex data with label"""
    if isinstance(data, str):
        data = data.encode('latin-1')
    print(f"{label}: {hexlify(data).decode().upper()}")
    
def analyze_kdf_input(key, const, L, context):
    """Analyze the exact structure of KDF input"""
    print("\n=== KDF Input Structure Analysis ===")
    print(f"Key length: {len(key)} bytes")
    print(f"Derivation constant: 0x{const:02X}")
    print(f"Output length: {L} bits ({L//8} bytes)")
    print(f"Context length: {len(context)} bytes")
    
    # Build the KDF input as per line 126 in SCP03.py
    # data = '\0'*11 + pack(">BBHB", const, 0, L, i) + context
    
    for i in range(1, 2):  # Just show first block
        data = b'\0'*11 + pack(">BBHB", const, 0, L, i) + context
        
        print(f"\nKDF Input Block {i}:")
        offset = 0
        
        # Label (11 bytes of 0x00)
        label_bytes = data[offset:offset+11]
        print_hex(f"  Label (11 bytes)", label_bytes)
        offset += 11
        
        # Derivation constant
        const_byte = data[offset:offset+1]
        print_hex(f"  Derivation Constant (1 byte)", const_byte)
        offset += 1
        
        # Separator (0x00)
        sep_byte = data[offset:offset+1]
        print_hex(f"  Separator (1 byte)", sep_byte)
        offset += 1
        
        # Length (2 bytes, big-endian)
        length_bytes = data[offset:offset+2]
        print_hex(f"  Length in bits (2 bytes)", length_bytes)
        print(f"    Decoded: {unpack('>H', length_bytes)[0]} bits")
        offset += 2
        
        # Counter (1 byte)
        counter_byte = data[offset:offset+1]
        print_hex(f"  Counter i (1 byte)", counter_byte)
        offset += 1
        
        # Context
        context_bytes = data[offset:]
        print_hex(f"  Context ({len(context_bytes)} bytes)", context_bytes)
        
        print(f"\nTotal KDF input length: {len(data)} bytes")
        print_hex("Complete KDF input", data)
        
        # Calculate CMAC for this block
        cmac_result = CMAC(key, data)
        print_hex("CMAC output (16 bytes)", cmac_result)
        
        # For cryptograms, we only take 8 bytes
        if L == 64:
            print_hex("Truncated output (8 bytes)", cmac_result[:8])

def test_scp03_cryptogram_derivation():
    """Test SCP03 cryptogram derivation with known test vectors"""
    print("\n=== SCP03 Cryptogram Derivation Test ===")
    
    # Test vector 1: Sequential pattern keys
    static_enc = unhexlify("000102030405060708090A0B0C0D0E0F")
    static_mac = unhexlify("101112131415161718191A1B1C1D1E1F")
    host_challenge = unhexlify("0001020304050607")
    card_challenge = unhexlify("08090A0B0C0D0E0F")
    
    # Context for all derivations
    context = host_challenge + card_challenge
    print_hex("Host Challenge", host_challenge)
    print_hex("Card Challenge", card_challenge)
    print_hex("Context (Host||Card)", context)
    
    # Derive S-MAC first (needed for cryptograms)
    print("\n--- S-MAC Derivation ---")
    s_mac = KDF(static_mac, DDC.S_MAC, 128, context)
    print_hex("S-MAC", s_mac)
    analyze_kdf_input(static_mac, DDC.S_MAC, 128, context)
    
    # Derive Card Cryptogram using S-MAC
    print("\n--- Card Cryptogram Derivation ---")
    card_cryptogram = KDF(s_mac, DDC.CardCrypto, 64, context)
    print_hex("Card Cryptogram", card_cryptogram)
    analyze_kdf_input(s_mac, DDC.CardCrypto, 64, context)
    
    # Derive Host Cryptogram using S-MAC
    print("\n--- Host Cryptogram Derivation ---")
    host_cryptogram = KDF(s_mac, DDC.HostCrypto, 64, context)
    print_hex("Host Cryptogram", host_cryptogram)
    analyze_kdf_input(s_mac, DDC.HostCrypto, 64, context)

def generate_c_sharp_test_case():
    """Generate C# test case code"""
    print("\n=== C# Test Case ===")
    print("""
// Verify KDF input structure matches Python exactly
[Test]
public void VerifyKdfInputStructure()
{
    // Test vector
    var staticMac = Convert.FromHexString("101112131415161718191A1B1C1D1E1F");
    var hostChallenge = Convert.FromHexString("0001020304050607");
    var cardChallenge = Convert.FromHexString("08090A0B0C0D0E0F");
    var context = hostChallenge.Concat(cardChallenge).ToArray();
    
    // Expected S-MAC KDF input for first block (i=1)
    var expectedInput = new byte[] {
        // Label (11 bytes of 0x00)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Derivation constant (S_MAC = 0x06)
        0x06,
        // Separator
        0x00,
        // Length in bits (128 = 0x0080)
        0x00, 0x80,
        // Counter (i = 1)
        0x01,
        // Context (16 bytes)
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,  // Host challenge
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F   // Card challenge
    };
    
    // Your KDF implementation should produce this exact input
    // before passing it to CMAC
}
""")

if __name__ == "__main__":
    print("SCP03 KDF Structure Verification Tool")
    print("=====================================")
    
    test_scp03_cryptogram_derivation()
    generate_c_sharp_test_case()