#!/usr/bin/env python3
"""
SCP03 Test Vector Generator
Correct AES-CMAC-based KDF per GlobalPlatform SCP03 v1.1.1 and NIST SP 800-108.
"""

from binascii import hexlify, unhexlify
from Cryptodome.Hash import CMAC
from Cryptodome.Cipher import AES
import struct


def scp03_kdf(key: bytes, deriv_constant: int, context: bytes, length_bits: int) -> bytes:
    """
    SCP03-compliant KDF per GP SCP03 v1.1.1 Section 4.1.5
    Uses NIST SP 800-108 KDF in counter mode with AES-CMAC as PRF
    
    Structure: label || separator || L || i || context
    Where:
      - label = 11 zero bytes || 1-byte derivation constant
      - separator = 0x00
      - L = 2-byte length in bits (big-endian)
      - i = 1-byte counter (0x01 for first block, 0x02 for second if needed)
      - context = concatenation of input data (e.g., challenges)
    """
    assert len(key) in {16, 24, 32}
    assert len(context) == 16
    assert length_bits in {64, 128, 192, 256}

    # Calculate number of blocks needed
    num_blocks = (length_bits + 127) // 128
    result = b''
    
    for i in range(1, num_blocks + 1):
        # Build input data according to GP spec
        label = b'\x00' * 11 + bytes([deriv_constant])
        separator = b'\x00'
        l_field = struct.pack('>H', length_bits)
        counter = bytes([i])
        
        # Concatenate in the correct order per spec
        input_data = label + separator + l_field + counter + context
        
        # Calculate CMAC
        c = CMAC.new(key, ciphermod=AES)
        c.update(input_data)
        result += c.digest()
    
    # Return only the requested number of bytes
    return result[:length_bits // 8]


def generate_scp03_vectors():
    """Generate SCP03 test vectors as structured JSON"""
    import json
    from datetime import datetime
    
    vectors = []
    
    test_data = [
        # (label, description, enc, mac, dek, host, card)
        (
            "Sequential Pattern Keys",
            "SCP03 with sequential pattern keys for testing per NIST SP800-108",
            unhexlify("000102030405060708090A0B0C0D0E0F"),
            unhexlify("101112131415161718191A1B1C1D1E1F"),
            unhexlify("202122232425262728292A2B2C2D2E2F"),
            unhexlify("0001020304050607"),
            unhexlify("08090A0B0C0D0E0F")
        ),
        (
            "All-Zeros Baseline",
            "SCP03 baseline test with all-zero keys and challenges",
            bytes(16), bytes(16), bytes(16),
            bytes(8), bytes(8)
        ),
        (
            "All 0xFF Keys and Challenges",
            "SCP03 test with all 0xFF pattern for boundary testing",
            bytes([0xFF] * 16), bytes([0xFF] * 16), bytes([0xFF] * 16),
            bytes([0xFF] * 8), bytes([0xFF] * 8)
        ),
        (
            "Mixed Patterns",
            "SCP03 test with mixed hex patterns",
            unhexlify("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"),
            unhexlify("B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"),
            unhexlify("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
            unhexlify("0123456789ABCDEF"),
            unhexlify("FEDCBA9876543210")
        ),
        (
            "Alternating 0xAA/0x55",
            "SCP03 test with alternating bit patterns",
            bytes([0xAA] * 16), bytes([0x55] * 16), bytes([0xAA] * 16),
            bytes([0x55] * 8), bytes([0xAA] * 8)
        )
    ]

    for label, description, base_enc, base_mac, base_dek, host_chal, card_chal in test_data:
        context = host_chal + card_chal

        s_enc = scp03_kdf(base_enc, 0x04, context, 128)
        s_mac = scp03_kdf(base_mac, 0x06, context, 128)
        s_rmac = scp03_kdf(base_mac, 0x07, context, 128)
        card_crypto = scp03_kdf(s_mac, 0x00, context, 64)
        host_crypto = scp03_kdf(s_mac, 0x01, context, 64)

        vectors.append({
            "name": label,
            "description": description,
            "static_keys": {
                "enc": hexlify(base_enc).decode().upper(),
                "mac": hexlify(base_mac).decode().upper(),
                "dek": hexlify(base_dek).decode().upper()
            },
            "challenges": {
                "host": hexlify(host_chal).decode().upper(),
                "card": hexlify(card_chal).decode().upper()
            },
            "expected_session_keys": {
                "s_enc": hexlify(s_enc).decode().upper(),
                "s_mac": hexlify(s_mac).decode().upper(),
                "s_rmac": hexlify(s_rmac).decode().upper()
            },
            "expected_cryptograms": {
                "card": hexlify(card_crypto).decode().upper(),
                "host": hexlify(host_crypto).decode().upper()
            }
        })
    
    # Output final JSON structure
    output = {
        "protocol": "SCP03",
        "source": "scripts/SCP03_minimal.py",
        "description": "SCP03 test vectors per GlobalPlatform SCP03 v1.1.1 and NIST SP800-108",
        "generated_at": datetime.now().isoformat(),
        "key_derivation": {
            "algorithm": "AES-CMAC KDF",
            "standard": "NIST SP 800-108",
            "constants": {
                "s_enc": "0x04",
                "s_mac": "0x06", 
                "s_rmac": "0x07",
                "card_cryptogram": "0x00",
                "host_cryptogram": "0x01"
            }
        },
        "vectors": vectors
    }
    
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    generate_scp03_vectors()
