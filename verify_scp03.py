#!/usr/bin/env python3
"""Verify SCP03 cryptogram calculation matches C# implementation"""

from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC

def scp03_kdf(base_key, derivation_constant, context, output_length_bits):
    """SCP03 Key Derivation Function per GP SCP03 v1.1.1 Section 4.1.5"""
    output_length_bytes = output_length_bits // 8
    derived_key = b''
    counter = 1
    
    while len(derived_key) < output_length_bytes:
        # Build input: counter || label || separator || L || context
        # Counter: 1 byte
        # Label: 11 bytes of 0x00
        # Derivation constant: 1 byte  
        # Separator: 1 byte (0x00)
        # L: 2 bytes (output length in bits, big-endian)
        # Context: 16 bytes
        kdf_input = (
            counter.to_bytes(1, 'big') +
            b'\x00' * 11 +
            derivation_constant.to_bytes(1, 'big') +
            b'\x00' +
            output_length_bits.to_bytes(2, 'big') +
            context
        )
        
        # AES-CMAC with base key
        cmac = CMAC.new(base_key, ciphermod=AES)
        cmac.update(kdf_input)
        derived_key += cmac.digest()
        counter += 1
    
    return derived_key[:output_length_bytes]

# Test vector from C# debug
base_mac_key = bytes.fromhex("101112131415161718191A1B1C1D1E1F")
host_challenge = bytes.fromhex("0001020304050607")
card_challenge = bytes.fromhex("08090A0B0C0D0E0F")
context = host_challenge + card_challenge

# Derive S-MAC
s_mac = scp03_kdf(base_mac_key, 0x06, context, 128)
print(f"S-MAC:           {s_mac.hex().upper()}")
print(f"Expected S-MAC:  E792DFFE94F89EB1407A797103A6CBEC")
print(f"S-MAC match:     {s_mac.hex().upper() == 'E792DFFE94F89EB1407A797103A6CBEC'}")
print()

# Derive card cryptogram using S-MAC
card_cryptogram = scp03_kdf(s_mac, 0x00, context, 64)
print(f"Card cryptogram: {card_cryptogram.hex().upper()}")
print(f"Expected:        DA6BE6D6F781BCF7")
print(f"Match:           {card_cryptogram.hex().upper() == 'DA6BE6D6F781BCF7'}")