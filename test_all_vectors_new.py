#!/usr/bin/env python3
"""Test all SCP03 vectors"""

import json
from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC

def scp03_kdf(base_key, derivation_constant, context, output_length_bits):
    """SCP03 Key Derivation Function per GP SCP03 v1.1.1 Section 4.1.5"""
    output_length_bytes = output_length_bits // 8
    derived_key = b''
    counter = 1
    
    while len(derived_key) < output_length_bytes:
        # Build input: counter || label || separator || L || context
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

# Load test vectors
with open('scripts/scp03_test_vectors.json') as f:
    data = json.load(f)

print("Testing all SCP03 vectors...")
print()

for vec in data['vectors']:
    print(f"Test: {vec['name']}")
    
    base_mac_key = bytes.fromhex(vec['static_keys']['mac'])
    host_challenge = bytes.fromhex(vec['challenges']['host'])
    card_challenge = bytes.fromhex(vec['challenges']['card'])
    context = host_challenge + card_challenge
    
    # Derive S-MAC
    s_mac = scp03_kdf(base_mac_key, 0x06, context, 128)
    expected_s_mac = bytes.fromhex(vec['expected_session_keys']['s_mac'])
    
    print(f"  S-MAC match: {s_mac == expected_s_mac}")
    if s_mac != expected_s_mac:
        print(f"    Calculated: {s_mac.hex().upper()}")
        print(f"    Expected:   {expected_s_mac.hex().upper()}")
    
    # Derive card cryptogram using S-MAC
    card_cryptogram = scp03_kdf(s_mac, 0x00, context, 64)
    expected_card = bytes.fromhex(vec['expected_cryptograms']['card'])
    
    print(f"  Card cryptogram match: {card_cryptogram == expected_card}")
    if card_cryptogram != expected_card:
        print(f"    Calculated: {card_cryptogram.hex().upper()}")
        print(f"    Expected:   {expected_card.hex().upper()}")
    
    print()