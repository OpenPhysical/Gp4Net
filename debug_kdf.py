#\!/usr/bin/env python3

# Debug SCP03 key derivation to match GP Pro trace
import binascii

# From GP Pro trace
host_challenge = "FE0530CF61BAA9F3"
card_challenge = "83FA042C5C10F778"
context = host_challenge + card_challenge
print(f"Host challenge: {host_challenge}")
print(f"Card challenge: {card_challenge}")
print(f"Context (16 bytes): {context}")

# Expected session keys from GP Pro
expected_enc = "7392646744DF8721131C4A995A845BAE"
expected_mac = "CD9F750E543E0CF862B0EA73E3812113"
expected_rmac = "D1B695D89DE01992B6CB238BDFB006D9"

print(f"\nExpected session keys:")
print(f"S-ENC:  {expected_enc}")
print(f"S-MAC:  {expected_mac}")
print(f"S-RMAC: {expected_rmac}")

# Base key (all same for GP test keys)
base_key = "404142434445464748494A4B4C4D4E4F"
print(f"\nBase key: {base_key}")

# SCP03 KDF structure for S-ENC (derivation constant 0x04)
# Counter (1 byte) || Label (11 bytes of 0x00) || 0x00 || Derivation Constant || 0x00 || L (2 bytes) || Context (16 bytes)

label = "00" * 11  # 11 bytes of zeros
derivation_enc = "04"
derivation_mac = "06" 
derivation_rmac = "07"
length_bits = "0080"  # 128 bits = 0x0080
context_bytes = context

print(f"\nKDF Structure for S-ENC:")
print(f"Label (11 bytes): {label}")
print(f"Separator: 00")
print(f"Derivation constant: {derivation_enc}")
print(f"Separator: 00")
print(f"Length in bits: {length_bits}")
print(f"Context: {context_bytes}")

# Build fixed input for S-ENC (without counter)
fixed_input_enc = label + "00" + derivation_enc + "00" + length_bits + context_bytes
print(f"\nFixed input for S-ENC (without counter): {fixed_input_enc}")

# With counter 0x01 prefix
full_input_enc = "01" + fixed_input_enc
print(f"Full input for S-ENC (with counter 01): {full_input_enc}")
print(f"Length: {len(full_input_enc)//2} bytes")

