import json

with open('scripts/scp03_test_vectors.json') as f:
    data = json.load(f)
    
# Find the first test vector (Sequential Pattern Keys)
for vec in data['vectors']:
    if vec['name'] == 'Sequential Pattern Keys':
        print(f"Name: {vec['name']}")
        print(f"Static MAC key: {vec['static_mac_key']}")
        print(f"Host challenge: {vec['host_challenge']}")
        print(f"Card challenge: {vec['card_challenge']}")
        print(f"Expected S-MAC: {vec['expected_s_mac_key']}")
        print(f"Expected card cryptogram: {vec['expected_card_cryptogram']}")
        print()
        break

print("Debug program used:")
print("Static MAC key: 101112131415161718191A1B1C1D1E1F")
print("Host challenge: 0001020304050607")
print("Card challenge: 08090A0B0C0D0E0F")
print("Expected S-MAC: E792DFFE94F89EB1407A797103A6CBEC")
print("Expected card cryptogram: DA6BE6D6F781BCF7")
