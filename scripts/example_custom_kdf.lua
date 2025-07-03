-- Example: Using custom key derivation
-- This demonstrates how to implement custom KDF logic

-- Load the standard KDF library
require("kdf")

-- Example 1: Custom static keys
function my_custom_keys(context)
    -- Your organization's specific keys
    return {
        enc = from_hex("0123456789ABCDEF0123456789ABCDEF"),
        mac = from_hex("FEDCBA9876543210FEDCBA9876543210"),
        dek = from_hex("0011223344556677889900AABBCCDDEE")
    }
end

-- Example 2: Custom diversification based on card serial
function my_diversified_keys(context)
    -- Base keys
    local base_enc = from_hex("404142434445464748494A4B4C4D4E4F")
    local base_mac = from_hex("505152535455565758595A5B5C5D5E5F")
    local base_dek = from_hex("606162636465666768696A6B6C6D6E6F")
    
    -- Get card serial from CPLC or other source
    local card_data = context.card_data
    if not card_data or #card_data < 8 then
        error("No card data available for diversification")
    end
    
    -- Extract serial number (example: bytes 4-7 of CPLC)
    local serial = card_data:sub(4, 7)
    print("Card serial: " .. hex(serial))
    
    -- Custom diversification algorithm
    -- This is a simple example - use proper KDF in production!
    local function diversify(base_key, serial)
        local div_data = serial .. serial  -- 8 bytes
        
        -- For SCP02, use 3DES ECB
        if context.scp_version == 0x02 then
            return des3_encrypt(base_key, div_data) .. 
                   des3_encrypt(base_key, increment_bytes(div_data))
        else
            -- For SCP03, you might use AES-CMAC or other
            return base_key  -- Placeholder
        end
    end
    
    return {
        enc = diversify(base_enc, serial),
        mac = diversify(base_mac, serial),
        dek = diversify(base_dek, serial)
    }
end

-- Example 3: HSM-based key derivation
function hsm_derived_keys(context)
    -- In production, this would interface with an HSM
    print("Deriving keys via HSM...")
    
    -- Simulate HSM call
    local hsm_request = {
        operation = "derive_gp_keys",
        master_key_id = "GP_MASTER_2024",
        diversification_data = hex(context.card_challenge),
        scp_version = context.scp_version
    }
    
    -- In real implementation, send request to HSM
    -- local response = hsm_call(hsm_request)
    
    -- For demo, return test keys
    return gp_test_keys(context)
end

-- Main script
print("Custom Key Derivation Example")
print("=============================\n")

-- Connect to card
local reader = connect()
if not reader then
    error("No card reader found")
end

print("Connected to: " .. reader)

-- Example 1: Use custom static keys
print("\n1. Testing custom static keys...")
local sc = secure_channel({
    keyset = "script:example_custom_kdf:my_custom_keys"
})

if not sc then
    print("Failed with custom static keys")
else
    print("Success with custom static keys!")
    disconnect()
    reader = connect()
end

-- Example 2: Use diversified keys
print("\n2. Testing diversified keys...")

-- First get card data
local info = get_card_info()
if info and info.cplc then
    -- Try with diversified keys
    sc = secure_channel({
        keyset = "script:example_custom_kdf:my_diversified_keys",
        keyset_param = hex(info.cplc)  -- Pass CPLC as parameter
    })
    
    if not sc then
        print("Failed with diversified keys")
    else
        print("Success with diversified keys!")
    end
else
    print("Could not get card data for diversification")
end

-- Example 3: Direct key specification
print("\n3. Testing direct key specification...")
disconnect()
reader = connect()

sc = secure_channel({
    key_enc = "404142434445464748494A4B4C4D4E4F",
    key_mac = "404142434445464748494A4B4C4D4E4F",
    key_dek = "404142434445464748494A4B4C4D4E4F"
})

if not sc then
    print("Failed with direct keys")
else
    print("Success with direct keys!")
    
    -- Show card status
    local apps = get_status()
    print(string.format("\nFound %d application(s)", #apps))
end

disconnect()
print("\nCustom KDF example complete.")