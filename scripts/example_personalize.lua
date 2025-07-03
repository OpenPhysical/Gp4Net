-- Example: Personalizing a card with custom keys
-- This script demonstrates key rotation and secure channel establishment

-- Configuration
local config = {
    -- Current keys (GP Test Keys)
    current_keyset = "gp_test_keys",
    
    -- New custom keys (should be randomly generated in production!)
    new_keys = {
        enc = "404142434445464748494A4B4C4D4E4F",
        mac = "505152535455565758595A5B5C5D5E5F",
        dek = "606162636465666768696A6B6C6D6E6F"
    },
    
    -- Key version for the new keys
    new_key_version = 0x01
}

-- Connect to card
local reader = connect()
if not reader then
    error("No card reader found")
end

print("Connected to: " .. reader)
print("Starting personalization process...")

-- Establish secure channel with current keys
local sc = secure_channel({
    keyset = config.current_keyset
})

if not sc then
    error("Failed to establish secure channel with current keys")
end

print("Secure channel established with current keys")

-- Get card and security domain info
local card_info = get_card_info()
print("\nCard Information:")
print("  CPLC: " .. hex(card_info.cplc))
print("  ISD AID: " .. hex(card_info.isd_aid))

-- Put the new keys on the card
print("\nInstalling new key set...")
local result = put_key({
    key_version = config.new_key_version,
    key_id = 1,  -- Start with key ID 1
    keys = {
        { type = "enc", value = config.new_keys.enc },
        { type = "mac", value = config.new_keys.mac },
        { type = "dek", value = config.new_keys.dek }
    },
    -- Use current secure channel to put keys
    replace_existing = true
})

if not result.success then
    error("Failed to put new keys: " .. result.error)
end

print("New keys installed successfully")

-- Disconnect and reconnect to test new keys
disconnect()
print("\nReconnecting with new keys...")

reader = connect()
if not reader then
    error("Failed to reconnect")
end

-- Try to establish secure channel with new keys
sc = secure_channel({
    key_enc = config.new_keys.enc,
    key_mac = config.new_keys.mac,
    key_dek = config.new_keys.dek,
    key_version = config.new_key_version
})

if not sc then
    error("Failed to establish secure channel with new keys")
end

print("Successfully authenticated with new keys!")

-- Optional: Delete old keys
print("\nDeleting old key set...")
result = delete_key({
    key_version = 0x00,  -- GP Test Keys version
    key_id = 0x00
})

if result.success then
    print("Old keys deleted")
else
    print("Warning: Failed to delete old keys: " .. result.error)
end

-- Set card lifecycle to SECURED
print("\nSetting card lifecycle to SECURED...")
result = set_status({
    target = "isd",
    lifecycle = "secured"
})

if result.success then
    print("Card is now in SECURED state")
else
    print("Warning: Failed to set lifecycle: " .. result.error)
end

-- Final status check
print("\nFinal card status:")
local apps = get_status()
for _, app in ipairs(apps) do
    if app.type == "ISD" then
        print(string.format("  ISD: %s", app.state))
        break
    end
end

disconnect()
print("\nPersonalization complete!")