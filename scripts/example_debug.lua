-- Example: Debug and diagnostics script
-- This script helps diagnose card communication issues

-- Enable debug output
debug_mode(true)

print("GlobalPlatform Card Diagnostics")
print("==============================\n")

-- Step 1: List readers
print("Step 1: Checking card readers...")
local readers = list_readers()
if #readers == 0 then
    error("No card readers found. Please check connections.")
end

print(string.format("Found %d reader(s):", #readers))
for i, reader in ipairs(readers) do
    print(string.format("  [%d] %s", i, reader))
end

-- Step 2: Connect to card
print("\nStep 2: Connecting to card...")
local reader = connect()
if not reader then
    error("Failed to connect to card. Is a card inserted?")
end
print("Connected to: " .. reader)

-- Step 3: Get ATR
print("\nStep 3: Reading ATR...")
local atr = get_atr()
if atr then
    print("ATR: " .. hex(atr))
    -- Basic ATR parsing
    if #atr >= 2 then
        local t0 = atr:byte(2)
        print(string.format("  T0: %02X", t0))
        print(string.format("  Historical bytes: %d", t0 & 0x0F))
    end
else
    print("Warning: Could not read ATR")
end

-- Step 4: Try SELECT ISD
print("\nStep 4: Selecting ISD...")
local resp = send_apdu("00A4040000")  -- SELECT with empty AID
print("Response: " .. hex(resp))
if resp:sub(-4) == "9000" then
    print("✓ ISD selected successfully")
else
    print("✗ Failed to select ISD: SW=" .. resp:sub(-4))
end

-- Step 5: Get card data (no secure channel)
print("\nStep 5: Getting card data...")
resp = send_apdu("80CA006600")  -- GET DATA [Card Data]
print("Response: " .. hex(resp))
if resp:sub(-4) == "9000" and #resp > 4 then
    print("✓ Card data retrieved")
else
    print("✗ Could not get card data (may require secure channel)")
end

-- Step 6: Test Initialize Update
print("\nStep 6: Testing INITIALIZE UPDATE...")
-- Generate 8 random bytes for host challenge
local host_challenge = ""
for i = 1, 8 do
    host_challenge = host_challenge .. string.char(math.random(0, 255))
end
print("Host challenge: " .. hex(host_challenge))

-- Build INITIALIZE UPDATE command
local init_update = "8050000008" .. hex(host_challenge) .. "00"
resp = send_apdu(init_update)
print("Response: " .. hex(resp))

if resp:sub(-4) == "9000" and #resp >= 32 then
    print("✓ INITIALIZE UPDATE successful")
    
    -- Parse response
    local key_info = resp:byte(11)
    local key_version = resp:byte(12)
    local scp = resp:byte(13)
    local i = resp:byte(14)
    
    print(string.format("  Key Version: %02X", key_version))
    print(string.format("  SCP: %02X", scp))
    print(string.format("  i parameter: %02X", i))
    
    -- Determine SCP version
    if scp == 0x02 then
        print("  Protocol: SCP02")
    elseif scp == 0x03 then
        print("  Protocol: SCP03")
    else
        print(string.format("  Protocol: Unknown (0x%02X)", scp))
    end
else
    print("✗ INITIALIZE UPDATE failed: SW=" .. resp:sub(-4))
end

-- Step 7: Test secure channel with different keysets
print("\nStep 7: Testing secure channel establishment...")
local keysets_to_try = {
    "gp_test_keys",
    "visa2_keys",
    "emv_keys"
}

local sc_established = false
for _, keyset in ipairs(keysets_to_try) do
    print("\nTrying keyset: " .. keyset)
    
    -- Disconnect and reconnect for clean state
    disconnect()
    reader = connect()
    if not reader then
        print("Failed to reconnect")
        break
    end
    
    local sc = secure_channel({ keyset = keyset })
    if sc then
        print("✓ Secure channel established with " .. keyset)
        sc_established = true
        
        -- Try to get more data with secure channel
        print("\nGetting secure data...")
        local apps = get_status()
        print(string.format("Found %d application(s):", #apps))
        for _, app in ipairs(apps) do
            print(string.format("  %s: %s (%s)", 
                app.type, hex(app.aid), app.state))
        end
        
        break
    else
        print("✗ Failed with " .. keyset)
    end
end

if not sc_established then
    print("\n✗ Could not establish secure channel with any known keyset")
    print("The card may be using custom keys")
end

-- Step 8: Summary
print("\n" .. string.rep("=", 50))
print("DIAGNOSTIC SUMMARY")
print(string.rep("=", 50))
print("Reader connection: ✓")
print("Card communication: ✓")
print("ISD selection: " .. (resp:sub(-4) == "9000" and "✓" or "✗"))
print("Secure channel: " .. (sc_established and "✓" or "✗"))

-- Cleanup
disconnect()
print("\nDisconnected from card")
print("\nDiagnostics complete.")