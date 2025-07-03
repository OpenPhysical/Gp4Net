-- Example: Installing OpenFIPS201 applet
-- This script demonstrates how to install an applet using GP Test Keys

-- Connect to the first available reader
local reader = connect()
if not reader then
    error("No card reader found")
end

print("Connected to: " .. reader)

-- Establish secure channel with GP Test Keys
local sc = secure_channel({
    keyset = "gp_test_keys"
})

if not sc then
    error("Failed to establish secure channel")
end

print("Secure channel established")

-- Get card status before installation
print("\nCard status before installation:")
local apps = get_status()
for _, app in ipairs(apps) do
    print(string.format("  %s: %s (%s)", app.type, hex(app.aid), app.state))
end

-- Install the CAP file
-- Note: Replace with actual path to OpenFIPS201.cap
local cap_file = "OpenFIPS201.cap"
print("\nInstalling " .. cap_file .. "...")

local result = install(cap_file, {
    -- OpenFIPS201 default AID
    instance_aid = "A000000116DB00",
    -- Make it selectable
    make_selectable = true,
    -- No special privileges needed for OpenFIPS201
    privileges = {}
})

if result.success then
    print("Installation successful!")
    print("Package AID: " .. hex(result.package_aid))
    print("Instance AID: " .. hex(result.instance_aid))
else
    error("Installation failed: " .. result.error)
end

-- Verify installation
print("\nVerifying installation...")
apps = get_status()
local found = false
for _, app in ipairs(apps) do
    if app.aid == from_hex("A000000116DB00") then
        found = true
        print("OpenFIPS201 applet found and " .. app.state)
        break
    end
end

if not found then
    print("Warning: OpenFIPS201 applet not found after installation")
end

-- Disconnect
disconnect()
print("\nDisconnected from card")