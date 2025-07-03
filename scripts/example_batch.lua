-- Example: Batch operations on multiple cards
-- This script demonstrates processing multiple cards in sequence

-- Configuration
local config = {
    -- CAP file to install
    cap_file = "myapp.cap",
    
    -- Installation parameters
    install_params = {
        instance_aid = "A0000001020304",
        make_selectable = true
    },
    
    -- Keyset to use
    keyset = "gp_test_keys",
    
    -- Number of cards to process (0 = unlimited)
    max_cards = 0,
    
    -- Wait time between cards (seconds)
    wait_between_cards = 2
}

-- Statistics
local stats = {
    processed = 0,
    successful = 0,
    failed = 0,
    errors = {}
}

-- Function to process a single card
function process_card()
    print("\n" .. string.rep("=", 50))
    print("Processing card #" .. (stats.processed + 1))
    print(string.rep("=", 50))
    
    -- Connect to card
    local reader = connect()
    if not reader then
        return false, "No card found"
    end
    
    print("Connected to: " .. reader)
    
    -- Get card info
    local info = get_card_info()
    if info and info.cplc then
        print("Card ID: " .. hex(info.cplc:sub(1, 8)))
    end
    
    -- Establish secure channel
    local sc = secure_channel({ keyset = config.keyset })
    if not sc then
        disconnect()
        return false, "Failed to establish secure channel"
    end
    
    print("Secure channel established")
    
    -- Check if applet already exists
    local apps = get_status()
    local already_installed = false
    for _, app in ipairs(apps) do
        if app.aid == from_hex(config.install_params.instance_aid) then
            already_installed = true
            break
        end
    end
    
    if already_installed then
        print("Applet already installed, skipping...")
        disconnect()
        return true, "Already installed"
    end
    
    -- Install the applet
    print("Installing applet...")
    local result = install(config.cap_file, config.install_params)
    
    if not result.success then
        disconnect()
        return false, "Installation failed: " .. result.error
    end
    
    print("Installation successful!")
    
    -- Verify installation
    apps = get_status()
    local verified = false
    for _, app in ipairs(apps) do
        if app.aid == from_hex(config.install_params.instance_aid) then
            verified = true
            print("Verification: Applet is " .. app.state)
            break
        end
    end
    
    if not verified then
        disconnect()
        return false, "Verification failed - applet not found"
    end
    
    disconnect()
    return true, "Success"
end

-- Main batch processing loop
print("Starting batch processing...")
print("Press Ctrl+C to stop\n")

while config.max_cards == 0 or stats.processed < config.max_cards do
    -- Prompt for card
    if stats.processed > 0 then
        print("\n" .. string.rep("-", 50))
        print("Please insert next card and press Enter...")
        print("(Press Ctrl+C to finish)")
        io.read()
    end
    
    -- Process the card
    stats.processed = stats.processed + 1
    local success, message = process_card()
    
    if success then
        stats.successful = stats.successful + 1
        print("\n✓ Card processed successfully: " .. message)
    else
        stats.failed = stats.failed + 1
        table.insert(stats.errors, {
            card = stats.processed,
            error = message
        })
        print("\n✗ Card processing failed: " .. message)
    end
    
    -- Show running statistics
    print("\nStatistics:")
    print(string.format("  Processed: %d", stats.processed))
    print(string.format("  Successful: %d (%.1f%%)", 
        stats.successful, 
        stats.successful / stats.processed * 100))
    print(string.format("  Failed: %d (%.1f%%)", 
        stats.failed, 
        stats.failed / stats.processed * 100))
    
    -- Wait between cards if configured
    if config.wait_between_cards > 0 and 
       (config.max_cards == 0 or stats.processed < config.max_cards) then
        print(string.format("\nWaiting %d seconds...", config.wait_between_cards))
        sleep(config.wait_between_cards)
    end
end

-- Final report
print("\n" .. string.rep("=", 50))
print("BATCH PROCESSING COMPLETE")
print(string.rep("=", 50))
print(string.format("Total cards processed: %d", stats.processed))
print(string.format("Successful: %d (%.1f%%)", 
    stats.successful, 
    stats.successful / stats.processed * 100))
print(string.format("Failed: %d (%.1f%%)", 
    stats.failed, 
    stats.failed / stats.processed * 100))

if #stats.errors > 0 then
    print("\nErrors encountered:")
    for _, err in ipairs(stats.errors) do
        print(string.format("  Card #%d: %s", err.card, err.error))
    end
end

print("\nBatch processing finished.")