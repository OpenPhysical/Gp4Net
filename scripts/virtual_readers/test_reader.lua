-- Test virtual reader that responds to SELECT commands
local current_index = 1

local test_exchanges = {
    {
        command = "00A4040000",  -- SELECT command
        response = "9000",       -- OK response
        response_time_ms = 15
    },
    {
        command = "80500000080102030405060708009",  -- INITIALIZE UPDATE
        response = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F9000",
        response_time_ms = 25
    }
}

function get_reader_name()
    return "Lua Test Virtual Reader"
end

function get_atr()
    return "3BD518FF8191FE1FC38073C821100A"
end

function process_apdu(command_hex)
    log_debug("Processing APDU: " .. command_hex)
    
    -- Remove spaces and convert to uppercase
    local clean_command = string.gsub(string.upper(command_hex), "%s", "")
    
    if current_index <= #test_exchanges then
        local expected = test_exchanges[current_index]
        
        -- Check if command matches
        if clean_command == expected.command then
            current_index = current_index + 1
            log_info("Matched exchange " .. (current_index - 1) .. ": " .. expected.response)
            return expected.response, expected.response_time_ms
        else
            error(string.format("Command mismatch at exchange %d: expected %s, got %s", 
                current_index, expected.command, clean_command))
        end
    else
        error(string.format("No more exchanges available (current index: %d)", current_index))
    end
end

function disconnect()
    log_info("Virtual reader disconnected")
end