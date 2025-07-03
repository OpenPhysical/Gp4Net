-- Generated from GP Pro trace
-- SCP Version: 3
-- Key Version: 1

local trace_data = {
    scp_version = 3,
    key_version = 1,
    host_challenges = {
        "FE0530CF61BAA9F3",
    },
    exchanges = {
        {
            command = "00A4040000",
            response = "6F108408A000000151000000A5049F6501FF9000",
            response_time_ms = 20
        },
        {
            command = "80CA9F7F00",
            response = "9F7F2A4790D32147000000000023455589192048390000000000000000186495353839313900000000000000009000",
            response_time_ms = 13
        },
        {
            command = "80CA004200",
            response = "6A88",
            response_time_ms = 12
        },
        {
            command = "80CA004500",
            response = "6A88",
            response_time_ms = 12
        },
        {
            command = "80CA00CF00",
            response = "CF0A037000000000000000009000",
            response_time_ms = 10
        },
        {
            command = "80CA00C100",
            response = "C1030000019000",
            response_time_ms = 13
        },
        {
            command = "80CA006600",
            response = "664D734B06072A864886FC6B01600B06092A864886FC6B020203630906072A864886FC6B03640B06092A864886FC6B040370650D060B2A864886FC6B0507020000660C060A2B060104012A026E01039000",
            response_time_ms = 17
        },
        {
            command = "80CA006700",
            response = "6728A00D800103810500102060708201078103E5BEC082031E030083010284010285017B86010C87017B9000",
            response_time_ms = 14
        },
        {
            command = "80CA00E000",
            response = "E012C00401018810C00402018810C004030188109000",
            response_time_ms = 15
        },
        {
            command = "8050000008FE0530CF61BAA9F300",
            response = "0370000000000000000001037083FA042C5C10F778148C0CAF84B0E1100000029000",
            response_time_ms = 50
        },
        {
            command = "84820100107B54E3B21E27DA5FFCA958062C7CA0C5",
            response = "9000",
            response_time_ms = 18
        },
        {
            command = "84F280020A4F0077E0CA70E6C9352600",
            response = "E3264F08A0000001510000009F700101C5039EFE80C407A0000001515350CC08A0000001510000009000",
            response_time_ms = 20
        },
        {
            command = "84F240020A4F00D46F411D631C8B2200",
            response = "6A88",
            response_time_ms = 12
        },
        {
            command = "84F210020A4F0016C521F604C31ED800",
            response = "E3254F07A00000015153509F700101CE02FFFF8408A000000151535041CC08A000000151000000E3314F0DA00000016443446F634C6974659F700101CE020100840EA00000016443446F634C69746501CC08A000000151000000E31B4F07A00000006202049F700101CE020100CC08A000000151000000E31B4F07A00000006202029F700101CE020103CC08A0000001510000009000",
            response_time_ms = 42
        },
        {
            command = "84F220020A4F00DA32B9900039656800",
            response = "E31B4F07A00000015153509F700101CE02FFFFCC08A000000151000000E3214F0DA00000016443446F634C6974659F700101CE020100CC08A000000151000000E31B4F07A00000006202049F700101CE020100CC08A000000151000000E31B4F07A00000006202029F700101CE020103CC08A0000001510000009000",
            response_time_ms = 38
        },
    }
}

-- Current exchange index
local current_index = 1
local challenge_index = 1

function get_reader_name()
    return "GP Pro Trace Replay"
end

function get_atr()
    return "3BD518FF8191FE1FC38073C821100A"  -- Default ATR from traces
end

function get_next_host_challenge()
    if challenge_index <= #trace_data.host_challenges then
        local challenge = trace_data.host_challenges[challenge_index]
        challenge_index = challenge_index + 1
        return challenge
    end
    -- Generate random challenge if we run out
    return "DEADBEEFCAFEBABE"
end

function process_apdu(command_hex)
    -- Remove spaces and convert to uppercase
    local clean_command = string.gsub(string.upper(command_hex), "%s", "")
    
    if current_index <= #trace_data.exchanges then
        local expected = trace_data.exchanges[current_index]
        
        -- Check if command matches
        if clean_command == expected.command then
            current_index = current_index + 1
            return expected.response, expected.response_time_ms
        else
            error(string.format("Command mismatch at exchange %d: expected %s, got %s", 
                current_index, expected.command, clean_command))
        end
    else
        error(string.format("No more exchanges available (current index: %d)", current_index))
    end
end

function get_status()
    return {
        current_exchange = current_index,
        total_exchanges = #trace_data.exchanges,
        completed = current_index > #trace_data.exchanges
    }
end

return trace_data
