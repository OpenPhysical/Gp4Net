-- GlobalPlatform Test Keys
-- Usage: gp_test_keys (no arguments needed)

function main(args)
    -- GP Test Keys are static: 404142434445464748494A4B4C4D4E4F
    local static_key = "404142434445464748494A4B4C4D4E4F"
    
    -- Return static keys for SCP03 - the card will handle session key derivation
    return {
        enc = static_key,
        mac = static_key,
        dek = static_key,
        rmac = static_key,  -- Include RMAC for SCP03
        version = 0x00      -- Key version 0 as shown in GP Pro output
    }
end

-- Apply diversification based on card response
function apply_diversification(base_key, context)
    -- Check for KDD (key diversification data)
    local kdd = context.key_diversification_data
    
    -- Check if we have diversification data
    if not kdd or #kdd == 0 then
        -- No diversification - return static keys
        return {
            enc = base_key,
            mac = base_key,
            dek = base_key,
            rmac = base_key,
            version = context.key_version or 0x00
        }
    end
    
    -- Detect protocol and apply appropriate diversification
    local protocol = context.protocol
    local scp_version = context.scp_version or context.scp_id
    
    if protocol == "SCP02" or scp_version == 0x02 then
        return scp02_diversify(base_key, context)
    elseif protocol == "SCP03" or scp_version == 0x03 then
        return scp03_diversify(base_key, context)
    else
        -- Try to auto-detect based on SCP ID if available
        if context.scp_id then
            local version = bit32.band(context.scp_id, 0x03)
            if version == 0x02 then
                return scp02_diversify(base_key, context)
            elseif version == 0x03 then
                return scp03_diversify(base_key, context)
            end
        end
        
        -- Default to SCP02 if version not clear
        return scp02_diversify(base_key, context)
    end
end

-- SCP02 Key Diversification
function scp02_diversify(base_key, context)
    local div_data = context.key_diversification_data
    local sequence = context.sequence_counter or bytes(2)
    
    -- Construct derivation data for each key type
    -- SCP02 uses: sequence_counter || key_type
    local enc_div = concat(sequence, hex("0182"))
    local mac_div = concat(sequence, hex("0101"))
    local dek_div = concat(sequence, hex("0181"))
    
    return {
        enc = derive_3des_key(base_key, concat(div_data, enc_div)),
        mac = derive_3des_key(base_key, concat(div_data, mac_div)),
        dek = derive_3des_key(base_key, concat(div_data, dek_div)),
        version = context.key_version or 0x00
    }
end

-- SCP03 Key Diversification (SP800-108)
function scp03_diversify(base_key, context)
    local div_data = context.key_diversification_data
    
    -- Label constants for SCP03 key derivation
    local labels = {
        enc = hex("0000000100"),  -- Label for S-ENC
        mac = hex("0000000200"),  -- Label for S-MAC
        rmac = hex("0000000300"), -- Label for S-RMAC
        dek = hex("0000000400")   -- Label for S-DEK
    }
    
    local keys = {}
    for name, label in pairs(labels) do
        -- SP800-108 context: label || 0x00 || L(i) || 0x01 || diversification_data
        local context_data = concat(
            label,
            bytes({0x00}),           -- Separator
            bytes({0x00, 0x80}),     -- Length (128 bits)
            bytes({0x01}),           -- Counter
            div_data
        )
        keys[name] = cmac_kdf(base_key, context_data, 16)
    end
    
    keys.version = context.key_version or 0xFF
    return keys
end

-- Helper: 3DES key derivation
function derive_3des_key(base_key, data)
    -- Pad data to 8-byte boundary
    local padded = pad80(data, 8)
    
    -- Encrypt each block with base key, use last block as result
    local result = bytes(8)
    for i = 1, #padded, 8 do
        local block = sub(padded, i, 8)
        result = crypto.des3_ecb(base_key, block)
    end
    
    -- For 3DES, we need 16 bytes minimum
    if #base_key == 16 then
        -- Already 16 bytes, use as-is
        return result
    elseif #result == 8 then
        -- Double the key for 2-key 3DES
        return concat(result, result)
    else
        return result
    end
end

-- CMAC-based KDF (SP800-108)
function cmac_kdf(key, context, length)
    local output = bytes(0)
    local counter = 1
    
    while #output < length do
        local input = concat(
            bytes({counter}),
            context
        )
        local block = crypto.cmac_aes(key, input)
        output = concat(output, block)
        counter = counter + 1
    end
    
    return sub(output, 1, length)
end