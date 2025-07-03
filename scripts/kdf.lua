-- GlobalPlatform Key Derivation Functions
-- This file contains all standard KDF implementations

-- GP Test Keys (default)
function gp_test_keys(context)
    local static_key = hex("404142434445464748494A4B4C4D4E4F")
    return apply_diversification(static_key, context)
end

-- Visa2 Test Keys
function visa2_keys(context, base_key)
    -- Use provided base key or fall back to default
    local key = base_key or hex("4041424344454647484948B4C4D4E4F")
    return apply_diversification(key, context)
end

-- Visa2 with parameter support (for command line usage)
function visa2(context)
    if not context.params or not context.params.base_key then
        error("visa2 requires parameter 'base_key'")
    end
    
    local base_key = hex(context.params.base_key)
    return apply_diversification(base_key, context)
end

-- JCOP Default Keys
function jcop_keys(context)
    local static_key = hex("404142434445464748494a4b4c4d4e4f")
    return apply_diversification(static_key, context)
end

-- Gemalto Default Keys
function gemalto_keys(context)
    local static_key = hex("47454d5850524553534f53414d504c45")
    return apply_diversification(static_key, context)
end

-- EMV Key Derivation
function emv_keys(context)
    local master_key = context.params and context.params.master_key and 
                      hex(context.params.master_key) or 
                      hex("0123456789ABCDEF0123456789ABCDEF")
    local option = context.params and context.params.option or "A"
    
    if option == "A" then
        return emv_option_a(master_key, context)
    elseif option == "B" then
        return emv_option_b(master_key, context)
    else
        error("Invalid EMV option: " .. option)
    end
end

-- Milenage (3GPP) Key Derivation
function milenage_keys(context)
    if not context.params then
        error("Milenage requires parameters")
    end
    
    local k = context.params.k and hex(context.params.k) or 
              error("Milenage requires parameter 'k'")
    local op = context.params.op and hex(context.params.op) or 
               hex("00000000000000000000000000000000")
    local sqn = context.params.sqn and hex(context.params.sqn) or 
                hex("000000000000")
    
    return milenage_derive(k, op, sqn, context)
end

-- Custom Static Keys
function static_keys(context)
    if not context.params or not context.params.key then
        error("Static keys require parameter 'key'")
    end
    
    local key = hex(context.params.key)
    return {
        enc = key,
        mac = key,
        dek = key,
        rmac = key,
        version = context.params and context.params.version or 0xFF
    }
end

-- Custom Individual Keys
function custom_keys(context)
    if not context.params then
        error("Custom keys require parameters")
    end
    
    return {
        enc = hex(context.params.enc or error("Missing 'enc' parameter")),
        mac = hex(context.params.mac or error("Missing 'mac' parameter")),
        dek = hex(context.params.dek or error("Missing 'dek' parameter")),
        rmac = context.params.rmac and hex(context.params.rmac) or 
               hex(context.params.mac), -- Default rmac to mac
        version = context.params.version or 0xFF
    }
end

-- Main diversification dispatcher
function apply_diversification(base_key, context)
    -- Check for KDD (key diversification data)
    local kdd = context.kdd or context.key_diversification_data
    
    -- Check if we have diversification data
    if not kdd or #kdd == 0 then
        -- No diversification
        return {
            enc = base_key,
            mac = base_key,
            dek = base_key,
            rmac = base_key,
            version = context.key_version or 0xFF
        }
    end
    
    -- Update context with normalized KDD
    context.key_diversification_data = kdd
    
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
            local version = context.scp_id & 0x03
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
        version = context.key_version or 0xFF
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

-- EMV Option A Key Derivation
function emv_option_a(master_key, context)
    local pan = context.params and context.params.pan or 
                context.card_serial or 
                error("EMV Option A requires PAN")
    local psn = context.params and context.params.psn or "00"
    
    -- Ensure PAN is properly formatted (16 digits)
    if type(pan) == "string" then
        pan = pan:gsub("[^0-9]", "") -- Remove non-digits
        while #pan < 16 do
            pan = "0" .. pan
        end
    end
    
    -- Derive keys using EMV Option A method
    -- Left half: PAN || PSN || "F00000000000"
    -- Right half: PAN || PSN || "0F0000000000"
    local data_a = hex(pan .. psn .. "F00000000000")
    local data_b = hex(pan .. psn .. "0F0000000000")
    
    return {
        enc = crypto.des3_ecb(master_key, data_a),
        mac = crypto.des3_ecb(master_key, data_b),
        dek = master_key, -- DEK is typically the master key
        version = 0x00
    }
end

-- EMV Option B Key Derivation
function emv_option_b(master_key, context)
    if not context.params then
        error("EMV Option B requires parameters")
    end
    
    local atc = context.params.atc or error("EMV Option B requires ATC")
    local un = context.params.un and hex(context.params.un) or bytes(4) -- Unpredictable number
    
    -- Ensure ATC is 2 bytes
    if type(atc) == "string" then
        atc = hex(atc)
    end
    if #atc ~= 2 then
        error("ATC must be 2 bytes")
    end
    
    -- Session key derivation
    -- Input: ATC || 00 00 00 00 00 00 || UN
    local sk_input = concat(atc, hex("000000000000"), un)
    
    return {
        enc = crypto.des3_ecb(master_key, concat(sk_input, hex("00000000"))),
        mac = crypto.des3_ecb(master_key, concat(sk_input, hex("00000001"))),
        dek = master_key,
        version = 0x00
    }
end

-- 3GPP Milenage Key Derivation
function milenage_derive(k, op, sqn, context)
    -- This is a simplified version - real Milenage is more complex
    local rand = context.card_challenge or random_bytes(16)
    
    -- Milenage uses AES with specific constants
    local temp = crypto.aes_ecb(k, xor(rand, op))
    
    -- Derive keys with different constants
    return {
        enc = crypto.aes_ecb(k, concat(temp, hex("00000001"))),
        mac = crypto.aes_ecb(k, concat(temp, hex("00000002"))),
        dek = crypto.aes_ecb(k, concat(temp, hex("00000003"))),
        rmac = crypto.aes_ecb(k, concat(temp, hex("00000004"))),
        version = 0x00
    }
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

-- Visa specific key derivation
function visa_derive(base_key, context)
    -- Visa uses a specific derivation method
    local div_data = context.key_diversification_data
    
    -- Visa method: Encrypt diversification data with base key
    local temp = crypto.des3_ecb(base_key, div_data)
    
    return {
        enc = temp,
        mac = temp,
        dek = temp,
        version = context.key_version or 0xFF
    }
end

-- NXP specific key derivation
function nxp_derive(base_key, context)
    -- NXP cards often use UID-based diversification
    local uid = context.card_serial or context.key_diversification_data
    
    if #uid < 8 then
        -- Pad UID to 8 bytes
        uid = concat(uid, bytes(8 - #uid))
    end
    
    -- NXP method varies by card type
    local div_input = concat(uid, uid) -- Simple example
    
    return {
        enc = crypto.des3_ecb(base_key, sub(div_input, 1, 8)),
        mac = crypto.des3_ecb(base_key, sub(div_input, 9, 8)),
        dek = base_key,
        version = context.key_version or 0xFF
    }
end