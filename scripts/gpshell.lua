-- GPShell compatibility layer
-- Provides gpshell-like scripting capabilities

-- Global card handle
local card = nil
local secure_channel = nil

-- Connect to card
function connect(reader)
    reader = reader or "auto"
    card = gp.connect(reader)
    if not card then
        error("Failed to connect to card")
    end
    print("Connected to: " .. card.reader)
    return card
end

-- Disconnect from card
function disconnect()
    if card then
        gp.disconnect(card)
        card = nil
        secure_channel = nil
        print("Disconnected")
    end
end

-- Establish secure channel
function open_sc(keyset, security_level, params)
    keyset = keyset or "gp_test_keys"
    security_level = security_level or 1
    
    if not card then
        error("Not connected to card")
    end
    
    -- Handle keyset parameters if provided
    local keyset_params = params or {}
    
    -- TODO: Integrate with proper keyset resolution
    secure_channel = gp.establish_secure_channel(card, keyset, security_level)
    if not secure_channel then
        error("Failed to establish secure channel")
    end
    
    print("Secure channel established (SCP" .. 
          string.format("%02X", secure_channel.protocol) .. 
          " S-Level=" .. security_level .. ")")
    return secure_channel
end

-- Close secure channel
function close_sc()
    if secure_channel then
        gp.close_secure_channel(card)
        secure_channel = nil
        print("Secure channel closed")
    end
end

-- Select application
function select(aid)
    if type(aid) == "string" then
        aid = hex(aid)
    end
    
    local response = gp.select(card, aid)
    if response.sw == 0x9000 then
        print("Selected: " .. hex_string(aid))
        return response.data
    else
        error(string.format("Select failed: SW=%04X", response.sw))
    end
end

-- Install CAP file
function install(cap_file, params)
    params = params or {}
    
    local result = gp.install_cap(card, cap_file, {
        instance_aid = params.instance_aid and hex(params.instance_aid),
        privileges = params.privileges or {},
        install_params = params.install_params and hex(params.install_params),
        make_selectable = params.make_selectable ~= false
    })
    
    if result.success then
        print("Installed: " .. cap_file)
        if result.package_aid then
            print("  Package: " .. hex_string(result.package_aid))
        end
        for _, aid in ipairs(result.installed_aids) do
            print("  Applet: " .. hex_string(aid))
        end
    else
        error("Installation failed: " .. (result.error or "Unknown error"))
    end
    
    return result
end

-- Load CAP file (package only)
function load(cap_file, params)
    params = params or {}
    
    local result = gp.load_cap(card, cap_file, {
        package_aid = params.package_aid and hex(params.package_aid),
        security_domain = params.security_domain and hex(params.security_domain),
        dap_blocks = params.dap_blocks
    })
    
    if result.success then
        print("Loaded package: " .. hex_string(result.package_aid))
    else
        error("Load failed: " .. (result.error or "Unknown error"))
    end
    
    return result
end

-- Install applet from loaded package
function install_applet(package_aid, applet_aid, params)
    params = params or {}
    
    if type(package_aid) == "string" then
        package_aid = hex(package_aid)
    end
    if type(applet_aid) == "string" then
        applet_aid = hex(applet_aid)
    end
    
    local result = gp.install_applet(card, package_aid, applet_aid, {
        instance_aid = params.instance_aid and hex(params.instance_aid),
        privileges = params.privileges or {},
        install_params = params.install_params and hex(params.install_params)
    })
    
    if result.success then
        print("Installed applet: " .. hex_string(result.instance_aid or applet_aid))
    else
        error("Install applet failed: " .. (result.error or "Unknown error"))
    end
    
    return result
end

-- Delete application
function delete(aid, params)
    params = params or {}
    
    if type(aid) == "string" then
        aid = hex(aid)
    end
    
    local result = gp.delete(card, aid, {
        cascade = params.cascade ~= false
    })
    
    if result.success then
        print("Deleted: " .. hex_string(aid))
        if result.deleted_aids and #result.deleted_aids > 1 then
            print("Also deleted:")
            for _, deleted_aid in ipairs(result.deleted_aids) do
                if not compare_bytes(deleted_aid, aid) then
                    print("  " .. hex_string(deleted_aid))
                end
            end
        end
    else
        error("Delete failed: " .. (result.error or "Unknown error"))
    end
    
    return result
end

-- Get card status
function get_status(filter)
    filter = filter or "all"
    
    local apps = gp.get_status(card, filter)
    
    print(string.format("%-20s %-35s %-12s %s", "Type", "AID", "State", "Privileges"))
    print(string.rep("-", 80))
    
    for _, app in ipairs(apps) do
        local privs = ""
        if app.privileges and #app.privileges > 0 then
            privs = table.concat(app.privileges, ", ")
        end
        
        print(string.format("%-20s %-35s %-12s %s", 
            app.type or "Unknown",
            hex_string(app.aid),
            app.lifecycle_state or "Unknown",
            privs
        ))
    end
    
    return apps
end

-- Send raw APDU
function send_apdu(apdu_hex)
    local apdu = type(apdu_hex) == "string" and hex(apdu_hex) or apdu_hex
    local response = gp.send_apdu(card, apdu)
    
    print(">> " .. hex_string(apdu))
    print("<< " .. hex_string(response.data) .. " " .. string.format("%04X", response.sw))
    
    return response
end

-- Set lifecycle state
function set_state(aid, state)
    if type(aid) == "string" then
        aid = hex(aid)
    end
    
    local result = gp.set_lifecycle_state(card, aid, state)
    
    if result.success then
        print("Set " .. hex_string(aid) .. " to " .. state)
    else
        error("Set state failed")
    end
    
    return result
end

-- Get card info
function card_info()
    local info = gp.get_card_info(card)
    
    print("Card Information:")
    if info.atr then
        print("  ATR: " .. hex_string(info.atr))
    end
    print("  Protocol: T=" .. (info.protocol or "?"))
    if info.serial then
        print("  Serial: " .. hex_string(info.serial))
    end
    if info.cplc then
        print("  CPLC: " .. hex_string(info.cplc))
    end
    
    return info
end

-- List readers
function list_readers()
    local readers = gp.list_readers()
    
    print("Available readers:")
    for i, reader in ipairs(readers) do
        print("  " .. i .. ": " .. reader)
    end
    
    return readers
end

-- Utility: sleep
function sleep(seconds)
    gp.sleep(seconds * 1000)
end

-- Utility: print hex
function print_hex(data, prefix)
    prefix = prefix or ""
    local hex_data = hex_string(data)
    for i = 1, #hex_data, 32 do
        print(prefix .. string.sub(hex_data, i, math.min(i + 31, #hex_data)))
    end
end

-- Utility: compare bytes
function compare_bytes(a, b)
    if #a ~= #b then
        return false
    end
    for i = 1, #a do
        if a[i] ~= b[i] then
            return false
        end
    end
    return true
end

-- GPShell script compatibility
function run_script(script_file)
    dofile(script_file)
end

-- Authenticate (alias for open_sc)
function authenticate(keyset, security_level)
    return open_sc(keyset, security_level)
end

-- Common aliases
auth = authenticate
sc = open_sc

-- Print banner
print("GPShell Compatibility Layer Loaded")
print("Use connect() to begin")