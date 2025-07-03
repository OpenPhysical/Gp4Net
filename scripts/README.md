# Gp4Net Example Scripts

This directory contains example Lua scripts demonstrating various GlobalPlatform operations using Gp4Net.

## Available Examples

### 1. example_install.lua
Demonstrates installing an applet (specifically OpenFIPS201) using GP Test Keys.

**Usage:**
```bash
gp4net script run example_install.lua
```

### 2. example_personalize.lua
Shows how to personalize a card with custom keys, including key rotation and lifecycle management.

**Usage:**
```bash
gp4net script run example_personalize.lua
```

### 3. example_batch.lua
Processes multiple cards in sequence, useful for production environments or testing.

**Usage:**
```bash
gp4net script run example_batch.lua
```

### 4. example_debug.lua
Diagnostic script that helps troubleshoot card communication issues.

**Usage:**
```bash
gp4net script run example_debug.lua
```

### 5. example_custom_kdf.lua
Demonstrates implementing custom key derivation functions for specific use cases.

**Usage:**
```bash
gp4net script run example_custom_kdf.lua
```

## Core Script Files

### kdf.lua
Contains all standard key derivation functions:
- `gp_test_keys` - GlobalPlatform test keys
- `visa2_keys` - Visa2 key derivation
- `emv_keys` - EMV key derivation
- `milenage_keys` - Milenage algorithm
- And more...

### gpshell.lua
Provides gpshell-compatible functions for easy migration from gpshell scripts.

## Quick Start

1. Ensure you have a smart card reader connected
2. Insert a GlobalPlatform-compliant card
3. Run any example script:
   ```bash
   gp4net script run example_debug.lua
   ```

## Writing Custom Scripts

Scripts have access to these main functions:

### Connection Management
- `connect([reader])` - Connect to a card
- `disconnect()` - Disconnect from card
- `list_readers()` - List available readers

### Secure Channel
- `secure_channel(options)` - Establish secure channel
- Options can include:
  - `keyset` - Name of keyset or script:file:function
  - `key_enc`, `key_mac`, `key_dek` - Direct key specification
  - `scp_version` - Force specific SCP version

### Card Operations
- `get_status()` - Get list of applications
- `get_card_info()` - Get card information
- `install(cap_file, options)` - Install applet
- `delete(aid)` - Delete applet
- `send_apdu(hex_string)` - Send raw APDU

### Utility Functions
- `hex(data)` - Convert binary to hex string
- `from_hex(string)` - Convert hex string to binary
- `sleep(seconds)` - Pause execution

## Tips

1. Always check return values for error handling
2. Use `debug_mode(true)` to see detailed APDU traces
3. Scripts are searched in order: current dir → ~/.gp4net/scripts → system dir
4. Custom KDFs can be implemented in any Lua file and referenced as `script:filename:function`

## Security Notes

- Never hardcode production keys in scripts
- Use environment variables or secure key storage for sensitive keys
- Always use random keys when personalizing cards
- Test scripts thoroughly with test cards before production use