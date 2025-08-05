# Trace Test Data

This directory contains JSON-formatted trace files used for automated testing of GlobalPlatform protocol implementations.

## Directory Structure

```
Traces/
├── SCP02/          # Traces using SCP02 protocol
├── SCP03/          # Traces using SCP03 protocol  
├── Mixed/          # Traces with protocol transitions or unknown versions
└── Invalid/        # Traces with errors or invalid operations
```

## Trace Format

Each JSON trace file contains:

1. **Metadata**: Information about the trace source and card
2. **Sessions**: Secure channel session information
3. **Exchanges**: APDU command/response pairs
4. **Test Hints**: Automatically generated testing metadata

### Example Structure

```json
{
  "metadata": {
    "source": {
      "file": "original_trace.txt",
      "type": "gp_pro",
      "generated": "2024-01-15T10:00:00Z"
    },
    "card": {
      "atr": "3BD518FF8191FE1FC38073C821100A",
      "isd_aid": "A000000151000000"
    }
  },
  "test_hints": {
    "testable_operations": [
      {
        "name": "initialize_update",
        "exchange_index": 3,
        "verify": ["key_derivation", "card_cryptogram"],
        "required_data": ["static_keys"]
      }
    ],
    "scp_version": 3
  },
  "exchanges": [
    {
      "command": "00A404000800A0000001510000",
      "response": "6F108408A000000151000000A5049F65019000"
    }
  ]
}
```

## Converting New Traces

To add new traces:

```bash
# Convert all traces in a directory
python scripts/convert_all_traces.py --input-dir new_traces/ --enhance

# Convert with known static keys for validation
python scripts/convert_all_traces.py --static-keys 404142434445464748494A4B4C4D4E4F

# Convert specific trace type
python scripts/convert_all_traces.py --filter scp03
```

## Test Discovery

The dynamic test discovery system automatically:
1. Scans all JSON files in this directory
2. Generates tests for each testable operation
3. Names tests as: `trace_test_{filename}_{operation}`

## Adding Test Hints

Test hints can be manually added to provide additional validation:

```json
{
  "metadata": {
    "hints": {
      "static_keys": "404142434445464748494A4B4C4D4E4F",
      "expected_session_keys": {
        "s_enc": "7392646744DF8721131C4A995A845BAE",
        "s_mac": "CD9F750E543E0CF862B0EA73E3812113"
      }
    }
  }
}
```

## Dynamic Test Discovery

The `DynamicTraceTests` class automatically:
- Scans all JSON files in subdirectories
- Generates individual tests for each testable operation
- Creates named tests visible in IDE: `trace_test_{filename}_{operation}`
- Provides detailed failure information for debugging

### Supported Operations
- **SELECT**: Application selection and FCI parsing
- **INITIALIZE UPDATE**: Key diversification and cryptogram verification
- **EXTERNAL AUTHENTICATE**: Host cryptogram and session establishment
- **Secure Commands**: C-MAC/R-MAC verification for wrapped commands

## Validation

Traces are validated for:
- Complete APDU structure
- Proper secure channel establishment  
- Response status words
- Required data for testing
- Protocol compliance per GP specifications

Warnings are added to traces with issues but they may still be used for negative testing.

## Implementation Status

Current implementation (as of 2025-08-04):
- ✅ Trace conversion pipeline (GP Pro, GPShell formats)
- ✅ Automatic test discovery and generation
- ✅ JSON schema with metadata and test hints
- ✅ Operation-specific verification framework
- 🚧 Full verifier implementations (basic framework in place)
- 🚧 Static key integration for cryptogram verification