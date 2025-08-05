#!/usr/bin/env python3
"""
Convert GP Pro traces to structured APDU trace format for testing.

Usage:
    python convert_gp_trace.py input.txt output.json
"""

import sys
import json
import re
from typing import List, Dict, Optional, Tuple

class ApduExchange:
    def __init__(self, command: str, response: str, response_time: Optional[int] = None):
        self.command = command.replace(" ", "").upper()
        self.response = response.replace(" ", "").upper()
        self.response_time = response_time
    
    def to_dict(self) -> Dict:
        result = {
            "command": self.command,
            "response": self.response
        }
        if self.response_time is not None:
            result["response_time_ms"] = self.response_time
        return result

class GpProTraceConverter:
    def __init__(self):
        # Regex patterns for GP Pro trace lines
        self.command_pattern = re.compile(r'^A>> T=\d+ \([\d+]+\) ([0-9A-F\s]+)$')
        self.response_pattern = re.compile(r'^A<< \([\d+]+\) \((\d+)ms\) ([0-9A-F\s]+)$')
        
    def parse_trace_file(self, filename: str) -> List[ApduExchange]:
        """Parse a GP Pro trace file and extract APDU exchanges."""
        exchanges = []
        current_command = None
        
        with open(filename, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#') or line.startswith('[') or line.startswith('WARNING:'):
                    continue
                
                # Try to match command
                cmd_match = self.command_pattern.match(line)
                if cmd_match:
                    current_command = cmd_match.group(1).strip()
                    continue
                
                # Try to match response
                resp_match = self.response_pattern.match(line)
                if resp_match and current_command:
                    response_time = int(resp_match.group(1))
                    response_data = resp_match.group(2).strip()
                    
                    exchange = ApduExchange(current_command, response_data, response_time)
                    exchanges.append(exchange)
                    current_command = None
                    continue
                
                # Handle other informational lines
                if line.startswith('# ') or 'SCardConnect' in line or 'SCardDisconnect' in line:
                    continue
                
                # Warn about unrecognized lines (but don't fail)
                if current_command is None and not any(x in line for x in ['deleted', 'not present', 'GPSession', 'INFO', 'DEBUG']):
                    print(f"Warning: Unrecognized line {line_num}: {line}")
        
        return exchanges
    
    def extract_challenges_and_keys(self, exchanges: List[ApduExchange]) -> Dict:
        """Extract challenges and session keys from the trace for Lua script."""
        info = {
            "host_challenges": [],
            "card_challenges": [],
            "session_keys": {},
            "key_version": None,
            "scp_version": None
        }
        
        for exchange in exchanges:
            cmd = exchange.command
            resp = exchange.response
            
            # INITIALIZE UPDATE command (80 50 00 00 08 xxxxxxxx 00)
            if cmd.startswith("80500000"):
                if len(cmd) >= 20:  # 80500000 + 08 + 8 bytes challenge + 00
                    host_challenge = cmd[10:26]  # Extract 8-byte challenge
                    info["host_challenges"].append(host_challenge)
            
            # INITIALIZE UPDATE response contains card challenge and other info
            if len(resp) >= 64 and resp.endswith("9000"):  # SCP03 32-byte response + SW
                response_data = resp[:-4]  # Remove SW
                if len(response_data) == 64:  # 32-byte SCP03 response
                    # Parse SCP03 response structure
                    # KDD (10 bytes) + Key Version (1) + SCP ID (1) + Key Info (3) + Card Challenge (8) + Card Cryptogram (8) + Sequence Counter (3)
                    kdd = response_data[:20]
                    key_version = int(response_data[20:22], 16)
                    scp_id = int(response_data[22:24], 16)
                    card_challenge = response_data[30:46]  # 8 bytes
                    card_cryptogram = response_data[46:62]  # 8 bytes
                    
                    info["key_version"] = key_version
                    info["scp_version"] = scp_id & 0x0F
                    info["card_challenges"].append(card_challenge)
        
        return info
    
    def convert_to_lua_format(self, exchanges: List[ApduExchange], info: Dict) -> str:
        """Convert exchanges to Lua script format."""
        lua_script = f'''-- Generated from GP Pro trace
-- SCP Version: {info.get("scp_version", "unknown")}
-- Key Version: {info.get("key_version", "unknown")}

local trace_data = {{
    scp_version = {info.get("scp_version", 3)},
    key_version = {info.get("key_version", 0)},
    host_challenges = {{
'''
        
        for challenge in info["host_challenges"]:
            lua_script += f'        "{challenge}",\n'
        
        lua_script += '''    },
    exchanges = {
'''
        
        for i, exchange in enumerate(exchanges):
            lua_script += f'''        {{
            command = "{exchange.command}",
            response = "{exchange.response}",
            response_time_ms = {exchange.response_time or 20}
        }},
'''
        
        lua_script += '''    }
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
'''
        
        return lua_script

def main():
    if len(sys.argv) != 3:
        print("Usage: python convert_gp_trace.py input.txt output.lua")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    converter = GpProTraceConverter()
    
    try:
        # Parse the trace file
        print(f"Parsing trace file: {input_file}")
        exchanges = converter.parse_trace_file(input_file)
        print(f"Found {len(exchanges)} APDU exchanges")
        
        # Extract additional information
        info = converter.extract_challenges_and_keys(exchanges)
        print(f"Extracted info: SCP{info.get('scp_version', '?')}, Key Version {info.get('key_version', '?')}")
        
        # Convert to appropriate format based on output extension
        if output_file.endswith('.lua'):
            # Generate Lua script
            lua_content = converter.convert_to_lua_format(exchanges, info)
            with open(output_file, 'w') as f:
                f.write(lua_content)
            print(f"Generated Lua trace script: {output_file}")
        else:
            # Generate JSON format
            output_data = {
                "metadata": info,
                "exchanges": [ex.to_dict() for ex in exchanges]
            }
            
            with open(output_file, 'w') as f:
                json.dump(output_data, f, indent=2)
            print(f"Generated JSON trace file: {output_file}")
        
        # Print summary
        print(f"\nSummary:")
        print(f"  Total exchanges: {len(exchanges)}")
        print(f"  Host challenges: {len(info['host_challenges'])}")
        print(f"  Card challenges: {len(info['card_challenges'])}")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()