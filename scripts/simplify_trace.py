#!/usr/bin/env python3
"""
Simplified trace converter for GP Pro traces to minimal JSON format.
"""

import sys
import json
import re
from pathlib import Path

def parse_gp_pro_trace(filename):
    """Parse GP Pro trace file and extract APDU exchanges."""
    exchanges = []
    command_pattern = re.compile(r'^A>> T=\d+ \((\d+)\+(\d+)\) ([0-9A-F\s]+)')
    response_pattern = re.compile(r'^A<< \((\d+)\+(\d+)\) \((\d+)ms\) ([0-9A-F\s]+)')
    
    current_command = None
    
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            
            # Match command
            cmd_match = command_pattern.match(line)
            if cmd_match:
                current_command = cmd_match.group(3).replace(' ', '').upper()
                continue
            
            # Match response
            resp_match = response_pattern.match(line)
            if resp_match and current_command:
                response_time = int(resp_match.group(3))
                response = resp_match.group(4).replace(' ', '').upper()
                exchanges.append({
                    'c': current_command,
                    'r': response,
                    't': response_time if response_time > 20 else None
                })
                current_command = None
    
    return exchanges

def get_description(command):
    """Get simple description for command."""
    if len(command) < 4:
        return None
    
    prefix = command[:4]
    descriptions = {
        '00A4': 'SELECT',
        '80CA': 'GET DATA',
        '80F2': 'GET STATUS',
        '8050': 'INIT UPDATE',
        '8482': 'EXT AUTH',
        '84E6': 'INSTALL',
        '84E8': 'LOAD',
        '84E4': 'DELETE'
    }
    
    desc = descriptions.get(prefix)
    if desc == 'GET DATA' and len(command) >= 8:
        tag = command[4:8]
        tag_names = {
            '9F7F': 'CPLC',
            '0066': 'CARD DATA',
            '0067': 'CARD CAPS',
            '00E0': 'KEY INFO',
            '00CF': 'KDD',
            '00C1': 'SSC',
            '0042': 'IIN',
            '0045': 'CIN'
        }
        tag_name = tag_names.get(tag)
        if tag_name:
            return f'GET {tag_name}'
    
    return desc

def detect_operations(exchanges):
    """Detect operation boundaries."""
    operations = {}
    current_op = None
    op_start = 0
    
    for i, ex in enumerate(exchanges):
        desc = get_description(ex['c'])
        if not desc:
            continue
            
        # Determine operation type
        if 'SELECT' in desc or ('GET' in desc and 'STATUS' not in desc):
            new_op = 'info'
        elif 'INIT UPDATE' in desc or 'EXT AUTH' in desc:
            new_op = 'auth'
        elif 'STATUS' in desc:
            new_op = 'list'
        elif 'INSTALL' in desc or 'LOAD' in desc:
            new_op = 'install'
        elif 'DELETE' in desc:
            new_op = 'delete'
        else:
            continue
            
        if new_op != current_op:
            if current_op:
                operations[current_op] = [op_start + 1, i]
            current_op = new_op
            op_start = i
    
    if current_op:
        operations[current_op] = [op_start + 1, len(exchanges)]
    
    return operations

def extract_card_info(exchanges):
    """Extract card information from exchanges."""
    card_type = "UNKNOWN"
    isd_aid = "A000000151000000"
    
    for ex in exchanges:
        # Check SELECT response for ISD AID
        if ex['c'].startswith('00A4') and 'A000000151' in ex['r']:
            isd_aid = "A000000151000000"
        
        # Check CPLC for card type
        if ex['c'].startswith('80CA9F7F') and ex['r'].startswith('9F7F'):
            if '4790' in ex['r']:
                card_type = "NXP_P71"
    
    return card_type, isd_aid

def convert_trace(input_file, output_file, include_descriptions=True):
    """Convert GP Pro trace to simplified JSON format."""
    exchanges = parse_gp_pro_trace(input_file)
    
    # Format exchanges for readability
    formatted_exchanges = []
    for ex in exchanges:
        formatted_ex = {
            'command': ex['c'],
            'response': ex['r']
        }
        
        # Add description if available
        if include_descriptions:
            desc = get_description(ex['c'])
            if desc:
                formatted_ex['description'] = desc
        
        # Add response time if significant
        if ex.get('t') and ex['t'] > 20:
            formatted_ex['responseTimeMs'] = ex['t']
            
        formatted_exchanges.append(formatted_ex)
    
    # Detect operations
    operations = detect_operations(exchanges)
    
    # Extract card info
    card_type, isd_aid = extract_card_info(exchanges)
    
    # Build final structure with readable formatting
    trace_data = {
        'metadata': {
            'cardType': card_type,
            'atr': '3BD518FF8191FE1FC38073C821100A',
            'isdAid': isd_aid
        },
        'operations': {
            op_name: {
                'startIndex': ranges[0],
                'endIndex': ranges[1]
            }
            for op_name, ranges in operations.items()
        },
        'exchanges': formatted_exchanges
    }
    
    # Write JSON with nice formatting
    with open(output_file, 'w') as f:
        json.dump(trace_data, f, indent=2, ensure_ascii=False)
    
    print(f"✓ Converted {input_file} -> {output_file}")
    print(f"  Exchanges: {len(exchanges)}")
    print(f"  Operations: {', '.join(operations.keys())}")

def main():
    if len(sys.argv) < 3:
        print("Usage: simplify_trace.py <input.txt> <output.json> [--no-descriptions]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    include_descriptions = '--no-descriptions' not in sys.argv
    
    convert_trace(input_file, output_file, include_descriptions)

if __name__ == '__main__':
    main()