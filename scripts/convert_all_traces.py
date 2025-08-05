#!/usr/bin/env python3
"""
Enhanced batch trace converter with automatic test hint generation.
Converts all trace files and adds testability metadata.
"""

import os
import sys
import json
import argparse
import hashlib
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime

# Import the existing converter
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from convert_trace_json import TraceConverter

# Define trace formats
class TraceFormat:
    GP_PRO = "gp_pro"
    GPSHELL = "gpshell"

@dataclass
class TestHint:
    """Test hint for a specific operation."""
    name: str
    exchange_index: int
    verify: List[str]
    required_data: List[str]
    depends_on: Optional[str] = None

@dataclass
class TestableOperation:
    """Represents a testable operation in the trace."""
    operation_name: str
    exchange_index: int
    command_apdu: str
    response_apdu: str
    scp_version: Optional[int] = None
    session_id: Optional[str] = None

class EnhancedTraceConverter:
    """Enhanced converter that adds test hints and calculates expected values."""
    
    # Known static test keys
    KNOWN_KEYS = {
        "404142434445464748494A4B4C4D4E4F": "GP test keys",
        "000102030405060708090A0B0C0D0E0F": "Sequential test keys"
    }
    
    def __init__(self, static_keys: Optional[str] = None):
        self.static_keys = static_keys
        self.base_converter = TraceConverter()
        
    def convert_with_enhancements(self, input_file: str, output_file: str, 
                                 trace_format: str) -> Dict[str, Any]:
        """Convert trace and add test enhancements."""
        # First, do the base conversion
        self.base_converter.convert_to_json(input_file, output_file, trace_format)
        
        # Load the converted JSON
        with open(output_file, 'r') as f:
            enhanced_data = json.load(f)
            
        # Add test hints
        enhanced_data['test_hints'] = self._generate_test_hints(enhanced_data)
        
        # Calculate expected values if possible
        if self.static_keys:
            self._add_expected_values(enhanced_data)
            
        # Add conversion metadata
        enhanced_data['metadata']['conversion'] = {
            'tool_version': '2.0',
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'warnings': self._validate_trace(enhanced_data),
            'enhancements': self._list_enhancements(enhanced_data)
        }
        
        # Save enhanced version
        with open(output_file, 'w') as f:
            json.dump(enhanced_data, f, indent=2)
            
        return enhanced_data
    
    def _generate_test_hints(self, trace_data: Dict) -> Dict[str, Any]:
        """Generate test hints based on trace content."""
        testable_ops = []
        scp_version = None
        
        # Analyze exchanges
        for i, exchange in enumerate(trace_data.get('exchanges', [])):
            op = self._analyze_exchange(exchange, i)
            if op:
                # Detect SCP version from INITIALIZE UPDATE response
                if op['name'] == 'initialize_update' and 'response' in exchange:
                    scp_version = self._detect_scp_version(exchange['response'])
                    
                testable_ops.append(op)
        
        # Determine skip reason if any
        skip_reason = None
        if not testable_ops:
            skip_reason = "no_testable_operations"
        elif any(op['name'] == 'initialize_update' for op in testable_ops):
            if not self.static_keys and not self._has_session_keys(trace_data):
                skip_reason = "missing_static_keys"
                
        return {
            'testable_operations': testable_ops,
            'skip_reason': skip_reason,
            'scp_version': scp_version,
            'detected_from': 'trace_analysis'
        }
    
    def _analyze_exchange(self, exchange: Dict, index: int) -> Optional[Dict]:
        """Analyze a single exchange for testability."""
        command = exchange.get('command', '')
        if len(command) < 4:
            return None
            
        cla_ins = command[:4].upper()
        
        # Map commands to test operations
        if cla_ins == '00A4':  # SELECT
            return {
                'name': 'select',
                'exchange_index': index,
                'verify': ['response_parsing'],
                'required_data': []
            }
        elif cla_ins == '8050':  # INITIALIZE UPDATE
            return {
                'name': 'initialize_update',
                'exchange_index': index,
                'verify': ['key_derivation', 'card_cryptogram'],
                'required_data': ['static_keys']
            }
        elif cla_ins in ['8482', '0482']:  # EXTERNAL AUTHENTICATE
            return {
                'name': 'external_authenticate',
                'exchange_index': index,
                'verify': ['host_cryptogram', 'mac'],
                'required_data': ['session_keys'],
                'depends_on': 'initialize_update'
            }
        elif self._is_secure_command(command):
            return {
                'name': 'secure_command',
                'exchange_index': index,
                'verify': ['c_mac', 'encryption'],
                'required_data': ['session_keys'],
                'depends_on': 'external_authenticate'
            }
            
        return None
    
    def _detect_scp_version(self, response: str) -> Optional[int]:
        """Detect SCP version from INITIALIZE UPDATE response."""
        if len(response) < 32:
            return None
            
        # Check response length to determine SCP version
        data_len = len(response) - 4  # Remove status word
        if data_len == 28:  # SCP02
            return 2
        elif data_len == 32:  # SCP03
            # Double-check with SCP ID byte
            if len(response) >= 48:
                scp_id = response[22:24]
                if scp_id == '03':
                    return 3
                elif scp_id == '02':
                    return 2
            return 3  # Default to SCP03 for 32-byte response
            
        return None
    
    def _is_secure_command(self, command: str) -> bool:
        """Check if command uses secure messaging."""
        if len(command) < 2:
            return False
        cla = int(command[:2], 16)
        return (cla & 0x04) != 0
    
    def _has_session_keys(self, trace_data: Dict) -> bool:
        """Check if trace contains session keys."""
        for session in trace_data.get('metadata', {}).get('sessions', []):
            if 'session_keys' in session:
                return True
        return False
    
    def _validate_trace(self, trace_data: Dict) -> List[str]:
        """Validate trace completeness and return warnings."""
        warnings = []
        
        # Check for complete secure channel establishment
        has_init_update = False
        has_ext_auth = False
        
        for exchange in trace_data.get('exchanges', []):
            cmd = exchange.get('command', '')[:4].upper()
            if cmd == '8050':
                has_init_update = True
            elif cmd in ['8482', '0482']:
                has_ext_auth = True
                
        if has_init_update and not has_ext_auth:
            warnings.append("incomplete_secure_channel")
            
        # Check for truncated responses
        for i, exchange in enumerate(trace_data.get('exchanges', [])):
            if not exchange.get('response'):
                warnings.append(f"missing_response_at_exchange_{i}")
                
        return warnings
    
    def _list_enhancements(self, trace_data: Dict) -> List[str]:
        """List enhancements made to the trace."""
        enhancements = ['added_test_hints']
        
        if 'expected_session_keys' in trace_data.get('metadata', {}):
            enhancements.append('calculated_expected_keys')
            
        if 'test_hints' in trace_data:
            enhancements.append('analyzed_operations')
            
        return enhancements
    
    def _add_expected_values(self, trace_data: Dict):
        """Add expected values if we can calculate them."""
        # This would integrate with the KeyDerivationService to calculate
        # expected session keys from static keys and challenges
        # For now, just mark that we have static keys
        if self.static_keys:
            trace_data['metadata']['static_keys_hash'] = hashlib.sha256(
                bytes.fromhex(self.static_keys)
            ).hexdigest()[:8]


def convert_all_traces(input_dir: str, output_dir: str, args):
    """Convert all traces in parallel."""
    trace_files = []
    
    # Find all trace files
    for ext in ['*.txt', '*.log']:
        trace_files.extend(Path(input_dir).glob(ext))
    
    # Filter if requested
    if args.filter:
        trace_files = [f for f in trace_files if args.filter.lower() in f.name.lower()]
    
    print(f"Found {len(trace_files)} trace files to convert")
    
    # Create converter
    converter = EnhancedTraceConverter(args.static_keys)
    
    # Convert in parallel
    results = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {}
        
        for trace_file in trace_files:
            # Determine format
            if 'gp_pro' in trace_file.name or trace_file.name.startswith('gp_'):
                format_type = TraceFormat.GP_PRO
            elif 'gpshell' in trace_file.name:
                format_type = TraceFormat.GPSHELL
            else:
                # Try to detect from content
                with open(trace_file, 'r') as f:
                    first_line = f.readline()
                    if 'GlobalPlatformPro' in first_line:
                        format_type = TraceFormat.GP_PRO
                    else:
                        format_type = TraceFormat.GPSHELL
            
            # Determine output directory based on detected SCP version
            output_file = Path(output_dir) / f"{trace_file.stem}.json"
            
            # Submit conversion task
            future = executor.submit(
                convert_single_file,
                converter, trace_file, output_file, format_type, args.verbose
            )
            futures[future] = trace_file
        
        # Process results
        for future in as_completed(futures):
            trace_file = futures[future]
            try:
                result = future.result()
                results.append(result)
                if args.verbose:
                    print(f"✓ Converted {trace_file.name}")
            except Exception as e:
                print(f"✗ Failed to convert {trace_file.name}: {e}")
    
    # Organize files by SCP version
    organize_by_scp_version(results, output_dir)
    
    print(f"\nConverted {len(results)} files successfully")
    

def convert_single_file(converter, input_file, output_file, format_type, verbose):
    """Convert a single file."""
    result = converter.convert_with_enhancements(str(input_file), str(output_file), format_type)
    
    # Return metadata for organization
    return {
        'file': output_file,
        'scp_version': result.get('test_hints', {}).get('scp_version'),
        'has_errors': 'error' in str(input_file).lower() or 'bad' in str(input_file).lower(),
        'warnings': result.get('metadata', {}).get('conversion', {}).get('warnings', [])
    }


def organize_by_scp_version(results: List[Dict], output_dir: str):
    """Organize converted files by SCP version."""
    base_path = Path(output_dir)
    
    for result in results:
        file_path = Path(result['file'])
        
        # Determine target directory
        if result['has_errors']:
            target_dir = base_path / 'Invalid'
        elif result['scp_version'] == 2:
            target_dir = base_path / 'SCP02'
        elif result['scp_version'] == 3:
            target_dir = base_path / 'SCP03'
        else:
            target_dir = base_path / 'Mixed'
        
        # Create directory if needed
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # Move file
        target_file = target_dir / file_path.name
        if file_path != target_file:
            file_path.rename(target_file)


def main():
    parser = argparse.ArgumentParser(description='Enhanced batch trace converter')
    parser.add_argument('--input-dir', default='docs/traces', help='Input directory')
    parser.add_argument('--output-dir', default='tests/Gp4Net.Tests/TestData/Traces',
                       help='Output directory')
    parser.add_argument('--enhance', action='store_true', default=True,
                       help='Add test hints and calculated values')
    parser.add_argument('--static-keys', help='Static keys for session key calculation')
    parser.add_argument('--validate', action='store_true', help='Validate trace completeness')
    parser.add_argument('--filter', help='Filter traces by name')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Create output directory
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    
    # Convert all traces
    convert_all_traces(args.input_dir, args.output_dir, args)


if __name__ == '__main__':
    main()