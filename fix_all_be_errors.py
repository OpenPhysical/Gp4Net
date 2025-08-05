#!/usr/bin/env python3
import os
import re
import sys

def fix_be_errors_comprehensive(filepath):
    """Fix all .Be() errors by converting byte array comparisons to .BeEquivalentTo()"""
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    original_content = content
    
    # Strategy: Find all .Should().Be(...) patterns and check if they are likely byte arrays
    # We'll be more aggressive and fix anything that looks like it could be a byte array
    
    # Pattern to find .Should().Be( with capturing groups
    pattern = r'(\s*)(.+?)\.Should\(\)\.Be\(([^)]+)\)(\);.*)?$'
    
    lines = content.split('\n')
    new_lines = []
    
    for line in lines:
        match = re.match(pattern, line)
        if match:
            indent = match.group(1)
            expression = match.group(2)
            value = match.group(3)
            rest = match.group(4) or ');'
            
            # Check if this is likely a byte array comparison
            is_byte_array = False
            
            # Common byte array indicators
            byte_array_indicators = [
                '.Data', '.Bytes', '.Value', '.GetBytes()', '.ToArray()', '.ToBytes()',
                'bytes', 'data', 'payload', 'buffer', 'result', 'expected', 'actual',
                'Convert.FromHexString', '.SEnc', '.SMac', '.Dek', '.SrMac', '.Key',
                'sessionKeys.', 'keys.', 'firstHalf', 'secondHalf', 'apdu[',
                '.Skip(', '.Take(', '.Tag', '.Content', '.Oid', '.Aid',
                'SecurityDomainAid', 'ImageData', 'LifeCycleData', 'CardRecognitionData',
                'CardManagementTypeAndVersion', 'element.', 'tlv.', 'decoded.Value.',
                'new byte[]', 'Array<byte>', 'IEnumerable<byte>', 'ReadOnlySpan<byte>',
                '.Children[', 'NumberToTag', 'command.Data', '.Mac', '.Enc',
                'result.Value[', 'apdu[5..]', '.GetCryptogram()', '.DeriveKey(',
                'cryptogram', 'challenge', 'counter'
            ]
            
            # Check if expression or value contains byte array indicators
            for indicator in byte_array_indicators:
                if indicator in expression or indicator in value:
                    is_byte_array = True
                    break
            
            # Also check if it's comparing against a byte array literal or hex string
            if 'new byte[]' in value or 'Convert.FromHexString' in value or re.match(r'^0x[0-9A-Fa-f]+$', value.strip()):
                is_byte_array = True
            
            # Skip if it's a single byte comparison (like apdu[0])
            if re.match(r'^\w+\[\d+\]$', expression.strip()) and not '..' in expression:
                is_byte_array = False
            
            # Skip if it's comparing simple types (numbers, booleans, etc)
            if value.strip() in ['true', 'false', 'null'] or re.match(r'^\d+$', value.strip()):
                is_byte_array = False
            
            if is_byte_array:
                new_line = f"{indent}{expression}.Should().BeEquivalentTo({value}){rest}"
                new_lines.append(new_line)
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)
    
    new_content = '\n'.join(new_lines)
    
    # Check if file was modified
    if new_content != original_content:
        with open(filepath, 'w') as f:
            f.write(new_content)
        return True
    return False

def main():
    test_dir = '/Users/mistial/Projects/Gp4Net/tests/Gp4Net.Tests'
    modified_files = []
    
    for root, dirs, files in os.walk(test_dir):
        for file in files:
            if file.endswith('.cs'):
                filepath = os.path.join(root, file)
                if fix_be_errors_comprehensive(filepath):
                    modified_files.append(filepath)
    
    print(f"Modified {len(modified_files)} files")
    for f in modified_files:
        print(f"  - {os.path.relpath(f, test_dir)}")

if __name__ == "__main__":
    main()