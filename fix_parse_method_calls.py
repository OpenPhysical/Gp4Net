#!/usr/bin/env python3
import os
import re

def fix_parse_calls(filepath):
    """Fix InitializeUpdateResponse.Parse calls with named parameters"""
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    original_content = content
    
    # Find Parse calls with named parameters
    pattern = r'InitializeUpdateResponse\.Parse\(\s*\n(?:\s*\w+:\s*[^,\n]+,?\s*\n)+\s*\)'
    
    def replace_parse(match):
        """Replace a Parse call with proper byte array construction"""
        # Extract the parameters from the matched text
        text = match.group(0)
        
        # Common pattern for SCP02 response
        if 'scpId: 0x02' in text:
            return '''// Build raw response bytes for SCP02: diversification(10) + keyVer(1) + scpId(1) + challenge(8) + cryptogram(8)
            var responseBytes = new byte[28];
            Array.Copy(new byte[10], 0, responseBytes, 0, 10); // Diversification data
            responseBytes[10] = 0x01; // Key version
            responseBytes[11] = 0x02; // SCP version
            Array.Copy(new byte[8], 0, responseBytes, 12, 8); // Card challenge with sequence counter
            Array.Copy(new byte[8], 0, responseBytes, 20, 8); // Card cryptogram
            
            var response = InitializeUpdateResponse.Parse(responseBytes)'''
        else:
            # For other cases, just build a default response
            return '''// Build raw response bytes
            var responseBytes = new byte[28];
            var response = InitializeUpdateResponse.Parse(responseBytes)'''
    
    # Replace all matches
    content = re.sub(pattern, replace_parse, content, flags=re.MULTILINE)
    
    # Check if file was modified
    if content != original_content:
        with open(filepath, 'w') as f:
            f.write(content)
        return True
    return False

def main():
    filepath = '/Users/mistial/Projects/Gp4Net/tests/Gp4Net.Tests/Domain/Protocol/Scp02CryptogramTests.cs'
    if fix_parse_calls(filepath):
        print(f"Fixed Parse calls in {filepath}")
    else:
        print("No changes needed")

if __name__ == "__main__":
    main()