#!/usr/bin/env python3
import os
import re
import sys

def fix_be_equivalentto_in_file(filepath):
    """Fix remaining .Be() to .BeEquivalentTo() for byte arrays"""
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    original_content = content
    
    # More aggressive patterns for byte array assertions
    patterns = [
        # Properties that are commonly byte arrays
        (r'(\.SEnc|\.SMac|\.Dek|\.SRMac|\.Key|\.Value|\.Enc|\.Mac)\.Should\(\)\.Be\(', r'\1.Should().BeEquivalentTo('),
        
        # Method calls that definitely return byte arrays  
        (r'(sessionKeys\.\w+|keys\.\w+)\.Should\(\)\.Be\(', r'\1.Should().BeEquivalentTo('),
        
        # firstHalf, secondHalf patterns from Derive3DesKeyTests
        (r'(firstHalf|secondHalf|expectedByte)\.Should\(\)\.Be\(', r'\1.Should().BeEquivalentTo('),
        
        # Arrays with indices
        (r'(result\.Value\[\d+ \+ i\]|apdu\[\d+\])\.Should\(\)\.Be\(', r'\1.Should().Be('),  # Keep Be() for single elements
        
        # Skip/Take patterns that return collections
        (r'(\.Skip\(\d+\)\.Take\(\d+\))\.Should\(\)\.Be\(', r'\1.Should().BeEquivalentTo('),
        
        # Specific fixes for files
        # TlvParserTests
        (r'(multiConstructedTlv\.Children\[\d+\]\.Tag)\.Should\(\)\.Be\(', r'\1.Should().BeEquivalentTo('),
        (r'(multiConstructedTlv\.Children\[\d+\]\.Value)\.Should\(\)\.Be\(', r'\1.Should().BeEquivalentTo('),
        (r'(multiConstructedTlv\.Children\[\d+\]\.Content)\.Should\(\)\.Be\(', r'\1.Should().BeEquivalentTo('),
        
        # StoreDataCommandTests
        (r'(command\.Data)\.Should\(\)\.Be\(', r'\1.Should().BeEquivalentTo('),
        
        # SecurityDomainInfoCodecTests & CardCapabilitiesCodecTests
        (r'(decoded\.Value\.\w+|tlv\.\w+|element\.Content)\.Should\(\)\.Be\(', r'\1.Should().BeEquivalentTo('),
    ]
    
    for pattern, replacement in patterns:
        content = re.sub(pattern, replacement, content)
    
    # Check if file was modified
    if content != original_content:
        with open(filepath, 'w') as f:
            f.write(content)
        return True
    return False

def main():
    test_dir = '/Users/mistial/Projects/Gp4Net/tests/Gp4Net.Tests'
    modified_files = []
    
    # Target specific files we know have issues
    target_files = [
        'Cryptography/KeyDerivationTests.cs',
        'Core/Tlv/TlvParserTests.cs',
        'Domain/Commands/StoreDataCommandTests.cs',
        'Cryptography/Derive3DesKeyTests.cs',
        'Domain/DataObjects/SecurityDomainInfoCodecTests.cs',
        'Domain/Keys/SecureSessionKeysTests.cs',
        'Domain/DataObjects/CardCapabilitiesCodecTests.cs',
    ]
    
    for target_file in target_files:
        filepath = os.path.join(test_dir, target_file)
        if os.path.exists(filepath):
            if fix_be_equivalentto_in_file(filepath):
                modified_files.append(filepath)
    
    print(f"Modified {len(modified_files)} files")
    for f in modified_files:
        print(f"  - {f}")

if __name__ == "__main__":
    main()