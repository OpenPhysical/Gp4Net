#!/usr/bin/env python3
import os
import re
import sys

def fix_be_equivalentto_in_file(filepath):
    """Fix .Be() to .BeEquivalentTo() for byte arrays and collections"""
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    original_content = content
    
    # Pattern to match byte array assertions with .Be()
    # This matches patterns like:
    # - someByteArray.Should().Be(otherByteArray)
    # - result.Value.Should().Be(expectedBytes)
    # - GetBytes().Should().Be(expected)
    
    patterns = [
        # Direct byte array comparisons
        (r'(\w+\.)?Should\(\)\.Be\(([^)]+)\);(\s*//.*byte)', r'\1Should().BeEquivalentTo(\2);\3'),
        
        # Byte array properties/methods
        (r'(\.Data|\.Bytes|\.Value|\.GetBytes\(\)|\.ToArray\(\)|\.ToBytes\(\))\.Should\(\)\.Be\(', r'\1.Should().BeEquivalentTo('),
        
        # Common byte array variable names
        (r'(bytes|data|payload|buffer|result|expected|actual)\.Should\(\)\.Be\(([^)]+)\);', r'\1.Should().BeEquivalentTo(\2);'),
        
        # Hex string conversions to byte arrays
        (r'(Convert\.FromHexString\([^)]+\))\.Should\(\)\.Be\(', r'\1.Should().BeEquivalentTo('),
        
        # Method calls returning byte arrays
        (r'(\.Get\w*Bytes\(\)|\.To\w*Bytes\(\)|\.Extract\w*\(\))\.Should\(\)\.Be\(', r'\1.Should().BeEquivalentTo('),
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
    
    for root, dirs, files in os.walk(test_dir):
        for file in files:
            if file.endswith('.cs'):
                filepath = os.path.join(root, file)
                if fix_be_equivalentto_in_file(filepath):
                    modified_files.append(filepath)
    
    print(f"Modified {len(modified_files)} files")
    for f in modified_files:
        print(f"  - {f}")

if __name__ == "__main__":
    main()