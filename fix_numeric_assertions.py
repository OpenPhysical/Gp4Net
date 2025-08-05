#!/usr/bin/env python3
import os
import re

def fix_numeric_assertions(filepath):
    """Fix incorrect use of .BeEquivalentTo() for numeric types"""
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    original_content = content
    
    # Fix numeric assertions that incorrectly use BeEquivalentTo
    replacements = [
        # For simple numeric types (int, uint, byte, etc)
        (r'\.Length\.Should\(\)\.BeEquivalentTo\(', '.Length.Should().Be('),
        (r'\.Count\.Should\(\)\.BeEquivalentTo\(', '.Count.Should().Be('),
        (r'\.Value\.Should\(\)\.BeEquivalentTo\((\d+)\)', r'.Value.Should().Be(\1)'),
        # For byte values (single byte, not arrays)
        (r'apdu\[(\d+)\]\.Should\(\)\.BeEquivalentTo\(', r'apdu[\1].Should().Be('),
        (r'(\w+)\[(\d+)\]\.Should\(\)\.BeEquivalentTo\((0x[0-9A-Fa-f]+|\d+)\)', r'\1[\2].Should().Be(\3)'),
    ]
    
    for pattern, replacement in replacements:
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
                if fix_numeric_assertions(filepath):
                    modified_files.append(filepath)
    
    print(f"Modified {len(modified_files)} files")
    for f in modified_files:
        print(f"  - {os.path.relpath(f, test_dir)}")

if __name__ == "__main__":
    main()