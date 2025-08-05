#!/usr/bin/env python3
import re
import sys

def fix_be_equivalent_to(file_path):
    """Fix BeEquivalentTo usage in test files."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    original_content = content
    
    # Pattern to match numeric assertions with BeEquivalentTo
    # This matches patterns like: .Should().BeEquivalentTo(123)
    # For numeric types (int, byte, ushort, etc.)
    numeric_pattern = r'(\.\s*Should\s*\(\s*\)\s*\.\s*)BeEquivalentTo\s*\(\s*(\d+|0x[0-9a-fA-F]+)\s*\)'
    content = re.sub(numeric_pattern, r'\1Be(\2)', content)
    
    # Pattern for boolean assertions
    bool_pattern = r'(\.\s*Should\s*\(\s*\)\s*\.\s*)BeEquivalentTo\s*\(\s*(true|false)\s*\)'
    content = re.sub(bool_pattern, r'\1Be(\2)', content)
    
    # Pattern for numeric variables that might be compared
    # This is trickier - we need to check if the variable being compared is numeric
    # Look for patterns where the assertion is on a numeric type property/field
    patterns_to_fix = [
        (r'(\.StatusWord\s*\.\s*Should\s*\(\s*\)\s*\.\s*)BeEquivalentTo', r'\1Be'),
        (r'(\.BlockNumber\s*\.\s*Should\s*\(\s*\)\s*\.\s*)BeEquivalentTo', r'\1Be'),
        (r'(\.Length\s*\.\s*Should\s*\(\s*\)\s*\.\s*)BeEquivalentTo', r'\1Be'),
        (r'(\.Count\s*\.\s*Should\s*\(\s*\)\s*\.\s*)BeEquivalentTo', r'\1Be'),
        (r'(\.Size\s*\.\s*Should\s*\(\s*\)\s*\.\s*)BeEquivalentTo', r'\1Be'),
        (r'(\.Value\s*\.\s*Should\s*\(\s*\)\s*\.\s*)BeEquivalentTo', r'\1Be'),
        (r'(\.Tag\s*\.\s*Should\s*\(\s*\)\s*\.\s*)BeEquivalentTo', r'\1Be'),
        (r'(\.Type\s*\.\s*Should\s*\(\s*\)\s*\.\s*)BeEquivalentTo', r'\1Be'),
        (r'(\.P1\s*\.\s*Should\s*\(\s*\)\s*\.\s*)BeEquivalentTo', r'\1Be'),
        (r'(\.P2\s*\.\s*Should\s*\(\s*\)\s*\.\s*)BeEquivalentTo', r'\1Be'),
        (r'(command\.BlockNumber\s*\.\s*Should\s*\(\s*\)\s*\.\s*)BeEquivalentTo', r'\1Be'),
        (r'(response\.StatusWord\s*\.\s*Should\s*\(\s*\)\s*\.\s*)BeEquivalentTo', r'\1Be'),
    ]
    
    for pattern, replacement in patterns_to_fix:
        content = re.sub(pattern, replacement, content)
    
    if content != original_content:
        with open(file_path, 'w') as f:
            f.write(content)
        return True
    return False

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: fix_beequivalentto.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    if fix_be_equivalent_to(file_path):
        print(f"Fixed: {file_path}")
    else:
        print(f"No changes: {file_path}")