#!/usr/bin/env python3
import re
import sys

def fix_assertions(file_path):
    """Fix various assertion issues in test files."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    original_content = content
    
    # Fix byte array assertions - .Be() doesn't work for byte arrays, use .BeEquivalentTo()
    # But for single bytes and numeric types, use .Be()
    
    # Fix patterns like: tlv.Value.Should().Be(new byte[] { ... })
    # These should use BeEquivalentTo
    content = re.sub(
        r'(\.Should\s*\(\s*\)\s*\.\s*)Be\s*\(\s*new\s+byte\s*\[\s*\]\s*\{',
        r'\1BeEquivalentTo(new byte[] {',
        content
    )
    
    # Fix patterns like: data.Should().Be(expectedBytes) where expectedBytes is likely a byte array
    # Look for .Be() calls on properties that are likely byte arrays
    byte_array_properties = [
        'Value', 'Data', 'Response', 'Cryptogram', 'Mac', 'Key',
        'EncKey', 'MacKey', 'DekKey', 'Kenc', 'Kmac', 'Kdek',
        'Aid', 'ApplicationAid', 'PackageAid', 'Payload',
        'Challenge', 'HostChallenge', 'CardChallenge'
    ]
    
    for prop in byte_array_properties:
        # Fix patterns like: xxx.Value.Should().Be(yyy)
        pattern = rf'(\.\s*{prop}\s*\.\s*Should\s*\(\s*\)\s*\.\s*)Be\s*\('
        content = re.sub(pattern, r'\1BeEquivalentTo(', content)
    
    # Fix enum assertions - enums should use Be() not BeEquivalentTo()
    enum_pattern = r'(\.\s*Should\s*\(\s*\)\s*\.\s*)BeEquivalentTo\s*\(\s*(StoreDataCommand\.[A-Za-z]+\.[A-Za-z]+)\s*\)'
    content = re.sub(enum_pattern, r'\1Be(\2)', content)
    
    # Fix numeric BeEquivalentTo that should be Be
    # For nullable numeric types
    nullable_numeric_pattern = r'(\.Should\s*\(\s*\)\s*\.\s*)BeEquivalentTo\s*\(\s*(\d+|null)\s*\)'
    content = re.sub(nullable_numeric_pattern, r'\1Be(\2)', content)
    
    if content != original_content:
        with open(file_path, 'w') as f:
            f.write(content)
        return True
    return False

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: fix_assertions.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    if fix_assertions(file_path):
        print(f"Fixed: {file_path}")
    else:
        print(f"No changes: {file_path}")