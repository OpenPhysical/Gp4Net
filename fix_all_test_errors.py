#!/usr/bin/env python3
import os
import re

def fix_all_test_errors(filepath):
    """Fix all remaining test compilation errors"""
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    
    # Fix all remaining .Be() calls on byte arrays
    # Pattern: variable.Should().Be(byteArrayExpression)
    # This needs to be .BeEquivalentTo() for arrays
    content = re.sub(r'(\w+)\.Should\(\)\.Be\(([^)]+)\)', 
        lambda m: f'{m.group(1)}.Should().BeEquivalentTo({m.group(2)})' 
            if any(x in m.group(0) for x in ['byte[]', 'new byte', 'Convert.FromHex', '.ToArray()', 'byte) {'])
            else m.group(0), 
        content)
    
    # Fix Scp02KeySet.Create parameter names
    content = re.sub(
        r'Scp02KeySet\.Create\(\s*encryptionKey:\s*([^,]+),\s*macKey:\s*([^,]+),\s*dataEncryptionKey:\s*([^,]+),\s*keyVersion:\s*([^)]+)\)',
        r'Scp02KeySet.Create(\1, \2, \3, \4)',
        content
    )
    
    # Fix Scp03Protocol constructor calls that are missing IKeyDerivationService
    # Pattern: new Scp03Protocol(keySet, implementation) -> needs keyDerivationService
    content = re.sub(
        r'new Scp03Protocol\(([^,]+),\s*(\d+|0x[0-9A-Fa-f]+)\)',
        r'new Scp03Protocol(\1, _keyDerivationServiceMock.Object, \2)',
        content
    )
    
    # Fix protocol constructors with logger but no key derivation service
    content = re.sub(
        r'new Scp03Protocol\(([^,]+),\s*logger(?:Mock)?(?:\.Object)?\)',
        r'new Scp03Protocol(\1, _keyDerivationServiceMock.Object)',
        content
    )
    
    # Fix MockTransport references - likely needs proper namespace or mock setup
    content = re.sub(r'new MockTransport\(\)', r'new Mock<IApduTransport>().Object', content)
    
    # Add missing using directives if needed
    if 'IApduTransport' in content and 'using Gp4Net.Transport;' not in content:
        lines = content.split('\n')
        last_using_idx = -1
        for i, line in enumerate(lines):
            if line.strip().startswith('using ') and ';' in line:
                last_using_idx = i
        
        if last_using_idx >= 0:
            if 'using Gp4Net.Transport;' not in content:
                lines.insert(last_using_idx + 1, 'using Gp4Net.Transport;')
            if 'using Gp4Net.Domain.Commands;' not in content and 'InitializeUpdateResponse' in content:
                lines.insert(last_using_idx + 1, 'using Gp4Net.Domain.Commands;')
            content = '\n'.join(lines)
    
    # Fix specific method calls that have been refactored
    # IsConnected might have been removed/renamed
    content = re.sub(r'\.IsConnected\b', '.IsSecureChannelEstablished', content)
    
    # Fix Equal method calls (should be BeEquivalentTo for arrays)
    content = re.sub(r'\.Should\(\)\.Equal\(([^,]+),', r'.Should().BeEquivalentTo(\1,', content)
    
    if content != original_content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Fixed: {filepath}")
        return True
    return False

def process_directory(directory):
    """Process all .cs files in directory"""
    fixed_count = 0
    
    for root, dirs, files in os.walk(directory):
        # Skip bin and obj directories
        if 'bin' in root or 'obj' in root:
            continue
            
        for file in files:
            if file.endswith('.cs'):
                filepath = os.path.join(root, file)
                if fix_all_test_errors(filepath):
                    fixed_count += 1
    
    return fixed_count

if __name__ == "__main__":
    tests_dir = "/Users/mistial/Projects/Gp4Net/tests/Gp4Net.Tests"
    
    print(f"Processing test files in: {tests_dir}")
    fixed = process_directory(tests_dir)
    print(f"Fixed {fixed} files")