#!/usr/bin/env python3
import os
import re

def add_missing_usings(content):
    """Add missing using directives"""
    lines = content.split('\n')
    
    # Find last using statement
    last_using_idx = -1
    for i, line in enumerate(lines):
        if line.strip().startswith('using ') and ';' in line:
            last_using_idx = i
    
    if last_using_idx < 0:
        return content
    
    # Add missing usings based on content
    usings_to_add = []
    
    if 'Option<' in content and 'using CSharpFunctionalExtensions;' not in content:
        usings_to_add.append('using CSharpFunctionalExtensions;')
    
    if 'Mock<' in content and 'using Moq;' not in content:
        usings_to_add.append('using Moq;')
    
    if 'IKeyDerivationService' in content and 'using Gp4Net.Cryptography;' not in content:
        usings_to_add.append('using Gp4Net.Cryptography;')
    
    # Insert usings
    for using in reversed(usings_to_add):
        lines.insert(last_using_idx + 1, using)
    
    return '\n'.join(lines)

def add_missing_fields(content):
    """Add missing fields to test classes"""
    
    # Check if _keyDerivationServiceMock is used but not declared
    if '_keyDerivationServiceMock' in content and 'private Mock<IKeyDerivationService> _keyDerivationServiceMock;' not in content:
        # Find the class declaration
        class_pattern = r'(public class \w+Tests[^{]*\{)'
        match = re.search(class_pattern, content)
        if match:
            # Add field after class opening
            insert_pos = match.end()
            field_decl = '\n        private Mock<IKeyDerivationService> _keyDerivationServiceMock;\n'
            content = content[:insert_pos] + field_decl + content[insert_pos:]
            
            # Also add initialization in SetUp if exists
            setup_pattern = r'(\[SetUp\]\s*public void SetUp\(\)\s*\{)'
            setup_match = re.search(setup_pattern, content)
            if setup_match:
                insert_pos = setup_match.end()
                init_code = '\n            _keyDerivationServiceMock = new Mock<IKeyDerivationService>();'
                content = content[:insert_pos] + init_code + content[insert_pos:]
    
    return content

def fix_remaining_issues(filepath):
    """Fix all remaining compilation issues"""
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    
    # Fix BeEquivalentTo on numeric types - should be Be
    content = re.sub(
        r'(\w+)\.Should\(\)\.BeEquivalentTo\((0x[0-9A-Fa-f]+|[0-9]+)\)',
        r'\1.Should().Be(\2)',
        content
    )
    
    # Fix remaining InitializeUpdateResponse.Parse calls with named parameters
    # This is the simplest form that still has named parameters
    content = re.sub(
        r'InitializeUpdateResponse\.Parse\(\s*keyDiversificationData:\s*([^,]+),\s*keyVersion:\s*([^,]+),\s*scpId:\s*([^,]+),\s*scpParameter:\s*([^,]+),\s*sequenceCounter:\s*([^,]+),\s*cardChallenge:\s*([^,]+),\s*cardCryptogram:\s*([^)]+)\)',
        lambda m: f'''InitializeUpdateResponse.Parse(
                {m.group(1).strip()} // KDD
                    .Concat(new byte[] {{ {m.group(2).strip()} }}) // Key version
                    .Concat(new byte[] {{ {m.group(3).strip()} }}) // SCP ID
                    .Concat(new byte[] {{ {m.group(4).strip()} }}) // SCP parameter
                    .Concat({m.group(5).strip()}) // Sequence counter
                    .Concat({m.group(6).strip()}) // Card challenge
                    .Concat({m.group(7).strip()}) // Card cryptogram
                    .ToArray()
            )''',
        content,
        flags=re.DOTALL
    )
    
    # Add missing usings
    content = add_missing_usings(content)
    
    # Add missing fields
    content = add_missing_fields(content)
    
    # Fix specific Be() calls that should remain BeEquivalentTo for arrays
    # This regex is more precise - only changes Be to BeEquivalentTo for byte arrays
    def fix_be_for_arrays(match):
        full_match = match.group(0)
        var = match.group(1)
        value = match.group(2)
        
        # Check if this is likely a byte array comparison
        if any(indicator in value for indicator in ['new byte[]', 'Convert.FromHex', '.ToArray()', 'byte) {']):
            return f'{var}.Should().BeEquivalentTo({value})'
        # Check if the variable name suggests it's a byte array
        elif any(name in var.lower() for name in ['key', 'data', 'challenge', 'cryptogram', 'mac', 'aid']):
            # But not if it's a single byte comparison
            if not re.match(r'^0x[0-9A-Fa-f]{1,2}$', value.strip()) and not re.match(r'^\d{1,3}$', value.strip()):
                return f'{var}.Should().BeEquivalentTo({value})'
        
        return full_match
    
    content = re.sub(r'(\w+)\.Should\(\)\.Be\(([^)]+)\)', fix_be_for_arrays, content)
    
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
                if fix_remaining_issues(filepath):
                    fixed_count += 1
    
    return fixed_count

if __name__ == "__main__":
    tests_dir = "/Users/mistial/Projects/Gp4Net/tests/Gp4Net.Tests"
    
    print(f"Processing test files in: {tests_dir}")
    fixed = process_directory(tests_dir)
    print(f"Fixed {fixed} files")