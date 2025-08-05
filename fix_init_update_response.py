#!/usr/bin/env python3
import os
import re

def fix_init_update_response(filepath):
    """Fix InitializeUpdateResponse.Parse calls"""
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    
    # Fix simpler InitializeUpdateResponse.Parse patterns still using named parameters
    # Pattern: InitializeUpdateResponse.Parse(keyDiversificationData: new byte[10], ...)
    content = re.sub(
        r'InitializeUpdateResponse\.Parse\(\s*keyDiversificationData:\s*new byte\[10\],\s*keyVersion:\s*([^,]+),\s*scpId:\s*([^,]+),\s*scpParameter:\s*([^,]+),\s*sequenceCounter:\s*([^,]+),\s*cardChallenge:\s*([^,]+),\s*cardCryptogram:\s*([^)]+)\)',
        lambda m: f'''InitializeUpdateResponse.Parse(
                new byte[10] // KDD (10 bytes)
                    .Concat(new byte[] {{ {m.group(1).strip()} }}) // Key version
                    .Concat(new byte[] {{ {m.group(2).strip()} }}) // SCP ID
                    .Concat(new byte[] {{ {m.group(3).strip()} }}) // SCP parameter
                    .Concat({m.group(4).strip()}) // Sequence counter
                    .Concat({m.group(5).strip()}) // Card challenge
                    .Concat({m.group(6).strip()}) // Card cryptogram
                    .ToArray()
            )''',
        content,
        flags=re.DOTALL
    )
    
    # Add missing using System.Linq if Concat is used but Linq is not imported
    if '.Concat(' in content and 'using System.Linq;' not in content:
        # Find the last using statement
        lines = content.split('\n')
        last_using_idx = -1
        for i, line in enumerate(lines):
            if line.strip().startswith('using ') and ';' in line:
                last_using_idx = i
        
        if last_using_idx >= 0:
            lines.insert(last_using_idx + 1, 'using System.Linq;')
            content = '\n'.join(lines)
    
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
                if fix_init_update_response(filepath):
                    fixed_count += 1
    
    return fixed_count

if __name__ == "__main__":
    tests_dir = "/Users/mistial/Projects/Gp4Net/tests/Gp4Net.Tests"
    
    print(f"Processing test files in: {tests_dir}")
    fixed = process_directory(tests_dir)
    print(f"Fixed {fixed} files")