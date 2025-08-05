#!/usr/bin/env python3
import os
import re

def fix_missing_usings(filepath):
    """Fix missing using directives"""
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    
    # Check if the file needs specific using directives
    needs_moq = 'Mock<' in content and 'using Moq;' not in content
    needs_cryptography = 'IKeyDerivationService' in content and 'using Gp4Net.Cryptography;' not in content
    
    if not (needs_moq or needs_cryptography):
        return False
    
    # Find the position to insert using directives
    lines = content.split('\n')
    last_using_idx = -1
    
    for i, line in enumerate(lines):
        if line.strip().startswith('using ') and ';' in line:
            last_using_idx = i
    
    # Insert missing using directives
    if last_using_idx >= 0:
        if needs_cryptography:
            lines.insert(last_using_idx + 1, 'using Gp4Net.Cryptography;')
        if needs_moq:
            lines.insert(last_using_idx + 1, 'using Moq;')
        
        content = '\n'.join(lines)
        
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
                if fix_missing_usings(filepath):
                    fixed_count += 1
    
    return fixed_count

if __name__ == "__main__":
    tests_dir = "/Users/mistial/Projects/Gp4Net/tests/Gp4Net.Tests"
    
    print(f"Processing test files in: {tests_dir}")
    fixed = process_directory(tests_dir)
    print(f"Fixed {fixed} files")