#!/usr/bin/env python3
import os
import re

def fix_empty_collections(filepath):
    """Fix empty collection syntax errors"""
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    
    # Fix incomplete List< syntax
    content = re.sub(r'\.Be\(new List<;', '.BeEmpty();', content)
    content = re.sub(r'\.Should\(\)\.Be\(new List<;', '.Should().BeEmpty();', content)
    
    # Fix .GetOrThrow() if still present
    content = re.sub(r'\.GetOrThrow\(\)', '.Value', content)
    
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
                if fix_empty_collections(filepath):
                    fixed_count += 1
    
    return fixed_count

if __name__ == "__main__":
    tests_dir = "/Users/mistial/Projects/Gp4Net/tests/Gp4Net.Tests"
    
    print(f"Processing test files in: {tests_dir}")
    fixed = process_directory(tests_dir)
    print(f"Fixed {fixed} files")