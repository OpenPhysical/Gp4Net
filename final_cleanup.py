#!/usr/bin/env python3
import os
import re

def final_cleanup(filepath):
    """Final cleanup of remaining issues"""
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    
    # Fix BeEquivalentTo on non-array types (enums, nullable numerics)
    # Pattern: EnumAssertions, NullableNumericAssertions
    content = re.sub(
        r'(EnumAssertions<\w+>|NullableNumericAssertions<\w+>|NumericAssertions<\w+>).*?\.BeEquivalentTo\(',
        r'\1.Be(',
        content
    )
    
    # Fix remaining InitializeUpdateResponse.Parse with named parameters
    # This catches the ones that weren't fixed before
    content = re.sub(
        r'InitializeUpdateResponse\.Parse\(\s*keyDiversificationData:\s*([^,]+)\)',
        r'InitializeUpdateResponse.Parse(\1)',
        content
    )
    
    # Fix .Should().Be() calls that still have issues
    # For arrays and collections, use BeEquivalentTo
    # For single values, use Be
    
    # Fix specific patterns
    content = re.sub(r'\.Should\(\)\.BeEquivalentTo\((\d+)\)', r'.Should().Be(\1)', content)
    content = re.sub(r'\.Should\(\)\.BeEquivalentTo\((true|false)\)', r'.Should().Be(\1)', content)
    content = re.sub(r'\.Should\(\)\.BeEquivalentTo\((\w+\.\w+)\)', 
        lambda m: f'.Should().Be({m.group(1)})' if not any(x in m.group(1) for x in ['byte[]', 'new byte', 'Convert.From'])
        else m.group(0), content)
    
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
                if final_cleanup(filepath):
                    fixed_count += 1
    
    return fixed_count

if __name__ == "__main__":
    tests_dir = "/Users/mistial/Projects/Gp4Net/tests/Gp4Net.Tests"
    
    print(f"Processing test files in: {tests_dir}")
    fixed = process_directory(tests_dir)
    print(f"Fixed {fixed} files")