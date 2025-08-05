#!/usr/bin/env python3
import os
import re

def fix_remaining_errors(filepath):
    """Fix remaining compilation errors"""
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    
    # Fix byte array assertions - Should() for arrays returns GenericCollectionAssertions which uses BeEquivalentTo
    content = re.sub(r'(\w+)\.Should\(\)\.Be\(new byte\[\] \{([^}]+)\}\)', r'\1.Should().BeEquivalentTo(new byte[] {\2})', content)
    content = re.sub(r'(\w+)\.Should\(\)\.Be\(Convert\.FromHexString\(([^)]+)\)\)', r'\1.Should().BeEquivalentTo(Convert.FromHexString(\2))', content)
    content = re.sub(r'(\w+)\.Should\(\)\.Be\(new List<byte>\[\]\)', r'\1.Should().BeEmpty()', content)
    content = re.sub(r'(\w+)\.Should\(\)\.Be\(Array\.Empty<byte>\(\)\)', r'\1.Should().BeEmpty()', content)
    
    # Fix generic byte array comparisons with variables
    # This regex looks for patterns like: someVar.Should().Be(otherByteVar)
    # where the variable is likely a byte[] based on context
    content = re.sub(r'(\b\w+\.(Tag|Value|Oid|SEnc|SMac|Dek|EncKey|MacKey|RmacKey|Data|ApplicationAid|CardData|ImageData|LifeCycleData|SecurityDomainAid|IssuerIdentificationNumber|CardImageNumber|DiscretionaryData|KeyTypes)\b\.Should\(\))\.Be\((\w+)\)', r'\1.BeEquivalentTo(\3)', content)
    
    # Fix exception message assertions  
    content = re.sub(r'var ex = act\.Should\(\)\.ThrowExactly<(\w+)>\(\);\s*ex\.Message\.Should\(\)\.Contain\("([^"]+)"\)', 
                    r'act.Should().ThrowExactly<\1>().WithMessage("*\2*")', content)
    
    # Fix standalone exception assertions that were split
    content = re.sub(r'(\w+)\.Should\(\)\.ThrowExactly<(\w+)>\(\);\s*ex\.Message\.Should\(\)\.Contain\("([^"]+)"\)', 
                    r'\1.Should().ThrowExactly<\2>().WithMessage("*\3*")', content)
    
    # Fix InitializeUpdateResponse constructor - likely needs Parse method
    content = re.sub(r'new InitializeUpdateResponse\(([^)]+)\)', r'InitializeUpdateResponse.Parse(\1)', content)
    
    # Fix Scp02KeySet constructor to use Create factory method
    content = re.sub(r'new Scp02KeySet\(([^,]+),\s*([^,]+),\s*([^,]+),\s*([^)]+)\)', 
                    r'Scp02KeySet.Create(\1, \2, \3, \4).Value', content)
    
    # Fix BeAssignableTo back to BeOfType (AwesomeAssertions uses BeOfType)
    content = re.sub(r'\.BeAssignableTo<', '.BeOfType<', content)
    
    # Fix Count assertions
    content = re.sub(r'\.Count\.Should\(\)\.Be\((\d+)\)', r'.Should().HaveCount(\1)', content)
    
    # Fix NotBeNull().And.NotBeEmpty()
    content = re.sub(r'\.Should\(\)\.NotBeNull\(\)\.And\.NotBeEmpty\(\)', '.Should().NotBeEmpty()', content)
    
    # Fix comparison operators
    content = re.sub(r'\.Should\(\)\.BeGreaterThanOrEqualTo\(', '.Should().BeGreaterThanOrEqualTo(', content)
    
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
                if fix_remaining_errors(filepath):
                    fixed_count += 1
    
    return fixed_count

if __name__ == "__main__":
    tests_dir = "/Users/mistial/Projects/Gp4Net/tests/Gp4Net.Tests"
    
    print(f"Processing test files in: {tests_dir}")
    fixed = process_directory(tests_dir)
    print(f"Fixed {fixed} files")