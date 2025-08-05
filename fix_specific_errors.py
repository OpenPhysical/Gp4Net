#!/usr/bin/env python3
import os
import re

def fix_specific_test_errors(filepath):
    """Fix specific compilation errors in tests"""

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    original_content = content

    # Fix InitializeUpdateResponse.Parse calls that try to pass multiple parameters
    # The Parse method takes a single byte[] parameter, not multiple parameters
    # Pattern: InitializeUpdateResponse.Parse(keyDiversificationData: ..., keyVersion: ..., etc.)
    # Need to convert to building the byte array and passing it
    pattern = r'InitializeUpdateResponse\.Parse\(\s*keyDiversificationData:\s*([^,]+),\s*keyVersion:\s*([^,]+),\s*scpId:\s*([^,]+),\s*scpParameter:\s*([^,]+),\s*sequenceCounter:\s*([^,]+),\s*cardChallenge:\s*([^,]+),\s*cardCryptogram:\s*([^)]+)\)'

    def replace_parse(match):
        kdd = match.group(1).strip()
        key_ver = match.group(2).strip()
        scp_id = match.group(3).strip()
        scp_param = match.group(4).strip()
        seq_counter = match.group(5).strip()
        card_chal = match.group(6).strip()
        card_crypt = match.group(7).strip()

        # Build the response byte array based on the protocol
        return f'''InitializeUpdateResponse.Parse(
                {kdd} // KDD (10 bytes)
                    .Concat(new byte[] {{ {key_ver} }}) // Key version
                    .Concat(new byte[] {{ {scp_id} }}) // SCP ID
                    .Concat(new byte[] {{ {scp_param} }}) // SCP parameter
                    .Concat({seq_counter}) // Sequence counter
                    .Concat({card_chal}) // Card challenge
                    .Concat({card_crypt}) // Card cryptogram
                    .ToArray()
            )'''

    content = re.sub(pattern, replace_parse, content, flags=re.DOTALL)

    # Fix numeric comparisons that should use BeEquivalentTo
    # Pattern: var.Value.Should().Be(0x...)
    content = re.sub(r'\.Value\.Should\(\)\.BeEquivalentTo\(0x([0-9A-Fa-f]+)u?\)', r'.Value.Should().Be(0x\1)', content)

    # Fix Scp02KeySet.Create usage - ensure we're using the Result properly
    content = re.sub(r'var scp02KeySet = Scp02KeySet\.Create\(([^)]+)\)\.Value;',
                    r'var keySetResult = Scp02KeySet.Create(\1);\n            keySetResult.IsSuccess.Should().BeTrue();\n            var scp02KeySet = keySetResult.Value;', content)

    # Fix specific method calls that might need adjustments
    # Example: sessionKeys.Dek (was SDek)
    content = re.sub(r'\.SDek\b', '.Dek', content)

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
                if fix_specific_test_errors(filepath):
                    fixed_count += 1

    return fixed_count

if __name__ == "__main__":
    tests_dir = "/Users/mistial/Projects/Gp4Net/tests/Gp4Net.Tests"

    print(f"Processing test files in: {tests_dir}")
    fixed = process_directory(tests_dir)
    print(f"Fixed {fixed} files")
