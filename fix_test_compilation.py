#!/usr/bin/env python3
import os
import re
import sys

def fix_file(filepath):
    """Fix compilation issues in a single file."""
    if not os.path.exists(filepath):
        return 0
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    changes = 0
    
    # 1. Fix byte array assertions - Be() should be BeEquivalentTo()
    # Look for patterns where we're asserting on byte arrays
    content = re.sub(
        r'(result\.(?:Value\.)?(?:EncKey|MacKey|KekKey|Data|Response|Payload|Certificate|Hash|Signature|Key|PublicKey|PrivateKey|Modulus|Exponent|P|Q|DP|DQ|InverseQ|D|CardChallenge|HostChallenge|CardCryptogram|HostCryptogram|SequenceCounter|DiversificationData|KeyCheckValue|Apdu|CommandApdu|ResponseApdu|Aid|Rid|Pix|Tag|Value|Tlv|Der|Asn1|X509|Pkcs)(?:\(\))?\.Should\(\))\.Be\(',
        r'\1.BeEquivalentTo(',
        content
    )
    
    # 2. Fix numeric assertions - BeEquivalentTo() should be Be()
    # Look for numeric properties
    content = re.sub(
        r'(result\.(?:Value\.)?(?:Length|Count|Size|Index|Position|Offset|Version|Level|Status|StatusWord|P1|P2|Lc|Le|Cla|Ins|Tag|Id|KeyId|KeyVersion|KeyIndex|SequenceNumber|Counter|Scp|ScpVersion|ScpParameter|MaxDataLength|MaxCommandLength|MaxResponseLength|MemorySize|FreeMemory|UsedMemory|NumberOfApplets|NumberOfPackages|NumberOfKeys)(?:\(\))?\.Should\(\))\.BeEquivalentTo\(',
        r'\1.Be(',
        content
    )
    
    # 3. Fix nullable numeric assertions
    content = re.sub(
        r'(\.Should\(\)\.HaveValue\(\)\.And)\.BeEquivalentTo\(',
        r'\1.Be(',
        content
    )
    
    # 4. Fix GetOrThrow() calls - use Value property instead
    content = re.sub(
        r'\.GetOrThrow\(\)',
        r'.Value',
        content
    )
    
    # 5. Add missing using directives
    if 'Unit' in content and 'using CSharpFunctionalExtensions;' not in content:
        # Find the last using statement
        match = re.search(r'(using [^;]+;\s*\n)(\s*namespace)', content)
        if match:
            content = content[:match.end(1)] + 'using CSharpFunctionalExtensions;\n' + content[match.end(1):]
            changes += 1
    
    # 6. Fix Result<SessionKeys> conversion issues
    # Replace direct usage with .Value
    content = re.sub(
        r'new SecureChannelSession\(([^,]+),\s*([^,]+),\s*(protocol\.DeriveSessionKeys\([^)]+\))\)',
        r'new SecureChannelSession(\1, \2, \3.Value)',
        content
    )
    
    # 7. Fix missing logger parameters in test constructors
    content = re.sub(
        r'new (Scp\d+(?:KeyDerivation|Cryptogram)Strategy)\(\)',
        r'new \1(NullLogger<\1>.Instance)',
        content
    )
    
    # 8. Fix SmartCardService method names
    content = re.sub(r'\.SendCommandAsync\(', r'.ExecuteCommandAsync(', content)
    content = re.sub(r'\.ConnectAsync\(', r'.Connect(', content)
    content = re.sub(r'\.DisconnectAsync\(', r'.Disconnect(', content)
    content = re.sub(r'\.SelectAsync\(', r'.SelectIsdAsync(', content)
    
    # 9. Fix IsSecureChannelEstablished property access
    content = re.sub(
        r'service\.IsSecureChannelEstablished',
        r'service.Session.HasValue',
        content
    )
    
    # 10. Fix specific byte array assertions in tests
    # Match patterns like: bytes.Should().Be(expectedBytes);
    lines = content.split('\n')
    new_lines = []
    for i, line in enumerate(lines):
        if '.Should().Be(' in line:
            # Check if this is likely a byte array by looking at variable names
            if any(keyword in line.lower() for keyword in ['byte', 'key', 'data', 'hash', 'cryptogram', 'challenge', 'response', 'apdu', 'tlv', 'payload', 'certificate', 'signature']):
                # Also check it's not a single byte or numeric
                if not re.search(r'\.Should\(\)\.Be\(0x[0-9A-Fa-f]{1,2}\)', line) and \
                   not re.search(r'\.Should\(\)\.Be\(\d+\)', line) and \
                   not re.search(r'\.Should\(\)\.Be\((true|false)\)', line):
                    line = line.replace('.Should().Be(', '.Should().BeEquivalentTo(')
                    changes += 1
        new_lines.append(line)
    content = '\n'.join(new_lines)
    
    # 11. Fix InitializeUpdateResponse.Parse calls
    content = re.sub(
        r'InitializeUpdateResponse\.Parse\(\s*keyDiversificationData:\s*([^,\)]+)\s*\)',
        r'InitializeUpdateResponse.Parse(\1)',
        content
    )
    
    # 12. Add missing NullLogger using directive if needed
    if 'NullLogger' in content and 'using Microsoft.Extensions.Logging;' not in content:
        match = re.search(r'(using [^;]+;\s*\n)(\s*namespace)', content)
        if match:
            content = content[:match.end(1)] + 'using Microsoft.Extensions.Logging;\n' + content[match.end(1):]
            changes += 1
    
    # Count actual changes
    if content != original_content:
        # Simple line diff count
        changes = sum(1 for a, b in zip(original_content.split('\n'), content.split('\n')) if a != b)
        changes += abs(len(original_content.split('\n')) - len(content.split('\n')))
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
    
    return changes

def main():
    test_dir = 'tests/Gp4Net.Tests'
    total_changes = 0
    files_changed = 0
    
    for root, dirs, files in os.walk(test_dir):
        for file in files:
            if file.endswith('.cs'):
                filepath = os.path.join(root, file)
                changes = fix_file(filepath)
                if changes > 0:
                    print(f"Fixed {changes} lines in {filepath}")
                    total_changes += changes
                    files_changed += 1
    
    print(f"\nTotal files changed: {files_changed}")
    print(f"Total lines changed: {total_changes}")

if __name__ == '__main__':
    main()