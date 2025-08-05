#!/usr/bin/env python3
import os
import re

def fix_specific_file(filepath, replacements):
    """Apply specific replacements to a file"""
    with open(filepath, 'r') as f:
        content = f.read()

    original_content = content

    for old, new in replacements:
        content = content.replace(old, new)

    if content != original_content:
        with open(filepath, 'w') as f:
            f.write(content)
        return True
    return False

def main():
    base_dir = '/Users/mistial/Projects/Gp4Net/tests/Gp4Net.Tests'

    # Define specific replacements for each file
    fixes = {
        'Domain/Commands/DeleteCommandTests.cs': [
            ('command.Aids[0].Should().Be(aid);', 'command.Aids[0].Should().BeEquivalentTo(aid);'),
            ('command.DeletionToken.Should().Be(deletionToken);', 'command.DeletionToken.Should().BeEquivalentTo(deletionToken);'),
            ('command.Aids[0].Should().Be(packageAid);', 'command.Aids[0].Should().BeEquivalentTo(packageAid);'),
            ('command.Aids[i].Should().Be(aids[i]);', 'command.Aids[i].Should().BeEquivalentTo(aids[i]);'),
            ('command.Aids[0].Should().Be(new byte[] { keyIdentifier, keyVersion });', 'command.Aids[0].Should().BeEquivalentTo(new byte[] { keyIdentifier, keyVersion });'),
            ('apdu.Skip(7).Take(8).Should().Be(aid);', 'apdu.Skip(7).Take(8).Should().BeEquivalentTo(aid);'),
            ('apdu.Skip(7).Take(aid.Length).Should().Be(aid);', 'apdu.Skip(7).Take(aid.Length).Should().BeEquivalentTo(aid);'),
            ('apdu.Skip(tokenOffset).Take(deletionToken.Length).Should().Be(deletionToken);', 'apdu.Skip(tokenOffset).Take(deletionToken.Length).Should().BeEquivalentTo(deletionToken);'),
            ('apdu.Skip(offset).Take(aid.Length).Should().Be(aid);', 'apdu.Skip(offset).Take(aid.Length).Should().BeEquivalentTo(aid);'),
            ('data.Skip(2).Take(aid.Length).Should().Be(aid);', 'data.Skip(2).Take(aid.Length).Should().BeEquivalentTo(aid);'),
            ('command.Aids[0].Should().Be(originalAids[0]);', 'command.Aids[0].Should().BeEquivalentTo(originalAids[0]);'),
        ],
        'Functional/DeleteCommandFunctionalTests.cs': [
            ('apdu.Skip(7).Take(9).Should().Be(aid);', 'apdu.Skip(7).Take(9).Should().BeEquivalentTo(aid);'),
            ('apdu.Skip(deletionTokenOffset).Take(8).Should().Be(deletionToken);', 'apdu.Skip(deletionTokenOffset).Take(8).Should().BeEquivalentTo(deletionToken);'),
            ('apdu.Skip(11).Should().Be(deletionToken);', 'apdu.Skip(11).Should().BeEquivalentTo(deletionToken);'),
        ],
        'Cryptography/Derive3DesKeyTests.cs': [
            ('derivedKey.Skip(16).Take(8).Should().Be(expectedThirdBlock);', 'derivedKey.Skip(16).Take(8).Should().Be(expectedThirdBlock);'),
        ],
        'Protocol/Scp03ProtocolComplianceTests.cs': [
            ('result.Value.Should().Be(errorResponse, "Error response should be returned as-is");', 'result.Value.Should().BeEquivalentTo(errorResponse, "Error response should be returned as-is");'),
        ],
        'Domain/Keys/SecureSessionKeysTests.cs': [
            ('sessionKeys.UseSEnc(key => key.Should().Be(this._testSEnc));', 'sessionKeys.UseSEnc(key => key.Should().BeEquivalentTo(this._testSEnc));'),
        ],
    }

    modified_files = []

    for relative_path, replacements in fixes.items():
        filepath = os.path.join(base_dir, relative_path)
        if os.path.exists(filepath):
            if fix_specific_file(filepath, replacements):
                modified_files.append(relative_path)

    print(f"Modified {len(modified_files)} files:")
    for f in modified_files:
        print(f"  - {f}")

if __name__ == "__main__":
    main()
